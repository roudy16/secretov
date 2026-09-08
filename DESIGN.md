# secretov — design

Local secrets service for developer environments. One daemon, one CLI.
Secrets live in one encrypted file instead of scattered `.env` files.

## Threat model

Protects: secrets at rest (encrypted), access from other UIDs, secret sprawl
across dotfiles/shell history. Does NOT protect against: malware running as
the same user, or root. Accepted ceiling; extend later if needed. Also accepted:
the plaintext header's `key_created_at` is not authenticated, so tampering with
it can only skew rotation scheduling (never expose or corrupt secrets).

After unlock the daemon holds only the data key (see Storage); the passphrase
and the key derived from it are zeroed once the data key is unwrapped. A
reader of daemon memory gets the data key and the decrypted secrets, not the
passphrase.

## Transport

Unix domain socket at `$XDG_RUNTIME_DIR/secretov.sock`, mode 0600, peer UID
checked via `SO_PEERCRED`. The unix socket is the only transport; Listener and
Connection are plain classes over it, not an interface.

## Auth

Single shared API token, minted at `init`, stored in a 0600 file
(`~/.config/secretov/token`). Every request carries it. Revocation =
regenerate. Upgrade path to per-client named tokens changes nothing on the
wire (token stays a string field).

## Protocol

Newline-delimited JSON over the socket.

Request:  `{"token": "...", "op": "get|set|list|getprefix|delete|rotate|passwd", "key": "...", "value": "..."}`
Response: `{"ok": true, "value"|"keys": ...}` or `{"ok": false, "error": "..."}`

Verbs kept minimal. `rotate` and `passwd` are token-guarded admin ops. Both
carry `"old"` (the current passphrase); `passwd` also carries `"new"`. The
daemon does not retain the passphrase, so it verifies `"old"` by deriving the
wrapping key from it and unwrapping the stored data key — a wrong passphrase
fails the MAC. The token alone can change neither the passphrase nor the data
key.

## Storage

One encrypted file (`~/.local/share/secretov/store`), envelope-encrypted:

- A random 256-bit **data key** encrypts the payload: libsodium secretbox
  (XSalsa20-Poly1305) over a JSON key→value map.
- A **wrapping key**, Argon2id-derived from the passphrase, encrypts only the
  data key (secretbox again, its own nonce). It never touches the payload.

The passphrase is entered at daemon start. The daemon derives the wrapping
key, unwraps the data key, then zeroes both passphrase and wrapping key; from
then on it holds only the data key (mlock'd). The binary has no keyring
dependency and works headless; the optional systemd service (`scripts/`)
feeds the passphrase from the session keyring at login.

File header (plaintext, before ciphertext): magic + format version byte (2),
Argon2id salt + params, key-created-at timestamp, wrap nonce, wrapped data
key, payload nonce. Version 1 stores (no envelope: the derived key encrypted
the payload directly) are upgraded in place on first open — decrypt with the
derived key, mint a data key, persist as version 2. One-way; keep a backup if
you might need to roll the binary back.

## Key rotation and passphrase change

Two distinct operations, as in envelope-based managers:

- `rotate` — new data key. Decrypt the payload, re-encrypt under a fresh data
  key, wrap it. Bounds a data-key compromise in time: a key read out of the
  daemon's memory at time T cannot open ciphertext written after the rotation.
  It does nothing for secrets already in the store (a reader of daemon memory
  has those too) and nothing against a leaked passphrase.
- `passwd` — new wrapping key. Fresh salt, derive from the new passphrase,
  re-wrap the existing data key. The payload is untouched, so it is cheap.
  This is the response to a leaked passphrase.

Both are daemon ops that carry the current passphrase (see Protocol), because
the daemon no longer retains it after unlock. Triggers:
- Auto: on unlock, if key-created-at is older than N days (default 30),
  rotate transparently — the passphrase is in hand at that moment.
- Manual: `secretov rotate` and `secretov passwd`, each prompting for the
  current passphrase.

Old ciphertext copies (backups) remain openable with the passphrase and data
key they were written under — copy hygiene is on the user.

## CLI

`secretov` binary: `init`, `daemon`, `get`, `set`, `list`, `delete`,
`rotate` and `passwd` (both prompt for the current passphrase), `tui` (interactive terminal UI over the daemon socket),
`exec --secret NAME ... -- cmd` (fetch secrets, inject into child
env, exec). `set KEY` creates or replaces — there is no separate update op;
it reads the value from stdin only, never an argv argument, which would leak
the secret via `/proc/<pid>/cmdline` to other UIDs.
No client-side caching — the daemon is a local socket away.

## Scopes: projects, environments, manifests

Store keys for scoped secrets are `env/project/KEY` (three segments). The
store stays a flat map; the hierarchy is a naming convention. `shared` is a
conventional environment name with no special handling — nothing is layered
implicitly. Raw `get`/`set`/`delete` remain free-form.

Project manifest, `.secretov.yaml` at the project root (safe to commit: names
only, never values):

```yaml
version: "1"
name: flows-admin
default_env: dev            # optional; -e omitted without it is an error
env:
  dev:
    vars:                                  # plaintext, committed, never stored
      LOG_LEVEL: debug
      API_URL: https://dev.example.com
    secrets:
      database-url:                        # -> dev/flows-admin/database-url
        env_var_name: DATABASE_URL
      openai-key:
        key: shared/flows-admin/openai-key   # explicit full path, any env/project
        env_var_name: OPENAI_API_KEY
```

`vars:` is optional non-secret config: the YAML key is the environment
variable name and the scalar value is injected verbatim, with no store lookup
and no daemon round-trip. It exists so a project needs one file rather than a
manifest plus a leftover `.env` for its non-sensitive settings. **Values here
are committed in plaintext — anything sensitive belongs under `secrets:`.**
Non-string scalars are stringified (`PORT: 8080` injects `"8080"`). A name
appearing in both `vars:` and a secret's `env_var_name` for the same
environment is rejected at parse time rather than given a silent precedence;
`exec` injects vars before secrets, so an explicit `--secret KEY=VAR` on the
command line still wins. `import` only ever writes `secrets:` — `vars:` is
hand-maintained, and manifest edits leave it untouched.

User registry, `~/.config/secretov/projects.yaml`, maps project name to root
(`${HOME}`/`${USER}` expanded) so `-p NAME` works from any directory:

```yaml
projects:
  flows-admin:
    root: "${HOME}/workspace/reshape/autocanvas/apps/flows-admin"
```

Resolution: project = `-p` (registry) else nearest `.secretov.yaml` walking up
from cwd; env = `-e` else `$SECRETOV_ENV` else manifest `default_env` else
error. Env var names come only from the manifest.

Commands: `exec [-p] [-e] [--dry-run] -- cmd` (dry-run prints secret var
names and their keys, never a secret value, and prints plaintext `vars:`
values in full since they are already committed; `--secret KEY[=VAR]` stays
for raw one-offs), `import [FILE]
[-p] [-e] [--overwrite]` (dotenv in, all-or-nothing on collisions, stores
`env/project/VAR` and adds `VAR: {env_var_name: VAR}` to the manifest),
`list [-p] [-e]`, `set KEY [-p] [-e]` (resolves `env/project/KEY`, so a
scoped secret can be replaced without retyping the three-segment key; a bare
`set KEY` still writes the raw key).

Manifest edits are text-level insertions into the matching `secrets:` block
— comments and formatting are preserved. The edited text is re-parsed and
checked for the new entries before it is written; on any doubt the manifest
is left untouched and the user is told to add the entries by hand.

Wire: `getprefix` returns every key under a prefix in one round-trip; `exec`
groups needed keys by `env/project/` prefix and issues one per group.

Trust note: a manifest in a cloned repo may name any scope. Running `exec`
inside an untrusted checkout hands its command those secrets — but you are
already running that repo's code, so this does not widen the same-UID
ceiling. File names (`.secretov.yaml`, `projects.yaml`, token, store, socket)
live as constants in paths.hpp only.

## Dependencies

libsodium (crypto), nlohmann/json (protocol + store serialization),
FTXUI (TUI components for `secretov tui`; FetchContent, pinned commit),
yaml-cpp (manifest + registry parsing; system package first, FetchContent
pinned commit fallback). C++20, CMake. Nothing else without a fight.
