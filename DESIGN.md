# secretov — design

Local secrets service for developer environments. One daemon, one CLI.
Secrets live in one encrypted file instead of scattered `.env` files.

## Threat model

Protects: secrets at rest (encrypted), access from other UIDs, secret sprawl
across dotfiles/shell history. Does NOT protect against: malware running as
the same user, or root. Accepted ceiling; extend later if needed. Also accepted:
the plaintext header's `key_created_at` is not authenticated, so tampering with
it can only skew rotation scheduling (never expose or corrupt secrets).

## Transport

Unix domain socket at `$XDG_RUNTIME_DIR/secretov.sock`, mode 0600, peer UID
checked via `SO_PEERCRED`. The socket is hidden behind a generic connection
interface (Listener/Connection adapter) so other transports can be added
without touching service logic.

## Auth

Single shared API token, minted at `init`, stored in a 0600 file
(`~/.config/secretov/token`). Every request carries it. Revocation =
regenerate. Upgrade path to per-client named tokens changes nothing on the
wire (token stays a string field).

## Protocol

Newline-delimited JSON over the socket.

Request:  `{"token": "...", "op": "get|set|list|delete|rotate|passwd", "key": "...", "value": "..."}`
Response: `{"ok": true, "value"|"keys": ...}` or `{"ok": false, "error": "..."}`

Verbs kept minimal. `rotate` and `passwd` are token-guarded admin ops;
`passwd` additionally carries `"old"` and `"new"` fields, and the daemon
verifies `"old"` against its retained passphrase (constant-time) before
re-keying — the token alone cannot change the passphrase.

## Storage

One encrypted file (`~/.local/share/secretov/store`): libsodium secretbox
(XSalsa20-Poly1305) over a JSON key→value map.

Master key: Argon2id-derived from a passphrase entered at daemon
start/unlock. No keyring dependency; works headless.

File header (plaintext, before ciphertext): magic + format version byte,
Argon2id salt + params, key-created-at timestamp, nonce. Version byte exists
so future format changes don't need migration heroics.

## Key rotation

Both triggers:
- Auto: on unlock, if key-created-at is older than N days (default 30),
  re-encrypt with fresh salt + nonce transparently.
- Manual: `secretov rotate` for on-demand rotation (e.g. suspected exposure).

Rotation = decrypt whole file, re-encrypt with new salt/nonce. No envelope
encryption; the store is one small file.

Rotation never changes the passphrase. For a leaked passphrase the response
is `secretov passwd` (daemon op, requires the current passphrase): fresh salt,
key re-derived from the new passphrase, store re-encrypted, retained
passphrase replaced. Old ciphertext copies (backups) remain decryptable with
the old passphrase — copy hygiene is on the user.

## CLI

`secretov` binary: `init`, `daemon`, `get`, `set`, `list`, `delete`,
`rotate`, `passwd`, `tui` (interactive terminal UI over the daemon socket),
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
