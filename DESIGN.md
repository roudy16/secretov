# secretov — design

Local secrets service for developer environments. One daemon, one CLI.
Secrets live in one encrypted file instead of scattered `.env` files.

## Threat model

Protects: secrets at rest (encrypted), access from other UIDs, secret sprawl
across dotfiles/shell history. Does NOT protect against: malware running as
the same user, or root. Accepted ceiling; extend later if needed. Also accepted:
the plaintext header's `key_created_at` is not authenticated, so tampering with
it can only skew rotation scheduling (never expose or corrupt secrets).

After unlock the daemon holds only the data key (see Storage). The startup
passphrase is read with `::read` straight into one pre-reserved buffer (no
stdio buffer, no reallocation) and zeroed after unlock; the key derived from
it is freed once the data key is unwrapped. For `rotate`/`passwd` requests the
daemon zeroes the receive buffer, the request line, and the parsed passphrase
fields. Ceilings: nlohmann::json's own parse-tree copies of those fields, and
the client processes' copies, are freed unscrubbed. Every secretov process is
non-dumpable (`PR_SET_DUMPABLE=0`), so those copies are reachable only via
root, swap, or physical memory — which already yield the data key and every
secret.

## Transport

Unix domain socket at `$XDG_RUNTIME_DIR/secretov.sock`, mode 0600, peer UID
checked via `SO_PEERCRED` on both ends: the daemon drops other UIDs, and the
client refuses to send anything to a socket another UID serves. The unix
socket is the only transport; Listener and Connection are plain classes over
it, not an interface.

One daemon per socket: `secretov daemon` exits with `daemon already running`
before prompting if a daemon already answers, so a second start can't
auto-rotate under a running daemon. The bind-time re-check catches a
concurrent start (both past the first check during Argon2id) only after
unlock and any auto-rotate. At bind it also refuses a path that is not a
socket and removes only a stale socket. On exit it unlinks the path only if it still
names the socket it bound. Line caps: 1 MiB per request at the daemon (the
client refuses a larger request before sending, since the daemon drops it
without a reply), 64 MiB per response at the client (a `getprefix` carries a
whole scope).

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
- `passwd` — new wrapping key AND new data key. Fresh salt, derive from the
  new passphrase at the stronger of the store's and the default Argon2id
  params (MODERATE: upgrades a weaker store, never downgrades), mint a data key, re-encrypt the payload under it,
  and reset key-created-at. This is the response to a leaked passphrase: an
  old copy plus the old passphrase opens only what that copy held. `rotate`
  keeps the store's KDF params (changing them would cost a second Argon2id).

Both build the new key and header as candidates and adopt them only after the
write succeeds; a failed write leaves the daemon on the old passphrase and
key.

Both are daemon ops that carry the current passphrase (see Protocol), because
the daemon no longer retains it after unlock. Triggers:
- Auto: on unlock, if key-created-at is older than N days (default 30),
  rotate transparently — the passphrase is in hand at that moment.
- Manual: `secretov rotate` and `secretov passwd`, each prompting for the
  current passphrase (`init` and `passwd` warn on a new passphrase under 12
  characters).

Old ciphertext copies (backups) remain openable with the passphrase and data
key they were written under — copy hygiene is on the user.

## CLI

`secretov` binary: `init`, `daemon`, `get`, `set`, `list`, `delete`,
`rotate` and `passwd` (both prompt for the current passphrase), `tui` (interactive terminal UI over the daemon socket),
`exec --secret NAME ... -- cmd` (fetch secrets, inject into child
env, exec). `set KEY` creates or replaces — there is no separate update op;
it reads the value from stdin only (a no-echo one-line prompt on a tty, the
whole stream when piped), never an argv argument, which would leak the secret
via `/proc/<pid>/cmdline` to other UIDs. Tty prompts refuse to run from a
background process group, where the typed line would land in the shell, and
fail (discarding the input) when more input follows the line, so the rest of a
multi-line paste never reaches the shell either; they drain a paste longer
than the tty queue before flushing. A tty line of 4095 bytes or more is
refused (the terminal silently truncates there), as is an empty tty `set`
value; a piped passphrase line is capped at 4096 bytes.
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
from cwd through directories owned by the caller (the walk stops at the first
one that is not); env = `-e` else `$SECRETOV_ENV` else manifest `default_env`
else error. Env var names come only from the manifest.

Commands: `exec [-p] [-e] [--dry-run] -- cmd` (dry-run prints secret var
names and their keys, never a secret value, and prints plaintext `vars:`
values in full since they are already committed; `--secret KEY[=VAR]` stays
for raw one-offs), `import [FILE]
[-p] [-e] [--overwrite]` (dotenv in, all-or-nothing on collisions, stores
`env/project/VAR` and adds `VAR: {env_var_name: VAR}` to the manifest; the
dotenv parser rejects duplicate keys and unknown `\` escapes and warns when it
strips an unquoted ` #` comment),
`list [-p] [-e]`, `set KEY [-p] [-e]` (resolves `env/project/KEY`, so a
scoped secret can be replaced without retyping the three-segment key; a bare
`set KEY` still writes the raw key).

Manifest edits are text-level insertions into the matching `secrets:` block
— comments and formatting are preserved. The edited text is re-parsed and
checked for the new entries before it is written; on any doubt the manifest
is left untouched and the user is told to add the entries by hand.

Wire: `getprefix` returns every key under a prefix in one round-trip; `exec`
groups needed keys by `env/project/` prefix and issues one per group.

Trust note: a manifest decides what runs with which secrets, so it is read
(only via `read_manifest_text`) under ssh-StrictModes rules: the file must be
owned by the caller, and its directory (and a symlink target's) owned by the
caller or root; none world-writable, and none group-writable unless the
group is the caller's user private group (their primary gid, named after
them) with no other member and no access ACL. Membership is the `gr_mem` of
the entry `getgrgid` returns and of every enumerated entry with that gid,
plus a passwd scan for primary members (`collect_group_members` is the
database-free core the tests drive); a second group name on the gid, with or
without members, or a scan error, refuses. An ACL makes the
group bits the ACL mask, which can stand for named users' write, so any
`system.posix_acl_access` on a group-writable inode refuses. The check sees
only the passwd and group databases: a gid granted outside them (systemd
`SupplementaryGroups=`, a setgid binary, processes of a member removed while
logged in) or accounts a non-enumerating NSS backend (sssd, LDAP) hides are
not seen. Each takes an admin deliberately sharing the caller's private gid.
Anything else is refused with the `chmod`, `setfacl`, or group fix, never
skipped for an ancestor.
`vars:` keys and `env_var_name` reject a deny list of names that make the
child or anything it spawns load code or config, or redirect its traffic
through a proxy or CA of the manifest's choosing (`LD_*`, `DYLD_*`,
`SECRETOV_*`, `GIT_*`, `XDG_*`, `PATH`, `HOME`, `BASH_ENV`, `PAGER`,
`NODE_OPTIONS`, ...; full list in manifest.cpp and USING.md — a deny list, so
a ceiling). With `PATH` denied, `exec` finds the program on the caller's own
PATH. A `key:` may still name any scope: a manifest the caller owns is the
caller's choice, and running `exec` inside an untrusted checkout already runs
that repo's code — within ceiling #1 (SECURITY.md). File names (`.secretov.yaml`, `projects.yaml`, token,
store, socket) live as constants in paths.hpp only.

## Dependencies

libsodium (crypto), nlohmann/json (protocol + store serialization),
FTXUI (TUI components for `secretov tui`; FetchContent, pinned commit),
yaml-cpp (manifest + registry parsing; system package first, FetchContent
pinned commit fallback). C++20, CMake. Nothing else without a fight.
