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
socket is the daemon's only transport; Listener and Connection are plain
classes over it, not an interface. The interface sits above transport: the
front end reaches secrets through `Backend` (src/backend.hpp), whose only
implementation, `LocalBackend`, speaks this socket (see Backends). Planned
(docs/backends-design.md, not in this build): outbound TLS from client
processes (`exec`, `tui`, `set`, ...) to fixed provider hosts for the AWS and
GCP backends, with no listener; the daemon and its `AF_UNIX`-only sandbox stay
untouched.

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
write_targets:               # optional, see Backends
  - gcp:acme-secrets
```

The registry is trust-bearing (it holds `write_targets:`), so it is read only
through `read_manifest_text`'s owner/mode check, below; a file or directory
that check would refuse is an error wherever the registry is read.

Resolution: project = `-p` (registry) else nearest `.secretov.yaml` walking up
from cwd through directories owned by the caller (the walk stops at the first
one that is not); env = `-e` else `$SECRETOV_ENV` else manifest `default_env`
else error. Env var names come only from the manifest.

Commands: `exec [-p] [-e] [--dry-run] -- cmd` (dry-run prints secret var
names and their keys, never a secret value, and prints plaintext `vars:`
values in full since they are already committed; `--secret KEY[=VAR]` stays
for raw one-offs; `exec` fetches every secret before it exports anything, then
exports `vars:`, manifest secrets, `--secret`, and sets `SECRETOV_INJECTED` in
the child to the comma-separated names it exported, appended to an inherited
value; the marker lets a nested secretov tell injected variables from the
caller's own, and manifests cannot set `SECRETOV_*`), `import [FILE]
[-p] [-e] [--overwrite]` (dotenv in, all-or-nothing on collisions, stores
`env/project/VAR` and adds `VAR: {env_var_name: VAR}` to the manifest; the
dotenv parser rejects duplicate keys and unknown `\` escapes and warns when it
strips an unquoted ` #` comment),
`list [-p] [-e]`, `set KEY [-p] [-e]`, `get KEY [-p] [-e]`, `delete KEY [-p]
[-e]` (each resolves `env/project/KEY`, so a scoped secret can be replaced,
read or removed without retyping the three-segment key; a bare KEY still names
the raw key).

Manifest edits are text-level insertions into the matching `secrets:` block
— comments and formatting are preserved. The edited text is re-parsed and
checked for the new entries before it is written; on any doubt the manifest
is left untouched and the user is told to add the entries by hand.

Wire: `getprefix` returns every key under a prefix in one round-trip;
`LocalBackend::get_many` groups the wanted keys by `env/project/` prefix and
issues one per prefix holding several of them (a lone key uses `get`). The
protocol is unchanged.

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
child or anything it spawns load code or config, or send its traffic or
credential loading through an endpoint, proxy, CA or file of the manifest's
choosing, or that select the credentials a nested secretov would write with
(`LD_*`, `DYLD_*`, `SECRETOV_*`, `GIT_*`, `XDG_*`, `AWS_ENDPOINT_URL*`,
`CLOUDSDK_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `AWS_PROFILE`, `PATH`, `HOME`,
`BASH_ENV`, `PAGER`, `NODE_OPTIONS`, ...; full list in manifest.cpp and
USING.md — a deny list, so a ceiling). Credentials themselves
(`AWS_ACCESS_KEY_ID`, ...) stay injectable: they hold a secret, not a loader
path. With `PATH` denied, `exec` finds the program on the caller's own
PATH. A `key:` may still name any scope: a manifest the caller owns is the
caller's choice, and running `exec` inside an untrusted checkout already runs
that repo's code — within ceiling #1 (SECURITY.md). File names (`.secretov.yaml`, `projects.yaml`, token,
store, socket) live as constants in paths.hpp only.

## Backends

The manifest front end (resolution, trust checks, `exec`, `import`, TUI) is
separate from where secrets live, behind `Backend` (`get_many`, `set`,
`remove`, `restore`; typed `BackendError`: NotFound, Denied, NoCredentials,
Unreachable, PendingDeletion). Callers pass resolved paths; values are opaque
strings. `LocalBackend` wraps the daemon client; `exec`, `get`, `set`,
`delete` and the TUI's get/set/delete go through it, while store-wide `list`
and `import` stay on the daemon client. Full design:
docs/backends-design.md.

Phase 1 parses all backend syntax but runs only `local`. The manifest takes an
optional `backend: {type: local|aws|gcp, region|project: ...}` block (absent
means local), a per-env `region:` (aws) / `project:` (gcp), and per-entry
`kind: text|kv`, `path:` and `key:`. A cloud entry needs an explicit `path:`
(`kind: kv` also `key:`, the JSON field); a local entry derives
`env/project/NAME` or takes `key:`, refuses `path:` and `kind: kv`. A manifest
naming `aws` or `gcp` parses, and `list -p/-e` prints its declared entries
(name, kind, path, field), but `exec` (not `--dry-run`), `get`, `set` and
`delete` fail with `backend 'aws' not compiled in`; `import` and `exec
--secret` with `-p`/`-e` are refused on any non-local manifest.

Parsing is a trust boundary:

- **Unknown keys are refused** at top level, in `backend:`, in an env and in a
  secret entry (`unknown key 'secrests' in .secretov.yaml`). Ignoring them is
  how an old binary reads `backend: aws` and queries the local store, so the
  refusal freezes the syntax for future additions. `version` stays `"1"`: the
  parser never read it.
- **Paths and locations are validated at parse time**, before any credential
  could be loaded. AWS name `^[A-Za-z0-9/_+=.@-]{1,512}$` or an ARN of the
  `aws` partition; AWS region from a compiled-in table (a newer region is
  refused: "not in this build's region table; upgrade secretov"); GCP project
  id (lowercase, 6-30 characters; numbers and domain-scoped ids refused), GCP
  secret id `^[A-Za-z0-9_-]{1,255}$` or `projects/PROJECT/secrets/ID`. No host
  is ever built from free text, and the manifest has no `endpoint:` field.
- **Request target.** A request's host and resource come only from validated
  manifest location fields and paths; identity and proxy only from the
  caller's own environment and credential files. Manifest `vars:` and fetched
  values reach only the `exec` child, after every fetch: secretov never
  applies them to its own environment.
- **Write pins.** For ARN paths and every GCP path the manifest chooses where
  a write goes, so writes there will need a pin in the local, uncommitted
  `write_targets:` list of `projects.yaml` (`aws-account:<12-digit account>`,
  `gcp:<project id>`). No auto-pin, trust-on-first-use or flag. Phase 1 only
  ships the parser and trust check (`registry_write_targets`); no command calls
  it yet, so a malformed list goes unreported until a cloud write path exists.
- **Nested exec.** `SECRETOV_INJECTED` (see CLI) is the marker by which a
  later secretov refuses cloud writes with credentials a parent `exec`
  injected. Phase 1 only sets it; the refusal arrives with the cloud write
  path. A child that unsets the marker is the repo's code running as the user
  (ceiling #1).

## Dependencies

libsodium (crypto), nlohmann/json (protocol + store serialization),
FTXUI (TUI components for `secretov tui`; FetchContent, pinned commit),
yaml-cpp (manifest + registry parsing; system package first, FetchContent
pinned commit fallback). C++20, CMake. Nothing else without a fight.
