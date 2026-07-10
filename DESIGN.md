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

Request:  `{"token": "...", "op": "get|set|list|delete", "key": "...", "value": "..."}`
Response: `{"ok": true, "value"|"keys": ...}` or `{"ok": false, "error": "..."}`

Verbs kept minimal: `get`, `set`, `list`, `delete`. Rotation gets a wire op
when implemented (token-guarded admin op), not before.

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

## CLI

`secretov` binary: `init`, `daemon`, `get`, `set`, `list`, `delete`,
`rotate`, `exec --secret NAME ... -- cmd` (fetch secrets, inject into child
env, exec). `set KEY` reads the value from stdin only — never an argv
argument, which would leak the secret via `/proc/<pid>/cmdline` to other UIDs.
No client-side caching — the daemon is a local socket away.

## Dependencies

libsodium (crypto), nlohmann/json (protocol + store serialization).
C++20, CMake. Nothing else without a fight.
