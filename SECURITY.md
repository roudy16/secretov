# secretov — security analysis

Findings from a code-level review (2026-08-30) of the daemon, store, transport,
client, and service scripts, evaluated against the threat model in DESIGN.md.
Finding 9 re-reviewed and closed out 2026-09-07.
Kept as a worklist: items below may be addressed in future sessions. Status
values: `open`, `accepted` (documented ceiling, no fix planned), `done`.

## What holds up

Matches DESIGN.md and is implemented carefully: secretbox (XSalsa20-Poly1305)
with Argon2id, fresh salt+nonce per persist, KDF params bounds-checked before
use (store.cpp), atomic fsync+rename writes, 0600 files/socket with the umask
race handled, SO_PEERCRED UID check, constant-time token compare, non-dumpable
daemon (RLIMIT_CORE=0, PR_SET_DUMPABLE=0), mlock+memzero on key and passphrase,
secrets never in argv, 1 MiB protocol line cap, in-memory rollback on failed
persist. 256-bit random token; brute force irrelevant.

## Findings (ranked)

### 1. Same-UID access is total — `accepted`

While the daemon is unlocked, any process running as this UID can read the
0600 token file, connect, `list`, and `get` everything (npm postinstall, pip
package, editor extension). The token is not a boundary against this attacker;
effective access control is "same UID". Explicitly accepted in DESIGN.md and no
worse than the `.env` files secretov replaces, but the unlocked daemon makes
the window continuous. Per-client named tokens would NOT fix this (same-UID
reads any token file); a real fix is per-request approval or a separate daemon
UID — out of scope unless the threat model changes.

### 2. Decrypted secrets live in ordinary heap — `open`

Passphrase and key get mlock+memzero; the secrets themselves do not: the
`nlohmann::json data_` map, the plaintext dump built in `Store::persist()`,
and every `std::string` copy through get/set are plain heap — swappable, and
freed copies are never zeroed. Core dumps are blocked, so practical exposure
is swap. Cheapest real mitigation is machine-level: encrypted swap or zram.
In-code zeroing of the persist buffer is possible; guarding the whole JSON map
is not worth it.

### 3. No passphrase change — `done` (2026-08-30)

`rotate` re-derives from the SAME passphrase with a new salt; if the
passphrase itself leaked, rotation did not help. Fixed: `secretov passwd`
is a token-guarded daemon op that verifies the current passphrase against
the daemon's retained copy (constant-time) before re-keying with a fresh
salt. Routed through the daemon rather than rewriting the file offline so a
running daemon can never clobber the new passphrase with its stale key.
Residual: old ciphertext copies (backups) remain decryptable with the old
passphrase.

### 4. Service-script passphrase handoff residue — `accepted`

`scripts/service start` passes the passphrase through a bash variable
(unzeroable heap) and a 0600 tmpfs file that lives a few hundred ms. Both are
same-UID-readable during the window (within ceiling #1). tmpfs pages can
swap — folds into #2's encrypted-swap advice. Nothing touches disk.

### 5. Socket squatting — `accepted`

A same-UID process can unlink the socket, bind its own, harvest the token,
and serve fake secrets; clients cannot authenticate the daemon. Second reason
the token is defense-in-depth only, not a boundary.

### 6. Single-connection DoS — `accepted` (threads when needed)

Daemon serves one connection at a time; `read_line` has no timeout, so a
client that connects and goes silent blocks all others. Same-UID-only
nuisance; already marked in daemon.cpp for threading if a real client blocks
another.

### 7. Unauthenticated header — `accepted`

Salt, KDF params, key_created_at, nonce are outside the MAC. Tampering with
salt/params/nonce fails decryption loudly; key_created_at tampering only skews
auto-rotation (documented in DESIGN.md). KDF-DoS variant already blocked by
the bounds check.

### 8. Dependency fetch lacks checksum pinning — `done` (2026-08-30)

`third_party/get-deps.sh` curled nlohmann/json and libsodium from GitHub
releases pinned by version only; FTXUI was FetchContent-pinned to tag v7.0.0
(tags can move). Fixed: get-deps.sh verifies sha256 of both downloads and
deletes the file on mismatch; FTXUI pinned by commit hash. Same day, all
three bumped to latest stable: nlohmann/json 3.12.0, libsodium 1.0.22, FTXUI
7.0.3 (commit f921fad2). Digests were cross-checked from two hosts each
(GitHub release asset vs. download.libsodium.org; release asset vs.
single_include at the git tag). Bumping a dependency means updating its
pinned digest in the same change; re-verify from two sources.

### 9. Housekeeping — `accepted` (2026-09-07)

Reviewed as three separate sub-items. None warrants code; one claim was simply
wrong.

**9a. Token read into unzeroed `std::string`s (both ends)** — `accepted`. The
copies are real: the client's `load_token()` result, the `nlohmann::json`
request and its `dump()`, the socket write buffer, and the daemon's
process-lifetime `expected_token` (daemon.cpp:161) are all ordinary heap. But
the token also sits in plaintext at `$CONFIG/token` (0600) for the life of the
store, so the only exposure zeroing removes is RAM copies reachable via swap —
and every attacker who can read swap (same UID, root, or an offline disk) reads
the plaintext token file by the same means. No asymmetry: scrubbing the RAM
copies buys nothing while the file itself is plaintext. Note the client, unlike
the daemon, sets neither `RLIMIT_CORE=0` nor `PR_SET_DUMPABLE=0`, so a client
crash can dump the token — same conclusion, since a reader of that core reads
the token file too. Folds into #2's encrypted-swap advice. Revisit only if the
token stops being an on-disk plaintext file.

**9b. `exec` secrets inherited by all descendants** — `accepted`. `cmd_exec`
calls `setenv` per secret and then `execvp` (client.cpp:385, 399); environment
inheritance *is* the injection mechanism, so the blast radius is the child's
whole process tree by construction. Not fixable without abandoning env
injection, which is the feature. Unchanged from the original note; it was
already labelled a standard tradeoff rather than a defect.

**9c. TUI leaves values in terminal scrollback** — `done`; the claim was false.
`run_ui` uses `ScreenInteractive::Fullscreen()` (tui.cpp:284), and in the pinned
FTXUI 7.0.3 `ScreenInteractive` is an alias for `App` (screen_interactive.hpp:10)
whose `Fullscreen()` delegates to `FullscreenAlternateScreen()` and enables
`DECMode::kAlternateScreen` (app.cpp:1452, 1465, 675). The TUI therefore draws
only on the alternate buffer, which the terminal discards on exit — nothing it
renders reaches primary-buffer scrollback. The genuine TUI ceiling is the one
already documented at the top of tui.cpp: FTXUI's per-frame copies of revealed
values are not zeroed.

## Priority order for fixes

1. ~~`secretov passwd` (finding 3)~~ — done 2026-08-30.
2. ~~Checksums in get-deps.sh + FTXUI commit pin (finding 8)~~ — done 2026-08-30.
3. Encrypted swap / zram on the host (findings 2, 4, 9a) — machine config, not
   code. This is now the only outstanding mitigation in the worklist.
