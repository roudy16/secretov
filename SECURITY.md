# secretov — security analysis

Findings from a code-level review (2026-08-30) of the daemon, store, transport,
client, and service scripts, evaluated against the threat model in DESIGN.md.
Finding 9 re-reviewed and closed out 2026-09-07. Findings 11–34 come from a
second review against the deployed host (2026-10-03, tagged with the review's
ids M1…I5), which also corrected 2, 3, 5, 9a and 10.
Kept as a worklist: items below may be addressed in future sessions. Status
values: `open`, `open (host)` (owner action on the machine, not code),
`accepted` (documented ceiling, no fix planned), `done`.

## What holds up

Matches DESIGN.md and is implemented carefully: envelope encryption
(secretbox/XSalsa20-Poly1305 data key wrapped by an Argon2id-derived wrapping
key), fresh payload nonce per persist, KDF params bounds-checked before use
(store.cpp), atomic fsync+rename writes with a parent-directory fsync, 0600
files/socket with the umask race handled, SO_PEERCRED UID check on both ends,
constant-time token compare, every secretov process non-dumpable
(PR_SET_DUMPABLE=0; the daemon also sets RLIMIT_CORE=0), mlock+memzero on all
key material. No network surface: AF_UNIX only, no listener. After unlock the
daemon holds only the data key; the wrapping key is freed as soon as the data
key is unwrapped. The startup passphrase is read with `::read` into one
pre-reserved buffer (no stdio buffer, no reallocation) and zeroed after
unlock; rotate/passwd request bytes are zeroed in the receive buffer, the
request line, and the parsed `Request` fields. Ceilings: nlohmann::json's own
parse-tree copies of those fields are freed unscrubbed, and so are client
processes' passphrase copies (both marked in code). Secrets never in argv,
1 MiB request cap, in-memory rollback on failed persist (including
rotate/passwd). 256-bit random token; brute force irrelevant.

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

The data key gets mlock+memzero (the passphrase and the wrapping key derived
from it are transient — zeroed right after the data key is unwrapped, never
retained); the secrets themselves do not: the `nlohmann::json data_` map, the
plaintext dump built in `Store::persist()`, and every `std::string` copy
through get/set are plain heap — swappable, and freed copies are never
zeroed. Core dumps are blocked, so practical exposure is swap. Cheapest real
mitigation is machine-level: encrypted swap or zram. In-code zeroing of the
persist buffer is possible; guarding the whole JSON map is not worth it.

2026-10-03: this host swaps to zram only (no disk swap, no resume device), so
the swap path is already closed here. Stays open for hosts with disk swap.

### 3. No passphrase change — `done` (2026-08-30)

`rotate` re-derives from the SAME passphrase with a new salt; if the
passphrase itself leaked, rotation did not help. Fixed: `secretov passwd`
is a token-guarded daemon op that verifies the current passphrase against
the daemon's retained copy (constant-time) before re-keying with a fresh
salt. Routed through the daemon rather than rewriting the file offline so a
running daemon can never clobber the new passphrase with its stale key.
Residual: old ciphertext copies (backups) remain decryptable with the old
passphrase.

2026-09-08: envelope encryption (format v2) landed; `passwd` is now a
re-wrap of the existing data key under a fresh wrapping key (fresh salt), not
a re-encrypt of the payload — cheap, and no passphrase is retained by the
daemon at any point (`rotate`/`passwd` both carry the current passphrase on
the request and verify it by unwrapping the stored data key).

2026-10-03 (8690859, finding 18): `passwd` again re-encrypts the payload,
under a freshly minted data key, so a backup plus the old passphrase opens
only what the backup itself holds, not anything written after `passwd`.
Residual narrowed to exactly that: old copies still open with the old
passphrase.

### 4. Service-script passphrase handoff residue — `superseded` (2026-09-08)

`scripts/service start` used to pass the passphrase through a bash variable
and a short-lived 0600 tmpfs file. Replaced by the keyring unlock in finding
10; the script no longer touches the passphrase itself.

### 5. Socket squatting — `accepted`

A same-UID process can unlink the socket, bind its own, harvest the token,
and serve fake secrets. Second reason the token is defense-in-depth only, not
a boundary. 2026-10-03 (afa8352, finding 22): clients now check the daemon's
peer UID and refuse a socket served by any other UID, so squatting needs the
same UID; the acceptance covers only that case.

### 6. Single-connection DoS — `accepted` (threads when needed)

Daemon serves one connection at a time; `read_line` has no timeout, so a
client that connects and goes silent blocks all others. Same-UID-only
nuisance; already marked in daemon.cpp for threading if a real client blocks
another.

### 7. Unauthenticated header — `accepted`

Salt, KDF params, key_created_at, and both nonces (wrap + payload) are
outside any MAC. The wrapped data key IS authenticated by its own MAC under
the wrapping key (secretbox), so tampering with it fails loudly on unwrap.
Tampering with salt/params/either nonce fails decryption loudly; key_created_at
tampering only skews auto-rotation (documented in DESIGN.md). Same
consequences as before envelope encryption. KDF-DoS variant already blocked
by the bounds check.

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
process-lifetime `expected_token` are all ordinary heap. But
the token also sits in plaintext at `$CONFIG/token` (0600) for the life of the
store, so the only exposure zeroing removes is RAM copies reachable via swap —
and every attacker who can read swap (same UID, root, or an offline disk) reads
the plaintext token file by the same means. No asymmetry: scrubbing the RAM
copies buys nothing while the file itself is plaintext. Folds into #2's
encrypted-swap advice. Revisit only if the token stops being an on-disk
plaintext file. 2026-10-03 (afa8352, finding 24): the reasoning weighed only
the token, but clients also hold values and passphrases; every secretov
process is now non-dumpable (`main()` sets PR_SET_DUMPABLE=0 for every
command), so no core dump and no same-UID ptrace of a client either.

**9b. `exec` secrets inherited by all descendants** — `accepted`. `cmd_exec`
calls `setenv` per secret and then execs the command; environment
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
values are not zeroed. (`get` is different: see finding 25.)

### 10. Passphrase in the session keyring — `accepted` (2026-09-08)

To start at login without a tty, `scripts/service` stores the store
passphrase in the Secret Service login collection (gnome-keyring) and the
unit pipes `secret-tool lookup` into the daemon. Consequences:

(a) While the session is up, any same-UID process can read the passphrase
from the keyring — within ceiling #1, but strictly worse than the token
file (corrected 2026-10-03): the token only works through the live socket,
while the passphrase opens every copy of the store offline, backups and
synced copies included. gnome-keyring has no per-app ACL, so a sandboxed app
granted `org.freedesktop.secrets` (on this host the `com.google.Chrome`
flatpak) can read it without any access to the token or socket. See finding
16 for the fix.

(b) At rest the passphrase is protected by the login password: the keyring
file is encrypted with it, so an offline disk image is bounded by the login
password rather than the store passphrase. On a machine without full-disk
encryption that is the real cost, and it is larger than the Argon2id on the
store suggests (corrected 2026-10-03): `login.keyring` here is the legacy
format, keyed by iterated SHA-256 (1000–5095 iterations, re-randomized on
each save; 3196 on 2026-10-03), roughly 10^5–10^6× cheaper per guess than
the store's Argon2id MODERATE. Effective at-rest strength = the login
password. See finding 15.

Not using the service keeps the old model: the passphrase exists only in your
head while the daemon is down. `secretov passwd` must be followed by
`scripts/service passphrase` or the next login fails to unlock and gives up
after the unit's start limit.

### 11. Manifest discovery trusts any `.secretov.yaml` up to `/` (M1) — `done` (2026-10-03, 7399ba7)

`find_manifest_upward` used `exists()` only and `load_manifest` did no stat,
so another UID could plant a manifest in `/tmp` or in a group-writable
ancestor (finding 12) whose `vars:`/`key:` ran code as the owner with prod
secrets. Fixed: every manifest read goes through `read_manifest_text`, which
refuses a file not owned by you or group/world-writable, and a directory
(the one holding the name, and a symlink target's) not owned by you or root
or group/world-writable; the error names the path and the `chmod g-w,o-w`
fix. The upward walk stops at the first directory you do not own, and a bad
nearer manifest is an error, never skipped for an ancestor. Applies to `-p`
registry manifests and `import` too.

### 12. Workspace writable by another account (M2) — `open (host)`

`devuser` (uid 1001, a live node runner) has primary group `roudy`; with
umask 0002, `~/workspace`, every project dir and some manifests are
group-writable, so devuser (or whoever compromises its runner) can trojan any
repo, git hook, or manifest — not a secretov defect, and only partly
mitigated by finding 11. Owner commands (first confirm the runner does not
rely on group-writing your files):

```sh
sudo groupadd devuser && sudo usermod -g devuser devuser   # own primary group
sudo chfn -o umask=027 roudy        # pam_umask: every session, graphical too
echo 'umask 027' >> ~/.bashrc       # terminals already open; re-login after
chmod -R g-w ~/workspace
```

Since finding 11, secretov REFUSES every manifest on this host until the
chmod runs: `blueowl/.secretov.yaml` and `wed_photo/.secretov.yaml` are 0664,
and all four project dirs under `~/workspace/roudy16` (blueowl, wed_photo,
homecloud, homestat) are 0775. The `chmod -R` above fixes all of them.

### 13. Secret values in shell history; interactive `set` echoed (M3) — `done` (2026-10-03, afa8352)

The docs showed `printf 'value' | secretov set KEY`, writing the value to
shell history (plaintext on an unencrypted disk), and `set` on a tty read
with echo on. Fixed: on a tty `set` prompts `Value for <key>:` with echo off
and reads one line (piped stdin is still read whole); README/USING show the
interactive form or `read -rs v; printf %s "$v" | secretov set K`.

### 14. Backup-verify recipe sent the passphrase to shell history (M4) — `done` (2026-10-03, afa8352)

The README ran `secretov daemon &`; the background job stopped on SIGTTOU and
the passphrase typed next went to the shell and its history. Fixed: every
tty prompt fails fast from a background process group ("cannot prompt from a
background process ..."), and the recipe now pipes a `read -rs` passphrase
into the daemon inside a subshell. Anyone who ran the old recipe: check
`$HISTFILE` for the passphrase, scrub it, then `secretov passwd` and
`scripts/service passphrase`.

### 15. Keyring KDF bounds the store at rest (L1) — `open (host)`

See #10(b). No code fix inside secretov's model. Owner actions, in order of
value: a strong, unique login password; keep `~/.local/share/keyrings` out of
backups; LUKS or an encrypted `/home` at the next reinstall (root here is
plain ext4 on `nvme0n1p6`). Later: a TPM2-sealed `systemd-creds` credential
instead of the keyring (needs systemd ≥ 256; this host has 255).

### 16. Keyring copy of the passphrase opens every backup (L2) — `open`

See #10(a). Fix is a design change: a random machine-local unlock key in a
second wrap slot, stored in the keyring instead of the passphrase —
revocable on its own and useless against backups taken before it existed.

### 17. Passphrase retained in daemon memory (L3) — `done` (2026-10-03, afa8352)

DESIGN.md and "What holds up" claimed the daemon never retained the
passphrase, but `std::getline(std::cin)` left it in glibc's unscrubbed stdin
buffer, and rotate/passwd requests left it in the receive buffer, request
line, and `Request` fields. Fixed as described in "What holds up". Ceilings
(`ponytail:` in code): nlohmann::json parse-tree copies; request lines over
64 KiB reallocate the receive buffer (passphrase requests are far smaller).

### 18. `passwd` re-wrapped the same data key (L4) — `done` (2026-10-03, 8690859)

An old store copy plus the old passphrase yielded the current data key, so
secrets written after `passwd` were exposed too — contradicting "the response
to a leaked passphrase". Fixed: `passwd` mints a fresh data key and
re-encrypts the payload (still two Argon2id calls) and resets
key_created_at.

### 19. rotate/passwd mutated in-memory state before persist (L5) — `done` (2026-10-03, 8690859)

A failed `passwd` (e.g. read-only data dir) silently took effect on the next
successful write, leaving the keyring copy stale. Fixed: both build the new
key and header as candidates, persist, and only then adopt them; on failure
nothing changes.

### 20. No parent-directory fsync after rename (L6) — `done` (2026-10-03, afa8352)

A power loss could roll back an acknowledged `set`/`delete`/`passwd`.
`write_file_atomic` now fsyncs the parent directory after the rename.

### 21. Manifest env names and `exec` program lookup (L7) — `done` (2026-10-03, 7399ba7); cross-scope `key:` `accepted`

`vars:` could set `PATH`, `LD_PRELOAD`, `BASH_ENV`, ..., and `PATH` was
applied before `execvp`, so a manifest could choose which `psql` ran. Fixed:
`vars:` keys and `env_var_name` reject `LD_*`, `DYLD_*`, `SECRETOV_*`,
`BASH_ENV`, `ENV`, `IFS`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`,
`PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `GIT_SSH_COMMAND`,
`GIT_EXEC_PATH` (a deny list — `ponytail:` ceiling; `PATH` stays allowed),
and `exec` resolves the program against the caller's PATH before any
manifest var is applied, then `execv`s it. `--secret KEY=VAR` on the command
line is not filtered (your own argv). A manifest `key:` naming another
project's scope is accepted under ceiling #1: since finding 11 a manifest is
only read if you own it and nobody else can write it.

### 22. Client never authenticated the daemon end (L8) — `done` (2026-10-03, afa8352)

Clients sent the token (and on rotate/passwd the passphrases) to whatever
served the socket path. Now `DaemonClient::send` refuses a peer whose UID is
not ours before writing anything. A set `XDG_RUNTIME_DIR` is still used as
given — `accepted`: the peer check covers a misconfigured shared dir.

### 23. Daemon start unlinked a live socket (L9) — `done` (2026-10-03, afa8352)

A second `secretov daemon` took over the path, leaving the service daemon
unlocked and unreachable. Now it exits 1 with "daemon already running at
<path>" before the passphrase prompt (and before any auto-rotate), refuses
a path that is not a socket, removes only a stale socket, and on exit
unlinks the path only if it still names its own inode.

### 24. Client processes were dumpable (L10) — `done` (2026-10-03, afa8352)

See 9a. `exec` children are unaffected (execve resets the flag), and no
RLIMIT_CORE is set outside the daemon, so children keep their core limit.

### 25. TUI reveal never auto-hides; `get` output in scrollback (L11) — `open`

A revealed value stays on screen until a keypress, selection change, or exit.
Fix: re-mask after 15–30 s via `screen.Post` (pair with TUI UX work). `get`
prints to the primary buffer, so values land in terminal scrollback;
documented in USING.md (pipe it, or clear scrollback).

### 26. Linger kept the unlocked daemon alive after logout (L12) — `done` (2026-10-03, eeb441a); linger `open (host)`

The unit is now PartOf/Requisite/WantedBy `graphical-session.target`: it
starts at graphical login and stops at graphical logout even with linger on,
and `scripts/service start` fails when no graphical session is active.
Existing installs keep the old unit until `scripts/service update` (it
re-enables, moving the link from `default.target.wants`). This host still has
Linger=yes; if nothing else needs it: `loginctl disable-linger`.

### 27. dotenv import silently changed values (L13) — `done` (2026-10-03, 7399ba7)

Duplicate keys silently kept the last (and wrote duplicate YAML keys); `\t`
decoded to `t`. Now: a duplicate key is an error naming both lines; double
quotes decode `\n \t \r \\ \"` and any other escape is an error; stripping an
unquoted ` #...` comment prints a warning naming the line and key.

### 28. Vendored dependency bumps never reached a checkout (L14) — `done` (2026-10-03, 295fec5, eeb441a)

get-deps.sh only checked that files existed, and `update` never ran it.
Now each artifact has a version+digest `.stamp` and is refetched when it
differs (libsodium's tree is removed first), and `scripts/service
install|update` run get-deps.sh every time (a no-op when stamps match).

### 29. Unit set only NoNewPrivileges (L15) — `done` (2026-10-03, eeb441a); namespace options `accepted`

Added: `UMask=0077`, `RestrictAddressFamilies=AF_UNIX`,
`SystemCallFilter=@system-service ~@privileged`,
`SystemCallArchitectures=native`, `MemoryDenyWriteExecute`,
`LockPersonality`, `RestrictNamespaces`, `RestrictRealtime`,
`RestrictSUIDSGID`, `KeyringMode=private` (verified with secret-tool unlock
under a transient unit). Not added: PrivateTmp/PrivateDevices/ProtectSystem/
ProtectHome and the other namespace-based options — in a user unit they need
unprivileged user namespaces, which stock Ubuntu 24.04 blocks via AppArmor,
and only same-UID peers reach the daemon anyway.

### 30. No passphrase floor; KDF params frozen at create (I1) — `done` (2026-10-03, afa8352, 8690859)

`init` and `passwd` warn (not refuse) below 12 characters. `passwd` writes
the current default Argon2id params (MODERATE), upgrading older stores;
`rotate` keeps the store's params (`accepted`: changing them would cost a
second Argon2id call).

### 31. Symmetric 1 MiB line cap broke `getprefix` (I2) — `done` (2026-10-03, afa8352)

`exec`/`import` failed once a scope's values passed 1 MiB. The client now
accepts responses up to 64 MiB (`ponytail:` cap); the daemon's 1 MiB
request cap is unchanged.

### 32. No lock op; auto-rotate only at daemon start (I3) — `open`

The daemon stays unlocked for the whole session, and "rotation bounds a key
compromise in time" depends on how often the daemon restarts. Fix: a `lock`
op (drop the data key, refuse until re-unlock) tied to logind's Lock signal.

### 33. Another UID can pre-create `/tmp/secretov-<uid>` (I4) — `accepted`

Only the no-`XDG_RUNTIME_DIR` fallback; it fails closed (the 0700/owner check
refuses the dir). For cron or ssh use, export
`XDG_RUNTIME_DIR=/run/user/$(id -u)`.

### 34. Binary hardening came only from distro compiler defaults (I5) — `done` (2026-10-03, 86732db)

CMake now sets PIE, `-z relro -z now -z noexecstack`,
`-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection`,
and `_FORTIFY_SOURCE=3` (optimized configs; the build type now defaults to
Release). `hardening_test` checks the ELF with readelf.

## Priority order for fixes

Done items are marked in the findings. Remaining, highest value first:

1. Host config (12, 26): devuser's own primary group, umask 027,
   `chmod -R g-w ~/workspace` (until then every manifest here is refused);
   `scripts/service update` to pick up the hardened, session-bound unit;
   disable linger if nothing needs it. Minutes.
2. `lock` op tied to logind Lock (32).
3. Keyring unlock-key slot instead of the passphrase in the keyring (16).
4. TPM2 `systemd-creds` credential (15; needs systemd ≥ 256).
5. LUKS or encrypted `/home` (15; also closes 2 on disk-swap hosts).
   Machine-level, high effort, biggest at-rest gain.
6. TUI auto re-mask timer (25).
