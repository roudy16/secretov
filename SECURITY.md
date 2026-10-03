# secretov — security analysis

Findings from a code-level review (2026-08-30) of the daemon, store, transport,
client, and service scripts, evaluated against the threat model in DESIGN.md.
Finding 9 re-reviewed and closed out 2026-09-07. Findings 11–34 come from a
second review against the deployed host (2026-10-03, tagged with the review's
ids M1…I5), which also corrected 2, 3, 5, 9a and 10. A verification pass over
those fixes (same day, 43219db) closed gaps in 13, 17, 20, 21 and 28,
accepted the concurrent-start case of 23, and corrected 29's rationale; each
carries a "verification pass" note. A second verification pass (same day,
7f36a00) closed further gaps in 11, 13 and 21, each under a "second
verification pass" note.
Kept as a worklist: items below may be addressed in future sessions. Status
values: `open`, `open (host)` (owner action on the machine, not code),
`accepted` (documented ceiling, no fix planned), `done`.

## What holds up

Matches DESIGN.md and is implemented carefully: envelope encryption
(secretbox/XSalsa20-Poly1305 data key wrapped by an Argon2id-derived wrapping
key), fresh payload nonce per persist, KDF params bounds-checked before use
(store.cpp), atomic fsync+rename writes with a best-effort parent-directory fsync, 0600
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
another. 2026-10-03: clients now give up after 5 s (60 s for
rotate/passwd) with `daemon busy` instead of hanging behind such a client;
the daemon side is unchanged. The request is already queued in the socket by
then and still runs once the daemon is free, so a timed-out `set`/`delete`
now says it "may still be applied" (the TUI marks the outcome unknown) rather
than reporting a plain failure.

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
copies are real: the DaemonClient's `token_` copy, the `nlohmann::json`
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

### 11. Manifest discovery trusts any `.secretov.yaml` up to `/` (M1) — `done` (2026-10-03, 7399ba7, 7f36a00)

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

Second verification pass: `import` checked the directory only when the
manifest already existed, so a first `import -p` under a 0002 umask stored
the secrets and wrote the manifest into a group-writable dir, which the next
`exec` refused. It also treated a dangling `.secretov.yaml` symlink as absent
and replaced it with a regular file. Now a manifest about to be created has
its directory checked before anything is stored, and existence is tested
without following symlinks, so a dangling link fails as it does for `exec`.

### 12. Workspace writable by another account (M2) — `open (host)`

The host account `devuser` (uid 1001) has primary group `roudy`; with umask
0002, `~/workspace`, every project dir and some manifests are
group-writable, so anything running as devuser could trojan any repo, git
hook, or manifest — not a secretov defect, and only partly mitigated by
finding 11.

Correction (2026-10-03): the review called devuser "a live node runner".
Wrong. That process is Plane's `plane-runner-1` Docker container, whose image
runs as uid 1001; `ps` shows the host name for that uid. Inside the
container its groups are `0`, not `roudy`, and it has no mounts, so it cannot
reach `~/workspace`. Nothing running uses the devuser account: no home dir,
no logins in wtmp. The exposure is a dormant account, not a live service.

Owner commands: lock or remove the account if it is not used; that does not
affect the container, which never reads the host's `/etc/passwd`. Fixing the
umask keeps new files private either way:

```sh
sudo usermod -L devuser             # or: sudo userdel devuser
sudo chfn -o umask=027 roudy        # pam_umask: every session, graphical too
echo 'umask 027' >> ~/.bashrc       # terminals already open; re-login after
chmod -R g-w ~/workspace            # optional once devuser is locked or gone
```

Since finding 11, secretov REFUSES every manifest on this host until the
chmod runs: `blueowl/.secretov.yaml` and `wed_photo/.secretov.yaml` are 0664,
and all four project dirs under `~/workspace/roudy16` (blueowl, wed_photo,
homecloud, homestat) are 0775. Either the `chmod -R` above or this narrower
one fixes them:

```sh
cd ~/workspace/roudy16 && chmod g-w,o-w {blueowl,wed_photo,homestat,homecloud} {blueowl,wed_photo,homestat,homecloud}/.secretov.yaml
```

### 13. Secret values in shell history; interactive `set` echoed (M3) — `done` (2026-10-03, afa8352, 43219db, 7f36a00)

The docs showed `printf 'value' | secretov set KEY`, writing the value to
shell history (plaintext on an unencrypted disk), and `set` on a tty read
with echo on. Fixed: on a tty `set` prompts `Value for <key>:` with echo off
and reads one line (piped stdin is still read whole); README/USING show the
interactive form or `IFS= read -rs v; printf %s "$v" | secretov set K`.

Verification pass: reading one line on a tty left the rest of a multi-line
paste (a PEM key) in the tty input queue, where the shell ran it and saved it
to history — the same leak, and a silently truncated value. Now every tty
prompt checks for input queued past the line (non-canonical, 100 ms, so a
trailing partial line counts), restores the terminal with TCSAFLUSH, and fails
with `more input followed the line` when there was any; nothing reaches the
shell (smoke test pastes three lines). The docs' `read -rs` stripped leading
and trailing blanks from the value; they now use `IFS= read -rs`.

Second verification pass: TCSAFLUSH discards only what is queued, and the tty
queue holds ~4 KiB, so the terminal wrote the rest of a longer paste (an
RSA-8192 or full-chain PEM) after secretov exited and the shell ran it. The
prompt now drains until the line is quiet for 100 ms (`ponytail:` 1 MiB cap)
before flushing; the smoke test pastes 9.6 KiB from a blocking writer. A paste
whose chunks arrive more than 100 ms apart can still slip past (the detection
window). The terminal also silently cut a line at 4095 bytes, so a long tty
value was stored truncated with exit 0; a tty line that long is now refused.
And a stray Enter at the `set` prompt stored an empty value over an existing
key; an empty tty `set` value is now refused (a piped one still works).

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

### 17. Passphrase retained in daemon memory (L3) — `done` (2026-10-03, afa8352, 43219db)

DESIGN.md and "What holds up" claimed the daemon never retained the
passphrase, but `std::getline(std::cin)` left it in glibc's unscrubbed stdin
buffer, and rotate/passwd requests left it in the receive buffer, request
line, and `Request` fields. Fixed as described in "What holds up". Ceilings
(`ponytail:` in code): nlohmann::json parse-tree copies; request lines over
64 KiB reallocate the receive buffer (passphrase requests are far smaller).
Verification pass: `read_line`'s erase slid a pipelined follow-up request
forward and left a stale copy past `size()` that teardown never zeroed; the
Connection now zeroes the whole allocation (`capacity()`) on destruction and
move-assignment.

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

### 20. No parent-directory fsync after rename (L6) — `done` (2026-10-03, afa8352, 43219db)

A power loss could roll back an acknowledged `set`/`delete`/`passwd`.
`write_file_atomic` now fsyncs the parent directory after the rename.

Verification pass: that fsync threw after the rename had already replaced the
store, and persist's callers read a throw as "nothing changed" — a failed
`passwd` could leave the disk under the new passphrase while the user was told
it was unchanged. A failure past the rename is now a stderr warning
(durability best-effort, `ponytail:` in code); paths_test injects it with a
0300 directory.

### 21. Manifest env names and `exec` program lookup (L7) — `done` (2026-10-03, 7399ba7, 43219db, 7f36a00); cross-scope `key:` `accepted`

`vars:` could set `PATH`, `LD_PRELOAD`, `BASH_ENV`, ..., and `PATH` was
applied before `execvp`, so a manifest could choose which `psql` ran. Fixed:
`vars:` keys and `env_var_name` reject a deny list (`ponytail:` ceiling; the
full list is in manifest.cpp and USING.md's Manifest rules).

Verification pass: the first list still let a manifest run code through the
child's own tools — psql runs `PAGER`/`PSQL_PAGER` via `sh -c`, git runs
`GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` (`core.sshCommand`, `core.pager`) and
reads a repo-local gitconfig via `HOME`/`XDG_CONFIG_HOME`, glibc iconv loads
from `GCONV_PATH`, bash runs `PROMPT_COMMAND` — and a manifest `PATH` still
chose every program the child spawned (resolving only `argv[0]` against the
caller's PATH did not cover grandchildren). Now also denied: the `GIT_*` and
`XDG_*` prefixes, `PATH`, `HOME`, `PROMPT_COMMAND`, `PS1`, `PS4`, `ZDOTDIR`,
`PAGER`, `PSQL_PAGER`, `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `EDITOR`,
`VISUAL`, `GCONV_PATH`, `NODE_PATH`, `PYTHONHOME`, `RUBYLIB`. With `PATH`
denied, the separate program resolution was dropped and `exec` is plain
`execvp` again, which also restores its `/bin/sh` fallback for shebang-less
scripts (lost with `execv`). `--secret KEY=VAR` on the command
line is not filtered (your own argv). A manifest `key:` naming another
project's scope is accepted under ceiling #1: since finding 11 a manifest is
only read if you own it and nobody else can write it.

Second verification pass: siblings of denied names still passed — `PERLLIB`,
`JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `PYTHONUSERBASE` (runs the user site's
`.pth` files), `PSQLRC` (psql `\!` at connect), `SSH_ASKPASS` with
`SSH_ASKPASS_REQUIRE`, `KUBECONFIG` (exec credential plugins) and
`AWS_CONFIG_FILE` (`credential_process`) — and proxy/CA overrides let a
manifest intercept the child's secret-bearing requests. All now denied:
those names, `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` in both cases,
`SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`. `NO_PROXY` stays allowed: it can only bypass a proxy,
not redirect traffic.

Third pass: `OPENSSL_CONF` (an engine/provider `.so` loaded inside curl,
Python ssl, libpq), `GOFLAGS=-toolexec`, and a mixed-case `Https_Proxy`
(Python lowercases every `*_proxy`) still passed. Names are now compared
upper-cased; denied as well: any `*_PROXY` but `NO_PROXY`, the `NPM_CONFIG_`,
`BUNDLE_`, `GEM_` and `LUA_` prefixes, `OPENSSL_CONF`/`_ENGINES`/`_MODULES`,
`GOFLAGS`, `CLASSPATH`, `MAVEN_OPTS`, `GRADLE_OPTS`, `SSLKEYLOGFILE`,
`AWS_SHARED_CREDENTIALS_FILE`, `DOCKER_HOST`. Still a deny list (ceiling).

Fourth pass: `PYTHONWARNINGS=...:antigravity...` with `BROWSER` ran a shell
command from any Python child, and more loader, interception and
package-index names passed (`PYTHONBREAKPOINT`, `PERL5DB`, `PHPRC`,
`DOTNET_STARTUP_HOOKS`, `RUSTC_WRAPPER`, `GLIBC_TUNABLES`, `SHELLOPTS`,
`GOPROXY`, `PIP_INDEX_URL`, `NODE_TLS_REJECT_UNAUTHORIZED`, `AWS_CA_BUNDLE`,
...). Now denied: those names and their siblings, and the `PIP_`, `UV_`,
`CARGO_`, `RUSTUP_`, `RUSTC_`, `DOTNET_` and `CORECLR_` prefixes (full list
in manifest.cpp and USING.md). Four passes in, the list keeps lagging each
tool's next loader or index variable: it is recorded as a lagging ceiling,
not a guarantee. An allow list would break ordinary app config; the real
boundary stays ceiling #1 (running `exec` in a checkout runs its code).
`import` now also requires the manifest's directory to be a writable
directory before storing anything, and updates a symlinked manifest at its
target instead of replacing the link.

Fifth pass: the prefixes also caught the registry credentials those tools
read, which then refused a whole manifest mapping one; `CARGO_REGISTRY_TOKEN`,
`CARGO_REGISTRIES_<NAME>_TOKEN` and `UV_PUBLISH_TOKEN`/`_PASSWORD`/`_USERNAME`
are now allowed. Also denied: `CC`, `CXX` (run by cc-rs, cgo, sdist builds),
`GOWORK` (`replace` swaps in local modules), `MAKEFLAGS`, `MFLAGS`,
`GNUMAKEFLAGS` (`SHELL=...` runs every recipe).

### 22. Client never authenticated the daemon end (L8) — `done` (2026-10-03, afa8352)

Clients sent the token (and on rotate/passwd the passphrases) to whatever
served the socket path. Now `DaemonClient::send` refuses a peer whose UID is
not ours before writing anything. A set `XDG_RUNTIME_DIR` is still used as
given — `accepted`: the peer check covers a misconfigured shared dir.

### 23. Daemon start unlinked a live socket (L9) — `done` (2026-10-03, afa8352)

A second `secretov daemon` took over the path, leaving the service daemon
unlocked and unreachable. Now it exits 1 with "daemon already running at
<path>" before the passphrase prompt (and before any auto-rotate) when a
daemon already answers, and on exit unlinks the path only if it still names
its own inode. At bind (after unlock and any auto-rotate) it re-checks for a
live daemon, refuses a path that is not a socket, and removes only a stale
socket. Verification pass, `accepted`: two daemons started together both pass
the pre-prompt check during Argon2id and can both auto-rotate before the
bind-time re-check stops the second; same-UID only.

### 24. Client processes were dumpable (L10) — `done` (2026-10-03, afa8352)

See 9a. `exec` children are unaffected (execve resets the flag), and no
RLIMIT_CORE is set outside the daemon, so children keep their core limit.

### 25. TUI reveal never auto-hides; `get` output in scrollback (L11) — `done` (TUI part)

A revealed value stayed on screen until a keypress, selection change, or exit.
Fixed 2026-10-03: a revealed value re-masks (and is zeroed) after 60 s, with a
countdown in the status bar; selection change re-masks synchronously. `get`
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

### 28. Vendored dependency bumps never reached a checkout (L14) — `done` (2026-10-03, 295fec5, eeb441a, 43219db)

get-deps.sh only checked that files existed, and `update` never ran it.
Now each artifact has a version+digest `.stamp` and is refetched when it
differs, and `scripts/service install|update` run get-deps.sh every time (a
no-op when stamps match).

Verification pass: get-deps.sh removed the vendored libsodium before
fetching, so an offline run left the checkout unbuildable (this host has no
system libsodium), and checkouts from before 295fec5 have no stamps, so their
first `install`/`update` always refetches. Now json.hpp is fetched to a
temporary name and libsodium's old tree is removed only after the new one
built; a failed fetch keeps both. README notes that the first run after
295fec5 (`just setup` or `scripts/service install|update`) needs network and
takes minutes.

### 29. Unit set only NoNewPrivileges (L15) — `done` (2026-10-03, eeb441a); namespace options `accepted`

Added: `UMask=0077`, `RestrictAddressFamilies=AF_UNIX`,
`SystemCallFilter=@system-service ~@privileged`,
`SystemCallArchitectures=native`, `MemoryDenyWriteExecute`,
`LockPersonality`, `RestrictNamespaces`, `RestrictRealtime`,
`RestrictSUIDSGID`, `KeyringMode=private` (verified with secret-tool unlock
under a transient unit). Not added: PrivateTmp/PrivateDevices/ProtectSystem/
ProtectHome and the other namespace-based options: only same-UID peers reach
the daemon, and a same-UID attacker reads the store, token and keyring
without going through it, so they would add little. (Corrected in the
verification pass: the earlier rationale said this host blocks unprivileged
user namespaces; it does not — Pop!_OS 24.04 here has no
`apparmor_restrict_unprivileged_userns`. Stock Ubuntu 24.04's AppArmor block
is a portability limit on adding them, not this host's constraint.)

### 30. No passphrase floor; KDF params frozen at create (I1) — `done` (2026-10-03, afa8352, 8690859)

`init` and `passwd` warn (not refuse) below 12 characters. `passwd` writes
the stronger of the store's and the default Argon2id params (MODERATE),
upgrading older stores and never downgrading;
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

1. Host config (12, 26): `chmod g-w` the four project dirs and manifests
   (until then every manifest here is refused); lock or remove the unused
   devuser account; umask 027;
   `scripts/service update` to pick up the hardened, session-bound unit;
   disable linger if nothing needs it. Minutes.
2. `lock` op tied to logind Lock (32).
3. Keyring unlock-key slot instead of the passphrase in the keyring (16).
4. TPM2 `systemd-creds` credential (15; needs systemd ≥ 256).
5. LUKS or encrypted `/home` (15; also closes 2 on disk-swap hosts).
   Machine-level, high effort, biggest at-rest gain.
6. ~~TUI auto re-mask timer (25).~~ Done 2026-10-03.
