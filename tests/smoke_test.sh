#!/usr/bin/env bash
# End-to-end smoke test for secretov. Uses a scratch HOME/XDG env so it never
# touches the real ~. Passes secretov as $1 (the built binary), else finds it.
set -eu
# Manifests in group/world-writable dirs are refused; don't inherit a 0002 umask.
umask 077

BIN="${1:-}"
if [ -z "$BIN" ]; then
    BIN="$(dirname "$0")/../build/secretov"
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
export HOME="$WORK/home"
export XDG_DATA_HOME="$WORK/data"
export XDG_CONFIG_HOME="$WORK/config"
export XDG_RUNTIME_DIR="$WORK/run"
mkdir -p "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"

SOCK="$XDG_RUNTIME_DIR/secretov.sock"
TOKEN="$XDG_CONFIG_HOME/secretov/token"
PASS="correct horse battery staple"
DAEMON_PID=""

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

# 1. init
printf '%s\n' "$PASS" | "$BIN" init >/dev/null || fail "init"
[ -f "$TOKEN" ] || fail "token file not created"
[ "$(stat -c %a "$XDG_DATA_HOME/secretov")" = "700" ] || fail "store dir not 0700"
# secret lines are capped (fixed buffer, never reallocated)
LONG_ERR="$(head -c 5000 /dev/zero | tr '\0' a | "$BIN" init 2>&1)" && fail "over-long passphrase accepted"
echo "$LONG_ERR" | grep -q "longer than 4096 bytes" || fail "long passphrase message: $LONG_ERR"

# 1b. daemon on a tty but in a background process group fails fast instead of
# stopping on SIGTTOU (the passphrase would then be typed into the shell).
python3 - "$BIN" <<'PY' || fail "background daemon on a tty did not fail fast"
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    child = os.fork()
    if child == 0:
        os.setpgid(0, 0)
        os.execv(sys.argv[1], [sys.argv[1], "daemon"])
    os.setpgid(child, child)
    status = None
    for _ in range(50):
        done, st = os.waitpid(child, os.WNOHANG | os.WUNTRACED)
        if done:
            status = st
            break
        time.sleep(0.1)
    ok = status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1
    if not ok:
        os.kill(child, 9)
    os._exit(0 if ok else 3)
out = b""
while True:
    try:
        chunk = os.read(fd, 1024)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
_, status = os.waitpid(pid, 0)
sys.exit(0 if os.WEXITSTATUS(status) == 0 and b"foreground" in out else "got %r" % out)
PY

# 2. daemon in background; wait for socket
printf '%s\n' "$PASS" | "$BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
    [ -S "$SOCK" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited early: $(cat "$WORK/daemon.log")"
    sleep 0.1
done
[ -S "$SOCK" ] || fail "socket did not appear"

# 2b. a second daemon is refused and leaves the first one's socket alone
SECOND_ERR="$(printf '%s\n' "$PASS" | timeout 5 "$BIN" daemon 2>&1)" && fail "second daemon should be refused"
echo "$SECOND_ERR" | grep -q "already running" || fail "second daemon message: $SECOND_ERR"
[ -S "$SOCK" ] || fail "second daemon removed the live socket"
"$BIN" list >/dev/null || fail "first daemon unreachable after a second start attempt"

# 2c. clients are non-dumpable (no core dumps of tokens/values); a non-dumpable
# process's /proc files are owned by root rather than by us.
{ sleep 3; } 2>/dev/null | "$BIN" set DUMPCHK &
SET_PID=$!
DUMPABLE_OFF=""
for _ in $(seq 1 50); do
    owner="$(stat -c %u "/proc/$SET_PID/environ" 2>/dev/null || true)"
    [ -n "$owner" ] && [ "$owner" != "$(id -u)" ] && { DUMPABLE_OFF=1; break; }
    sleep 0.1
done
kill "$SET_PID" 2>/dev/null || true
wait "$SET_PID" 2>/dev/null || true
[ -n "$DUMPABLE_OFF" ] || fail "client process is still dumpable"

# 3. set/get round-trip (set reads value from stdin only), list, delete
printf '%s' "bar" | "$BIN" set FOO
[ "$("$BIN" get FOO)" = "bar" ] || fail "get after set (stdin)"
# argv VALUE form is rejected (would leak the secret via /proc/<pid>/cmdline)
if "$BIN" set BADKEY somevalue 2>/dev/null; then fail "argv-form 'set KEY VALUE' should fail"; fi
printf '%s' "s3cr3t-value" | "$BIN" set VIA_STDIN
# piped stdin is read whole: multi-line values survive
printf 'line1\nline2\n' | "$BIN" set MULTI
[ "$("$BIN" get MULTI)" = "$(printf 'line1\nline2')" ] || fail "multi-line piped set"
# on a tty, set prompts with echo off and reads one line
python3 - "$BIN" <<'PY' || fail "tty set"
import os, pty, select, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], "set", "TTY_KEY"])
out = b""
while b"Value for TTY_KEY" not in out:
    if not select.select([fd], [], [], 5)[0]:
        sys.exit("no prompt: %r" % out)
    out += os.read(fd, 1024)
os.write(fd, b"tty-secret\n")
while True:
    if not select.select([fd], [], [], 5)[0]:
        os.kill(pid, 9)
        sys.exit("set did not finish after one line: %r" % out)
    try:
        chunk = os.read(fd, 1024)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
_, status = os.waitpid(pid, 0)
if os.WEXITSTATUS(status) != 0 or b"tty-secret" in out:
    sys.exit("status %d, output %r" % (status, out))
PY
[ "$("$BIN" get TTY_KEY)" = "tty-secret" ] || fail "tty set value"
# Run `set KEY` on a pty and type PAYLOAD_FILE's bytes in one blocking write,
# as a terminal emulator pastes; once quiet, type "marker". Passes when set
# exits 1 with EXPECTED in its output and the shell's next `read` gets only the
# marker: nothing of the payload reached the shell (which would run it as
# commands and save it to history).
tty_set_refused() {
    python3 - "$BIN" "$@" <<'PY'
import os, pty, select, sys, threading, time
binary, key, payload_path, expected = sys.argv[1:5]
payload = open(payload_path, "rb").read()
pid, fd = pty.fork()
if pid == 0:
    script = '"$0" set "$1"; s=$?; IFS= read -r rest; echo "STATUS=$s LEFTOVER=[$rest]"'
    os.execv("/bin/sh", ["sh", "-c", script, binary, key])
out = b""
while ("Value for " + key).encode() not in out:
    if not select.select([fd], [], [], 5)[0]:
        sys.exit("no prompt: %r" % out)
    out += os.read(fd, 1024)
def write_all():
    view = memoryview(payload)
    while view:
        view = view[os.write(fd, view):]
writer = threading.Thread(target=write_all, daemon=True)
writer.start()
sent_marker = False
deadline = time.monotonic() + 20
while b"LEFTOVER=" not in out and time.monotonic() < deadline:
    if not select.select([fd], [], [], 1)[0]:
        if sent_marker:
            break
        if not writer.is_alive():
            os.write(fd, b"marker\n")
            sent_marker = True
        continue
    try:
        out += os.read(fd, 65536)
    except OSError:
        break
if b"LEFTOVER=" not in out:
    os.kill(pid, 9)
os.waitpid(pid, 0)
if b"STATUS=1 LEFTOVER=[marker]" not in out or expected.encode() not in out:
    sys.exit("got %r" % out[-2000:])
PY
}
# a multi-line paste at the tty prompt fails and leaves nothing for the shell
printf -- '-----BEGIN KEY-----\nc2VjcmV0LWxpbmUtMg==\n-----END KEY-----\n' > "$WORK/paste"
tty_set_refused PASTED "$WORK/paste" "more input followed the line" || fail "tty multi-line paste"
# ...even one larger than the ~4 KiB tty input queue, which the terminal
# writes in pieces as the queue drains
python3 -c 'import sys; sys.stdout.write("-----BEGIN KEY-----\n" + "".join("SECRETLINE%03d%s\n" % (i, "A" * 50) for i in range(150)) + "-----END KEY-----\n")' > "$WORK/paste"
tty_set_refused PASTED "$WORK/paste" "more input followed the line" || fail "tty paste over 8 KiB"
# a tty line the terminal may have truncated (4095 bytes kept) is refused
{ head -c 5000 /dev/zero | tr '\0' a; printf '\n'; } > "$WORK/paste"
tty_set_refused PASTED "$WORK/paste" "truncated by the terminal" || fail "tty over-long line"
# a stray Enter at the tty prompt does not overwrite the key with ""
printf '\n' > "$WORK/paste"
tty_set_refused TTY_KEY "$WORK/paste" "empty value on the terminal" || fail "tty empty value"
[ "$("$BIN" get TTY_KEY)" = "tty-secret" ] || fail "tty empty value overwrote the key"
if "$BIN" get PASTED >/dev/null 2>&1; then fail "multi-line tty paste stored a value"; fi
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after set (stdin)"
"$BIN" list | grep -qx FOO || fail "list missing FOO"
"$BIN" list | grep -qx VIA_STDIN || fail "list missing VIA_STDIN"
"$BIN" delete FOO
if "$BIN" get FOO >/dev/null 2>&1; then fail "get after delete should fail"; fi

# 4. rotate; get still works. Wrong passphrase is rejected.
if printf 'wrong\n' | "$BIN" rotate >/dev/null 2>&1; then fail "rotate with wrong passphrase should fail"; fi
printf '%s\n' "$PASS" | "$BIN" rotate
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after rotate"

# 5. exec injects secret into child env
OUT="$("$BIN" exec --secret VIA_STDIN=INJECTED -- sh -c 'printf %s "$INJECTED"')"
[ "$OUT" = "s3cr3t-value" ] || fail "exec injection got '$OUT'"

# 5b. tui without a terminal exits 1 with a clear message
TUI_ERR="$("$BIN" tui </dev/null 2>&1 1>/dev/null)" && fail "tui with no tty should exit 1"
echo "$TUI_ERR" | grep -q "requires a terminal" || fail "tui no-tty message: got '$TUI_ERR'"

# 5c. passwd: wrong current passphrase rejected; correct one re-keys the store,
# and a daemon restart requires the new passphrase.
NEWPASS="staple battery horse correct"
if printf 'wrong\n%s\n' "$NEWPASS" | "$BIN" passwd >/dev/null 2>&1; then
    fail "passwd with wrong current passphrase should fail"
fi
printf '%s\n%s\n' "$PASS" "$NEWPASS" | "$BIN" passwd >/dev/null || fail "passwd"
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after passwd"
# a short new passphrase is accepted with a warning
SHORT_OUT="$(printf '%s\n%s\n' "$NEWPASS" "short" | "$BIN" passwd 2>&1)" || fail "passwd to short"
echo "$SHORT_OUT" | grep -q "shorter than 12" || fail "no short-passphrase warning: $SHORT_OUT"
printf '%s\n%s\n' "short" "$NEWPASS" | "$BIN" passwd >/dev/null 2>&1 || fail "passwd back from short"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] || break
    sleep 0.1
done
if printf '%s\n' "$PASS" | "$BIN" daemon >/dev/null 2>&1; then
    fail "daemon start with old passphrase should fail after passwd"
fi
printf '%s\n' "$NEWPASS" | "$BIN" daemon >>"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
    [ -S "$SOCK" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited early after passwd: $(cat "$WORK/daemon.log")"
    sleep 0.1
done
[ -S "$SOCK" ] || fail "socket did not reappear after passwd restart"
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after restart with new passphrase"
printf '%s\n' "$NEWPASS" | "$BIN" rotate
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after rotate with new passphrase"

# 5d. scopes: import a dotenv into dev/demo (manifest created), exec injects via
# the manifest, collisions refused without --overwrite, list filters, registry
# makes -p work from elsewhere, comments in the manifest survive a second import.
PROJ="$WORK/demo"
mkdir -p "$PROJ"
printf 'DB_URL=postgres://x\n# a comment\nexport API_KEY="k # v"\n' > "$PROJ/.env"
( cd "$PROJ" && "$BIN" import -p demo -e dev >/dev/null ) || fail "import"
[ -f "$PROJ/.secretov.yaml" ] || fail "manifest not created"
[ "$("$BIN" get dev/demo/DB_URL)" = "postgres://x" ] || fail "imported value"
[ "$("$BIN" get dev/demo/API_KEY)" = "k # v" ] || fail "imported quoted value"
if ( cd "$PROJ" && "$BIN" import -e dev >/dev/null 2>&1 ); then fail "re-import without --overwrite should fail"; fi
printf '# keep me\n' >> "$PROJ/.secretov.yaml"
printf 'DB_URL=postgres://y\nNEW_ONE=n\n' > "$PROJ/.env"
( cd "$PROJ" && "$BIN" import -e dev --overwrite >/dev/null ) || fail "import --overwrite"
grep -q '^# keep me$' "$PROJ/.secretov.yaml" || fail "manifest comment lost on import"
grep -q '^      NEW_ONE:$' "$PROJ/.secretov.yaml" || fail "manifest entry not added"
OUT="$(cd "$PROJ" && "$BIN" exec -e dev -- sh -c 'printf "%s|%s|%s" "$DB_URL" "$API_KEY" "$NEW_ONE"')"
[ "$OUT" = "postgres://y|k # v|n" ] || fail "scoped exec got '$OUT'"
DRY="$(cd "$PROJ" && "$BIN" exec -e dev --dry-run)"
echo "$DRY" | grep -q "API_KEY <- dev/demo/API_KEY" || fail "dry-run missing mapping: $DRY"
echo "$DRY" | grep -q "postgres" && fail "dry-run leaked a value"
if ( cd "$PROJ" && "$BIN" exec -- true 2>/dev/null ); then fail "exec without env and without default_env should fail"; fi
OUT="$(cd "$PROJ" && SECRETOV_ENV=dev "$BIN" exec -- sh -c 'printf %s "$NEW_ONE"')"
[ "$OUT" = "n" ] || fail "SECRETOV_ENV not honoured"
"$BIN" list -p demo -e dev | grep -qx "dev/demo/API_KEY" || fail "scoped list"
if "$BIN" list -p demo -e dev | grep -qx "VIA_STDIN"; then fail "scoped list leaked unscoped key"; fi
mkdir -p "$XDG_CONFIG_HOME/secretov"
printf 'projects:\n  demo:\n    root: "%s"\n' "$PROJ" > "$XDG_CONFIG_HOME/secretov/projects.yaml"
OUT="$(cd / && "$BIN" exec -p demo -e dev -- sh -c 'printf %s "$DB_URL"')"
[ "$OUT" = "postgres://y" ] || fail "registry exec got '$OUT'"
if ( cd / && "$BIN" exec -p nope -e dev -- true 2>/dev/null ); then fail "unregistered -p should fail"; fi
# raw --secret still works anywhere, without a manifest
OUT="$(cd / && "$BIN" exec --secret VIA_STDIN=RAW -- sh -c 'printf %s "$RAW"')"
[ "$OUT" = "s3cr3t-value" ] || fail "raw exec got '$OUT'"

# 5e. set -p/-e resolves env/project/NAME (same helper as list/exec/import).
printf '%s' "postgres://z" | ( cd "$PROJ" && "$BIN" set DB_URL -e dev ) || fail "scoped set (manifest)"
[ "$("$BIN" get dev/demo/DB_URL)" = "postgres://z" ] || fail "scoped set value"
printf '%s' "from-registry" | ( cd / && "$BIN" set DB_URL -p demo -e dev ) || fail "scoped set (registry)"
[ "$("$BIN" get dev/demo/DB_URL)" = "from-registry" ] || fail "registry scoped set value"
# unscoped set still writes the raw key, and set can still create
printf '%s' "raw" | "$BIN" set RAW_KEY || fail "unscoped set"
[ "$("$BIN" get RAW_KEY)" = "raw" ] || fail "unscoped set value"
# scoped set replaces, never duplicates
[ "$("$BIN" list -p demo -e dev | grep -cx 'dev/demo/DB_URL')" = "1" ] || fail "scoped set duplicated key"
if ( cd / && "$BIN" set DB_URL -e dev 2>/dev/null </dev/null ); then fail "set -e outside a project should fail"; fi

# 5f. plaintext vars: injected from the manifest, never stored, shown by dry-run.
python3 - "$PROJ/.secretov.yaml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
t = t.replace("  dev:\n", "  dev:\n    vars:\n      LOG_LEVEL: debug\n      PORT: 8080\n", 1)
p.write_text(t)
PY
OUT="$(cd "$PROJ" && "$BIN" exec -e dev -- sh -c 'printf "%s|%s|%s" "$LOG_LEVEL" "$PORT" "$DB_URL"')"
[ "$OUT" = "debug|8080|from-registry" ] || fail "plaintext vars injection got '$OUT'"
# vars are manifest-only; nothing was written to the store
if "$BIN" get dev/demo/LOG_LEVEL >/dev/null 2>&1; then fail "plaintext var leaked into the store"; fi
"$BIN" list -p demo -e dev | grep -qx "dev/demo/LOG_LEVEL" && fail "plaintext var appeared in list"
# dry-run shows plaintext values (safe: they are committed) but still no secrets
DRY="$(cd "$PROJ" && "$BIN" exec -e dev --dry-run)"
echo "$DRY" | grep -q "LOG_LEVEL = debug" || fail "dry-run missing plaintext var: $DRY"
echo "$DRY" | grep -q "DB_URL <- dev/demo/DB_URL" || fail "dry-run lost secret mapping"
echo "$DRY" | grep -q "from-registry" && fail "dry-run leaked a secret value"
# a var colliding with a secret's env_var_name is refused
cp "$PROJ/.secretov.yaml" "$PROJ/.secretov.yaml.bak"
python3 - "$PROJ/.secretov.yaml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("      PORT: 8080\n", "      PORT: 8080\n      DB_URL: oops\n", 1))
PY
if ( cd "$PROJ" && "$BIN" exec -e dev -- true 2>/dev/null ); then fail "vars/secrets collision should fail"; fi
( cd "$PROJ" && "$BIN" exec -e dev -- true 2>&1 || true ) | grep -q "set in both vars and secrets" \
    || fail "collision message"
mv "$PROJ/.secretov.yaml.bak" "$PROJ/.secretov.yaml"
# import still edits the secrets block without disturbing vars
printf 'LATER=x\n' > "$PROJ/.env"
( cd "$PROJ" && "$BIN" import -e dev >/dev/null ) || fail "import alongside vars"
grep -q "LOG_LEVEL: debug" "$PROJ/.secretov.yaml" || fail "import clobbered the vars block"
OUT="$(cd "$PROJ" && "$BIN" exec -e dev -- sh -c 'printf "%s|%s" "$LOG_LEVEL" "$LATER"')"
[ "$OUT" = "debug|x" ] || fail "post-import injection got '$OUT'"
# a scope whose values total more than the daemon's 1 MiB request cap still
# fetches: the client's response cap is far larger
head -c 700000 /dev/zero | tr '\0' x | "$BIN" set dev/demo/BIG1 || fail "set BIG1"
head -c 700000 /dev/zero | tr '\0' y | "$BIN" set dev/demo/BIG2 || fail "set BIG2"
( cd "$PROJ" && "$BIN" exec -e dev -- true ) || fail "exec with a >1 MiB scope"
"$BIN" delete dev/demo/BIG1
"$BIN" delete dev/demo/BIG2

# 5g. a manifest cannot set PATH (it would pick the program and every program
# the child spawns); a shebang-less executable still runs via /bin/sh like
# execvp. A group-writable project dir is refused.
mkdir -p "$PROJ/bin"
printf 'printf noshebang-ran\n' > "$PROJ/bin/nosb"
chmod +x "$PROJ/bin/nosb"
OUT="$(PATH="$PROJ/bin:$PATH" "$BIN" exec --secret VIA_STDIN=X -- nosb)" || fail "shebang-less exec"
[ "$OUT" = "noshebang-ran" ] || fail "shebang-less exec got '$OUT'"
cp "$PROJ/.secretov.yaml" "$PROJ/.secretov.yaml.bak"
python3 - "$PROJ/.secretov.yaml" <<'PY2'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
p.write_text(t.replace("    vars:\n", "    vars:\n      PATH: /tmp/evil\n", 1))
PY2
ERR="$(cd "$PROJ" && "$BIN" exec -e dev -- true 2>&1)" && fail "manifest PATH should be refused"
echo "$ERR" | grep -q "cannot be set from a manifest" || fail "manifest PATH message: $ERR"
mv "$PROJ/.secretov.yaml.bak" "$PROJ/.secretov.yaml"
chmod g+w "$PROJ"
ERR="$(cd "$PROJ" && "$BIN" exec -e dev -- true 2>&1)" && fail "group-writable project dir should be refused"
echo "$ERR" | grep -q "chmod g-w,o-w '$PROJ'" || fail "untrusted dir message: $ERR"
chmod g-w "$PROJ"
# import refuses a new manifest's untrusted dir before storing anything, and a
# dangling manifest symlink fails as it does for exec instead of being replaced
GW="$WORK/gw"
mkdir -p "$GW"
printf 'GWTOK=x\n' > "$GW/.env"
chmod g+w "$GW"
ERR="$(cd "$GW" && "$BIN" import -p gw -e dev 2>&1)" && fail "import into a group-writable dir should fail"
echo "$ERR" | grep -q "writable by group or others" || fail "import untrusted dir message: $ERR"
if "$BIN" get dev/gw/GWTOK >/dev/null 2>&1; then fail "refused import stored a secret"; fi
chmod g-w "$GW"
ln -s missing "$GW/.secretov.yaml"
if ( cd "$GW" && "$BIN" import -p gw -e dev >/dev/null 2>&1 ); then fail "import replaced a dangling manifest link"; fi
[ -L "$GW/.secretov.yaml" ] || fail "dangling manifest link was replaced"

# 6. wrong token is rejected (corrupt the client's token file copy, then restore)
cp "$TOKEN" "$TOKEN.good"
printf 'deadbeefdeadbeef' > "$TOKEN"
if "$BIN" get VIA_STDIN >/dev/null 2>&1; then
    cp "$TOKEN.good" "$TOKEN"
    fail "request with wrong token should be rejected"
fi
cp "$TOKEN.good" "$TOKEN"

# 7. SIGTERM stops daemon and removes socket
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] || break
    sleep 0.1
done
[ -S "$SOCK" ] && fail "socket still present after SIGTERM"

echo "SMOKE OK"
