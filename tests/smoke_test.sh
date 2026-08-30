#!/usr/bin/env bash
# End-to-end smoke test for secretov. Uses a scratch HOME/XDG env so it never
# touches the real ~. Passes secretov as $1 (the built binary), else finds it.
set -eu

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

# 2. daemon in background; wait for socket
printf '%s\n' "$PASS" | "$BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
    [ -S "$SOCK" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited early: $(cat "$WORK/daemon.log")"
    sleep 0.1
done
[ -S "$SOCK" ] || fail "socket did not appear"

# 3. set/get round-trip (set reads value from stdin only), list, delete
printf '%s' "bar" | "$BIN" set FOO
[ "$("$BIN" get FOO)" = "bar" ] || fail "get after set (stdin)"
# argv VALUE form is rejected (would leak the secret via /proc/<pid>/cmdline)
if "$BIN" set BADKEY somevalue 2>/dev/null; then fail "argv-form 'set KEY VALUE' should fail"; fi
printf '%s' "s3cr3t-value" | "$BIN" set VIA_STDIN
[ "$("$BIN" get VIA_STDIN)" = "s3cr3t-value" ] || fail "get after set (stdin)"
"$BIN" list | grep -qx FOO || fail "list missing FOO"
"$BIN" list | grep -qx VIA_STDIN || fail "list missing VIA_STDIN"
"$BIN" delete FOO
if "$BIN" get FOO >/dev/null 2>&1; then fail "get after delete should fail"; fi

# 4. rotate; get still works
"$BIN" rotate
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
