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
