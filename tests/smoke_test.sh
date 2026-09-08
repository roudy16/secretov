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
[ "$(stat -c %a "$XDG_DATA_HOME/secretov")" = "700" ] || fail "store dir not 0700"

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
