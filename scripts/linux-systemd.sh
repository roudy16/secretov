#!/usr/bin/env bash
# Linux/systemd implementation of scripts/service. Installs the secretov
# binary (CLI + daemon are one binary) to $PREFIX and runs the daemon as a
# systemd user unit.
#
# The daemon needs a passphrase and a service has no tty: `start` prompts,
# writes the passphrase 0600 to $XDG_RUNTIME_DIR (tmpfs, never disk), the
# unit reads it as stdin via StandardInput=file:, and the file is removed
# right after start — systemd opens the fd before exec, so unlink is safe.
# Consequence: the daemon cannot auto-start at boot; `start` is interactive.
set -euo pipefail

REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX="${SECRETOV_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/secretov"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
PASS_FILE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/secretov.pass"

usage() {
    cat <<EOF
usage: scripts/service <verb>

  install   build, install CLI+daemon binary to $PREFIX/bin, register user unit
  update    rebuild + reinstall; restarts the daemon if it is running
  start     start the daemon (prompts for store passphrase)
  stop      stop the daemon
  status    show daemon status
EOF
    exit 2
}

build_and_install() {
    cd "$REPO_DIR"
    if [ ! -d build ]; then
        ./third_party/get-deps.sh
        cmake -B build
    fi
    cmake --build build -j
    cmake --install build --prefix "$PREFIX"
}

write_unit() {
    mkdir -p "$UNIT_DIR"
    cat >"$UNIT_DIR/secretov.service" <<EOF
[Unit]
Description=secretov secrets daemon

[Service]
Type=exec
ExecStart=$BIN daemon
StandardInput=file:$PASS_FILE
NoNewPrivileges=yes
EOF
    systemctl --user daemon-reload
}

start() {
    if systemctl --user is-active --quiet secretov; then
        echo "secretov daemon already running"
        return
    fi
    local pass
    if [ -t 0 ]; then
        read -rsp "Passphrase: " pass
        echo
    else
        pass=$(cat)
    fi
    trap 'rm -f "$PASS_FILE"' RETURN
    (umask 077; printf '%s\n' "$pass" >"$PASS_FILE")
    unset pass
    systemctl --user start secretov
    rm -f "$PASS_FILE"
    # Argon2id unlock takes a moment; watch for early exit (wrong passphrase).
    for _ in $(seq 10); do
        if ! systemctl --user is-active --quiet secretov; then
            echo "secretov daemon failed to start:" >&2
            journalctl --user -u secretov -n 5 --no-pager >&2
            exit 1
        fi
        sleep 0.5
    done
    echo "secretov daemon running"
}

case "${1:-}" in
install)
    build_and_install
    write_unit
    echo "installed $BIN and user unit secretov.service"
    echo "next: '$BIN init' if no store yet, then 'scripts/service start'"
    ;;
update)
    was_active=false
    systemctl --user is-active --quiet secretov && was_active=true
    $was_active && systemctl --user stop secretov
    build_and_install
    write_unit
    $was_active && start
    echo "updated $BIN"
    ;;
start) start ;;
stop) systemctl --user stop secretov ;;
status) exec systemctl --user status secretov --no-pager ;;
*) usage ;;
esac
