#!/usr/bin/env bash
# Linux/systemd implementation of scripts/service. Installs the secretov
# binary (CLI + daemon are one binary) to $PREFIX and runs the daemon as a
# systemd user unit bound to the graphical session: it starts at graphical
# login and stops at logout (even with linger on).
#
# The daemon reads its passphrase from stdin and a service has no tty, so the
# passphrase lives in the session keyring (Secret Service — gnome-keyring's
# login collection, unlocked by PAM at login). The unit runs
# `secret-tool lookup ... | secretov daemon`. If the keyring is still locked
# when the unit fires, the daemon exits on an empty passphrase and systemd
# retries for a few minutes. Threat-model note: SECURITY.md finding 10.
set -euo pipefail

REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX="${SECRETOV_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/secretov"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

usage() {
    cat <<USAGE
usage: scripts/service <verb>

  install     build, install CLI+daemon binary to $PREFIX/bin, register + enable user unit
  update      rebuild + reinstall; restarts the daemon if it is running
  passphrase  store (or replace) the store passphrase in the session keyring
  start       start the daemon (stores the passphrase first if the keyring has none)
  stop        stop the daemon
  status      show daemon status
USAGE
    exit 2
}

need_secret_tool() {
    command -v secret-tool >/dev/null 2>&1 && return
    echo "service: secret-tool not found (Debian/Ubuntu: apt install libsecret-tools)" >&2
    exit 1
}

have_passphrase() { secret-tool lookup service secretov >/dev/null 2>&1; }

store_passphrase() {
    need_secret_tool
    # secret-tool prompts (echo off) on a tty, otherwise reads stdin.
    secret-tool store --label='secretov store passphrase' service secretov
    echo "passphrase stored in the session keyring"
}

# get-deps.sh runs every time: it is a no-op unless a pinned dep changed.
build() {
    cd "$REPO_DIR"
    ./third_party/get-deps.sh
    [ -d build ] || cmake -B build
    cmake --build build -j
}

install_binary() { cmake --install "$REPO_DIR/build" --prefix "$PREFIX"; }

write_unit() {
    mkdir -p "$UNIT_DIR"
    cat >"$UNIT_DIR/secretov.service" <<UNIT
[Unit]
Description=secretov secrets daemon
# The keyring is only unlocked inside the graphical session; never outlive it.
PartOf=graphical-session.target
Requisite=graphical-session.target
After=graphical-session.target
# Retry while the keyring is still locked after login; give up after a while
# so a stale keyring passphrase does not burn Argon2id forever.
StartLimitIntervalSec=300
StartLimitBurst=20

[Service]
Type=exec
ExecStart=/bin/sh -c 'secret-tool lookup service secretov | exec "\$0" daemon' $BIN
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
KeyringMode=private

[Install]
WantedBy=graphical-session.target
UNIT
    systemctl --user daemon-reload
    # reenable drops links from an older [Install] (e.g. default.target.wants).
    systemctl --user reenable --quiet secretov
}

start() {
    if systemctl --user is-active --quiet secretov; then
        echo "secretov daemon already running"
        return
    fi
    have_passphrase || store_passphrase
    systemctl --user reset-failed secretov 2>/dev/null || true
    systemctl --user start secretov
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
    need_secret_tool
    build
    install_binary
    write_unit
    echo "installed $BIN and user unit secretov.service (enabled at graphical login)"
    if have_passphrase; then
        echo "next: scripts/service start"
    else
        echo "next: '$BIN init' if no store yet, then 'scripts/service start' (stores the passphrase in the keyring)"
    fi
    ;;
update)
    was_active=false
    systemctl --user is-active --quiet secretov && was_active=true
    build   # before stopping; a failed build must not take the daemon down
    $was_active && systemctl --user stop secretov
    install_binary
    write_unit
    echo "updated $BIN"
    if $was_active; then start; fi
    ;;
passphrase) store_passphrase ;;
start) start ;;
stop) systemctl --user stop secretov ;;
status) exec systemctl --user status secretov --no-pager ;;
*) usage ;;
esac
