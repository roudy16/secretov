#!/usr/bin/env bash
# Checks the link-time hardening declared in CMakeLists.txt reached the binary.
set -eu
BIN="$1"
fail() { echo "HARDENING FAIL: $*" >&2; exit 1; }

readelf -h "$BIN" | grep -q 'Type:.*DYN' || fail "not PIE"
readelf -d "$BIN" | grep -q 'BIND_NOW' || fail "no BIND_NOW (-z now)"
readelf -lW "$BIN" | grep -q 'GNU_RELRO' || fail "no GNU_RELRO"
readelf -lW "$BIN" | grep 'GNU_STACK' | grep -q 'RW ' || fail "executable stack"
echo "hardening test passed"
