#!/bin/sh
# Fetches vendored deps when system packages (libsodium-dev, nlohmann-json3-dev)
# are absent. Installs into third_party/ (gitignored). Downloads are verified
# against pinned sha256 digests; a mismatch aborts before anything is used.
set -eu
cd "$(dirname "$0")"

JSON_URL=https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp
JSON_SHA256=aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63
SODIUM_VERSION=1.0.22
SODIUM_URL=https://github.com/jedisct1/libsodium/releases/download/$SODIUM_VERSION-RELEASE/libsodium-$SODIUM_VERSION.tar.gz
SODIUM_SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349

# fetch URL SHA256 DEST — download to DEST, verify, delete on mismatch.
fetch() {
  curl -fsSL -o "$3" "$1"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$3" | cut -d' ' -f1)
  else
    actual=$(shasum -a 256 "$3" | cut -d' ' -f1)
  fi
  if [ "$actual" != "$2" ]; then
    rm -f "$3"
    echo "get-deps: sha256 mismatch for $1" >&2
    echo "  expected $2" >&2
    echo "  got      $actual" >&2
    exit 1
  fi
}

if [ ! -f nlohmann/json.hpp ]; then
  mkdir -p nlohmann
  fetch "$JSON_URL" "$JSON_SHA256" nlohmann/json.hpp
fi

if [ ! -f sodium/lib/libsodium.a ]; then
  fetch "$SODIUM_URL" "$SODIUM_SHA256" libsodium.tar.gz
  tar xzf libsodium.tar.gz
  cd "libsodium-$SODIUM_VERSION"
  ./configure --prefix="$(cd .. && pwd)/sodium" --disable-shared --quiet
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
  cd ..
  rm -rf "libsodium-$SODIUM_VERSION" libsodium.tar.gz
fi
echo "deps ready"
