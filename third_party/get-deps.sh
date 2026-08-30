#!/bin/sh
# Fetches vendored deps when system packages (libsodium-dev, nlohmann-json3-dev)
# are absent. Installs into third_party/ (gitignored). Downloads are verified
# against pinned sha256 digests; a mismatch aborts before anything is used.
set -eu
cd "$(dirname "$0")"

JSON_URL=https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
JSON_SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
SODIUM_URL=https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz
SODIUM_SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19

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
  cd libsodium-1.0.20
  ./configure --prefix="$(cd .. && pwd)/sodium" --disable-shared --quiet
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
  cd ..
  rm -rf libsodium-1.0.20 libsodium.tar.gz
fi
echo "deps ready"
