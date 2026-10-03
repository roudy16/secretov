#!/bin/sh
# Fetches vendored deps when system packages (libsodium-dev, nlohmann-json3-dev)
# are absent. Installs into third_party/ (gitignored). Downloads are verified
# against pinned sha256 digests; a mismatch aborts before anything is used.
# Each artifact gets a <artifact>.stamp recording version + digest; a missing
# or different stamp (a pin bump) refetches, so bumps reach existing checkouts.
set -eu
cd "$(dirname "$0")"

JSON_VERSION=3.12.0
JSON_URL=https://github.com/nlohmann/json/releases/download/v$JSON_VERSION/json.hpp
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

# stamp_ok ARTIFACT STAMP — artifact exists and its stamp matches STAMP.
stamp_ok() {
  [ -f "$1" ] && [ -f "$1.stamp" ] && [ "$(cat "$1.stamp")" = "$2" ]
}

JSON_STAMP="json $JSON_VERSION $JSON_SHA256"
if ! stamp_ok nlohmann/json.hpp "$JSON_STAMP"; then
  mkdir -p nlohmann
  fetch "$JSON_URL" "$JSON_SHA256" nlohmann/json.hpp.new  # a failed fetch keeps the old header
  mv nlohmann/json.hpp.new nlohmann/json.hpp
  echo "$JSON_STAMP" >nlohmann/json.hpp.stamp
fi

SODIUM_STAMP="libsodium $SODIUM_VERSION $SODIUM_SHA256"
if ! stamp_ok sodium/lib/libsodium.a "$SODIUM_STAMP"; then
  fetch "$SODIUM_URL" "$SODIUM_SHA256" libsodium.tar.gz
  tar xzf libsodium.tar.gz
  cd "libsodium-$SODIUM_VERSION"
  ./configure --prefix="$(cd .. && pwd)/sodium" --disable-shared --quiet
  make -j"$(nproc)" >/dev/null
  # Only now drop the old tree (no stale headers from an older version): a
  # failed fetch or build above leaves the working one in place.
  rm -rf ../sodium
  make install >/dev/null
  cd ..
  rm -rf "libsodium-$SODIUM_VERSION" libsodium.tar.gz
  echo "$SODIUM_STAMP" >sodium/lib/libsodium.a.stamp
fi
echo "deps ready"
