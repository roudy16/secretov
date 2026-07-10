#!/bin/sh
# Fetches vendored deps when system packages (libsodium-dev, nlohmann-json3-dev)
# are absent. Installs into third_party/ (gitignored).
set -eu
cd "$(dirname "$0")"

if [ ! -f nlohmann/json.hpp ]; then
  mkdir -p nlohmann
  curl -fsSL -o nlohmann/json.hpp \
    https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
fi

if [ ! -f sodium/lib/libsodium.a ]; then
  curl -fsSL -o libsodium.tar.gz \
    https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz
  tar xzf libsodium.tar.gz
  cd libsodium-1.0.20
  ./configure --prefix="$(cd .. && pwd)/sodium" --disable-shared --quiet
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
  cd ..
  rm -rf libsodium-1.0.20 libsodium.tar.gz
fi
echo "deps ready"
