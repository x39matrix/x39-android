#!/bin/bash
# Crea el crate x39-core y descarga dependencias desde crates.io.
set -e
source ~/.cargo/env
cd ~/x39_mensajeria
[ -d x39-core ] || cargo new --lib x39-core --vcs none -q
cd x39-core
cargo add libcrux-ml-kem aes-gcm hkdf hmac sha2 zeroize getrandom 2>&1 | grep -E 'Adding|error' || true
cargo add --dev serde_json hex 2>&1 | grep -E 'Adding|error' || true
cargo add --dev serde --features derive 2>&1 | grep -E 'Adding|error' || true
cargo fetch 2>&1 | tail -3
echo "--- Cargo.toml"
cat Cargo.toml
echo "--- versiones resueltas"
grep -A1 -E '^name = "(libcrux-ml-kem|aes-gcm|hkdf|hmac|sha2|getrandom|zeroize)"$' Cargo.lock | grep -E 'name|version' | paste - - | sed 's/name = //; s/version = //'
