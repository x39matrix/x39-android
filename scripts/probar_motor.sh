#!/bin/bash
# Tests y clippy del motor Rust y del puente JNI.
source "$HOME/.cargo/env" 2>/dev/null
cd /home/x39matrix/x39_mensajeria/x39-core || exit 1
echo "### x39-core: tests"
cargo test --release 2>&1 | grep -vE "^\s+(Compiling|Downloaded|Downloading|Locking|Adding|Updating)" | tail -60
echo "### x39-core: clippy"
cargo clippy --release --all-targets 2>&1 | grep -E "^(warning|error)" -A7 | head -60
echo "### x39-jni: clippy"
cd ../x39-jni || exit 1
cargo clippy --release 2>&1 | grep -E "^(warning|error)" -A7 | head -60
echo FIN
