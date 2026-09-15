#!/bin/bash
# Estado previo a la v0.3: tamaños, git y crates ML-DSA disponibles.
source "$HOME/.cargo/env" 2>/dev/null
cd /home/x39matrix/x39_mensajeria || exit 1
wc -l android/app/src/main/java/org/x39/bolsillo/*.java x39-core/src/*.rs x39-jni/src/*.rs
git status --short
echo "--- crates en caché"
ls "$HOME"/.cargo/registry/cache/*/ 2>/dev/null | grep -iE "libcrux|dsa"
echo "--- libcrux-ml-dsa en crates.io"
cargo search libcrux-ml-dsa --limit 3 2>&1 | head -5
cargo info libcrux-ml-dsa 2>&1 | head -25
