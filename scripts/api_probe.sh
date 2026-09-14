#!/bin/bash
# Lee firmas exactas de las APIs descargadas (solo lectura).
R=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f
cd ~/x39_mensajeria/x39-core
ver() { grep -A1 "^name = \"$1\"$" Cargo.lock | grep version | head -1 | cut -d'"' -f2; }
AEAD=$R/aead-$(ver aead); HA=$R/hybrid-array-$(ver hybrid-array); LC=$R/libcrux-ml-kem-0.0.10

echo "### aead $(ver aead): metodos con AAD"
grep -nE 'fn (encrypt|decrypt)[a-z_]*\(' "$AEAD/src/lib.rs" | head -20
grep -nE -A6 'fn encrypt_to_vec|fn decrypt_to_vec' "$AEAD/src/lib.rs" | head -30

echo; echo "### hybrid-array $(ver hybrid-array): conversiones"
grep -rnE 'impl<.*> (From|TryFrom)<' "$HA/src/" | grep -E '\[T; ?N\]|&\[T\]|&.a \[T\]' | head -8

echo; echo "### libcrux-ml-kem: construir tipos desde bytes"
grep -nE 'impl.*(From|TryFrom).*for (MlKem|$)|impl.*From<.*u8' "$LC/src/types.rs" | head -20
grep -nE 'pub (const )?fn (as_slice|as_ref|len|public_key|private_key|value)' "$LC/src/types.rs" | head -12
grep -nE 'pub type MlKemSharedSecret|SHARED_SECRET_SIZE: usize|KEY_GENERATION_SEED_SIZE: usize' -r "$LC/src/" | head -5

echo; echo "### hkdf 0.13: GenericHkdf::new / expand"
sed -n '85,100p;170,180p' $R/hkdf-0.13.0/src/lib.rs
