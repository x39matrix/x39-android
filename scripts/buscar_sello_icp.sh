#!/bin/bash
# ¿Está la huella del sello dorado registrada en ICP? Solo consultas anónimas.
DFX=/home/x39matrix/.local/share/dfx/bin/dfx
export DFX_WARNING=-mainnet_plaintext_identity
H=08e9db781dc79c9fbbe77a56cd0120d2830650d4bcf52a2dae9acb73091d449c
q() { "$DFX" canister call "$1" "$2" "$3" --query --network ic --identity anonymous 2>&1 | grep -v deprecated; }

echo "### HUB arn4r · cert_verify_hash"
q arn4r-lqaaa-aaaao-baxwq-cai cert_verify_hash "(\"$H\")"

echo; echo "### HUB arn4r · cadena de certificados (nombres, índices y huellas)"
q arn4r-lqaaa-aaaao-baxwq-cai cert_list "()" | grep -E 'index|name|sha256 =|timestamp_ns|notes' | paste - - - - - | head -20

echo; echo "### HUB arn4r · raíz Merkle actual e integridad"
q arn4r-lqaaa-aaaao-baxwq-cai cert_merkle_root "()"
q arn4r-lqaaa-aaaao-baxwq-cai cert_chain_verify "()" | grep -E 'intact|total_blocks|broken_blocks'
