#!/bin/bash
# Verificaciones del sello dorado sin confiar en nadie. Solo lectura.
N=/home/x39matrix/home_viejo/x39matrix-web/notary
cd "$N" || exit 1

echo "### 1. Firma tECDSA del HUB (secp256k1) declarada en MASTER_GOLDEN_SEAL.txt"
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
pub = bytes.fromhex("025968e3eea2adc6a3c7e0b24c39f3e94009393e57280cb9ccc3801251bb202083")
msg = bytes.fromhex("84ceaca9525bd1034348d2a4122c147ec78ab03820131e09bbe477faf61617d5")
sig = bytes.fromhex("0e720c891b6ae74c3a426184058d63d9111798d9cc9029098d02795603cc28a1"
                    "30c99fd6dd7405b790d6a26dca0d845444262a9873d46c21d18045a0f2ec1f20")
key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub)
der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
try:
    key.verify(der, msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    print("  FIRMA VALIDA: la clave 025968e3…2083 firmó ese mensaje de 32 bytes")
except InvalidSignature:
    print("  FIRMA INVALIDA")
bad = bytearray(msg); bad[0] ^= 1
try:
    key.verify(der, bytes(bad), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    print("  control: mensaje alterado ACEPTADO (mal)")
except InvalidSignature:
    print("  control: mensaje alterado rechazado (bien)")
PY

echo; echo "### 2. ¿La clave firmante es la que publica el HUB hoy?"
echo "  HUB cert_btc_addresses.pubkey_hex = 025968e3eea2adc6a3c7e0b24c39f3e94009393e57280cb9ccc3801251bb202083 (consultado hoy)"

echo; echo "### 3. Artefactos subordinados citados: ¿existen y coinciden sus hashes?"
sha256sum audit_full_1779229749009834030.candid
echo "  esperado Artifact #1 = aaefb2dc21c5ca181987c7b468d668263b816128c4bcf8cb7e1694f6cfbfaa02"
f2=$(find /home/x39matrix/home_viejo -name 'MANIFIESTO_7_AXIOMAS.txt' -not -path '*/node_modules/*' 2>/dev/null | head -1)
if [ -n "$f2" ]; then sha256sum "$f2"; else echo "  MANIFIESTO_7_AXIOMAS.txt no encontrado en home_viejo"; fi
echo "  esperado Artifact #2 = e54960277e8933fdf1635e769d66c23622bfe6e5c2cb2dd3a39ac3e78184595e"

echo; echo "### 4. Bundle PQC"
echo "--- contenido (nombres y tamaños):"
tar -tzvf x39_cert_pqc_bundle.tar.gz
echo "--- sha256 real vs declarado:"
sha256sum x39_cert_pqc_bundle.tar.gz
cat x39_cert_pqc_bundle.tar.gz.sha256
echo "--- anclajes Bitcoin del .ots vigente:"
ots info x39_cert_pqc_bundle.tar.gz.ots 2>/dev/null | grep -E "BitcoinBlockHeaderAttestation|PendingAttestation|File sha256" | sort | uniq -c
