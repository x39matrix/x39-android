#!/bin/bash
# ¿Funciona hoy el verificador público x39_verify.py? Claves EFÍMERAS, nada real.
set -uo pipefail
T=$(mktemp -d)
V="$HOME/home_viejo/x39_paris/bin/x39_verify.py"
python3 - "$T" <<'PY'
import sys, os, hashlib, datetime, inspect
import pqcrypto.sign.ml_dsa_87 as d
out = sys.argv[1]
print("pqcrypto sign API:", [a for a in dir(d) if not a.startswith("_")])
print("verify signature:", inspect.signature(d.verify) if callable(d.verify) else d.verify)
kp = d.keygen()
a, b = (bytes(x) for x in kp)
pk, sk = (a, b) if len(a) == d.PUBLIC_KEY_SIZE else (b, a)
doc = b"ACTA DE PRUEBA - junta de distrito (efimera)\n"
open(os.path.join(out, "acta.txt"), "wb").write(doc)
utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
stmt = ("\n".join(["X39-NOTARIZE-v1", f"document_sha256: {hashlib.sha256(doc).hexdigest()}",
                   f"utc: {utc}", f"operator_pubkey_sha256: {hashlib.sha256(pk).hexdigest()}"]) + "\n").encode()
try:
    sig = bytes(d.sign(sk, stmt))
except TypeError:
    sig = bytes(d.sign(stmt, sk))
open(os.path.join(out, "statement.txt"), "wb").write(stmt)
open(os.path.join(out, "signature.bin"), "wb").write(sig)
open(os.path.join(out, "operator.pub.raw"), "wb").write(pk)
print("pk", len(pk), "sig", len(sig))
PY
N="$HOME/x39_mensajeria/tools/x39_verify.py"
echo "=== 1. paquete auténtico · verificador ORIGINAL v1 (esperado: falso INVALIDO con pqcrypto 1.0)"
python3 "$V" --bundle "$T" | grep -E "FIRMA|VEREDICTO"; echo "rc=${PIPESTATUS[0]}"
echo "=== 2. paquete auténtico · verificador v1.1 (esperado: VALIDO)"
python3 "$N" --bundle "$T" --openssl | grep -E "FIRMA|VEREDICTO|OpenSSL"; echo "rc=${PIPESTATUS[0]}"
echo "=== 3. firma manipulada · v1.1 (esperado: INVALIDO)"
cp "$T/signature.bin" "$T/sig.bak"
python3 -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[100]^=1; open(p,'wb').write(b)" "$T/signature.bin"
python3 "$N" --bundle "$T" | grep -E "FIRMA|VEREDICTO"; echo "rc=${PIPESTATUS[0]}"
cp "$T/sig.bak" "$T/signature.bin"; rm "$T/sig.bak"
echo "=== 4. documento manipulado · v1.1 (esperado: INVALIDO)"
printf 'ACTA DE PRUEBA - junta de distrito (MODIFICADA)\n' > "$T/acta.txt"
python3 "$N" --bundle "$T" | grep -E "sha256\(documento\)|VEREDICTO"; echo "rc=${PIPESTATUS[0]}"
echo "=== 5. versión de OpenSSL disponible"
openssl version
rm -rf "$T"
