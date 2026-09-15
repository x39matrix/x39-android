#!/bin/bash
# Mide la clave pública COLD y su firma tal como las publica X-39 en un paquete de evidencia.
# Solo datos públicos: no toca la Pi 500 ni nada de la ceremonia COLD.
# Comprueba: tamaños ML-DSA-87 (2592 / 4627 bytes), huella publicada y firma válida con OpenSSL.
set -uo pipefail
ID="${1:-31e1cf09a5b2a74cd978}"
HUELLA_PUBLICADA="8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cd "$T" || exit 1

descargado=""
for url in "https://api.x39matrix.org/api/notaria/proof/$ID.zip" "https://x39matrix.org/api/notaria/proof/$ID.zip"; do
  if curl -fsSL -m 60 -A "x39-medidor" -o evidencia.zip "$url" && unzip -tq evidencia.zip >/dev/null 2>&1; then
    descargado="$url"; break
  fi
done
[ -n "$descargado" ] || { echo "No he podido descargar el paquete de evidencia de $ID"; exit 1; }
echo "Paquete : $descargado ($(stat -c %s evidencia.zip) bytes)"
unzip -oq evidencia.zip
ls -la

python3 - "$HUELLA_PUBLICADA" <<'PY'
import base64, hashlib, json, os, subprocess, sys
esperada = sys.argv[1]
firmas = json.load(open("signatures.json", encoding="utf-8"))

# Recorre el JSON buscando cadenas base64 del tamaño de una clave o firma ML-DSA.
TAM = {1312: "clave ML-DSA-44", 1952: "clave ML-DSA-65", 2592: "clave ML-DSA-87",
       2420: "firma ML-DSA-44", 3309: "firma ML-DSA-65", 4627: "firma ML-DSA-87"}
hallados = []
def recorrer(x, ruta):
    if isinstance(x, dict):
        for k, v in x.items(): recorrer(v, ruta + "." + k)
    elif isinstance(x, list):
        for i, v in enumerate(x): recorrer(v, f"{ruta}[{i}]")
    elif isinstance(x, str) and len(x) > 1000:
        for dec in (base64.b64decode, bytes.fromhex):
            try:
                b = dec(x)
            except Exception:
                continue
            hallados.append((ruta, len(b), TAM.get(len(b), "¿?"), b))
            break
recorrer(firmas, "signatures")
print()
for ruta, n, tipo, _ in hallados:
    print(f"  {ruta:<45} {n:>5} bytes  → {tipo}")

claves = [(r, b) for r, n, t, b in hallados if t.startswith("clave")]
sigs = [(r, b) for r, n, t, b in hallados if t.startswith("firma")]
if not claves or not sigs:
    print("\nNo encuentro pares clave/firma. Estructura de signatures.json:")
    print(json.dumps(firmas, indent=1)[:1500]); sys.exit(1)

# El mensaje firmado: los bytes canónicos de proof.json dentro del paquete.
msg = open("proof.json", "rb").read()
PREFIJO_87 = bytes.fromhex("30820a32300b060960864801650304031303820a2100")   # SPKI DER, OID 2.16.840.1.101.3.4.3.19
open("mensaje.bin", "wb").write(msg)
print()
for rc, clave in claves:
    fp = hashlib.sha256(clave).hexdigest()
    print(f"Clave {rc}: huella {fp[:16]}…  {'= PUBLICADA COLD' if fp == esperada else '≠ huella COLD publicada'}")
    if len(clave) != 2592:
        continue
    open("clave.der", "wb").write(PREFIJO_87 + clave)
    for rs, firma in sigs:
        open("firma.bin", "wb").write(firma)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "clave.der", "-keyform", "DER",
                            "-rawin", "-in", "mensaje.bin", "-sigfile", "firma.bin"], capture_output=True, text=True)
        ok = "Signature Verified Successfully" in (r.stdout + r.stderr)
        malo = bytearray(firma); malo[10] ^= 1
        open("firma_mala.bin", "wb").write(bytes(malo))
        r2 = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "clave.der", "-keyform", "DER",
                             "-rawin", "-in", "mensaje.bin", "-sigfile", "firma_mala.bin"], capture_output=True, text=True)
        rechaza = "Signature Verified Successfully" not in (r2.stdout + r2.stderr)
        print(f"  con {rs} ({len(firma)} B): firma {'VÁLIDA' if ok else 'NO verifica'} · control con firma alterada: {'rechazada (bien)' if rechaza else 'ACEPTADA (mal)'}")
        if not ok:
            print("   ", (r.stdout + r.stderr).strip()[:300])
print("\n" + subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip())
PY
