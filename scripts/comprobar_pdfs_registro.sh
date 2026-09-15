#!/bin/bash
# Comprueba que cada PDF del registro incluido en la app existe en el portal y que su SHA-256
# coincide con la huella registrada. El portal devuelve su página HTML (200) para rutas inexistentes,
# así que se exige Content-Type application/pdf. Solo lectura; descarga a un directorio temporal.
set -uo pipefail
cd /home/x39matrix/x39_mensajeria || exit 1
python3 - <<'PY'
import hashlib, json, sys, tempfile, urllib.request
reg = json.load(open("android/app/src/main/assets/registro.json", encoding="utf-8"))
ok = mal = 0
for d in reg["documentos"]:
    url = "https://sevilla.x39matrix.org/" + d["pdf"]
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x39-comprobador"}), timeout=60) as r:
            tipo = r.headers.get("Content-Type", "")
            datos = r.read()
    except Exception as e:
        print(f"  ERROR  {d['id']}: {e}"); mal += 1; continue
    if "application/pdf" not in tipo:
        print(f"  FALTA  {d['id']}: el portal no sirve el PDF ({tipo}, {len(datos)} bytes)"); mal += 1; continue
    h = hashlib.sha256(datos).hexdigest()
    if h != d["sha256"]:
        print(f"  DISTINTO {d['id']}: huella {h[:16]}… ≠ registro {d['sha256'][:16]}…"); mal += 1; continue
    ok += 1
print(f"RESULTADO: {ok} PDF correctos · {mal} con problemas · {len(reg['documentos'])} en el registro")
sys.exit(1 if mal else 0)
PY
