#!/bin/bash
# Comprueba que cada PDF del registro público existe en el portal y que su SHA-256 coincide con la huella
# registrada. El portal devuelve su página HTML (200) para rutas inexistentes, así que se exige
# Content-Type application/pdf. Solo lectura: nada se guarda en disco.
# Uso: comprobar_pdfs_registro.sh            → registro público (api.x39matrix.org)
#      comprobar_pdfs_registro.sh --app      → copia incluida en la app
set -uo pipefail
cd /home/x39matrix/x39_mensajeria || exit 1
ORIGEN=${1:-}
python3 -u - "$ORIGEN" <<'PY'
import hashlib, json, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.argv[1] == "--app":
    reg = json.load(open("android/app/src/main/assets/registro.json", encoding="utf-8"))
    print("Registro: copia incluida en la app")
else:
    url = "https://api.x39matrix.org/registro/registro.json"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x39-comprobador"}), timeout=30) as r:
        reg = json.load(r)
    print(f"Registro: {url} (actualizado {reg.get('actualizado', '?')})")
docs = reg["documentos"]
print(f"Comprobando {len(docs)} PDF, 6 a la vez; cada línea es un documento terminado…\n")

def comprobar(d):
    url = "https://sevilla.x39matrix.org/" + urllib.parse.quote(d["pdf"])
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x39-comprobador"}), timeout=30) as r:
            tipo = r.headers.get("Content-Type", "")
            datos = r.read()
    except Exception as e:
        return "ERROR", d, f"no se pudo descargar ({e})"
    if "application/pdf" not in tipo:
        return "FALTA", d, "el portal no tiene este PDF"
    if hashlib.sha256(datos).hexdigest() != d.get("sha256"):
        return "DISTINTO", d, "el PDF publicado no coincide con la huella"
    return "OK", d, f"{len(datos) // 1024} kB"

import urllib.parse
inicio = time.time()
cuenta = {}
with ThreadPoolExecutor(max_workers=6) as grupo:
    tareas = [grupo.submit(comprobar, d) for d in docs]
    for n, t in enumerate(as_completed(tareas), 1):
        estado, d, detalle = t.result()
        cuenta[estado] = cuenta.get(estado, 0) + 1
        print(f"[{n:>2}/{len(docs)}] {estado:<8} {d.get('id', '?')} · {detalle}")

print(f"\nRESULTADO en {time.time() - inicio:.0f} s: " + " · ".join(f"{k} {v}" for k, v in sorted(cuenta.items())))
sys.exit(0 if cuenta.get("OK", 0) == len(docs) else 1)
PY
