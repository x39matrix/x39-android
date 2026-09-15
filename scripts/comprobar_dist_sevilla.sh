#!/bin/bash
# Antes de desplegar el portal: ¿cada PDF del registro público está en x39sevilla/dist/actas
# con la misma SHA-256? Solo lectura, no toca el canister.
set -uo pipefail
DIST=/home/x39matrix/x39sevilla/dist
python3 -u - "$DIST" <<'PY'
import hashlib, json, os, sys, urllib.request
dist = sys.argv[1]
url = "https://api.x39matrix.org/registro/registro.json"
with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x39-comprobador"}), timeout=30) as r:
    reg = json.load(r)
docs = reg["documentos"]
print(f"Registro público: {len(docs)} documentos · dist: {dist}\n")
cuenta = {}
for d in docs:
    ruta = os.path.join(dist, d["pdf"])
    extra = []
    if not os.path.isfile(ruta):
        estado = "NO ESTÁ"
    else:
        with open(ruta, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        estado = "OK" if h == d["sha256"] else "DISTINTO"
        for campo in ("ots", "fuente", "tsr"):
            if d.get(campo) and not os.path.isfile(os.path.join(dist, d[campo])):
                extra.append(f"falta {campo}")
    cuenta[estado] = cuenta.get(estado, 0) + 1
    marca = f" · {', '.join(extra)}" if extra else ""
    if estado != "OK" or extra:
        print(f"  {estado:<9} {d['id']}{marca}")
print("\nRESULTADO: " + " · ".join(f"{k} {v}" for k, v in sorted(cuenta.items())))
PY
