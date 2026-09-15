#!/bin/bash
# Descarga el registro público de actas y lo guarda dentro de la app (assets/registro.json).
# Solo se quedan los campos que usa la app, con huellas y rutas de PDF validadas.
# Sin conexión o con una respuesta no válida, se conserva la copia anterior.
set -uo pipefail
cd /home/x39matrix/x39_mensajeria || exit 1
URL=https://api.x39matrix.org/registro/registro.json
DEST=android/app/src/main/assets/registro.json
mkdir -p "$(dirname "$DEST")"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if ! curl -fsS -m 30 -o "$TMP" "$URL"; then
  if [ -f "$DEST" ]; then echo "registro: sin conexión, se mantiene la copia incluida"; exit 0; fi
  echo "registro: sin conexión y sin copia previa"; exit 1
fi

if ! python3 - "$TMP" "$DEST" "$URL" <<'PY'
import json, re, sys
src, dest, url = sys.argv[1:4]
d = json.load(open(src, encoding="utf-8"))
docs = d.get("documentos")
assert isinstance(docs, list) and docs, "respuesta sin documentos"
campos = ("id", "area", "nombre", "sesion", "anclaje", "sha256", "bloque",
          "verificado_bloque", "qtst", "qtst_tsa", "pdf")
limpios, descartados = [], []
for x in docs:
    ident = x.get("id", "?")
    if not re.fullmatch(r"[0-9a-f]{64}", x.get("sha256", "")):
        descartados.append(f"{ident}: huella inválida")
        continue
    if not re.fullmatch(r"actas/[A-Za-z0-9._-]+\.pdf", x.get("pdf", "")):
        descartados.append(f"{ident}: ruta de PDF no permitida ({x.get('pdf', '')!r})")
        continue
    limpios.append({k: str(x.get(k, "")) for k in campos})
# Solo lo emitido y comprobado: el PDF debe existir en el portal y su SHA-256 coincidir con el registro.
# (El portal responde 200 con su página HTML para rutas inexistentes, por eso se exige application/pdf.)
import hashlib, urllib.request
from concurrent.futures import ThreadPoolExecutor

def comprobar(doc):
    url = "https://sevilla.x39matrix.org/" + doc["pdf"]
    try:
        peticion = urllib.request.Request(url, headers={"User-Agent": "x39-registro"})
        with urllib.request.urlopen(peticion, timeout=60) as r:
            tipo = r.headers.get("Content-Type", "")
            datos = r.read()
    except Exception as e:
        return f"{doc['id']}: no se pudo descargar el PDF ({e})"
    if "application/pdf" not in tipo:
        return f"{doc['id']}: el PDF no está publicado en el portal"
    if hashlib.sha256(datos).hexdigest() != doc["sha256"]:
        return f"{doc['id']}: el PDF publicado no coincide con la huella registrada"
    return None

with ThreadPoolExecutor(max_workers=6) as grupo:
    resultados = list(grupo.map(comprobar, limpios))
verificados = []
for doc, problema in zip(limpios, resultados):
    if problema:
        descartados.append(problema)
    else:
        verificados.append(doc)
limpios = verificados

for motivo in descartados:
    print(f"registro: AVISO, se descarta {motivo}")
assert limpios, "ningún documento válido"
salida = {"version": d.get("version", 1), "actualizado": d.get("actualizado", ""), "fuente": url, "documentos": limpios}
with open(dest, "w", encoding="utf-8") as f:
    json.dump(salida, f, ensure_ascii=False, indent=1)
areas = sorted({x["area"] for x in limpios})
print(f"registro: {len(limpios)} documentos en {len(areas)} áreas · actualizado {salida['actualizado']}")
PY
then
  if [ -f "$DEST" ]; then echo "registro: respuesta no válida, se mantiene la copia incluida"; exit 0; fi
  echo "registro: respuesta no válida y sin copia previa"; exit 1
fi
