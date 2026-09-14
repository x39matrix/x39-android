#!/bin/bash
# Verifica un .ots sin nodo propio: recalcula la prueba desde el archivo y compara cada raíz Merkle
# con el bloque real consultado en la API pública de mempool.space. Solo lectura.
# Uso: verificar_ots_sin_nodo.sh <archivo.ots>   (el archivo sellado debe estar al lado, sin .ots)
set -uo pipefail
OTS_BIN=/home/x39matrix/.local/bin/ots
OTSF="$1"
cd "$(dirname "$OTSF")" || exit 1
BASE=$(basename "$OTSF")
DOC="${BASE%.ots}"
case "$DOC" in *.v1_originalmente_sellado_*) DOC="${DOC%%.v1_originalmente_sellado_*}";; esac

echo "archivo: $DOC · sha256 $(sha256sum "$DOC" | cut -c1-16)…"
salida=$("$OTS_BIN" --no-bitcoin verify -f "$DOC" "$BASE" 2>&1)
echo "$salida" | grep -qi "digest" && echo "$salida" | grep -i "digest" | head -1
pares=$(echo "$salida" | grep -oE "block [0-9]+ has merkleroot [0-9a-f]{64}" | sort -u)
[ -z "$pares" ] && { echo "sin atestaciones de bloque reconocibles"; echo "$salida" | tail -5; exit 1; }
fallos=0
while read -r _ altura _ _ raiz; do
  hash=$(curl -fsS "https://mempool.space/api/block-height/$altura")
  json=$(curl -fsS "https://mempool.space/api/block/$hash")
  real=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["merkle_root"])' <<< "$json")
  fecha=$(python3 -c 'import sys,json,datetime; print(datetime.datetime.fromtimestamp(json.load(sys.stdin)["timestamp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))' <<< "$json")
  if [ "$real" = "$raiz" ]; then echo "  bloque $altura · $fecha · COINCIDE"; else echo "  bloque $altura · $fecha · NO COINCIDE"; fallos=$((fallos+1)); fi
done <<< "$pares"
[ "$fallos" -eq 0 ] && echo "VEREDICTO: anclaje Bitcoin confirmado (contra explorador público)" || echo "VEREDICTO: $fallos raíces no coinciden"
