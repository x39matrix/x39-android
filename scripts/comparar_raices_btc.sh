#!/bin/bash
# Compara las raíces Merkle que exige una prueba OTS con las de los bloques reales (API pública de mempool.space).
declare -A ESPERADA=(
  [950381]=5efe64785f3fc37e312534495a3fe3082e9fdbe88deb87c13194f76aef2b5f52
  [950398]=45062d04dab13968eb816c080ab46af0071cd0ebf04713758a98f98800679359
  [950408]=ce2f36396d6fa1d139f5975357fb7b45a0b3e071d3e7015fd297124373b54f07
)
for h in 950381 950398 950408; do
  hash=$(curl -fsS "https://mempool.space/api/block-height/$h")
  json=$(curl -fsS "https://mempool.space/api/block/$hash")
  raiz=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["merkle_root"])' <<< "$json")
  fecha=$(python3 -c 'import sys,json,datetime; print(datetime.datetime.fromtimestamp(json.load(sys.stdin)["timestamp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))' <<< "$json")
  if [ "$raiz" = "${ESPERADA[$h]}" ]; then r="COINCIDE"; else r="NO COINCIDE (explorador: $raiz)"; fi
  echo "bloque $h · $fecha · $r"
done
