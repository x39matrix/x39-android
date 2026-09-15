#!/bin/bash
# Comprueba en vivo el directorio del buzón (canister/buzon, desde 0.10): publica una entrada de prueba
# con claves recién creadas (se descartan) y la busca por código y por dirección.
# Uso: bash scripts/comprobar_directorio.sh [URL del buzón]
set -euo pipefail
source "$HOME/.cargo/env"
URL="${1:-https://gx4ic-yqaaa-aaaah-qu43a-cai.raw.icp0.io}"
cd "$HOME/x39_mensajeria/x39-core"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "### estado del buzón"
curl -s --compressed "$URL/estado"; echo
if ! curl -s --compressed "$URL/estado" | grep -q '"directorio"'; then
  echo "✗ el canister desplegado NO tiene directorio todavía: hace falta dfx deploy --network ic --no-wallet"
  exit 1
fi

echo "### entrada de prueba"
cargo run --quiet --example directorio -- nueva > "$TMP/nueva.txt"
CODIGO=$(awk '/^codigo/{print $3}' "$TMP/nueva.txt")
DIR=$(awk '/^direccion/{print $3}' "$TMP/nueva.txt")
tail -1 "$TMP/nueva.txt" > "$TMP/entrada.txt"
python3 -c 'import json,sys; json.dump({"entrada": open(sys.argv[1]).read().strip()}, open(sys.argv[2], "w"))' "$TMP/entrada.txt" "$TMP/pub.json"
echo "código $CODIGO · dirección ${DIR:0:16}…"

echo "### publicar"
R=$(curl -s --compressed -X POST "$URL/publicar" -H 'Content-Type: application/json' --data-binary @"$TMP/pub.json")
echo "$R"
echo "$R" | grep -q "\"codigo\":\"$CODIGO\"" && echo "✓ publicada" || { echo "✗ no se publicó"; exit 1; }

echo "### buscar por código (en minúsculas y sin guiones, como lo teclearía alguien)"
TECLEADO=$(echo "$CODIGO" | tr 'A-Z' 'a-z' | tr -d '-')
R=$(curl -s --compressed "$URL/buscar?codigo=$TECLEADO")
echo "$R" | head -c 120; echo
echo "$R" | grep -q "$(cat "$TMP/entrada.txt")" && echo "✓ encontrada por código" || { echo "✗ no encontrada por código"; exit 1; }

echo "### buscar por dirección (16 hex, el id de contacto)"
R=$(curl -s --compressed "$URL/buscar?dir=${DIR:0:16}")
echo "$R" | grep -q "$(cat "$TMP/entrada.txt")" && echo "✓ encontrada por dirección" || { echo "✗ no encontrada por dirección"; exit 1; }

echo "### entrada manipulada (debe rechazarse)"
python3 - "$TMP/entrada.txt" "$TMP/rota.json" <<'PY'
import json, sys
e = open(sys.argv[1]).read().strip()
i = len(e) // 2
r = e[:i] + ("B" if e[i] != "B" else "C") + e[i+1:]
json.dump({"entrada": r}, open(sys.argv[2], "w"))
PY
R=$(curl -s --compressed -X POST "$URL/publicar" -H 'Content-Type: application/json' --data-binary @"$TMP/rota.json")
echo "$R"
echo "$R" | grep -q '"error"' && echo "✓ rechazada" || { echo "✗ ACEPTÓ UNA ENTRADA ROTA"; exit 1; }
echo "TODO OK"
