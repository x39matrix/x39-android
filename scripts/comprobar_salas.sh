#!/bin/bash
# Prueba en vivo de las salas (canister/buzon /sala/*) desde el PC con el cliente de examples/cliente.rs.
# Uso: bash scripts/comprobar_salas.sh <carpeta A> <carpeta B> <sala> [URL]
#   Las carpetas son identidades creadas con `cargo run --example cliente -- <carpeta> crear <invitacion>`
#   (ya publicadas en el directorio). A crea la clave de la sala si no existe, se la entrega a B, los dos
#   escriben y los dos leen comprobando firma y cadena.
set -euo pipefail
source "$HOME/.cargo/env"
A="$1"; B="$2"; SALA="$3"; URL="${4:-https://gx4ic-yqaaa-aaaah-qu43a-cai.raw.icp0.io}"
cd "$HOME/x39_mensajeria/x39-core"
CLI="cargo run --quiet --example cliente --"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
DA=$(cat "$A/direccion.txt"); DB=$(cat "$B/direccion.txt")
post() { curl -s --compressed -X POST "$URL$1" -H 'Content-Type: application/json' --data-binary @"$2"; }

echo "### estado de la sala «$SALA»"
curl -s --compressed "$URL/sala/estado?sala=$SALA" | head -c 300; echo
EPOCA=$(curl -s --compressed "$URL/sala/estado?sala=$SALA" | python3 -c 'import json,sys; e=json.load(sys.stdin)["epoca"]; print(-1 if e is None else e)')

if [ "$EPOCA" -lt 0 ]; then
  echo "### la sala no tiene clave: A la crea y se la entrega a sí mismo (nace la época 0)"
  $CLI "$A" sobre "$SALA" 0 "$A/kem.pk" "$DA" > "$TMP/sobre_a.json"
  post /sala/sobre "$TMP/sobre_a.json"; echo
  EPOCA=0
elif [ ! -f "$A/sala-$SALA-$EPOCA.key" ]; then
  echo "### A no tiene la clave de la época $EPOCA: la busca en sus sobres"
  curl -s --compressed "$URL/sala/sobres?sala=$SALA&para=$DA" > "$TMP/sobres_a.json"
  if python3 - "$TMP/sobres_a.json" "$EPOCA" "$TMP/sobre_a_recibido.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); ep = int(sys.argv[2])
s = [x for x in r["sobres"] if x["epoca"] == ep]
if not s: print("A no tiene sobre para esta época"); sys.exit(1)
json.dump(s[-1], open(sys.argv[3], "w")); print("remitente del sobre:", s[-1]["de"][:16])
PY
  then
    echo "(el remitente tiene que ser B u otro miembro; aquí se acepta el de B)"
    $CLI "$A" abrir "$SALA" "$EPOCA" "$TMP/sobre_a_recibido.json" "$B/dsa.pk"
  else
    echo "### nadie tiene aún la clave de la época $EPOCA (la sala rotó): A la crea y se la entrega a sí mismo"
    $CLI "$A" sobre "$SALA" "$EPOCA" "$A/kem.pk" "$DA" > "$TMP/sobre_a.json"
    post /sala/sobre "$TMP/sobre_a.json"; echo
  fi
fi

echo "### A entrega la clave a B"
$CLI "$A" sobre "$SALA" "$EPOCA" "$B/kem.pk" "$DB" > "$TMP/sobre_b.json"
post /sala/sobre "$TMP/sobre_b.json"; echo
echo "### B recoge su sobre y lo abre (firma de A comprobada)"
curl -s --compressed "$URL/sala/sobres?sala=$SALA&para=$DB" > "$TMP/sobres_b.json"
python3 - "$TMP/sobres_b.json" "$EPOCA" "$TMP/sobre_b_recibido.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); ep = int(sys.argv[2])
s = [x for x in r["sobres"] if x["epoca"] == ep]
assert s, "B no tiene sobre"
json.dump(s[-1], open(sys.argv[3], "w")); print("sobres para B:", len(r["sobres"]))
PY
$CLI "$B" abrir "$SALA" "$EPOCA" "$TMP/sobre_b_recibido.json" "$A/dsa.pk"

echo "### A y B escriben"
$CLI "$A" mensaje "$SALA" "$EPOCA" "Hola a todos, esto queda para siempre ($(date +%H:%M:%S))" > "$TMP/m1.json"
post /sala/mensaje "$TMP/m1.json"; echo
$CLI "$B" mensaje "$SALA" "$EPOCA" "Recibido, firmado y encadenado ($(date +%H:%M:%S))" > "$TMP/m2.json"
post /sala/mensaje "$TMP/m2.json"; echo

echo "### mensaje manipulado (debe rechazarse con 403)"
python3 - "$TMP/m2.json" "$TMP/m_roto.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); s = m["msg"]; i = len(s)//2
m["msg"] = s[:i] + ("B" if s[i] != "B" else "C") + s[i+1:]
json.dump(m, open(sys.argv[2], "w"))
PY
R=$(post /sala/mensaje "$TMP/m_roto.json"); echo "$R"
echo "$R" | grep -q '"error"' && echo "✓ rechazado" || { echo "✗ ACEPTÓ UN MENSAJE MANIPULADO"; exit 1; }

echo "### los dos leen toda la sala (firma de cada autor + cadena de hashes)"
curl -s --compressed "$URL/sala/mensajes?sala=$SALA&desde=0" > "$TMP/mensajes.json"
echo "-- lo que ve A:"; $CLI "$A" leer "$SALA" "$TMP/mensajes.json" "$A/entrada.txt" "$B/entrada.txt"
echo "-- lo que ve B:"; $CLI "$B" leer "$SALA" "$TMP/mensajes.json" "$A/entrada.txt" "$B/entrada.txt"
echo "### estado final"; curl -s --compressed "$URL/estado"; echo
echo "TODO OK"
