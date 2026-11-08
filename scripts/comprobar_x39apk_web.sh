#!/bin/bash
# Comprueba en vivo el APK publicado en x39matrix.org/app/x39.apk: cabeceras, huella, ficheros al lado y firma.
# Uso: bash scripts/comprobar_x39apk_web.sh [ruta_del_apk | huella_esperada] [certificado_esperado]
#   ruta_del_apk:    el APK que se ha subido (p. ej. pruebas_ots/apks/x39-0.3.2-release.apk); su sha256 es la esperada.
#   huella_esperada: los 64 caracteres hex, si no se tiene el APK a mano.
#   sin argumento:   la última release de Evidencia en pruebas_ots/apks (x39-<versión>-release.apk.sha256).
set -uo pipefail
if [ -n "${1:-}" ] && [ -f "$1" ]; then
  ORIGEN="$1"
  ESPERADA=$(sha256sum "$1" | cut -d' ' -f1)
elif [ -n "${1:-}" ]; then
  ORIGEN="argumento"
  ESPERADA="$1"
  [[ "$ESPERADA" =~ ^[0-9a-f]{64}$ ]] || { echo "«$1» no es un fichero ni una huella sha256 (64 hex)"; exit 2; }
else
  # x39-<número>… y no x39-*: si no, también cuenta x39-llamadas-…-release (otra app).
  ORIGEN=$(ls -t "$HOME"/x39_mensajeria/pruebas_ots/apks/x39-[0-9]*-release.apk.sha256 2>/dev/null | head -1)
  ESPERADA=$(cut -d' ' -f1 "$ORIGEN" 2>/dev/null)
fi
[ -n "$ESPERADA" ] || { echo "no hay huella esperada: pasa la ruta del APK o la huella"; exit 2; }
echo "huella esperada: $ESPERADA (${ORIGEN##*/})"
CERT="${2:-8d46f850509ebfd4778156195c14bb69719dd09f799a4fb661b940e7e2b22fbe}"
BASE="https://x39matrix.org"
D="$HOME/x39_mensajeria/pruebas_ots/web_x39apk"
mkdir -p "$D"
fallo=0

echo "--- main.js en vivo"
curl -s --compressed -m 20 "$BASE/" | grep -o 'main\.[a-f0-9]*\.js'

echo "--- cabeceras de /app/x39.apk"
curl -s -I -m 20 "$BASE/app/x39.apk" | grep -iE '^HTTP|content-type|content-disposition|content-length'

echo "--- descarga y huella"
curl -s --compressed -m 90 -o "$D/x39.apk" "$BASE/app/x39.apk"
H=$(sha256sum "$D/x39.apk" | cut -d' ' -f1)
echo "$H  $(stat -c %s "$D/x39.apk") bytes"
if [ "$H" = "$ESPERADA" ]; then echo "✓ huella igual a la firmada"; else echo "✗ huella distinta (esperada $ESPERADA)"; fallo=1; fi

echo "--- x39.apk.sha256 publicado"
S=$(curl -s --compressed -m 20 "$BASE/app/x39.apk.sha256")
echo "$S"
echo "$S" | grep -q "^$ESPERADA  x39.apk" && echo "✓ coincide" || { echo "✗ no coincide o no existe"; fallo=1; }

echo "--- x39.apk.certificado.txt publicado"
C=$(curl -s --compressed -m 20 "$BASE/app/x39.apk.certificado.txt")
echo "$C" | grep -E 'Firmado|certificado de firma'
echo "$C" | grep -q "$CERT" && echo "✓ lleva la huella del certificado" || { echo "✗ falta la huella del certificado"; fallo=1; }

echo "--- firma del APK descargado"
FIRMA=$(bash "$HOME/x39_mensajeria/scripts/firma_apk.sh" "$D/x39.apk")
echo "$FIRMA" | grep -E 'Verifies|certificate DN|certificate SHA-256'
echo "$FIRMA" | grep -q "certificate SHA-256 digest: $CERT" && echo "✓ firmado con la clave x39" || { echo "✗ firma distinta"; fallo=1; }

[ "$fallo" -eq 0 ] && echo "TODO OK" || { echo "HAY FALLOS"; exit 1; }
