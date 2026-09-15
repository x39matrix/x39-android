#!/bin/bash
# Comprueba en vivo el APK publicado en x39matrix.org/app/x39.apk: cabeceras, huella, ficheros al lado y firma.
# Uso: bash scripts/comprobar_x39apk_web.sh [huella_esperada] [certificado_esperado]
set -uo pipefail
ESPERADA="${1:-6d873c5703c6973bf9203696099e503ca8383ac5866af44074c75fb3aaaac0f3}"
CERT="${2:-72f0745f993605b1b3cd30966162b6d98d84fcacbd23e2e07e24c3d15f7d8935}"
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
