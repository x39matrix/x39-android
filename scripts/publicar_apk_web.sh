#!/bin/bash
# Deja un APK release YA REVISADO como /app/x39.apk en dist de la web (x39matrix.org), con su .sha256 y su
# .certificado.txt, y guarda copia del anterior. No publica: eso lo hace el usuario con publicar.sh.
# Uso: bash scripts/publicar_apk_web.sh pruebas_ots/apks/x39-0.2.0-release.apk
set -euo pipefail
source "$HOME/Android/env.sh"
APK="${1:?falta el APK release}"
D="$HOME/home_viejo/x39web/dist/app"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)
[ -f "$APK" ] || { echo "no existe $APK"; exit 1; }
FIRMA=$("$BT/apksigner" verify --print-certs "$APK" 2>&1 | grep -vE '^WARNING: META-INF')
CERT=$(echo "$FIRMA" | grep -oP 'Signer #1 certificate SHA-256 digest: \K\S+')
DN=$(echo "$FIRMA" | grep -oP 'Signer #1 certificate DN: \K.*')
[ "$CERT" = "72f0745f993605b1b3cd30966162b6d98d84fcacbd23e2e07e24c3d15f7d8935" ] || { echo "✗ certificado distinto del de x39: $CERT"; exit 1; }
BADGING=$("$BT/aapt2" dump badging "$APK")
echo "$BADGING" | grep -q 'application-debuggable' && { echo "✗ depurable"; exit 1; }
VER=$(echo "$BADGING" | grep -oP "versionName='\K[^']+")
PKG=$(echo "$BADGING" | grep -oP "^package: name='\K[^']+")
[ "$PKG" = "org.x39matrix.evidencia" ] || { echo "✗ paquete $PKG"; exit 1; }
SHA=$(sha256sum "$APK" | cut -d' ' -f1)
ANTERIOR=$(cut -d' ' -f1 "$D/x39.apk.sha256" 2>/dev/null || true)
mkdir -p "$D/anteriores"
if [ -f "$D/x39.apk" ]; then
  cp "$D/x39.apk" "$D/anteriores/x39-$ANTERIOR.apk"
  cp "$D/x39.apk.sha256" "$D/anteriores/x39-$ANTERIOR.apk.sha256" 2>/dev/null || true
  cp "$D/x39.apk.certificado.txt" "$D/anteriores/x39-$ANTERIOR.apk.certificado.txt" 2>/dev/null || true
fi
cp "$APK" "$D/x39.apk"
echo "$SHA  x39.apk" > "$D/x39.apk.sha256"
cat > "$D/x39.apk.certificado.txt" <<EOF
x39 · versión $VER · paquete $PKG
Firmado por: $DN
SHA-256 del certificado de firma: $CERT
SHA-256 del APK: $SHA

Comprobar (Android SDK):
  apksigner verify --print-certs x39.apk
Las futuras versiones de x39 deben ir firmadas con este mismo certificado.
EOF
echo "dist/app listo: x39.apk = $VER ($SHA)"
ls -la "$D"
echo "Ahora: cd ~/home_viejo/x39web && bash publicar.sh   (y después bash ~/x39_mensajeria/scripts/comprobar_x39apk_web.sh)"
