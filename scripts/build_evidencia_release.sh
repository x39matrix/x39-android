#!/bin/bash
# x39 · Evidencia: APK de PUBLICACIÓN firmado con la clave de X-39.
# - La contraseña se pide sin eco, se pasa solo al proceso de Gradle (sin demonio) y se borra al terminar.
# - Comprueba: firma con la clave de X-39 (no «Android Debug»), NO depurable, permisos exactos, sin Google.
# - Deja el APK con su .sha256 en pruebas_ots/apks y lo sella con OpenTimestamps.
# Uso: bash scripts/build_evidencia_release.sh [ruta_almacen] [alias]
set -euo pipefail
ALMACEN="${1:-$HOME/x39-release.jks}"
ALIAS="${2:-x39}"
source "$HOME/Android/env.sh"
source "$HOME/.cargo/env"
cd "$HOME/x39_mensajeria"
[ -f "$ALMACEN" ] || { echo "no existe $ALMACEN"; exit 1; }

VERSION=$(grep -oP "versionName '\K[^']+" android/evidencia/build.gradle)
# El nombre visible es solo «x39». «-release» evita confundirlo con los APK de pruebas de esa carpeta
# (x39-0.1.1-debug.apk es una versión antigua de la app del Ayuntamiento). En la web se publica como app/x39.apk.
SALIDA="pruebas_ots/apks/x39-$VERSION-release.apk"
[ ! -e "$SALIDA" ] || { echo "ya existe $SALIDA; muévelo antes de volver a compilar"; exit 1; }
echo "Versión $VERSION · almacén $ALMACEN · alias $ALIAS"

read -r -s -p "Contraseña del almacén (no se muestra): " PASS; echo
[ -n "$PASS" ] || { echo "contraseña vacía"; exit 1; }
trap 'unset PASS' EXIT

echo "### 1. Motor Rust (arm64 + x86_64)"
( cd x39-jni && cargo ndk -t arm64-v8a -t x86_64 --platform 28 -o ../android/app/src/main/jniLibs build --release 2>&1 \
    | grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tail -3 )

echo "### 2. APK release firmado"
( cd android && X39_KEYSTORE="$ALMACEN" X39_KEY_ALIAS="$ALIAS" X39_STORE_PASS="$PASS" \
    ./gradlew --no-daemon -q :evidencia:clean :evidencia:assembleRelease 2>&1 | { grep -vE '^\s*$' || true; } | tail -30 )
unset PASS
APK=android/evidencia/build/outputs/apk/release/evidencia-release.apk
[ -f "$APK" ] || { echo "✗ no se generó $APK (¿contraseña incorrecta?)"; exit 1; }

echo "### 3. Comprobaciones"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)
fallo=0
FIRMA=$("$BT/apksigner" verify --print-certs "$APK" 2>&1 | grep -vE '^WARNING: META-INF')
echo "$FIRMA" | grep -E 'Signer #1 certificate (DN|SHA-256)'
if echo "$FIRMA" | grep -q 'CN=Android Debug'; then echo "✗ firmado con la clave de pruebas"; fallo=1; fi
BADGING=$("$BT/aapt2" dump badging "$APK")
echo "$BADGING" | grep -E '^package:'
if echo "$BADGING" | grep -q 'application-debuggable'; then echo "✗ el APK es depurable"; fallo=1; else echo "✓ no depurable"; fi
if echo "$BADGING" | grep -q "name='org.x39matrix.evidencia' "; then echo "✓ paquete org.x39matrix.evidencia"; else echo "✗ paquete inesperado"; fallo=1; fi
PERMISOS=$("$BT/aapt2" dump permissions "$APK" | grep -oP "uses-permission: name='\K[^']+" | sort | tr '\n' ' ')
echo "permisos: $PERMISOS"
[ "$PERMISOS" = "android.permission.ACCESS_NETWORK_STATE android.permission.CAMERA android.permission.INTERNET " ] \
  && echo "✓ permisos exactos" || { echo "✗ permisos distintos de los tres esperados"; fallo=1; }
if unzip -l "$APK" | grep -qiE 'google|firebase|gms'; then echo "✗ contiene ficheros de Google"; fallo=1; else echo "✓ sin Google"; fi
[ "$fallo" -eq 0 ] || { echo "NO publicar este APK."; exit 1; }

echo "### 4. Archivo y sello"
cp "$APK" "$SALIDA"
( cd "$(dirname "$SALIDA")" && sha256sum "$(basename "$SALIDA")" | tee "$(basename "$SALIDA").sha256" )
echo "huella del certificado de firma:"
echo "$FIRMA" | grep -oP 'Signer #1 certificate SHA-256 digest: \K\S+' | tee "$SALIDA.certificado-sha256"
if command -v ots >/dev/null || [ -x "$HOME/.local/bin/ots" ]; then
  OTS=$(command -v ots || echo "$HOME/.local/bin/ots")
  "$OTS" stamp "$SALIDA" "$SALIDA.sha256"
fi
echo "Listo: $SALIDA"
