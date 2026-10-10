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

VERSION=$(grep -oP "versionName '\K[^']+" android/evidencia/build.gradle || true)
[ -n "$VERSION" ] || { echo "✗ no encuentro versionName en android/evidencia/build.gradle"; exit 1; }
# El nombre visible es solo «x39». «-release» evita confundirlo con los APK de pruebas de esa carpeta
# (x39-0.1.1-debug.apk es una versión antigua de la app del Ayuntamiento). En la web se publica como app/x39.apk.
SALIDA="pruebas_ots/apks/x39-$VERSION-release.apk"
[ ! -e "$SALIDA" ] || { echo "ya existe $SALIDA; muévelo antes de volver a compilar"; exit 1; }
echo "Versión $VERSION · almacén $ALMACEN · alias $ALIAS"

# Se comprueba la contraseña con keytool ANTES de compilar: un error de tecleo se ve al momento.
KEYTOOL="$JAVA_HOME/bin/keytool"
trap 'unset PASS' EXIT
for intento in 1 2 3; do
  read -r -s -p "Contraseña del almacén (no se muestra): " PASS; echo
  if [ -n "$PASS" ] && X39_STORE_PASS="$PASS" "$KEYTOOL" -list -keystore "$ALMACEN" -storetype PKCS12 -alias "$ALIAS" \
       -storepass:env X39_STORE_PASS >/dev/null 2>&1; then
    echo "✓ la contraseña abre el almacén"
    break
  fi
  PASS=""
  echo "✗ la contraseña no abre $ALMACEN (intento $intento de 3)"
  [ "$intento" -lt 3 ] || exit 1
done

echo "### 1. Motor Rust (arm64 + x86_64)"
( cd x39-jni && cargo ndk -t arm64-v8a -t x86_64 --platform 28 -o ../android/app/src/main/jniLibs build --release 2>&1 \
    | { grep -vE '^\s+(Compiling|Downloaded|Downloading)' || true; } | tail -3 )

echo "### 2. APK release firmado"
( cd android && X39_KEYSTORE="$ALMACEN" X39_KEY_ALIAS="$ALIAS" X39_STORE_PASS="$PASS" \
    ./gradlew --no-daemon -q :evidencia:clean :evidencia:assembleRelease 2>&1 | { grep -vE '^\s*$' || true; } | tail -30 )
unset PASS
APK=android/evidencia/build/outputs/apk/release/evidencia-release.apk
[ -f "$APK" ] || { echo "✗ no se generó $APK (¿contraseña incorrecta?)"; exit 1; }

echo "### 3. Comprobaciones"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)
fallo=0
FIRMA=$("$BT/apksigner" verify --print-certs "$APK" 2>&1 | { grep -vE '^WARNING: META-INF' || true; })
if echo "$FIRMA" | grep -E 'Signer #1 certificate (DN|SHA-256)'; then :; else echo "✗ el APK no está firmado o la firma no verifica:"; echo "$FIRMA" | head -3; fallo=1; fi
if echo "$FIRMA" | grep -q 'CN=Android Debug'; then echo "✗ firmado con la clave de pruebas"; fallo=1; fi
BADGING=$("$BT/aapt2" dump badging "$APK")
echo "$BADGING" | grep -E '^package:' || { echo "✗ aapt2 no lee el paquete"; fallo=1; }
if echo "$BADGING" | grep -q 'application-debuggable'; then echo "✗ el APK es depurable"; fallo=1; else echo "✓ no depurable"; fi
if echo "$BADGING" | grep -q "name='org.x39matrix.evidencia' "; then echo "✓ paquete org.x39matrix.evidencia"; else echo "✗ paquete inesperado"; fallo=1; fi
PERMISOS=$("$BT/aapt2" dump permissions "$APK" | { grep -oP "uses-permission: name='\K[^']+" || true; } | sort | tr '\n' ' ')
echo "permisos: $PERMISOS"
[ "$PERMISOS" = "android.permission.ACCESS_NETWORK_STATE android.permission.CAMERA android.permission.FOREGROUND_SERVICE android.permission.FOREGROUND_SERVICE_SPECIAL_USE android.permission.INTERNET android.permission.POST_NOTIFICATIONS android.permission.RECORD_AUDIO " ] \
  && echo "✓ permisos exactos (los 7 de 0.3.1: INTERNET, ACCESS_NETWORK_STATE, CAMERA, RECORD_AUDIO, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS)" || { echo "✗ permisos distintos de los 7 esperados"; fallo=1; }
# Google 0. Los nombres de fichero no bastan: Play Services, Firebase o AndroidX viajan DENTRO de classes*.dex.
# Se miran las clases: la única excepción es com/google/zxing (lector de QR; Java puro, Apache 2.0, sin red ni permisos).
if unzip -l "$APK" | grep -qiE 'google|firebase|gms'; then echo "✗ contiene ficheros de Google"; fallo=1; else echo "✓ sin ficheros de Google"; fi
DEXDIR=$(mktemp -d)
unzip -q -o "$APK" 'classes*.dex' -d "$DEXDIR"
CLASES=$(for d in "$DEXDIR"/classes*.dex; do "$BT/dexdump" -f "$d" 2>/dev/null | { grep -oE "Class descriptor *: 'L[^;]+" || true; } | sed "s/.*'L//"; done)
rm -rf "$DEXDIR"
[ -n "$CLASES" ] || { echo "✗ no se pudieron leer las clases del APK"; fallo=1; }
GOOGLE=$(echo "$CLASES" | { grep -E '^com/google/' || true; } | { grep -vE '^com/google/zxing/' || true; })
if [ -n "$GOOGLE" ]; then echo "✗ clases de Google que no son ZXing ($(echo "$GOOGLE" | wc -l)):"; echo "$GOOGLE" | cut -d/ -f1-4 | sort -u | head -5; fallo=1
else echo "✓ sin Play Services, Firebase ni otras clases de Google (solo com/google/zxing: $(echo "$CLASES" | { grep -c '^com/google/zxing/' || true; }) clases)"; fi
if echo "$CLASES" | grep -qE '^androidx/|^android/support/'; then echo "✗ contiene AndroidX"; fallo=1; else echo "✓ sin AndroidX"; fi
if echo "$CLASES" | grep -qiE 'firebase|/gms/'; then echo "✗ contiene clases de Firebase/GMS"; fallo=1; fi
if "$BT/aapt2" dump xmltree --file AndroidManifest.xml "$APK" | grep -qiE 'com\.google\.android\.gms|firebase'; then echo "✗ el manifiesto declara Play Services o Firebase"; fallo=1; else echo "✓ manifiesto sin Play Services ni Firebase"; fi
[ "$fallo" -eq 0 ] || { echo "NO publicar este APK."; exit 1; }

echo "### 4. Archivo y sello"
cp "$APK" "$SALIDA"
( cd "$(dirname "$SALIDA")" && sha256sum "$(basename "$SALIDA")" | tee "$(basename "$SALIDA").sha256" )
echo "huella del certificado de firma:"
CERT=$(echo "$FIRMA" | { grep -oP 'Signer #1 certificate SHA-256 digest: \K\S+' || true; })
[ -n "$CERT" ] || { echo "✗ no se pudo leer la huella del certificado"; exit 1; }
echo "$CERT" | tee "$SALIDA.certificado-sha256"
if command -v ots >/dev/null || [ -x "$HOME/.local/bin/ots" ]; then
  OTS=$(command -v ots || echo "$HOME/.local/bin/ots")
  "$OTS" stamp "$SALIDA" "$SALIDA.sha256"
fi
echo "Listo: $SALIDA"
