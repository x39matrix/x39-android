#!/bin/bash
# x39 · Llamadas: APK de PUBLICACIÓN firmado con la clave de X-39 (mismo almacén y alias que Evidencia).
# - La contraseña se pide sin eco, se pasa solo al proceso de Gradle (sin demonio) y se borra al terminar.
# - Comprueba: firma con la clave de X-39 (no «Android Debug»), NO depurable, paquete org.x39matrix.llamadas,
#   permisos exactos, sin tráfico en claro, sin restos del ejemplo de LiveKit, sin servicios de Google.
# - Deja el APK con su .sha256 en ~/x39_mensajeria/pruebas_ots/apks (junto a los de Evidencia) y lo sella con OpenTimestamps.
# - NO instala nada en ningún móvil.
# Uso: bash scripts/build_llamadas_release.sh [ruta_almacen] [alias]
set -euo pipefail
ALMACEN="${1:-$HOME/x39-release.jks}"
ALIAS="${2:-x39}"
source "$HOME/Android/env.sh"
PROYECTO="$HOME/client-sdk-android"
MODULO="sample-app"
PAQUETE="org.x39matrix.llamadas"
ARCHIVO="$HOME/x39_mensajeria/pruebas_ots/apks"
cd "$PROYECTO"
[ -f "$ALMACEN" ] || { echo "no existe $ALMACEN"; exit 1; }

VERSION=$(grep -oP 'versionName "\K[^"]+' "$MODULO/build.gradle")
SALIDA="$ARCHIVO/x39-llamadas-$VERSION-release.apk"
[ ! -e "$SALIDA" ] || { echo "ya existe $SALIDA; muévelo antes de volver a compilar"; exit 1; }
echo "Versión $VERSION · almacén $ALMACEN · alias $ALIAS"

# El motor Rust (libx39jni.so) no se compila aquí: es el mismo binario de scripts/build_apk.sh, copiado a jniLibs.
JNI="$MODULO/src/main/jniLibs/arm64-v8a/libx39jni.so"
[ -f "$JNI" ] || { echo "falta $JNI (cópialo del motor compilado por scripts/build_apk.sh)"; exit 1; }
echo "motor Rust: $(sha256sum "$JNI" | cut -c1-16)… ($(stat -c %y "$JNI" | cut -d. -f1))"

# Se comprueba la contraseña con keytool ANTES de compilar: un error de tecleo se ve al momento.
# -storetype PKCS12: keytool de JDK 17 crea PKCS12 aunque el fichero se llame .jks.
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

echo "### 1. APK release firmado"
( X39_KEYSTORE="$ALMACEN" X39_KEY_ALIAS="$ALIAS" X39_STORE_PASS="$PASS" \
    ./gradlew --no-daemon -q ":$MODULO:clean" ":$MODULO:assembleComunicacionesRelease" 2>&1 | { grep -vE '^\s*$' || true; } | tail -30 )
unset PASS
APK="$MODULO/build/outputs/apk/comunicaciones/release/$MODULO-comunicaciones-release.apk"
[ -f "$APK" ] || { echo "✗ no se generó $APK (¿contraseña incorrecta?)"; exit 1; }

echo "### 2. Comprobaciones"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)
fallo=0
# contiene PATRON TEXTO: grep sobre una variable SIN tubería. Con «pipefail», `echo "$X" | grep -q` puede
# dar falso cuando grep -q cierra antes de que echo termine (SIGPIPE) y una comprobación se pasaría en falso.
contiene() { grep -qE -- "$1" <<< "$2"; }
FIRMA=$("$BT/apksigner" verify --print-certs "$APK" 2>&1 | grep -vE '^WARNING: META-INF' || true)
if contiene 'Signer #1 certificate DN' "$FIRMA"; then
  grep -E 'Signer #1 certificate (DN|SHA-256)' <<< "$FIRMA"
else
  echo "✗ el APK no está firmado o la firma no verifica:"; head -3 <<< "$FIRMA"; fallo=1
fi
if contiene 'CN=Android Debug' "$FIRMA"; then echo "✗ firmado con la clave de pruebas"; fallo=1; fi
BADGING=$("$BT/aapt2" dump badging "$APK")
grep -E '^package:' <<< "$BADGING"
if contiene 'application-debuggable' "$BADGING"; then echo "✗ el APK es depurable"; fallo=1; else echo "✓ no depurable"; fi
if contiene "name='$PAQUETE' " "$BADGING"; then echo "✓ paquete $PAQUETE"; else echo "✗ paquete inesperado"; fallo=1; fi

# Permisos exactos. Los tres FOREGROUND_SERVICE_* extra del ejemplo/SDK (DATA_SYNC, MEDIA_PLAYBACK,
# MEDIA_PROJECTION) se quitan en el manifiesto con tools:node="remove". SCHEDULE_EXACT_ALARM es el
# vigilante de Doze de ServicioX39 (cada 10 min). El último lo genera AndroidX a partir del applicationId.
ESPERADOS="android.permission.ACCESS_NETWORK_STATE
android.permission.BLUETOOTH
android.permission.BLUETOOTH_ADMIN
android.permission.CAMERA
android.permission.FOREGROUND_SERVICE
android.permission.FOREGROUND_SERVICE_CAMERA
android.permission.FOREGROUND_SERVICE_MICROPHONE
android.permission.FOREGROUND_SERVICE_SPECIAL_USE
android.permission.INTERNET
android.permission.MODIFY_AUDIO_SETTINGS
android.permission.POST_NOTIFICATIONS
android.permission.RECEIVE_BOOT_COMPLETED
android.permission.RECORD_AUDIO
android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
android.permission.SCHEDULE_EXACT_ALARM
android.permission.USE_FULL_SCREEN_INTENT
android.permission.WAKE_LOCK
$PAQUETE.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
PERMISOS=$("$BT/aapt2" dump permissions "$APK" | grep -oP "uses-permission: name='\K[^']+" | LC_ALL=C sort -u)
if [ "$PERMISOS" = "$ESPERADOS" ]; then
  echo "✓ permisos exactos ($(echo "$PERMISOS" | wc -l))"
else
  echo "✗ permisos distintos de los esperados:"
  diff <(echo "$ESPERADOS") <(echo "$PERMISOS") | grep -E '^[<>]' | sed 's/^</  falta:/; s/^>/  sobra:/'
  fallo=1
fi

# Restos del ejemplo de LiveKit / del SDK / de depuración que no pueden estar. (android.permission.DUMP sí
# aparece: lo lleva el ProfileInstallReceiver de AndroidX como guardia, igual que en cualquier app; no es un permiso pedido.)
MANIFIESTO=$("$BT/aapt2" dump xmltree --file AndroidManifest.xml "$APK")
for resto in io.livekit.android.sample.service.ForegroundService \
             io.livekit.android.room.track.screencapture.ScreenCaptureService \
             VolcadoVerificacion; do
  if contiene "$resto" "$MANIFIESTO"; then echo "✗ el manifiesto aún contiene $resto"; fallo=1; fi
done
if contiene 'ServicioX39' "$MANIFIESTO"; then echo "✓ ServicioX39 presente, sin restos del ejemplo"; else echo "✗ falta ServicioX39"; fallo=1; fi
# En release AGP acorta las rutas de recursos (res/8G.xml…): el fichero se localiza por su nombre de recurso.
RUTA_RED=$("$BT/aapt2" dump resources "$APK" | grep -A2 'xml/network_security_config' | grep -oP '\(file\) \K\S+' | head -1)
if [ -z "$RUTA_RED" ]; then
  echo "✗ el APK no lleva xml/network_security_config"; fallo=1
else
  RED=$("$BT/aapt2" dump xmltree --file "$RUTA_RED" "$APK")
  if contiene 'cleartextTrafficPermitted=true' "$RED"; then echo "✗ permite tráfico en claro"; fallo=1; else echo "✓ sin tráfico en claro"; fi
  if contiene 'example\.com' "$RED"; then echo "✗ queda example.com en la configuración de red"; fallo=1; fi
fi
LISTA=$(unzip -l "$APK")
# ZXing, Material y Dagger son bibliotecas de código abierto de Google sin servicios; lo que no puede haber
# es Play Services / Firebase.
if grep -qiE 'firebase|gms|play-services' <<< "$LISTA"; then echo "✗ contiene Play Services / Firebase"; fallo=1; else echo "✓ sin Play Services ni Firebase"; fi
for lib in libwg-go.so libx39jni.so liblkjingle_peerconnection_so.so; do
  contiene "lib/arm64-v8a/$lib" "$LISTA" || { echo "✗ falta $lib"; fallo=1; }
done
if contiene 'lib/(armeabi|x86)' "$LISTA"; then echo "✗ hay binarios que no son arm64-v8a"; fallo=1; else echo "✓ solo arm64-v8a"; fi
[ "$fallo" -eq 0 ] || { echo "NO publicar este APK."; exit 1; }

echo "### 3. Archivo y sello"
mkdir -p "$ARCHIVO"
cp "$APK" "$SALIDA"
( cd "$(dirname "$SALIDA")" && sha256sum "$(basename "$SALIDA")" | tee "$(basename "$SALIDA").sha256" )
echo "huella del certificado de firma:"
echo "$FIRMA" | grep -oP 'Signer #1 certificate SHA-256 digest: \K\S+' | tee "$SALIDA.certificado-sha256"
if command -v ots >/dev/null || [ -x "$HOME/.local/bin/ots" ]; then
  OTS=$(command -v ots || echo "$HOME/.local/bin/ots")
  "$OTS" stamp "$SALIDA" "$SALIDA.sha256"
fi
echo "Listo: $SALIDA"
