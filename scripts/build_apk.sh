#!/bin/bash
# Compila x39 Bolsillo: motor Rust para Android + APK de depuración.
set -euo pipefail
source "$HOME/Android/env.sh"
source "$HOME/.cargo/env"
cd "$HOME/x39_mensajeria"

echo "### 0. Registro de actas incluido en la app"
bash scripts/actualizar_registro.sh
if [ -f android/app/src/main/assets/autoridad.pk ]; then
  echo "autoridad del Ayuntamiento: clave pública sha256 $(sha256sum android/app/src/main/assets/autoridad.pk | cut -c1-16)…"
else
  echo "AVISO: no hay android/app/src/main/assets/autoridad.pk (scripts/invitaciones.sh crear):"
  echo "       «Soy personal del Ayuntamiento» dirá que esta versión no lleva la clave de la autoridad."
fi

echo "### 1. Motor Rust para arm64 (móviles) y x86_64 (emulador)"
( cd x39-jni && cargo ndk -t arm64-v8a -t x86_64 --platform 28 -o ../android/app/src/main/jniLibs build --release 2>&1 \
    | grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tail -5 )
find android/app/src/main/jniLibs -name '*.so' -exec ls -la {} \;

echo "### 2. APK"
cd android
[ -f gradlew ] || gradle wrapper --gradle-version 8.10.2 -q
./gradlew --no-daemon -q assembleDebug 2>&1 | { grep -vE '^\s*$' || true; } | tail -30
APK=app/build/outputs/apk/debug/app-debug.apk
ls -la "$APK"
sha256sum "$APK"

echo "### 3. Comprobaciones de privacidad"
AAPT2=$(ls "$ANDROID_HOME"/build-tools/*/aapt2 | tail -1)
echo "--- permisos declarados (desde 0.8: exactamente INTERNET y ACCESS_NETWORK_STATE, para el buzón):"
"$AAPT2" dump permissions "$APK"
PERMISOS=$("$AAPT2" dump permissions "$APK" | grep -oP "uses-permission: name='\K[^']+" | sort | tr '\n' ' ')
[ "$PERMISOS" = "android.permission.ACCESS_NETWORK_STATE android.permission.INTERNET " ] \
  && echo "✓ permisos exactos" || echo "✗ PERMISOS INESPERADOS: $PERMISOS"
echo "--- contenido nativo y código:"
python3 - "$APK" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for n in z.namelist():
    if n.startswith("lib/") or n.endswith(".dex"):
        print(f"  {z.getinfo(n).file_size:>9}  {n}")
google = [n for n in z.namelist() if "google" in n.lower() or "firebase" in n.lower() or "gms" in n.lower()]
print("--- archivos con google/firebase/gms en el nombre:", google or "NINGUNO")
PY
