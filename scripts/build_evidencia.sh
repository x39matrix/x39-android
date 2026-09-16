#!/bin/bash
# Compila x39 · Evidencia: motor Rust para Android + APK de depuración + comprobaciones.
set -euo pipefail
source "$HOME/Android/env.sh"
source "$HOME/.cargo/env"
cd "$HOME/x39_mensajeria"

echo "### 1. Motor Rust para arm64 (móviles) y x86_64 (emulador)"
( cd x39-jni && cargo ndk -t arm64-v8a -t x86_64 --platform 28 -o ../android/app/src/main/jniLibs build --release 2>&1 \
    | grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tail -5 )

echo "### 2. APK"
cd android
./gradlew --no-daemon -q :evidencia:assembleDebug 2>&1 | { grep -vE '^\s*$' || true; } | tail -40
APK=evidencia/build/outputs/apk/debug/evidencia-debug.apk
ls -la "$APK"
sha256sum "$APK"

echo "### 3. Comprobaciones"
AAPT2=$(ls "$ANDROID_HOME"/build-tools/*/aapt2 | tail -1)
echo "--- permisos declarados (deben ser exactamente INTERNET, ACCESS_NETWORK_STATE, CAMERA y RECORD_AUDIO):"
"$AAPT2" dump permissions "$APK"
"$AAPT2" dump badging "$APK" | grep -E "^package:|application-label:" || true
python3 - "$APK" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for n in z.namelist():
    if n.startswith("lib/") or n.endswith(".dex"):
        print(f"  {z.getinfo(n).file_size:>9}  {n}")
google = [n for n in z.namelist() if "google" in n.lower() or "firebase" in n.lower() or "gms" in n.lower()]
print("--- archivos con google/firebase/gms en el nombre:", google or "NINGUNO")
PY
