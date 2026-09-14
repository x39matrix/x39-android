#!/bin/bash
# Verifica nombre, icono, permisos y contenido de la APK de depuración.
set -uo pipefail
source "$HOME/Android/env.sh"
APK="$HOME/x39_mensajeria/android/app/build/outputs/apk/debug/app-debug.apk"
AAPT2=$(ls "$ANDROID_HOME"/build-tools/*/aapt2 | tail -1)

ls -la --time-style=long-iso "$APK"
sha256sum "$APK"
echo "--- badging:"
"$AAPT2" dump badging "$APK" | grep -E "package:|application-label:|application-icon-|uses-permission|sdkVersion|targetSdkVersion" || true
echo "--- recursos del icono:"
"$AAPT2" dump resources "$APK" | grep -E "mipmap/ic_launcher|drawable/ic_launcher" || true
echo "--- archivos Google/Firebase/GMS:"
python3 - "$APK" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
g = [n for n in z.namelist() if any(k in n.lower() for k in ("google", "firebase", "gms"))]
print("  ", g or "NINGUNO")
PY
