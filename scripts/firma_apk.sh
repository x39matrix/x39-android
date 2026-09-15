#!/bin/bash
# Quién firmó un APK (esquemas v1/v2/v3) y la huella SHA-256 del certificado.
# keytool -printcert -jarfile solo ve la firma v1; los APK con minSdk >= 24 suelen ir solo con v2/v3.
# Uso: bash scripts/firma_apk.sh <fichero.apk>
set -uo pipefail
APK="${1:?falta el fichero .apk}"
source "$HOME/Android/env.sh"
APKSIGNER=$(ls "$ANDROID_HOME"/build-tools/*/apksigner | tail -1)
echo "apksigner: $APKSIGNER"
sha256sum "$APK"
"$APKSIGNER" verify --verbose --print-certs "$APK" 2>&1 | grep -vE '^WARNING: META-INF'
