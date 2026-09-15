#!/bin/bash
# ¿Se puede arrancar un emulador para sacar capturas? Solo lectura.
cd /home/x39matrix/x39_mensajeria || exit 1
echo "--- build_apk.sh / setup_android.sh (rutas SDK)"
grep -nE "ANDROID|sdk" scripts/build_apk.sh scripts/setup_android.sh | head -20
for d in /home/x39matrix/android-sdk /home/x39matrix/Android/Sdk /opt/android-sdk "$ANDROID_HOME"; do
  [ -d "$d" ] && { echo "SDK en $d"; ls "$d"; ls "$d/system-images" 2>/dev/null; }
done
echo "--- sudo sin contraseña:"; sudo -n true 2>/dev/null && echo si || echo no
echo "--- WSLg (pantalla):"; echo "DISPLAY=$DISPLAY WAYLAND=$WAYLAND_DISPLAY"; ls /mnt/wslg 2>/dev/null | head -3
echo "--- Windows: hipervisor"; powershell.exe -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent" 2>/dev/null
