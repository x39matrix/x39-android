#!/bin/bash
# Instala en ~/Android el toolchain para compilar la APK. Sin sudo.
# Autorizado por el usuario: descargas (Adoptium, Google SDK/NDK, Gradle, rustup, crates.io)
# y aceptación de las licencias del Android SDK. Nada de esto va dentro de la app.
set -euo pipefail
A=$HOME/Android
SDK=$A/sdk
GV=8.10.2
NDK_VER=27.2.12479018
mkdir -p "$A"
cd "$A"

log() { echo "[$(date +%H:%M:%S)] $*"; }
dl() {
  if command -v curl >/dev/null; then curl -fL --retry 3 -sS -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
unz() {
  if command -v unzip >/dev/null; then unzip -q -o "$1" -d "$2"
  else python3 -c 'import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"; fi
}

# 1. JDK 17 (Eclipse Temurin / Adoptium)
if [ ! -x "$A/jdk/bin/java" ]; then
  log "1/5 JDK 17 (Adoptium)"
  dl "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse" jdk.tar.gz
  mkdir -p jdk && tar -xzf jdk.tar.gz -C jdk --strip-components=1 && rm jdk.tar.gz
fi
export JAVA_HOME=$A/jdk
export PATH=$A/jdk/bin:$PATH
java -version 2>&1 | head -1

# 2. Android command-line tools + SDK + NDK
if [ ! -f "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  log "2/5 Android command-line tools"
  dl "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" clt.zip
  mkdir -p "$SDK/cmdline-tools"
  unz clt.zip "$SDK/cmdline-tools" && rm clt.zip
  rm -rf "$SDK/cmdline-tools/latest"
  mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
  chmod +x "$SDK/cmdline-tools/latest/bin/"*
fi
SM=$SDK/cmdline-tools/latest/bin/sdkmanager
log "2/5 licencias del Android SDK (aceptadas por el usuario)"
yes | "$SM" --sdk_root="$SDK" --licenses > /dev/null || true
log "2/5 platform-tools, android-35, build-tools 35.0.0, NDK $NDK_VER"
"$SM" --sdk_root="$SDK" "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;$NDK_VER" 2>&1 \
  | tr '\r' '\n' | grep -vE '^\s*\[|^\s*$' | tail -5

# 3. Gradle
if [ ! -f "$A/gradle-$GV/bin/gradle" ]; then
  log "3/5 Gradle $GV"
  dl "https://services.gradle.org/distributions/gradle-$GV-bin.zip" gradle.zip
  unz gradle.zip "$A" && rm gradle.zip
  chmod +x "$A/gradle-$GV/bin/gradle"
fi

# 4. Rust para Android
source "$HOME/.cargo/env"
log "4/5 targets Rust aarch64 (móviles) y x86_64 (emulador)"
rustup target add aarch64-linux-android x86_64-linux-android
if ! command -v cargo-ndk >/dev/null; then
  log "4/5 cargo-ndk"
  cargo install cargo-ndk --locked 2>&1 | tail -2
fi

# 5. Entorno
cat > "$A/env.sh" <<EOF
export JAVA_HOME=$A/jdk
export ANDROID_HOME=$SDK
export ANDROID_NDK_HOME=$SDK/ndk/$NDK_VER
export PATH=$A/jdk/bin:$A/gradle-$GV/bin:$SDK/platform-tools:\$HOME/.cargo/bin:\$PATH
EOF
log "5/5 comprobación"
source "$A/env.sh"
echo "  java:      $(java -version 2>&1 | head -1)"
echo "  gradle:    $(gradle --version 2>/dev/null | grep -m1 Gradle)"
echo "  ndk:       $(ls "$SDK/ndk" 2>/dev/null)"
echo "  build-tools: $(ls "$SDK/build-tools" 2>/dev/null)"
echo "  cargo-ndk: $(cargo ndk --version 2>/dev/null)"
echo "  espacio:   $(du -sh "$A" | cut -f1)"
log "LISTO. Entorno: source ~/Android/env.sh"
