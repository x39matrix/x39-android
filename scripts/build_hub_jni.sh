#!/usr/bin/env bash
# Compila el puente de cobro para Comunicaciones.
(
set -euo pipefail
export LC_ALL=C
cd -- "$HOME/x39_mensajeria"
comprobar_rama() {
    [[ $(git branch --show-current) == hub-aparte ]] || {
        echo 'Se requiere la rama hub-aparte.' >&2
        exit 1
    }
}
comprobar_rama
if (( $# )); then
    echo 'El destino es fijo. Este script se ejecuta sin argumentos.' >&2
    exit 1
fi

source "$HOME/Android/env.sh"
source "$HOME/.cargo/env"
motor=$(pwd -P)
casa=$(realpath -e -- "$HOME")
directorio="$casa/client-sdk-android/sample-app/src/main/jniLibs/arm64-v8a"
protegido=$(realpath -e -- "$motor/android")
nombre=libx39hub.so
herramientas="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

comprobar_destino() {
    local fisico
    fisico=$(realpath -e -- "$directorio")
    if [[ $fisico != "$directorio" || $fisico == "$protegido" || $fisico == "$protegido/"* ]]; then
        echo "Se rechaza el directorio de destino: $fisico" >&2
        exit 1
    fi
    if [[ -L $fisico/$nombre || ( -e $fisico/$nombre && ! -f $fisico/$nombre ) ]]; then
        echo "Se rechaza el destino: $fisico/$nombre" >&2
        exit 1
    fi
}
simbolos() {
    "$herramientas/llvm-nm" --dynamic --extern-only --defined-only --format=posix "$1" |
        awk '$1 ~ /^Java_/ {print $1}' | sort
}
comprobar_destino

trabajo=$(mktemp -d /tmp/x39-hub-arm64.XXXXXXXX)
trap 'rm -rf -- "$trabajo"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$trabajo" CARGO_TARGET_DIR="$trabajo/target" CARGO_BUILD_BUILD_DIR="$trabajo/build"
(
    cd -- "$motor/x39-hub-jni"
    cargo ndk -t arm64-v8a --platform 28 -o "$trabajo/jni" build --release --locked
)

biblioteca="$trabajo/jni/arm64-v8a/$nombre"
"$herramientas/llvm-readelf" -h "$biblioteca" > "$trabajo/cabecera"
grep -Eq '^[[:space:]]*Class:[[:space:]]+ELF64([[:space:]]|$)' "$trabajo/cabecera"
grep -Eq '^[[:space:]]*Machine:[[:space:]]+AArch64([[:space:]]|$)' "$trabajo/cabecera"
cat > "$trabajo/esperados" <<'SIMBOLOS'
Java_org_x39_bolsillo_X39Hub_cobroFirmar
Java_org_x39_bolsillo_X39Hub_cobroLeer
Java_org_x39_bolsillo_X39Hub_cobroVerificar
SIMBOLOS
simbolos "$biblioteca" > "$trabajo/exportados"
diff -u -- "$trabajo/esperados" "$trabajo/exportados"

comprobar_rama
comprobar_destino
(
    cd -P -- "$directorio"
    [[ $(pwd -P) == "$directorio" ]]
    if ! cmp -s -- "$biblioteca" "$nombre"; then
        copia=$(mktemp .libx39hub.so.XXXXXXXX)
        trap 'rm -f -- "$copia"' EXIT
        install -m 0644 -- "$biblioteca" "$copia"
        mv -fT -- "$copia" "$nombre"
    fi
    cmp -- "$biblioteca" "$nombre"
    sha256sum -- "$directorio/$nombre"
    simbolos "$nombre"
)
)
