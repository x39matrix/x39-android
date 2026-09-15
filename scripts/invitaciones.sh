#!/bin/bash
# Autoridad del Ayuntamiento: crea su clave de firma y emite invitaciones para activar el modo personal de x39.
# - La semilla secreta vive SOLO en ~/x39-llaves (permisos 0600). Nunca en git ni en la app.
# - La clave pública se copia a android/app/src/main/assets/autoridad.pk y viaja dentro de la app.
# Uso:
#   bash scripts/invitaciones.sh crear
#   bash scripts/invitaciones.sh emitir 2026-12-31 "Concejalía de Cultura"
#   bash scripts/invitaciones.sh verificar 'X39INV1:...'
set -euo pipefail
source "$HOME/.cargo/env"
cd "$HOME/x39_mensajeria/x39-core"
SEMILLA="${X39_AUTORIDAD:-$HOME/x39-llaves/autoridad-ayuntamiento.seed}"
PK_APP="$HOME/x39_mensajeria/android/app/src/main/assets/autoridad.pk"

case "${1:-}" in
  crear)
    [ ! -e "$SEMILLA" ] || { echo "ya existe $SEMILLA; no se sobrescribe"; exit 1; }
    mkdir -p "$(dirname "$SEMILLA")"
    cargo run -q --example invitacion -- nueva-autoridad "$SEMILLA"
    cp "$SEMILLA.pk" "$PK_APP"
    echo "clave pública copiada a $PK_APP: recompila la app (scripts/build_apk.sh) para que la lleve."
    ;;
  emitir)
    [ $# -eq 3 ] || { echo "uso: $0 emitir AAAA-MM-DD 'Nombre o cargo'"; exit 2; }
    [ -f "$SEMILLA" ] || { echo "no existe $SEMILLA: primero '$0 crear'"; exit 1; }
    cargo run -q --example invitacion -- emitir "$SEMILLA" "$2" "$3"
    ;;
  verificar)
    [ $# -eq 2 ] || { echo "uso: $0 verificar 'X39INV1:...'"; exit 2; }
    [ -f "$PK_APP" ] || { echo "no existe $PK_APP: primero '$0 crear'"; exit 1; }
    cargo run -q --example invitacion -- verificar "$PK_APP" "$(date +%F)" "$2"
    ;;
  *)
    echo "uso: $0 crear | emitir AAAA-MM-DD 'Nombre o cargo' | verificar 'X39INV1:...'"
    exit 2
    ;;
esac
