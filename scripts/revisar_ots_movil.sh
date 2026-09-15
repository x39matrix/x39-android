#!/bin/bash
# Revisa con la herramienta oficial de OpenTimestamps un .ots exportado desde x39 · Evidencia.
# Uso: bash scripts/revisar_ots_movil.sh <ruta/al/fichero.ots>
# No modifica el original: la actualización se hace sobre una copia «<id>.actualizada.ots».
set -uo pipefail
F="${1:?falta el fichero .ots}"
OTS=$(command -v ots || true)
if [ -z "$OTS" ]; then
  for c in "$HOME/.local/bin/ots" "$HOME"/*/bin/ots "$HOME"/*/*/bin/ots; do
    [ -x "$c" ] && { OTS="$c"; break; }
  done
fi
[ -n "$OTS" ] || { echo "no encuentro el comando ots"; exit 1; }
echo "ots: $OTS"
sha256sum "$F"
ls -l "$F"
echo "=== ots info (original)"
"$OTS" info "$F"
COPIA="${F%.ots}.actualizada.ots"
cp "$F" "$COPIA"
echo "=== ots upgrade (sobre la copia)"
"$OTS" upgrade "$COPIA"
echo "=== atestaciones tras upgrade"
"$OTS" info "$COPIA" | grep -iE "bitcoin|pending|block" || true
