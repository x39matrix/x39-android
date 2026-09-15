#!/bin/bash
# Prueba REAL del cliente OpenTimestamps del motor: envía un compromiso a los calendarios públicos,
# monta el .ots con el motor Rust y lo valida con el cliente oficial `ots`.
# Para actualizar más tarde:  bash probar_ots_calendarios.sh --actualizar
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null
export PATH="$HOME/.local/bin:$PATH"
cd /home/x39matrix/x39_mensajeria/x39-core || exit 1
# Fuera de /tmp: la prueba tiene que sobrevivir a un reinicio hasta que Bitcoin la confirme.
D=/home/x39matrix/x39_mensajeria/pruebas_ots/x39_ots_real
CLI=target/debug/examples/ots_cli
cargo build -q --example ots_cli || exit 1
CABECERAS=(-H 'Accept: application/vnd.opentimestamps.v1' -H 'User-Agent: x39-evidencia')

if [ "${1:-}" = "--actualizar" ]; then
  [ -f "$D/documento.txt.ots" ] || { echo "no hay prueba previa en $D"; exit 1; }
  while read -r uri msg; do
    f="$D/mejora_$(echo "$uri" | tr -cd 'a-z').bin"
    code=$(curl -sS -m 20 "${CABECERAS[@]}" -o "$f" -w '%{http_code}' "$uri/timestamp/$msg")
    if [ "$code" = "200" ]; then "$CLI" actualizar "$D/documento.txt.ots" "$msg" "$f"; else echo "$uri: aún pendiente (HTTP $code)"; fi
  done < <("$CLI" pendientes "$D/documento.txt.ots")
  echo "--- ots info:"; ots info "$D/documento.txt.ots" | grep -E "Attestation|File sha256" | sort | uniq -c
  exit 0
fi

rm -rf "$D"; mkdir -p "$D"
printf 'x39 evidencia · prueba del cliente OTS · %s\n' "$(date -u +%FT%TZ)" > "$D/documento.txt"
HUELLA=$(sha256sum "$D/documento.txt" | cut -d' ' -f1)
NONCE=$(head -c16 /dev/urandom | xxd -p)
C=$("$CLI" compromiso "$HUELLA" "$NONCE")
echo "$C" | xxd -r -p > "$D/compromiso.bin"
echo "huella $HUELLA · compromiso $C"

resps=()
for cal in https://a.pool.opentimestamps.org https://b.pool.opentimestamps.org https://a.pool.eternitywall.com https://ots.btc.catallaxy.com; do
  f="$D/resp_$(echo "$cal" | tr -cd 'a-z').bin"
  if curl -fsS -m 20 -X POST "${CABECERAS[@]}" --data-binary "@$D/compromiso.bin" -o "$f" "$cal/digest"; then
    echo "calendario OK    $cal ($(stat -c %s "$f") B)"; resps+=("$f")
  else
    echo "calendario FALLA $cal"
  fi
done
[ ${#resps[@]} -ge 2 ] || { echo "menos de dos calendarios respondieron"; exit 1; }

"$CLI" montar "$HUELLA" "$NONCE" "$D/documento.txt.ots" "${resps[@]}" || exit 1
echo; echo "--- ots info (cliente oficial) sobre el .ots del motor:"
ots info "$D/documento.txt.ots"
echo; echo "--- ots verify sin nodo (lo correcto ahora es 'pendiente', nunca un error de formato):"
ots --no-bitcoin verify -f "$D/documento.txt" "$D/documento.txt.ots" 2>&1 | tail -5
echo; echo "--- pendientes según el motor:"; "$CLI" pendientes "$D/documento.txt.ots"
