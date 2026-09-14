#!/bin/bash
# Bundle PQC y origen del mensaje firmado del sello dorado. Solo lectura, trabaja en /tmp.
N=/home/x39matrix/home_viejo/x39matrix-web/notary
T=$(mktemp -d)
tar -xzf "$N/x39_cert_pqc_bundle.tar.gz" -C "$T"
cd "$T" || exit 1

echo "### A. Algoritmo real de la clave poscuántica"
openssl pkey -pubin -in ml_dsa_public.pem -noout -text 2>&1 | head -2
python3 -c "import base64,re; d=base64.b64decode(''.join(l for l in open('ml_dsa_public.pem') if not l.startswith('-----'))); print('  SPKI DER:', len(d), 'bytes')"
echo "  firma: $(stat -c %s x39_ecdsa_cert.der.sha256.mldsa_sig) bytes  (ML-DSA-44=2420 · ML-DSA-65=3309 · ML-DSA-87=4627)"

echo; echo "### B. ¿La firma ML-DSA es válida? (OpenSSL 3.5)"
echo "--- sha256 del certificado ECDSA vs archivo .sha256:"
sha256sum x39_ecdsa_cert.der
cat x39_ecdsa_cert.der.sha256; echo
for entrada in x39_ecdsa_cert.der.sha256 x39_ecdsa_cert.der; do
  r=$(openssl pkeyutl -verify -pubin -inkey ml_dsa_public.pem -rawin -in "$entrada" -sigfile x39_ecdsa_cert.der.sha256.mldsa_sig 2>&1 | tail -1)
  echo "  verificando sobre $entrada -> $r"
done
printf '%s' "$(tr -d '\n ' < x39_ecdsa_cert.der.sha256 | cut -c1-64)" > sin_salto.txt
r=$(openssl pkeyutl -verify -pubin -inkey ml_dsa_public.pem -rawin -in sin_salto.txt -sigfile x39_ecdsa_cert.der.sha256.mldsa_sig 2>&1 | tail -1)
echo "  verificando sobre el hex sin salto de línea -> $r"

echo; echo "### C. Certificados"
echo "--- ECDSA (DER):"
openssl x509 -inform DER -in x39_ecdsa_cert.der -noout -subject -issuer -dates 2>&1
openssl x509 -inform DER -in x39_ecdsa_cert.der -noout -text 2>&1 | grep -E "Public Key Algorithm|ASN1 OID|NIST CURVE|Signature Algorithm" | sort -u
openssl x509 -inform DER -in x39_ecdsa_cert.der -noout -pubkey 2>/dev/null | openssl ec -pubin -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | xxd -p | tr -d '\n' | sed 's/^/  pubkey comprimida: /'; echo
echo "  (HUB publica: 025968e3eea2adc6a3c7e0b24c39f3e94009393e57280cb9ccc3801251bb202083)"
echo "--- ML-DSA (PEM):"
openssl x509 -in ml_dsa_cert.pem -noout -subject -issuer -dates 2>&1
openssl x509 -in ml_dsa_cert.pem -noout -text 2>&1 | grep -E "Public Key Algorithm|Signature Algorithm" | sort -u
openssl verify -CAfile ml_dsa_cert.pem ml_dsa_cert.pem 2>&1 | tail -1

echo; echo "### D. Anclajes Bitcoin de los .ots del bundle"
for o in "$N/x39_cert_pqc_bundle.tar.gz.ots" "$N/x39_cert_pqc_bundle.tar.gz.v1_originalmente_sellado_953819.ots"; do
  echo "--- $(basename "$o")"
  ots info "$o" 2>&1 | grep -E "File sha256|BitcoinBlockHeaderAttestation|PendingAttestation|Error|error" | sort | uniq -c
done

echo; echo "### E. ¿De dónde sale el mensaje firmado 84ceaca9… del sello dorado?"
grep -rIl "84ceaca9525bd1034348d2a4122c147ec78ab03820131e09bbe477faf61617d5" /home/x39matrix/home_viejo \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=target --exclude-dir=ic --exclude-dir=.cache \
  --exclude-dir=keys --exclude-dir=operator 2>/dev/null | head -10
echo "--- ¿es el sha256 de algún archivo de notary/ o evidencias?"
for f in "$N"/* /home/x39matrix/home_viejo/x39matrix-protocol/notary/*; do
  [ -f "$f" ] && [ "$(sha256sum "$f" | cut -c1-64)" = "84ceaca9525bd1034348d2a4122c147ec78ab03820131e09bbe477faf61617d5" ] && echo "  COINCIDE: $f"
done
echo "  (fin de búsqueda)"
rm -rf "$T"
