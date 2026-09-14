#!/usr/bin/env python3
"""X-39 CARRIL A — VERIFICADOR de notarizacion post-cuantica.  (v1.1)

v1.1: compatible con pqcrypto >= 1.0 (verify devuelve None y LANZA si la firma no es valida)
      y con pqcrypto < 1.0 (verify devuelve True/False). La v1 hacia bool(verify(...)) y con
      pqcrypto 1.0 marcaba como INVALIDO cualquier paquete autentico.
      Nueva via independiente: --openssl verifica la firma con OpenSSL >= 3.5 (ML-DSA nativo),
      sin depender de pqcrypto.

Verifica, 100% OFFLINE y sin confiar en la infraestructura de X-39, que un documento fue
firmado por el operador con ML-DSA-87 (FIPS-204) y (opcional) anclado en Bitcoin via OpenTimestamps.

Un PAQUETE de notarizacion contiene:
  statement.txt        los bytes EXACTOS que se firmaron (formato canonico X39-NOTARIZE-v1)
  signature.bin        firma ML-DSA-87 (4627 B)
  operator.pub.raw     pubkey del operador (2592 B, raw)
  documento            (opcional) el fichero original; se recomputa su sha256 y se cruza
  statement.txt.ots    (opcional) prueba OpenTimestamps del statement (anclaje Bitcoin)

Uso:
  x39_verify.py --bundle <directorio> [--expect-pubkey-sha256 HEX] [--openssl]
"""
import argparse, sys, os, hashlib, subprocess, shutil, tempfile

MAGIC = "X39-NOTARIZE-v1"
PUB_LEN, SIG_LEN = 2592, 4627
# DER SubjectPublicKeyInfo de ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19) para una clave raw de 2592 B.
SPKI_PREFIX_MLDSA87 = bytes.fromhex("30820a32300b060960864801650304031303820a2100")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def build_statement(doc_sha256, utc, pub_sha256, note=""):
    lines = [MAGIC, f"document_sha256: {doc_sha256}", f"utc: {utc}", f"operator_pubkey_sha256: {pub_sha256}"]
    if note:
        lines.append(f"note: {note}")
    return ("\n".join(lines) + "\n").encode()


def parse_statement(raw):
    txt = raw.decode("utf-8", errors="replace")
    lines = txt.split("\n")
    if not lines or lines[0].strip() != MAGIC:
        raise ValueError(f"cabecera invalida (esperado {MAGIC})")
    fields = {}
    for l in lines[1:]:
        if not l.strip():
            continue
        if ":" not in l:
            raise ValueError(f"linea no clave:valor -> {l!r}")
        k, v = l.split(":", 1)
        fields[k.strip()] = v.strip()
    for req in ("document_sha256", "utc", "operator_pubkey_sha256"):
        if req not in fields:
            raise ValueError(f"falta campo obligatorio: {req}")
    return fields


def verify_pqcrypto(pub, msg, sig):
    """True solo si la firma es valida. Soporta ambas APIs de pqcrypto sin aceptar nunca por defecto."""
    from pqcrypto.sign.ml_dsa_87 import verify as ml_verify
    try:
        result = ml_verify(pub, msg, sig)
    except Exception:
        return False                    # pqcrypto >= 1.0: firma invalida lanza
    if result is True:
        return True                     # pqcrypto < 1.0: True = valida
    if result is None:
        return True                     # pqcrypto >= 1.0: sin excepcion = valida
    return False                        # pqcrypto < 1.0: False = invalida (el bug 3.9 lo ignoraba)


def verify_openssl(pub, msg, sig):
    ossl = shutil.which("openssl")
    if not ossl:
        return None, "openssl no encontrado"
    with tempfile.TemporaryDirectory() as t:
        pem = os.path.join(t, "pub.der")
        open(pem, "wb").write(SPKI_PREFIX_MLDSA87 + pub)
        mp, sp = os.path.join(t, "m"), os.path.join(t, "s")
        open(mp, "wb").write(msg)
        open(sp, "wb").write(sig)
        r = subprocess.run([ossl, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", pem,
                            "-rawin", "-in", mp, "-sigfile", sp], capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        if "not supported" in out.lower() or "unsupported" in out.lower() or "unknown" in out.lower():
            return None, f"este OpenSSL no soporta ML-DSA-87 ({out[:80]})"
        return r.returncode == 0, out[:120]


def main():
    ap = argparse.ArgumentParser(description="Verificador Carril A (ML-DSA-87 + OTS), offline.")
    ap.add_argument("--bundle")
    ap.add_argument("--statement"); ap.add_argument("--signature"); ap.add_argument("--pubkey")
    ap.add_argument("--document"); ap.add_argument("--ots")
    ap.add_argument("--expect-pubkey-sha256", dest="expect_pub")
    ap.add_argument("--openssl", action="store_true", help="verificar ademas con OpenSSL >= 3.5")
    a = ap.parse_args()

    if a.bundle:
        b = a.bundle
        a.statement = a.statement or os.path.join(b, "statement.txt")
        a.signature = a.signature or os.path.join(b, "signature.bin")
        a.pubkey = a.pubkey or os.path.join(b, "operator.pub.raw")
        ots = os.path.join(b, "statement.txt.ots")
        if not a.ots and os.path.isfile(ots):
            a.ots = ots
        if not a.document:
            for cand in sorted(os.listdir(b)):
                if cand not in ("statement.txt", "signature.bin", "operator.pub.raw", "statement.txt.ots", "MANIFEST.sha256"):
                    a.document = os.path.join(b, cand)
                    break
    if not (a.statement and a.signature and a.pubkey):
        ap.error("faltan --statement/--signature/--pubkey (o usa --bundle)")

    ncheck = [0]; fails = [0]

    def line(ok, msg):
        ncheck[0] += 1
        print(f"  [{'OK ' if ok else 'FAIL'}] {msg}")
        if not ok:
            fails[0] += 1

    print("=" * 67); print(" X-39 CARRIL A — VERIFICACION OFFLINE (ML-DSA-87 / FIPS-204 + OTS)  v1.1"); print("=" * 67)

    raw = open(a.statement, "rb").read()
    try:
        f = parse_statement(raw)
    except Exception as e:
        print(f"  [FATAL] statement invalido: {e}"); sys.exit(2)
    print(f"  statement: document_sha256={f['document_sha256'][:24]}.. utc={f['utc']} op_pk={f['operator_pubkey_sha256'][:24]}..")
    if f.get("note"):
        print(f"             note: {f['note']}")

    canon = build_statement(f["document_sha256"], f["utc"], f["operator_pubkey_sha256"], f.get("note", ""))
    line(canon == raw, "statement en formato canonico X39-NOTARIZE-v1 (sin bytes ocultos)")

    pub = open(a.pubkey, "rb").read()
    line(len(pub) == PUB_LEN, f"pubkey operador = {PUB_LEN} B (ML-DSA-87)  [visto {len(pub)}]")
    pub_sha = sha256_bytes(pub)
    line(pub_sha == f["operator_pubkey_sha256"], f"pubkey coincide con el statement (sha256 {pub_sha[:24]}..)")
    if a.expect_pub:
        line(pub_sha == a.expect_pub.lower(), "pubkey coincide con el hash esperado/pineado")
    else:
        print("  [.. ] sin --expect-pubkey-sha256: comprueba el hash de la clave contra una fuente oficial publicada")

    sig = open(a.signature, "rb").read()
    line(len(sig) == SIG_LEN, f"firma = {SIG_LEN} B (ML-DSA-87)  [visto {len(sig)}]")
    try:
        sig_ok = verify_pqcrypto(pub, raw, sig)
    except ImportError as e:
        print(f"  [FATAL] falta pqcrypto (ML-DSA-87). Instala: pip install pqcrypto   ({e})"); sys.exit(10)
    line(sig_ok, "FIRMA ML-DSA-87 VALIDA sobre el statement (pqcrypto)")

    if a.openssl:
        ok, detail = verify_openssl(pub, raw, sig)
        if ok is None:
            print(f"  [.. ] OpenSSL: {detail}")
        else:
            line(ok, f"FIRMA ML-DSA-87 VALIDA sobre el statement (OpenSSL, implementacion independiente)")

    if a.document and os.path.isfile(a.document):
        d = sha256_file(a.document)
        line(d == f["document_sha256"], f"sha256(documento) == statement  ({d[:24]}..)")
    else:
        print("  [.. ] documento no aportado: se verifica la firma del hash, no el fichero en si")

    ots_status = "ausente"
    if a.ots and os.path.isfile(a.ots):
        if shutil.which("ots"):
            info = subprocess.run(["ots", "info", a.ots], capture_output=True, text=True).stdout
            btc = [l.strip() for l in info.splitlines() if "BitcoinBlockHeaderAttestation" in l]
            pend = [l for l in info.splitlines() if "PendingAttestation" in l]
            if btc:
                for l in btc[:4]:
                    print("        " + l)
                print("  [OK ] OTS anclado en bloque Bitcoin (existencia sellada en el tiempo)")
                ots_status = "anclado"
            elif pend:
                print("  [.. ] OTS PENDIENTE: aun no anclado en un bloque Bitcoin. Ejecuta: ots upgrade")
                ots_status = "pendiente"
            else:
                ots_status = "desconocido"
        else:
            print("  [.. ] cliente `ots` no instalado: pip install opentimestamps-client")
            ots_status = "sin-cliente"
    else:
        print("  [.. ] sin .ots: no se verifica anclaje temporal en Bitcoin (opcional)")

    print("-" * 67)
    print("  Nota: el campo utc es la hora DECLARADA por el firmante; el sello OTS/TSA prueba el 'no despues de'.")
    if fails[0] == 0:
        print(f"  VEREDICTO: VALIDO (criptografia). {ncheck[0]} comprobaciones, 0 fallos.")
        print(f"  Firmante = operador cuyo sha256(pubkey) = {pub_sha}")
        print(f"  Sello temporal Bitcoin (OTS): {ots_status.upper()}")
        sys.exit(0)
    print(f"  VEREDICTO: INVALIDO. {fails[0]} de {ncheck[0]} comprobaciones fallaron. NO confies en este paquete.")
    sys.exit(1)


if __name__ == "__main__":
    main()
