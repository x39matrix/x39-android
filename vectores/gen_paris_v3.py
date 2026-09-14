#!/usr/bin/env python3
"""Genera vectores de prueba Paris v3 (formato de paris_seal.py 3.10+) para validar x39-core.

Formato v3:  header(40) = MAGIC(8) | VERSION(1)=3 | flags(1) | reserved(6) | cid(16) | ts(8, BE)
             cápsula    = header | ct_kem(1568) | nonce(12) | AES-256-GCM(pt, aad = header || aad_usuario)
             clave AES  = HKDF-SHA256(shared, info=b"x39-paris-sealed-v1", salt=None, len=32)

Negativos: réplica a nivel de formato de las categorías H/K/N/G/D/S de Mesopotamia v2.
TTL: vectores de política con `now` fijo. Replay: requiere estado y se prueba en el test de Rust.

SOLO CLAVES EFÍMERAS DE TEST. Nunca uses claves reales aquí.
"""
import json, os, struct, hashlib, pathlib
from pqcrypto.kem import ml_kem_1024 as kem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC, VERSION, CTX = b"X39PARIS", 3, b"x39-paris-sealed-v1"
HDR, CTK, NON = 40, kem.CIPHERTEXT_SIZE, 12
OFF_CTKEM, OFF_NONCE = HDR, HDR + CTK
OFF_CT = OFF_NONCE + NON
NOW = 1_790_000_000           # instante fijo para vectores TTL
TTL = 3600

# --- pqcrypto 1.0.0 (API nueva). Se resuelve el orden por tamaños, no por suposición. ---
def keygen():
    a, b = (bytes(x) for x in kem.keygen())
    return (a, b) if len(a) == kem.PUBLIC_KEY_SIZE and len(b) == kem.SECRET_KEY_SIZE else (b, a)

def encaps(pk):
    a, b = (bytes(x) for x in kem.encaps(pk))
    return (a, b) if len(a) == CTK else (b, a)          # (ct, shared)

def decaps(sk, ct):
    try:
        return bytes(kem.decaps(sk, ct))
    except TypeError:
        return bytes(kem.decaps(ct, sk))

def hkdf(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CTX).derive(shared)

def seal(pk, pt, aad=b"", cid=None, ts=NOW, flags=0, reserved=b"\x00" * 6):
    ct_kem, shared = encaps(pk)
    nonce = os.urandom(NON)
    header = MAGIC + bytes([VERSION, flags]) + reserved + (cid or os.urandom(16)) + struct.pack(">Q", ts)
    return header + ct_kem + nonce + AESGCM(hkdf(shared)).encrypt(nonce, pt, header + aad)

# --- apertura de referencia (misma lógica que paris_open.py v3, sin estado .seen) ---
class Reject(Exception): pass

def open_ref(sk, cap, aad=b"", now=None, ttl=0):
    if len(cap) < 8 or cap[:8] != MAGIC: raise Reject("magic")
    if len(cap) < 9 or cap[8] != VERSION: raise Reject("version")
    if len(cap) < OFF_CT + 16: raise Reject("longitud")
    header = cap[:HDR]
    ts = struct.unpack(">Q", header[32:40])[0]
    if ttl:
        age = now - ts
        if age > ttl or age < -300: raise Reject("ttl")
    try:
        key = hkdf(decaps(sk, cap[OFF_CTKEM:OFF_NONCE]))
        return AESGCM(key).decrypt(cap[OFF_NONCE:OFF_CT], cap[OFF_CT:], header + aad)
    except Reject: raise
    except Exception: raise Reject("aead")

# --- mutadores ---
def flip(b, i): a = bytearray(b); a[i] ^= 1; return bytes(a)
def setb(b, i, v): a = bytearray(b); a[i] = v; return bytes(a)
def fill(b, i, n, v): a = bytearray(b); a[i:i+n] = bytes([v]) * n; return bytes(a)
def rep(b, i, d): a = bytearray(b); a[i:i+len(d)] = d; return bytes(a)

def main():
    pk, sk = keygen()
    mal_pk, _ = keygen()
    PT = b"x39-mensajeria :: vector de prueba\n"
    cap  = seal(pk, PT)
    capA = seal(pk, PT, aad=b"x39-ctx")
    cap2 = seal(pk, PT)
    capM = seal(mal_pk, PT)
    capAB = seal(pk, PT, aad=b"AB")
    L = len(cap)

    V = []
    def add(vid, cat, name, c, expect, aad=b"", ttl=0):
        V.append(dict(id=vid, cat=cat, name=name, capsule=c.hex(), aad=aad.hex(),
                      now=NOW, ttl=ttl, expect=expect))

    # CONTROL
    add("C01", "CONTROL", "abre_base", cap, "accept")
    add("C02", "CONTROL", "abre_con_aad", capA, "accept", aad=b"x39-ctx")
    add("C03", "CONTROL", "pt_vacio", seal(pk, b""), "accept")
    add("C04", "CONTROL", "pt_64KB", seal(pk, os.urandom(65536)), "accept")
    add("C05", "CONTROL", "ttl_dentro", cap, "accept", ttl=TTL)
    # H: cabecera autenticada
    add("H01", "HEADER", "magic_bitflip", flip(cap, 0), "reject")
    add("H02", "HEADER", "version_2", setb(cap, 8, 2), "reject")
    add("H03", "HEADER", "version_1_downgrade", setb(cap, 8, 1), "reject")
    add("H04", "HEADER", "flags_ff", setb(cap, 9, 0xFF), "reject")
    add("H05", "HEADER", "reserved0_ff", setb(cap, 10, 0xFF), "reject")
    add("H06", "HEADER", "reserved5_ff", setb(cap, 15, 0xFF), "reject")
    add("H07", "HEADER", "cid0_bitflip", flip(cap, 16), "reject")
    add("H08", "HEADER", "cid15_bitflip", flip(cap, 31), "reject")
    add("H09", "HEADER", "ts0_bitflip", flip(cap, 32), "reject")
    add("H10", "HEADER", "ts7_bitflip", flip(cap, 39), "reject")
    # K: ct_kem
    add("K01", "KEM", "ctkem0_bitflip", flip(cap, OFF_CTKEM), "reject")
    add("K02", "KEM", "ctkem_mid_bitflip", flip(cap, OFF_CTKEM + CTK // 2), "reject")
    add("K03", "KEM", "ctkem_last_bitflip", flip(cap, OFF_NONCE - 1), "reject")
    add("K04", "KEM", "ctkem_ceros", fill(cap, OFF_CTKEM, CTK, 0), "reject")
    add("K05", "KEM", "ctkem_ff", fill(cap, OFF_CTKEM, CTK, 0xFF), "reject")
    add("K06", "KEM", "ctkem_truncar_1B", cap[:OFF_NONCE - 1] + cap[OFF_NONCE:], "reject")
    add("K07", "KEM", "ctkem_otra_capsula", rep(cap, OFF_CTKEM, cap2[OFF_CTKEM:OFF_NONCE]), "reject")
    add("K08", "KEM", "ctkem_aleatorio", rep(cap, OFF_CTKEM, os.urandom(CTK)), "reject")
    add("K09", "KEM", "ctkem_de_mallory", rep(cap, OFF_CTKEM, capM[OFF_CTKEM:OFF_NONCE]), "reject")
    add("K10", "KEM", "capsula_para_mallory", capM, "reject")
    # N: nonce
    add("N01", "NONCE", "nonce0_bitflip", flip(cap, OFF_NONCE), "reject")
    add("N02", "NONCE", "nonce11_bitflip", flip(cap, OFF_CT - 1), "reject")
    add("N03", "NONCE", "nonce_ceros", fill(cap, OFF_NONCE, NON, 0), "reject")
    add("N04", "NONCE", "nonce_ff", fill(cap, OFF_NONCE, NON, 0xFF), "reject")
    add("N05", "NONCE", "nonce_otra_capsula", rep(cap, OFF_NONCE, cap2[OFF_NONCE:OFF_CT]), "reject")
    add("N06", "NONCE", "nonce_insertar_1B", cap[:OFF_NONCE] + b"\x00" + cap[OFF_NONCE:], "reject")
    # G: AES-GCM
    add("G01", "GCM", "ct0_bitflip", flip(cap, OFF_CT), "reject")
    add("G02", "GCM", "ct_pre_tag_bitflip", flip(cap, L - 17), "reject")
    add("G03", "GCM", "tag0_bitflip", flip(cap, L - 16), "reject")
    add("G04", "GCM", "tag15_bitflip", flip(cap, L - 1), "reject")
    add("G05", "GCM", "truncar_10B", cap[:-10], "reject")
    add("G06", "GCM", "quitar_tag", cap[:-16], "reject")
    add("G07", "GCM", "extender_16B", cap + os.urandom(16), "reject")
    add("G08", "GCM", "ct_tag_ceros", fill(cap, OFF_CT, L - OFF_CT, 0), "reject")
    # D: AAD
    add("D01", "AAD", "aad_distinto", capA, "reject", aad=b"WRONG")
    add("D02", "AAD", "aad_quitado", capA, "reject")
    add("D03", "AAD", "aad_añadido", cap, "reject", aad=b"x")
    add("D04", "AAD", "aad_prefijo", capAB, "reject", aad=b"A")
    add("D05", "AAD", "aad_espacio_final", capA, "reject", aad=b"x39-ctx ")
    # S: estructura
    add("S01", "STRUCT", "vacio", b"", "reject")
    add("S02", "STRUCT", "1_byte", b"\x00", "reject")
    add("S03", "STRUCT", "magic_parcial", b"X39PARI", "reject")
    add("S04", "STRUCT", "solo_magic", MAGIC, "reject")
    add("S05", "STRUCT", "solo_header", cap[:HDR], "reject")
    add("S06", "STRUCT", "header_ctkem_parcial", cap[:OFF_CTKEM + 100], "reject")
    add("S07", "STRUCT", "magic_basura_4KB", MAGIC + bytes([3, 0]) + os.urandom(4090), "reject")
    add("S08", "STRUCT", "sin_ct_ni_tag", cap[:OFF_CT], "reject")
    # W: ventana temporal (política)
    add("W01", "TTL", "expirada", seal(pk, PT, ts=NOW - 7200), "reject", ttl=60)
    add("W02", "TTL", "futuro_mas_300s", seal(pk, PT, ts=NOW + 7200), "reject", ttl=60)
    add("W03", "TTL", "futuro_menos_300s", seal(pk, PT, ts=NOW + 200), "accept", ttl=60)
    add("W04", "TTL", "limite_exacto", seal(pk, PT, ts=NOW - 60), "accept", ttl=60)
    add("W05", "TTL", "limite_mas_1s", seal(pk, PT, ts=NOW - 61), "reject", ttl=60)
    # R: replay (estado) — mismo cid dos veces; el test Rust lo abre dos veces con el mismo registro
    fixed = os.urandom(16)
    add("R01", "REPLAY", "cid_repetido_a", seal(pk, PT, cid=fixed), "accept")
    add("R02", "REPLAY", "cid_repetido_b", seal(pk, PT, cid=fixed), "reject_si_R01_consumido")

    # --- autoverificación con la apertura de referencia ---
    fallos = 0
    for v in V:
        c, a = bytes.fromhex(v["capsule"]), bytes.fromhex(v["aad"])
        try:
            got = open_ref(sk, c, a, now=v["now"], ttl=v["ttl"])
            ok = v["expect"] in ("accept", "reject_si_R01_consumido")
            if v["id"].startswith("C") and v["name"] == "abre_base":
                ok = ok and got == PT
        except Reject as r:
            ok = v["expect"] == "reject"
            v["motivo_ref"] = str(r)
        if not ok:
            fallos += 1
            print(f"[FALLO] {v['id']} {v['name']} expect={v['expect']}")

    out = pathlib.Path(__file__).with_name("paris_v3.json")
    doc = dict(
        formato="x39-paris-v3", test_only=True, generador="gen_paris_v3.py", pqcrypto="1.0.0",
        now=NOW, plaintext_base=PT.hex(),
        recipient_pk=pk.hex(), recipient_sk=sk.hex(),
        vectores=V,
    )
    out.write_text(json.dumps(doc, indent=1))
    h = hashlib.sha256(out.read_bytes()).hexdigest()
    cats = {}
    for v in V: cats[v["cat"]] = cats.get(v["cat"], 0) + 1
    print(f"vectores: {len(V)}  por categoría: {cats}")
    print(f"autoverificación con apertura de referencia: {'OK' if not fallos else f'{fallos} FALLOS'}")
    print(f"archivo: {out}  sha256={h[:16]}…")
    raise SystemExit(1 if fallos else 0)

if __name__ == "__main__":
    main()
