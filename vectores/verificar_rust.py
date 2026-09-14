#!/usr/bin/env python3
"""Abre con la lógica de Paris v3 (Python) las cápsulas selladas por x39-core (Rust).

Requiere haber ejecutado antes `cargo test` en x39-core, que genera rust_sealed.json.
"""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from gen_paris_v3 import open_ref, Reject

doc = json.loads(pathlib.Path(__file__).with_name("rust_sealed.json").read_text())
sk = bytes.fromhex(doc["recipient_sk"])
fallos = 0
for i, c in enumerate(doc["capsulas"]):
    esperado = bytes.fromhex(c["pt"])
    try:
        pt = open_ref(sk, bytes.fromhex(c["capsule"]), bytes.fromhex(c["aad"]))
        ok = pt == esperado
        detalle = f"{len(pt)} B"
    except Reject as r:
        ok, detalle = False, f"rechazada: {r}"
    print(f"  cápsula Rust #{i}: {'OK' if ok else 'FALLO'} ({detalle})")
    fallos += not ok
print(f"Python abre lo que sella Rust: {'OK' if not fallos else f'{fallos} FALLOS'}")
sys.exit(1 if fallos else 0)
