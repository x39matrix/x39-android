#!/usr/bin/env python3
"""¿Qué devuelve verify() en pqcrypto 1.0.0? Claves efímeras."""
import inspect
import pqcrypto.sign.ml_dsa_87 as d

print("sign  ", inspect.signature(d.sign))
print("verify", inspect.signature(d.verify))
a, b = (bytes(x) for x in d.keygen())
pk, sk = (a, b) if len(a) == d.PUBLIC_KEY_SIZE else (b, a)
msg = b"hola"
sig = bytes(d.sign(sk, msg))
print("verify(firma válida)     ->", repr(d.verify(pk, msg, sig)))
bad = bytearray(sig)
bad[0] ^= 1
try:
    print("verify(firma manipulada) ->", repr(d.verify(pk, msg, bytes(bad))))
except Exception as e:
    print("verify(firma manipulada) LANZA", type(e).__name__, e)
try:
    print("verify(mensaje distinto) ->", repr(d.verify(pk, b"adios", sig)))
except Exception as e:
    print("verify(mensaje distinto) LANZA", type(e).__name__, e)
