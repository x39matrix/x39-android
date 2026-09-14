#!/bin/bash
# Patas Solana y Arbitrum del sello dorado. Solo lectura, RPC públicos.
H=08e9db781dc79c9fbbe77a56cd0120d2830650d4bcf52a2dae9acb73091d449c
N=/home/x39matrix/home_viejo/x39matrix-web/notary
SOL_TX=57eF2upphvaWuRaD2PdEeL5vZ7hqivJTJ6pYvxwXRh9GzbQFWJV5JKfb2n7jh1sigvfxNcaiH7xuUUanYQGYsh5a
ARB_TX=0x16dfaecd7c9616f24a598c6a23084163e53834c44766601d6926a8fb65e2ad8b
rpc() { curl -fsS "$1" -X POST -H 'Content-Type: application/json' -d "$2"; }

echo "### 0. Huella del documento"
echo "  sha256 MASTER_GOLDEN_SEAL.txt = $(sha256sum "$N/MASTER_GOLDEN_SEAL.txt" | cut -c1-64)"
echo "  esperada                      = $H"

echo; echo "### 1. Solana"
rpc https://api.mainnet-beta.solana.com "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$SOL_TX\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":0,\"commitment\":\"finalized\"}]}" > /tmp/sol.json
rpc https://api.mainnet-beta.solana.com "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignatureStatuses\",\"params\":[[\"$SOL_TX\"],{\"searchTransactionHistory\":true}]}" > /tmp/solst.json
python3 - "$H" <<'PY'
import json,sys,datetime
h=sys.argv[1]
t=json.load(open('/tmp/sol.json'))['result']
st=json.load(open('/tmp/solst.json'))['result']['value'][0]
memo=[i['parsed'] for i in t['transaction']['message']['instructions'] if i.get('program')=='spl-memo'][0]
print('  slot', t['slot'], '·', datetime.datetime.fromtimestamp(t['blockTime'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
print('  error:', t['meta']['err'], '· confirmación:', st['confirmationStatus'])
print('  firmante:', [k['pubkey'] for k in t['transaction']['message']['accountKeys'] if k['signer']])
print('  memo contiene la huella:', memo=='X39_OMEGA_SEAL:'+h)
PY

echo; echo "### 2. Arbitrum One"
rpc https://arb1.arbitrum.io/rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionByHash\",\"params\":[\"$ARB_TX\"]}" > /tmp/arb.json
rpc https://arb1.arbitrum.io/rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$ARB_TX\"]}" > /tmp/arbr.json
BN=$(python3 -c "import json;print(json.load(open('/tmp/arb.json'))['result']['blockNumber'])")
rpc https://arb1.arbitrum.io/rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$BN\",false]}" > /tmp/arbb.json
python3 - "$H" <<'PY'
import json,sys,datetime
h=sys.argv[1]
t=json.load(open('/tmp/arb.json'))['result']; r=json.load(open('/tmp/arbr.json'))['result']; b=json.load(open('/tmp/arbb.json'))['result']
print('  bloque', int(t['blockNumber'],16), '·', datetime.datetime.fromtimestamp(int(b['timestamp'],16),datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), '· chainId', int(t['chainId'],16))
print('  estado recibo:', r['status'], '(0x1 = éxito)')
data=bytes.fromhex(t['input'][2:])
print('  input =', data[:14], '+', data[14:].hex()[:16]+'…')
print('  input contiene la huella:', data==b'X39_OMEGA_SEAL'+bytes.fromhex(h))
print('  from:', t['from'])
PY

echo; echo "### 3. ¿Las direcciones salen de la clave tECDSA del HUB?"
python3 - <<'PY'
# keccak-256 puro (sin dependencias) para derivar la dirección Ethereum de la clave del HUB
R=[1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
rol=lambda x,n:((x<<n)|(x>>(64-n)))&M if n else x
def f(A):
    for rc in R:
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
        A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0]^=rc
    return A
def keccak(m):
    m=bytearray(m)+b'\x01'; m+=b'\x00'*((-len(m))%136); m[-1]|=0x80
    A=[[0]*5 for _ in range(5)]
    for i in range(0,len(m),136):
        for j in range(17): A[j%5][j//5]^=int.from_bytes(m[i+8*j:i+8*j+8],'little')
        A=f(A)
    return b''.join(A[j%5][j//5].to_bytes(8,'little') for j in range(4))
assert keccak(b'').hex().startswith('c5d2460186f7233c')
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
pub=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),bytes.fromhex('025968e3eea2adc6a3c7e0b24c39f3e94009393e57280cb9ccc3801251bb202083'))
raw=pub.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
print('  dirección EVM de la clave HUB 025968e3…:', '0x'+keccak(raw)[-20:].hex())
print('  firmante Arbitrum                      : 0x1f4f2e84b7af1046539a6c2946981f1776493813')
PY
echo "--- métodos del HUB relacionados con Solana/EVM/Schnorr:"
/home/x39matrix/.local/share/dfx/bin/dfx canister metadata arn4r-lqaaa-aaaao-baxwq-cai candid:service --network ic 2>/dev/null | grep -iE "sol|evm|eth|arb|schnorr|ed25519" | head -20
