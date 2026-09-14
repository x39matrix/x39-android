//! Firma del remitente con ML-DSA-87 (FIPS 204), misma implementación que el canister Joseph.
//!
//! ```text
//! cuerpo firmado  = 0x02 | firma(4627) | carga
//! mensaje firmado = SHA-256(clave ML-KEM del destinatario) || carga      contexto = "x39-msg-v1"
//! ```
//! El cuerpo firmado va dentro de la cápsula Paris v3, así que la firma también queda cifrada.
//! Incluir la clave del destinatario impide reenviar a un tercero un mensaje firmado para otro
//! y hacerlo pasar por dirigido a él. La clave secreta se guarda como semilla de 32 bytes.

use crate::{Error, PK_LEN};
use ml_dsa::{B32, EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa87, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const DSA_PK_LEN: usize = 2592;
pub const DSA_SEED_LEN: usize = 32;
pub const SIG_LEN: usize = 4627;
pub const SIGNED_TAG: u8 = 0x02;
pub const MSG_CTX: &[u8] = b"x39-msg-v1";
const OFF_PAYLOAD: usize = 1 + SIG_LEN;

pub fn generate_seed() -> Result<Zeroizing<[u8; DSA_SEED_LEN]>, Error> {
    Ok(Zeroizing::new(crate::random::<DSA_SEED_LEN>()?))
}

fn expanded(seed: &[u8; DSA_SEED_LEN]) -> ExpandedSigningKey<MlDsa87> {
    ExpandedSigningKey::from_seed(&B32::from(*seed))
}

pub fn public_key(seed: &[u8; DSA_SEED_LEN]) -> [u8; DSA_PK_LEN] {
    expanded(seed).verifying_key().encode().as_slice().try_into().expect("2592 bytes")
}

/// ML-DSA.Sign con aleatoriedad (variante «hedged» de FIPS 204):
/// Sign_internal(sk, 0 || len(ctx) || ctx || M, rnd).
fn sign_parts(seed: &[u8; DSA_SEED_LEN], parts: &[&[u8]], ctx: &[u8], rnd: &[u8; 32]) -> [u8; SIG_LEN] {
    let ctx_len = u8::try_from(ctx.len()).expect("contexto de 255 bytes como máximo");
    let prefix = [0u8, ctx_len];
    let mut mp: Vec<&[u8]> = vec![&prefix, ctx];
    mp.extend_from_slice(parts);
    let sig = expanded(seed).sign_internal(&mp, &B32::from(*rnd));
    sig.encode().as_slice().try_into().expect("4627 bytes")
}

pub fn sign(seed: &[u8; DSA_SEED_LEN], msg: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    if ctx.len() > 255 {
        return Err(Error::Length);
    }
    Ok(sign_parts(seed, &[msg], ctx, &crate::random::<32>()?))
}

/// ML-DSA.Verify con contexto. Cualquier firma mal formada devuelve `false`.
pub fn verify(public_key: &[u8; DSA_PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; SIG_LEN]>::try_from(sig) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&EncodedVerifyingKey::<MlDsa87>::from(*public_key));
    match Signature::<MlDsa87>::decode(&EncodedSignature::<MlDsa87>::from(sig)) {
        Some(s) => vk.verify_with_context(msg, ctx, &s),
        None => false,
    }
}

/// Firma `payload` para `recipient_pk` y devuelve el cuerpo `0x02 | firma | payload` que se sella.
pub fn sign_for(seed: &[u8; DSA_SEED_LEN], recipient_pk: &[u8; PK_LEN], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let digest = Sha256::digest(recipient_pk);
    let sig = sign_parts(seed, &[&digest, payload], MSG_CTX, &crate::random::<32>()?);
    let mut out = Zeroizing::new(Vec::with_capacity(OFF_PAYLOAD + payload.len()));
    out.push(SIGNED_TAG);
    out.extend_from_slice(&sig);
    out.extend_from_slice(payload);
    Ok(out)
}

/// ¿El cuerpo abierto lleva firma? Los mensajes de x39 0.2 empiezan por `{` y los de 0.1 son texto.
pub fn is_signed(body: &[u8]) -> bool {
    body.len() >= OFF_PAYLOAD && body[0] == SIGNED_TAG
}

/// Carga de un cuerpo firmado SIN verificar: solo para leer quién dice ser el remitente y buscar su clave.
pub fn unverified_payload(body: &[u8]) -> Option<&[u8]> {
    is_signed(body).then(|| &body[OFF_PAYLOAD..])
}

/// Verifica que `sender_pk` firmó el cuerpo para `my_kem_pk` y devuelve la carga.
pub fn verify_from<'a>(sender_pk: &[u8; DSA_PK_LEN], my_kem_pk: &[u8; PK_LEN], body: &'a [u8]) -> Result<&'a [u8], Error> {
    if !is_signed(body) {
        return Err(Error::Firma);
    }
    let payload = &body[OFF_PAYLOAD..];
    let mut msg = Zeroizing::new(Vec::with_capacity(32 + payload.len()));
    msg.extend_from_slice(&Sha256::digest(my_kem_pk));
    msg.extend_from_slice(payload);
    if verify(sender_pk, &msg, MSG_CTX, &body[1..OFF_PAYLOAD]) {
        Ok(payload)
    } else {
        Err(Error::Firma)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formato_fips204_coincide_con_la_libreria() {
        // Con rnd = 0 la variante hedged debe ser idéntica a la determinista de la librería:
        // demuestra que el prefijo 0 || len(ctx) || ctx se construye exactamente como FIPS 204.
        let seed = [7u8; DSA_SEED_LEN];
        let msg = b"x39 formato";
        let propia = sign_parts(&seed, &[&msg[..4], &msg[4..]], MSG_CTX, &[0u8; 32]);
        let libreria = expanded(&seed).sign_deterministic(msg, MSG_CTX).unwrap().encode();
        assert_eq!(propia.as_slice(), libreria.as_slice());
    }

    #[test]
    fn firma_y_verifica_con_contexto() {
        let seed = generate_seed().unwrap();
        let pk = public_key(&seed);
        let sig = sign(&seed, b"acta", b"ctx").unwrap();
        assert!(verify(&pk, b"acta", b"ctx", &sig));
        assert!(!verify(&pk, b"acta", b"otro", &sig), "contexto distinto");
        assert!(!verify(&pk, b"actA", b"ctx", &sig), "mensaje distinto");
        assert!(!verify(&pk, b"acta", b"ctx", &sig[..SIG_LEN - 1]), "firma truncada");
    }
}
