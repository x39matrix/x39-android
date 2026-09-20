//! call_key — X39-CALL-KEY-v1: acuerdo de clave post-cuántico para las llamadas.
//!
//! Produce los 32 bytes de la clave de fotograma que se entregan a LiveKit
//! (setSharedKey). Reproduce **byte a byte** la referencia `x39_call_key.py` en lo
//! que de verdad importa: la clave. Los dos extremos aportan (ML-KEM-1024), la
//! oferta la firma la identidad (ML-DSA-87), y la clave sale por HKDF-SHA256 atada
//! a la llamada, la época y la transcripción (las dos claves efímeras).
//!
//! Nota honesta: la referencia añade una co-firma **Ed25519** anclada en la
//! vinculación. Es una defensa **adicional** de autenticación y **no entra en los
//! 32 bytes**; este motor aún no tiene Ed25519, así que aquí la oferta se firma con
//! ML-DSA-87. La co-firma Ed25519 se añade al cablear el binding, sin cambiar la clave.

use crate::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};
use crate::{CT_KEM_LEN, Error, PK_LEN, SK_LEN};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const VERSION_OFERTA: &str = "X39-CALL-KEYOFFER-v1";
pub const KEY_INFO: &str = "X39-CALL-KEY-v1";
pub const SAS_INFO: &str = "X39-CALL-SAS-v1";
/// Contexto de dominio para la firma ML-DSA de la oferta (separa de otros usos de la clave).
pub const CALL_CTX: &[u8] = b"x39-call-v1";
pub const CLAVE_LEN: usize = 32;

/// Lista SAS: pública y fija. Muestra corta como en la referencia; en producción,
/// una lista cerrada de 256 palabras sin homófonos.
const SAS_PALABRAS: &[&str] = &[
    "lago", "cobre", "vela", "matriz", "nido", "ambar", "sauce", "hierro", "faro", "musgo",
    "bruma", "cedro", "ancla", "trigo", "perla", "yunque", "roble", "duna", "cresta", "liquen",
    "brasa", "junco", "marfil", "ocaso", "pina", "rombo", "tejo", "urna", "vid", "zafiro",
    "noria", "quilla",
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex(&h.finalize())
}

/// base64 estándar sin relleno (como `_b64` de la referencia). Solo para la cadena
/// de oferta que se firma; no interviene en la clave.
const B64STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn b64_std_nopad(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(B64STD[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// La cadena canónica de una oferta (una sola línea, lo que se firma).
pub fn cadena_oferta(call_hash: &str, from_bh: &str, epoch: u32, ek: &[u8], ts: &str) -> String {
    format!(
        "{VERSION_OFERTA}|call_hash={call_hash}|from={from_bh}|epoch={epoch}|ek={}|ts={ts}",
        b64_std_nopad(ek)
    )
}

/// Deriva los 32 bytes de la clave de fotograma. Orden canónico por binding_hash
/// (hex, lexicográfico): los dos extremos llegan al mismo resultado sin importar
/// quién llamó primero. El `info` ata la clave a `call_hash`, la época y la
/// transcripción (las dos `ek`), de modo que sustituir una `ek` cambia la clave y el
/// SAS lo delata. Se falla cerrado: sin las dos partes no hay clave.
pub fn derivar_material(
    bh_a: &str,
    bh_b: &str,
    ek_a: &[u8],
    ek_b: &[u8],
    ss_a: &[u8; 32],
    ss_b: &[u8; 32],
    call_hash: &str,
    call_salt: &[u8; 32],
    epoch: u32,
) -> Zeroizing<[u8; CLAVE_LEN]> {
    let (lo_ss, hi_ss, lo_ek, hi_ek): (&[u8; 32], &[u8; 32], &[u8], &[u8]) = if bh_a < bh_b {
        (ss_a, ss_b, ek_a, ek_b)
    } else {
        (ss_b, ss_a, ek_b, ek_a)
    };
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(lo_ss);
    ikm[32..].copy_from_slice(hi_ss);
    let transcript = sha256_hex(&[lo_ek, hi_ek]); // 64 caracteres hex
    let info = format!("{KEY_INFO}|{call_hash}|epoch={epoch}|{transcript}");
    let mut key = Zeroizing::new([0u8; CLAVE_LEN]);
    Hkdf::<Sha256>::new(Some(call_salt.as_slice()), ikm.as_ref())
        .expand(info.as_bytes(), key.as_mut())
        .expect("32 bytes está dentro del límite de HKDF");
    key
}

/// Las seis palabras que los dos comparan por un canal aparte. Misma clave → mismas
/// palabras; clave de intermediario → distintas.
pub fn sas(clave: &[u8; CLAVE_LEN], call_hash: &str) -> Vec<&'static str> {
    let mut raw = [0u8; 6];
    Hkdf::<Sha256>::new(Some(call_hash.as_bytes()), clave.as_slice())
        .expand(SAS_INFO.as_bytes(), &mut raw)
        .expect("6 bytes");
    raw.iter()
        .map(|&b| SAS_PALABRAS[b as usize % SAS_PALABRAS.len()])
        .collect()
}

/// Una oferta firmada de un extremo para ESTA llamada.
pub struct Oferta {
    pub canonical: String,
    pub ek: [u8; PK_LEN],
    pub sig_mldsa: [u8; SIG_LEN],
    pub from_bh: String,
}

/// Genera par efímero ML-KEM para esta llamada, construye la oferta y la firma con
/// ML-DSA-87. Devuelve `(Oferta, clave secreta efímera)`. La secreta NUNCA sale del aparato.
pub fn hacer_oferta(
    call_hash: &str,
    epoch: u32,
    from_bh: &str,
    mldsa_seed: &[u8; DSA_SEED_LEN],
    ts: &str,
) -> Result<(Oferta, Zeroizing<[u8; SK_LEN]>), Error> {
    let seed = Zeroizing::new(crate::random::<64>()?);
    let kp = mlkem1024::generate_key_pair(*seed);
    let ek: [u8; PK_LEN] = *kp.public_key().as_slice();
    let dk = Zeroizing::new(*kp.private_key().as_slice());
    let canonical = cadena_oferta(call_hash, from_bh, epoch, &ek, ts);
    let sig = firma::sign(mldsa_seed, canonical.as_bytes(), CALL_CTX)?;
    Ok((
        Oferta {
            canonical,
            ek,
            sig_mldsa: sig,
            from_bh: from_bh.to_string(),
        },
        dk,
    ))
}

/// Verifica una oferta recibida contra la identidad YA verificada del emisor.
/// Rechaza si la cadena no cuadra con lo declarado (atadura a esta llamada/época/emisor)
/// o si la firma ML-DSA-87 no es válida.
pub fn verificar_oferta(
    of: &Oferta,
    call_hash: &str,
    epoch: u32,
    emisor_bh: &str,
    emisor_mldsa_pk: &[u8; DSA_PK_LEN],
) -> Result<(), Error> {
    let ts = of.canonical.rsplit("|ts=").next().unwrap_or("");
    let esperada = cadena_oferta(call_hash, emisor_bh, epoch, &of.ek, ts);
    if of.canonical != esperada || of.from_bh != emisor_bh {
        return Err(Error::Formato);
    }
    if firma::verify(emisor_mldsa_pk, of.canonical.as_bytes(), CALL_CTX, &of.sig_mldsa) {
        Ok(())
    } else {
        Err(Error::Firma)
    }
}

/// Encapsula contra la clave efímera del otro. Devuelve `(criptograma, secreto)`.
pub fn encapsular(ek: &[u8; PK_LEN]) -> Result<([u8; CT_KEM_LEN], Zeroizing<[u8; 32]>), Error> {
    let pk = mlkem1024::MlKem1024PublicKey::from(ek);
    if !mlkem1024::validate_public_key(&pk) {
        return Err(Error::InvalidKey);
    }
    let (ct, ss) = mlkem1024::encapsulate(&pk, crate::random::<32>()?);
    Ok((*ct.as_slice(), Zeroizing::new(ss)))
}

/// Desencapsula el criptograma que nos llegó con nuestra clave secreta efímera.
pub fn desencapsular(dk: &[u8; SK_LEN], ct: &[u8; CT_KEM_LEN]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let sk = mlkem1024::MlKem1024PrivateKey::from(dk);
    let ct = mlkem1024::MlKem1024Ciphertext::try_from(ct.as_slice()).map_err(|_| Error::Length)?;
    Ok(Zeroizing::new(mlkem1024::decapsulate(&sk, &ct)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector byte a byte contra la referencia x39_call_key.py (misma entrada fija).
    #[test]
    fn vector_derivacion_byte_a_byte() {
        let bh_a = "11".repeat(32);
        let bh_b = "22".repeat(32);
        let ss_a = [1u8; 32];
        let ss_b = [2u8; 32];
        let ek_a = [0xAAu8; PK_LEN];
        let ek_b = [0xBBu8; PK_LEN];
        let call_hash = "cc".repeat(32);
        let call_salt = [0x5Au8; 32];
        let key = derivar_material(
            &bh_a, &bh_b, &ek_a, &ek_b, &ss_a, &ss_b, &call_hash, &call_salt, 0,
        );
        assert_eq!(
            hex(key.as_ref()),
            "4047eebb358831d0d5cbaffb186ed21195ae43d864b6dd24805c6223cd5d3f2a"
        );
    }

    /// El orden canónico es por binding_hash: invertir los papeles da la MISMA clave.
    #[test]
    fn orden_canonico_simetrico() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let sa = [7u8; 32];
        let sb = [9u8; 32];
        let ea = [0x01u8; PK_LEN];
        let eb = [0x02u8; PK_LEN];
        let ch = "cc".repeat(32);
        let salt = [3u8; 32];
        let k1 = derivar_material(&a, &b, &ea, &eb, &sa, &sb, &ch, &salt, 0);
        let k2 = derivar_material(&b, &a, &eb, &ea, &sb, &sa, &ch, &salt, 0);
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    /// Acuerdo 1:1 real: keygen efímero + encaps cruzado + derivación en los dos extremos.
    #[test]
    fn acuerdo_1a1_misma_clave() {
        let seed_a = firma::generate_seed().unwrap();
        let seed_b = firma::generate_seed().unwrap();
        let bh_a = "1a".repeat(32);
        let bh_b = "2b".repeat(32);
        let ch = "cc".repeat(32);
        let salt = [0x5Au8; 32];
        let ts = "2026-09-19T12:00:00Z";

        let (of_a, dk_a) = hacer_oferta(&ch, 0, &bh_a, &seed_a, ts).unwrap();
        let (of_b, dk_b) = hacer_oferta(&ch, 0, &bh_b, &seed_b, ts).unwrap();

        // Cada uno verifica la oferta del otro contra su identidad.
        let pk_a = firma::public_key(&seed_a);
        let pk_b = firma::public_key(&seed_b);
        verificar_oferta(&of_b, &ch, 0, &bh_b, &pk_b).unwrap();
        verificar_oferta(&of_a, &ch, 0, &bh_a, &pk_a).unwrap();

        // Encapsulación cruzada.
        let (ct_a, ss_a) = encapsular(&of_b.ek).unwrap(); // A → ek de B
        let (ct_b, ss_b) = encapsular(&of_a.ek).unwrap(); // B → ek de A

        // A deriva: su ss_a + desencapsular ct_b con dk_a → ss_b.
        let ss_b_en_a = desencapsular(&dk_a, &ct_b).unwrap();
        let key_a = derivar_material(
            &bh_a, &bh_b, &of_a.ek, &of_b.ek, &ss_a, &ss_b_en_a, &ch, &salt, 0,
        );
        // B deriva: su ss_b + desencapsular ct_a con dk_b → ss_a.
        let ss_a_en_b = desencapsular(&dk_b, &ct_a).unwrap();
        let key_b = derivar_material(
            &bh_a, &bh_b, &of_a.ek, &of_b.ek, &ss_a_en_b, &ss_b, &ch, &salt, 0,
        );

        assert_eq!(key_a.as_ref(), key_b.as_ref(), "las dos claves deben coincidir");
        // Y el SAS coincide.
        assert_eq!(sas(&key_a, &ch), sas(&key_b, &ch));
    }

    /// Una oferta con un byte cambiado tras firmar se rechaza.
    #[test]
    fn oferta_alterada_rechazada() {
        let seed = firma::generate_seed().unwrap();
        let pk = firma::public_key(&seed);
        let bh = "3c".repeat(32);
        let ch = "cc".repeat(32);
        let (mut of, _dk) = hacer_oferta(&ch, 0, &bh, &seed, "2026-09-19T12:00:00Z").unwrap();
        of.ek[0] ^= 0x01; // manipular la clave efímera tras firmar
        assert!(verificar_oferta(&of, &ch, 0, &bh, &pk).is_err());
    }
}
