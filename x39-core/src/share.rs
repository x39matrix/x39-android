//! Formatos de texto para compartir claves públicas y cápsulas por QR, copiar/pegar o cualquier chat.
//!
//! ```text
//! clave pública: "X39PK1:"  + base64url(pk      || check)
//! mensaje:       "X39MSG1:" + base64url(cápsula || check)
//! check = SHA-256(prefijo || datos)[..4]   (detecta errores de copia; NO es seguridad)
//! ```
//! La seguridad la da la criptografía de la cápsula; el check solo evita pegar algo corrupto.

use crate::{Error, MIN_LEN, PK_LEN};
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256, Sha512};

pub const PREFIX_PK: &str = "X39PK1:";
pub const PREFIX_MSG: &str = "X39MSG1:";
/// Capacidad máxima de un QR versión 40 con corrección de errores L en modo byte.
pub const QR_MAX_BYTES: usize = 2953;
const CHECK_LEN: usize = 4;
const FINGERPRINT_CTX: &[u8] = b"x39-fingerprint-v1";

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn b64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a' + 26) as u32),
        b'0'..=b'9' => Some((b - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodificación estricta: rechaza caracteres ajenos, longitudes imposibles y bits sobrantes no nulos.
fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= b64_value(b)? << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        for i in 0..bytes {
            out.push((n >> (16 - 8 * i)) as u8);
        }
        let extra_bits = 6 * chunk.len() - 8 * bytes;
        if extra_bits > 0 && (n >> (24 - 6 * chunk.len())) & ((1 << extra_bits) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

fn checksum(prefix: &str, data: &[u8]) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(prefix.as_bytes());
    h.update(data);
    h.finalize()[..CHECK_LEN].try_into().expect("4 bytes")
}

fn encode(prefix: &str, data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(data.len() + CHECK_LEN);
    payload.extend_from_slice(data);
    payload.extend_from_slice(&checksum(prefix, data));
    format!("{prefix}{}", b64_encode(&payload))
}

fn decode(prefix: &str, text: &str) -> Result<Vec<u8>, Error> {
    // Los chats y el correo suelen partir líneas o añadir espacios: se ignoran.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix(prefix).ok_or(Error::Formato)?;
    let mut payload = b64_decode(body.as_bytes()).ok_or(Error::Formato)?;
    if payload.len() < CHECK_LEN {
        return Err(Error::Formato);
    }
    let check = payload.split_off(payload.len() - CHECK_LEN);
    if check != checksum(prefix, &payload) {
        return Err(Error::Formato);
    }
    Ok(payload)
}

/// Longitud en caracteres del texto que produce `encode` para `n` bytes de datos.
pub fn encoded_len(prefix: &str, n: usize) -> usize {
    prefix.len() + ((n + CHECK_LEN) * 4).div_ceil(3)
}

pub fn encode_public_key(pk: &[u8; PK_LEN]) -> String {
    encode(PREFIX_PK, pk)
}

pub fn decode_public_key(text: &str) -> Result<[u8; PK_LEN], Error> {
    let data = decode(PREFIX_PK, text)?;
    let pk: [u8; PK_LEN] = data.try_into().map_err(|_| Error::Formato)?;
    if !mlkem1024::validate_public_key(&mlkem1024::MlKem1024PublicKey::from(&pk)) {
        return Err(Error::InvalidKey);
    }
    Ok(pk)
}

pub fn encode_capsule(capsule: &[u8]) -> String {
    encode(PREFIX_MSG, capsule)
}

pub fn decode_capsule(text: &str) -> Result<Vec<u8>, Error> {
    let data = decode(PREFIX_MSG, text)?;
    if data.len() < MIN_LEN {
        return Err(Error::Formato);
    }
    Ok(data)
}

/// Bytes máximos de texto que caben en un único QR como mensaje `X39MSG1:`.
pub fn max_plaintext_for_qr() -> usize {
    let mut pt = 0;
    while encoded_len(PREFIX_MSG, MIN_LEN + pt + 1) <= QR_MAX_BYTES {
        pt += 1;
    }
    pt
}

/// Huella de seguridad de una clave pública: 12 grupos de 5 dígitos, estilo número de seguridad de Signal.
/// Dos personas la comparan en persona o por llamada para descartar un intermediario.
pub fn fingerprint(pk: &[u8; PK_LEN]) -> String {
    let mut h = Sha512::new();
    h.update(FINGERPRINT_CTX);
    h.update(pk);
    let digest = h.finalize();
    digest
        .chunks(5)
        .take(12)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_ida_y_vuelta_y_estricto() {
        for n in 0..40 {
            let data: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64_decode(b64_encode(&data).as_bytes()).unwrap(), data);
        }
        assert!(b64_decode(b"A").is_none(), "longitud imposible");
        assert!(b64_decode(b"AB=C").is_none(), "carácter ajeno");
        assert!(b64_decode(b"AB").is_none(), "bits sobrantes no nulos");
        assert_eq!(b64_decode(b"AA").unwrap(), vec![0]);
    }
}
