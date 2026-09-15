//! Salas (grupos por departamento): mensajes cifrados con una clave de sala, firmados por su autor y
//! encadenados por hash en el canister. Nada se borra: la sala es un registro por orden de llegada.
//!
//! ```text
//! clave de sala : 32 bytes AES-256-GCM, la crea el primer miembro y viaja a cada miembro dentro de una
//!                 cápsula X39MSG1 firmada (el «sobre»). Cambiar de época = clave nueva.
//! mensaje       : "X39SALA1:" + base64url(nonce(12) || AES-256-GCM(texto, aad = sala || 0x00 || época BE) || check)
//! firma         : "X39FIRMA1:" + base64url(firma ML-DSA-87(4627) || check), sobre
//!                 sala || 0x00 || época BE || acción UTF-8, contexto "x39-sala-v1"
//!                 acción = el texto X39SALA1 del mensaje, o "sobre:<para>:<sobre>", o "miembro:<dirección>"
//! eslabón       : SHA-256(anterior(32) || sala || 0x00 || seq BE || 0x00 || de || 0x00 || mensaje || 0x00 || firma)
//! ```
//! El canister comprueba la firma de cada publicación contra la clave de firma que ese remitente tiene en
//! el directorio (solo escribe quien está acreditado) y calcula el eslabón; cada móvil vuelve a comprobar
//! firma y cadena al leer. El canister ve sala, remitente, tamaño y hora; nunca el texto.

use crate::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};
use crate::{Error, share};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};
use sha2::{Digest, Sha256};

pub const PREFIX_MSG: &str = "X39SALA1:";
pub const PREFIX_FIRMA: &str = "X39FIRMA1:";
pub const SALA_CTX: &[u8] = b"x39-sala-v1";
pub const CLAVE_LEN: usize = 32;
const NONCE_LEN: usize = 12;
pub const MAX_SALA_ID: usize = 48;

/// Identificador de sala: minúsculas, dígitos y guiones («general», «los-remedios»).
pub fn sala_valida(sala: &str) -> bool {
    !sala.is_empty()
        && sala.len() <= MAX_SALA_ID
        && sala.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !sala.starts_with('-')
        && !sala.ends_with('-')
}

pub fn nueva_clave() -> Result<[u8; CLAVE_LEN], Error> {
    crate::random::<CLAVE_LEN>()
}

fn aad(sala: &str, epoca: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(sala.len() + 5);
    a.extend_from_slice(sala.as_bytes());
    a.push(0);
    a.extend_from_slice(&epoca.to_be_bytes());
    a
}

/// Cifra el texto de un mensaje para la sala. Devuelve el texto «X39SALA1:…».
pub fn cifrar(clave: &[u8; CLAVE_LEN], sala: &str, epoca: u32, texto: &[u8]) -> Result<String, Error> {
    if !sala_valida(sala) {
        return Err(Error::Formato);
    }
    let nonce = crate::random::<NONCE_LEN>()?;
    let cipher = Aes256Gcm::new(clave.into());
    let mut cuerpo = texto.to_vec();
    cipher.encrypt_in_place(&nonce.into(), &aad(sala, epoca), &mut cuerpo).map_err(|_| Error::Aead)?;
    let mut datos = Vec::with_capacity(NONCE_LEN + cuerpo.len());
    datos.extend_from_slice(&nonce);
    datos.extend_from_slice(&cuerpo);
    Ok(share::encode(PREFIX_MSG, &datos))
}

pub fn descifrar(clave: &[u8; CLAVE_LEN], sala: &str, epoca: u32, texto: &str) -> Result<Vec<u8>, Error> {
    let datos = share::decode(PREFIX_MSG, texto)?;
    if datos.len() < NONCE_LEN + 16 {
        return Err(Error::Length);
    }
    let (nonce, cuerpo) = datos.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("12 bytes");
    let cipher = Aes256Gcm::new(clave.into());
    let mut cuerpo = cuerpo.to_vec();
    cipher.decrypt_in_place(&nonce.into(), &aad(sala, epoca), &mut cuerpo).map_err(|_| Error::Aead)?;
    Ok(cuerpo)
}

fn firmado(sala: &str, epoca: u32, accion: &str) -> Vec<u8> {
    let mut m = aad(sala, epoca);
    m.extend_from_slice(accion.as_bytes());
    m
}

/// Firma una publicación (mensaje, sobre o alta de miembro) en la sala. Devuelve «X39FIRMA1:…».
pub fn firmar(seed: &[u8; DSA_SEED_LEN], sala: &str, epoca: u32, accion: &str) -> Result<String, Error> {
    if !sala_valida(sala) {
        return Err(Error::Formato);
    }
    let sig = firma::sign(seed, &firmado(sala, epoca, accion), SALA_CTX)?;
    Ok(share::encode(PREFIX_FIRMA, &sig))
}

/// Comprueba una publicación con la clave de firma del remitente. Error::Firma si no es suya.
pub fn verificar(pk: &[u8; DSA_PK_LEN], sala: &str, epoca: u32, accion: &str, firma_texto: &str) -> Result<(), Error> {
    if !sala_valida(sala) {
        return Err(Error::Formato);
    }
    let sig = share::decode(PREFIX_FIRMA, firma_texto)?;
    if sig.len() != SIG_LEN {
        return Err(Error::Formato);
    }
    if firma::verify(pk, &firmado(sala, epoca, accion), SALA_CTX, &sig) {
        Ok(())
    } else {
        Err(Error::Firma)
    }
}

/// Acción que firma quien entrega la clave de la sala a `para`.
pub fn accion_sobre(para: &str, sobre: &str) -> String {
    format!("sobre:{para}:{sobre}")
}

/// Acción que firma quien añade a `direccion` a la sala.
pub fn accion_miembro(direccion: &str) -> String {
    format!("miembro:{direccion}")
}

/// Eslabón de la cadena de una sala. `anterior` es todo ceros para el primer mensaje.
pub fn eslabon(anterior: &[u8; 32], sala: &str, seq: u64, de: &str, mensaje: &str, firma_texto: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(anterior);
    h.update(sala.as_bytes());
    h.update([0]);
    h.update(seq.to_be_bytes());
    h.update([0]);
    h.update(de.as_bytes());
    h.update([0]);
    h.update(mensaje.as_bytes());
    h.update([0]);
    h.update(firma_texto.as_bytes());
    h.finalize().into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn de_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, par) in s.as_bytes().chunks(2).enumerate() {
        let p = std::str::from_utf8(par).ok()?;
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}
