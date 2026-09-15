//! Directorio: cómo añadir a alguien con un código corto en vez de pegar su clave entera.
//!
//! ```text
//! código:  12 símbolos (base32 de Crockford, sin I/L/O/U) = primeros 60 bits de
//!          SHA-256("x39-codigo-v1" || clave ML-DSA-87). Se enseña como "XXXX-XXXX-XXXX".
//! entrada: "X39DIR1:" + base64url(kem(1568) || dsa(2592) || acreditación UTF-8 (0 o más) || firma(4627) || check)
//! firma:   ML-DSA-87 sobre kem || dsa || acreditación, contexto "x39-directorio-v1", con la semilla del titular.
//! ```
//! El titular publica su entrada en el buzón (canister/buzon, `POST /publicar`); quien conoce su código la
//! pide (`GET /buscar?codigo=`) y comprueba aquí que (1) la firma es de la clave que va dentro y (2) el código
//! sale de esa clave. Así el buzón no puede colar otra clave bajo un código ajeno: solo guarda lo que verifica,
//! y la app vuelve a comprobarlo. La acreditación (X39ACR1) se verifica aparte con la clave del Ayuntamiento.
//! Lo que el directorio sí revela: claves públicas y, si la hay, la acreditación (nombre y fecha) de quien
//! publica, a cualquiera que sepa su código o su dirección de buzón.

use crate::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};
use crate::invitacion::PREFIX_ACR;
use crate::{Error, PK_LEN, share};
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256};

pub const PREFIX_DIR: &str = "X39DIR1:";
pub const DIR_CTX: &[u8] = b"x39-directorio-v1";
const CODIGO_CTX: &[u8] = b"x39-codigo-v1";
/// Símbolos del código (sin separadores).
pub const CODIGO_LEN: usize = 12;
/// Tamaño máximo de la acreditación que se admite dentro de una entrada.
pub const MAX_ACREDITACION: usize = 20_000;
/// Base32 de Crockford: sin I, L, O ni U, para dictarlo por teléfono sin confusiones.
const ALFABETO: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    pub kem_pk: [u8; PK_LEN],
    pub dsa_pk: [u8; DSA_PK_LEN],
    /// «X39ACR1:…» tal como lo publicó el titular, o None. No se verifica aquí.
    pub acreditacion: Option<String>,
    /// Código canónico (12 símbolos, sin guiones) derivado de `dsa_pk`.
    pub codigo: String,
}

/// Código canónico de una clave de firma: 12 símbolos sin separadores.
pub fn codigo(dsa_pk: &[u8; DSA_PK_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(CODIGO_CTX);
    h.update(dsa_pk);
    let d = h.finalize();
    // 60 bits = 12 símbolos de 5 bits, leídos de los primeros 8 bytes.
    let n = u64::from_be_bytes(d[..8].try_into().expect("8 bytes"));
    (0..CODIGO_LEN)
        .map(|i| ALFABETO[((n >> (59 - 5 * i)) & 31) as usize] as char)
        .collect()
}

/// "XXXX-XXXX-XXXX" a partir del código canónico.
pub fn codigo_visible(canonico: &str) -> String {
    canonico
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

/// Pasa lo que tecleó una persona al código canónico: ignora espacios y guiones, admite minúsculas
/// y corrige las confusiones habituales (O→0, I y L→1). Error si no quedan exactamente 12 símbolos válidos.
pub fn normalizar_codigo(texto: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(CODIGO_LEN);
    for c in texto.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '\n' | '\r' | '\t' | '.' | '·' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALFABETO.contains(&(c as u8)) {
            return Err(Error::Formato);
        }
        out.push(c);
    }
    if out.len() != CODIGO_LEN {
        return Err(Error::Formato);
    }
    Ok(out)
}

/// Dirección de buzón de una clave ML-KEM: SHA-256 en hexadecimal (la app usa sus 16 primeros
/// caracteres como identificador de contacto).
pub fn direccion(kem_pk: &[u8; PK_LEN]) -> String {
    Sha256::digest(kem_pk).iter().map(|b| format!("{b:02x}")).collect()
}

fn acreditacion_compacta(acr: Option<&str>) -> Result<String, Error> {
    let Some(a) = acr else {
        return Ok(String::new());
    };
    let compacta: String = a.chars().filter(|c| !c.is_whitespace()).collect();
    if compacta.is_empty() {
        return Ok(compacta);
    }
    if !compacta.starts_with(PREFIX_ACR) || compacta.len() > MAX_ACREDITACION {
        return Err(Error::Formato);
    }
    Ok(compacta)
}

/// Entrada firmada por el titular para publicarla en el directorio.
pub fn publicar(seed: &[u8; DSA_SEED_LEN], kem_pk: &[u8; PK_LEN], acreditacion: Option<&str>) -> Result<String, Error> {
    let acr = acreditacion_compacta(acreditacion)?;
    let dsa_pk = firma::public_key(seed);
    let mut datos = Vec::with_capacity(PK_LEN + DSA_PK_LEN + acr.len() + SIG_LEN);
    datos.extend_from_slice(kem_pk);
    datos.extend_from_slice(&dsa_pk);
    datos.extend_from_slice(acr.as_bytes());
    let sig = firma::sign(seed, &datos, DIR_CTX)?;
    datos.extend_from_slice(&sig);
    Ok(share::encode(PREFIX_DIR, &datos))
}

/// Lee y verifica una entrada del directorio. Error::Firma si la firma no es de la clave que lleva dentro.
pub fn leer(texto: &str) -> Result<Entrada, Error> {
    let datos = share::decode(PREFIX_DIR, texto)?;
    if datos.len() < PK_LEN + DSA_PK_LEN + SIG_LEN {
        return Err(Error::Formato);
    }
    let (firmado, sig) = datos.split_at(datos.len() - SIG_LEN);
    let kem_pk: [u8; PK_LEN] = firmado[..PK_LEN].try_into().expect("1568 bytes");
    let dsa_pk: [u8; DSA_PK_LEN] = firmado[PK_LEN..PK_LEN + DSA_PK_LEN].try_into().expect("2592 bytes");
    if !mlkem1024::validate_public_key(&mlkem1024::MlKem1024PublicKey::from(&kem_pk)) {
        return Err(Error::InvalidKey);
    }
    let acr = std::str::from_utf8(&firmado[PK_LEN + DSA_PK_LEN..]).map_err(|_| Error::Formato)?;
    let acr = acreditacion_compacta(Some(acr))?;
    if acr.len() != firmado.len() - PK_LEN - DSA_PK_LEN {
        // La acreditación firmada tiene que ser exactamente la que va en la entrada (sin espacios).
        return Err(Error::Formato);
    }
    if !firma::verify(&dsa_pk, firmado, DIR_CTX, sig) {
        return Err(Error::Firma);
    }
    Ok(Entrada {
        kem_pk,
        dsa_pk,
        acreditacion: if acr.is_empty() { None } else { Some(acr) },
        codigo: codigo(&dsa_pk),
    })
}

/// Comprueba que una entrada corresponde al código que tecleó la persona (canónico) y la devuelve.
pub fn leer_para_codigo(texto: &str, codigo_canonico: &str) -> Result<Entrada, Error> {
    let e = leer(texto)?;
    if e.codigo != codigo_canonico {
        return Err(Error::Firma);
    }
    Ok(e)
}
