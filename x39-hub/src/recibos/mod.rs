//! Tipos y reglas comunes de los recibos firmados.
mod cobro;
mod custodia;
mod entrega;
mod rotacion;
pub use cobro::{RedCobro, SolicitudCobroBtc};
pub use custodia::{Previo, ReciboCustodia};
pub use entrega::{ClaseAdjunto, ReciboEntregaAdjunto, ResultadoEntrega};
pub use rotacion::{DeclaracionRotacionClave, IdentidadNueva};

use crate::{ErrorHub, a_hex, de_hex_exacto};
use sha2::{Digest, Sha256};
use std::fmt;
use x39_core::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};

pub type Hash32 = [u8; 32];
pub type SemillaDsa = [u8; DSA_SEED_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HuellaDsa(Hash32);

impl HuellaDsa {
    pub fn de_clave(clave: &[u8; DSA_PK_LEN]) -> Self {
        Self(Sha256::digest(clave).into())
    }

    pub fn de_hex(texto: &str) -> Result<Self, ErrorHub> {
        Ok(Self(hex_fijo(texto)?))
    }
}

impl fmt::Display for HuellaDsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&a_hex(&self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    pub fn de_hex(texto: &str) -> Result<Self, ErrorHub> {
        Ok(Self(hex_variable(texto, 8)?))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nonce(String);

impl Nonce {
    pub fn de_hex(texto: &str) -> Result<Self, ErrorHub> {
        Ok(Self(hex_variable(texto, 16)?))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

/// Vista aportada por la aplicación para el contacto y el tipo de operación en curso.
pub trait NoncesBloqueados {
    fn contiene(&self, nonce: &Nonce) -> bool;
}

fn es_hex_minusculo(texto: &str) -> bool {
    texto.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex_variable(texto: &str, minimo_bytes: usize) -> Result<String, ErrorHub> {
    if !(2 * minimo_bytes..=64).contains(&texto.len())
        || texto.len() % 2 != 0
        || !es_hex_minusculo(texto)
    {
        return Err(ErrorHub::Formato);
    }
    Ok(texto.to_owned())
}

fn hex_fijo<const N: usize>(texto: &str) -> Result<[u8; N], ErrorHub> {
    if texto.len() != 2 * N || !es_hex_minusculo(texto) {
        return Err(ErrorHub::Formato);
    }
    de_hex_exacto(texto)
}

fn entero_positivo(texto: &str) -> Result<u64, ErrorHub> {
    if !matches!(texto.as_bytes().first(), Some(b'1'..=b'9'))
        || !texto.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ErrorHub::Formato);
    }
    texto.parse().map_err(|_| ErrorHub::Formato)
}

fn campos<const N: usize>(entrada: &[u8]) -> Result<[&str; N], ErrorHub> {
    let texto = std::str::from_utf8(entrada).map_err(|_| ErrorHub::Formato)?;
    let mut partes = texto.split('|');
    let mut campos = [""; N];
    for campo in &mut campos {
        *campo = partes.next().ok_or(ErrorHub::Formato)?;
        if campo.is_empty() || !campo.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ErrorHub::Formato);
        }
    }
    if partes.next().is_some() {
        return Err(ErrorHub::Formato);
    }
    Ok(campos)
}

fn firmar_mensaje(
    semilla: &SemillaDsa,
    mensaje: &str,
    contexto: &[u8],
) -> Result<[u8; SIG_LEN], ErrorHub> {
    firma::sign(semilla, mensaje.as_bytes(), contexto).map_err(|error| match error {
        x39_core::Error::Rng => ErrorHub::Rng,
        _ => ErrorHub::Firma,
    })
}

fn verificar_mensaje(
    esperada: &HuellaDsa,
    declarada: &HuellaDsa,
    clave: &[u8; DSA_PK_LEN],
    mensaje: &str,
    contexto: &[u8],
    firma: &[u8; SIG_LEN],
) -> Result<(), ErrorHub> {
    if esperada != declarada || HuellaDsa::de_clave(clave) != *esperada {
        return Err(ErrorHub::HuellaNoCoincide);
    }
    if !firma::verify(clave, mensaje.as_bytes(), contexto, firma) {
        return Err(ErrorHub::Firma);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limites_de_identificador_nonce_y_decimal() {
        for n in [16, 64] {
            let s = "0".repeat(n);
            assert_eq!(Id::de_hex(&s).unwrap().como_str(), s);
        }
        for n in [0, 14, 17, 66] {
            assert_eq!(Id::de_hex(&"0".repeat(n)), Err(ErrorHub::Formato));
        }
        for n in [32, 64] {
            let s = "0".repeat(n);
            assert_eq!(Nonce::de_hex(&s).unwrap().como_str(), s);
        }
        for n in [30, 33, 66] {
            assert_eq!(Nonce::de_hex(&"0".repeat(n)), Err(ErrorHub::Formato));
        }
        assert_eq!(Nonce::de_hex(&"AB".repeat(16)), Err(ErrorHub::Formato));
        assert_eq!(entero_positivo("18446744073709551615"), Ok(u64::MAX));
        for s in ["", "0", "01", "+1", "-1", "1 ", "18446744073709551616"] {
            assert_eq!(entero_positivo(s), Err(ErrorHub::Formato));
        }
    }
}
