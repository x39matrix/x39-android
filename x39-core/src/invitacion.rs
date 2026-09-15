//! Invitación firmada por la autoridad (el Ayuntamiento) para activar el modo personal de la app.
//!
//! ```text
//! texto: "X39INV1:" + base64url(firma(4627) || carga || check)      (mismo formato que share.rs)
//! carga: "X39-INV-v1|AAAA-MM-DD|nombre o cargo"                       (UTF-8)
//! firma: ML-DSA-87 sobre la carga, contexto "x39-invitacion-v1", con la semilla de la autoridad.
//! ```
//! La app lleva dentro la clave pública de la autoridad y solo crea la identidad del personal si la
//! invitación verifica y no ha caducado. Sin servidor: la invitación se manda por cualquier canal.
//! Lo que NO hace: revocar (una invitación vale hasta su fecha) ni atar la invitación a un móvil concreto.

use crate::Error;
use crate::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};
use crate::share;

pub const PREFIX_INV: &str = "X39INV1:";
pub const INV_CTX: &[u8] = b"x39-invitacion-v1";
pub const MAX_NOMBRE: usize = 80;
const CARGA_PREFIJO: &str = "X39-INV-v1|";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitacion {
    /// Último día de validez, AAAA-MM-DD.
    pub caduca: String,
    /// Persona o cargo para quien se emitió. Solo informativo: no se comprueba contra nada.
    pub nombre: String,
}

/// Emite una invitación válida hasta `caduca` (AAAA-MM-DD, inclusive) para `nombre`.
pub fn emitir(seed: &[u8; DSA_SEED_LEN], caduca: &str, nombre: &str) -> Result<String, Error> {
    validar_fecha(caduca)?;
    validar_nombre(nombre)?;
    let carga = format!("{CARGA_PREFIJO}{caduca}|{nombre}");
    let sig = firma::sign(seed, carga.as_bytes(), INV_CTX)?;
    let mut datos = Vec::with_capacity(SIG_LEN + carga.len());
    datos.extend_from_slice(&sig);
    datos.extend_from_slice(carga.as_bytes());
    Ok(share::encode(PREFIX_INV, &datos))
}

/// Verifica `texto` con la clave pública de la autoridad. `hoy` es AAAA-MM-DD según el reloj del móvil.
pub fn verificar(pk: &[u8; DSA_PK_LEN], texto: &str, hoy: &str) -> Result<Invitacion, Error> {
    validar_fecha(hoy)?;
    let datos = share::decode(PREFIX_INV, texto)?;
    if datos.len() <= SIG_LEN {
        return Err(Error::Formato);
    }
    let (sig, carga) = datos.split_at(SIG_LEN);
    if !firma::verify(pk, carga, INV_CTX, sig) {
        return Err(Error::Firma);
    }
    let carga = std::str::from_utf8(carga).map_err(|_| Error::Formato)?;
    let resto = carga.strip_prefix(CARGA_PREFIJO).ok_or(Error::Formato)?;
    let (caduca, nombre) = resto.split_once('|').ok_or(Error::Formato)?;
    validar_fecha(caduca)?;
    validar_nombre(nombre)?;
    // Fechas ISO: el orden alfabético coincide con el cronológico.
    if hoy > caduca {
        return Err(Error::Caducada);
    }
    Ok(Invitacion { caduca: caduca.to_string(), nombre: nombre.to_string() })
}

fn validar_fecha(f: &str) -> Result<(), Error> {
    let b = f.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(Error::Formato);
    }
    if b.iter().enumerate().any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit()) {
        return Err(Error::Formato);
    }
    let mes: u8 = f[5..7].parse().map_err(|_| Error::Formato)?;
    let dia: u8 = f[8..10].parse().map_err(|_| Error::Formato)?;
    if !(1..=12).contains(&mes) || !(1..=31).contains(&dia) {
        return Err(Error::Formato);
    }
    Ok(())
}

fn validar_nombre(n: &str) -> Result<(), Error> {
    if n.is_empty() || n.chars().count() > MAX_NOMBRE || n.contains('|') || n.chars().any(char::is_control) {
        return Err(Error::Formato);
    }
    Ok(())
}
