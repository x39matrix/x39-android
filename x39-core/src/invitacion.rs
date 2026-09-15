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
/// «Nombre Apellidos · Cargo · Área» cabe de sobra.
pub const MAX_NOMBRE: usize = 120;
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

pub const PREFIX_ACR: &str = "X39ACR1:";
pub const ACR_CTX: &[u8] = b"x39-acreditacion-v1";

/// Acreditación: el titular firma su invitación con su propia clave ML-DSA-87.
/// `"X39ACR1:" + base64url(firma_titular(4627) || invitación UTF-8 || check)`.
/// Quien la recibe junto a la identidad comprueba que (1) la invitación la firmó el Ayuntamiento y
/// (2) la acreditación la firmó la clave de ese contacto: el nombre de la invitación queda unido a la clave.
/// Límite: la invitación funciona como una llave; si se difunde, otra clave podría acreditarse con ese nombre.
pub fn acreditar(seed_titular: &[u8; DSA_SEED_LEN], invitacion: &str) -> Result<String, Error> {
    let compacta: String = invitacion.chars().filter(|c| !c.is_whitespace()).collect();
    if !compacta.starts_with(PREFIX_INV) {
        return Err(Error::Formato);
    }
    let sig = firma::sign(seed_titular, compacta.as_bytes(), ACR_CTX)?;
    let mut datos = Vec::with_capacity(SIG_LEN + compacta.len());
    datos.extend_from_slice(&sig);
    datos.extend_from_slice(compacta.as_bytes());
    Ok(share::encode(PREFIX_ACR, &datos))
}

/// Verifica una acreditación contra la clave de la autoridad y la clave de firma del titular.
pub fn verificar_acreditacion(
    pk_autoridad: &[u8; DSA_PK_LEN],
    pk_titular: &[u8; DSA_PK_LEN],
    texto: &str,
    hoy: &str,
) -> Result<Invitacion, Error> {
    let datos = share::decode(PREFIX_ACR, texto)?;
    if datos.len() <= SIG_LEN {
        return Err(Error::Formato);
    }
    let (sig, inv) = datos.split_at(SIG_LEN);
    if !firma::verify(pk_titular, inv, ACR_CTX, sig) {
        return Err(Error::Firma);
    }
    let inv = std::str::from_utf8(inv).map_err(|_| Error::Formato)?;
    verificar(pk_autoridad, inv, hoy)
}

pub const PREFIX_REV: &str = "X39REV1:";
pub const REV_CTX: &[u8] = b"x39-revocacion-v1";
const REV_PREFIJO: &str = "X39-REV-v1|";
pub const MAX_MOTIVO: usize = 120;

/// Revocación firmada por la autoridad: la persona con ese código de contacto deja de estar acreditada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocacion {
    /// Código canónico (12 símbolos) de la clave de firma revocada.
    pub codigo: String,
    /// Fecha de la revocación, AAAA-MM-DD.
    pub fecha: String,
    pub motivo: String,
}

/// `"X39REV1:" + base64url(firma_autoridad(4627) || "X39-REV-v1|codigo|fecha|motivo" || check)`.
/// Se publica en el canister (POST /revocar), que la comprueba con la misma clave pública que la app.
pub fn revocar(seed: &[u8; DSA_SEED_LEN], codigo: &str, fecha: &str, motivo: &str) -> Result<String, Error> {
    let codigo = crate::directorio::normalizar_codigo(codigo)?;
    validar_fecha(fecha)?;
    if motivo.chars().count() > MAX_MOTIVO || motivo.contains('|') || motivo.chars().any(char::is_control) {
        return Err(Error::Formato);
    }
    let carga = format!("{REV_PREFIJO}{codigo}|{fecha}|{motivo}");
    let sig = firma::sign(seed, carga.as_bytes(), REV_CTX)?;
    let mut datos = Vec::with_capacity(SIG_LEN + carga.len());
    datos.extend_from_slice(&sig);
    datos.extend_from_slice(carga.as_bytes());
    Ok(share::encode(PREFIX_REV, &datos))
}

pub fn verificar_revocacion(pk: &[u8; DSA_PK_LEN], texto: &str) -> Result<Revocacion, Error> {
    let datos = share::decode(PREFIX_REV, texto)?;
    if datos.len() <= SIG_LEN {
        return Err(Error::Formato);
    }
    let (sig, carga) = datos.split_at(SIG_LEN);
    if !firma::verify(pk, carga, REV_CTX, sig) {
        return Err(Error::Firma);
    }
    let carga = std::str::from_utf8(carga).map_err(|_| Error::Formato)?;
    let resto = carga.strip_prefix(REV_PREFIJO).ok_or(Error::Formato)?;
    let mut partes = resto.splitn(3, '|');
    let codigo = partes.next().ok_or(Error::Formato)?;
    let fecha = partes.next().ok_or(Error::Formato)?;
    let motivo = partes.next().unwrap_or("");
    let codigo = crate::directorio::normalizar_codigo(codigo)?;
    validar_fecha(fecha)?;
    Ok(Revocacion { codigo, fecha: fecha.to_string(), motivo: motivo.to_string() })
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
