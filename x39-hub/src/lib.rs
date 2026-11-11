//! Caja aislada x39-hub: verificacion de cabeceras Bitcoin frente a sellos OTS,
//! pruebas de inclusion Merkle con total de asientos contrastado y recibos
//! portables firmados con FIPS 204 ML-DSA-87 bajo contextos dedicados.
#![forbid(unsafe_code)]

pub const HUB_CANISTER_ID: &str = "arn4r-lqaaa-aaaao-baxwq-cai";
pub const HUB_SUBNET_ID: &str = "o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae";

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorHub {
    Formato,
    Firma,
    HuellaNoCoincide,
    ClaveCifradoInvalida,
    Caducado,
    Replay,
    InclusionMerkle,
    Ots,
    AlturaSinModoSinRed,
    TrabajoInsuficiente,
    CabeceraNoCoincideConNodo,
    Rng,
}

impl std::fmt::Display for ErrorHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorHub::Formato => "formato canonico o hexadecimal no valido",
            ErrorHub::Firma => "firma poscuantica ML-DSA-87 no valida",
            ErrorHub::HuellaNoCoincide => "la huella no coincide con el contacto o receptor esperado",
            ErrorHub::ClaveCifradoInvalida => "clave publica ML-KEM-1024 no valida",
            ErrorHub::Caducado => "la solicitud ha caducado",
            ErrorHub::Replay => "identificador unico ya consumido o en curso",
            ErrorHub::InclusionMerkle => "prueba de inclusion, total de asientos o raiz del HUB no validos",
            ErrorHub::Ots => "prueba OpenTimestamps no valida o de otro archivo",
            ErrorHub::AlturaSinModoSinRed => "altura inferior al corte permitido para verificacion sin nodo",
            ErrorHub::TrabajoInsuficiente => "prueba de trabajo insuficiente o por debajo del suelo exigido",
            ErrorHub::CabeceraNoCoincideConNodo => "la cabecera no coincide con la raiz OTS o con el bloque del nodo",
            ErrorHub::Rng => "generador aleatorio no disponible",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ErrorHub {}

#[cfg(feature = "rng")]
pub fn azar<const N: usize>() -> Result<[u8; N], ErrorHub> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| ErrorHub::Rng)?;
    Ok(b)
}

#[cfg(not(feature = "rng"))]
pub fn azar<const N: usize>() -> Result<[u8; N], ErrorHub> {
    Err(ErrorHub::Rng)
}

pub fn a_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn de_hex_exacto<const N: usize>(hex: &str) -> Result<[u8; N], ErrorHub> {
    if hex.len() != N * 2 {
        return Err(ErrorHub::Formato);
    }
    let mut out = [0u8; N];
    let b = hex.as_bytes();
    for i in 0..N {
        let hi = match b[2 * i] {
            b'0'..=b'9' => b[2 * i] - b'0',
            b'a'..=b'f' => b[2 * i] - b'a' + 10,
            b'A'..=b'F' => b[2 * i] - b'A' + 10,
            _ => return Err(ErrorHub::Formato),
        };
        let lo = match b[2 * i + 1] {
            b'0'..=b'9' => b[2 * i + 1] - b'0',
            b'a'..=b'f' => b[2 * i + 1] - b'a' + 10,
            b'A'..=b'F' => b[2 * i + 1] - b'A' + 10,
            _ => return Err(ErrorHub::Formato),
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

pub fn de_hex_32(hex: &str) -> Result<[u8; 32], ErrorHub> {
    de_hex_exacto::<32>(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ida_y_vuelta_y_rechazos() {
        let muestra = [0x00u8, 0x1a, 0xbc, 0xff];
        let txt = a_hex(&muestra);
        assert_eq!(txt, "001abcff");
        assert_eq!(de_hex_exacto::<4>(&txt).unwrap(), muestra);
        assert_eq!(de_hex_exacto::<4>("001ABCFF").unwrap(), muestra);
        assert_eq!(de_hex_exacto::<4>("001abc").unwrap_err(), ErrorHub::Formato);
        assert_eq!(de_hex_exacto::<4>("001abcgg").unwrap_err(), ErrorHub::Formato);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn generador_propio_con_rng() {
        let a = azar::<32>().unwrap();
        let b = azar::<32>().unwrap();
        assert_ne!(a, b);
    }

    #[cfg(not(feature = "rng"))]
    #[test]
    fn generador_propio_sin_rng_falla_limpio() {
        assert_eq!(azar::<32>().unwrap_err(), ErrorHub::Rng);
    }
}
