//! Estados verificables de sellos OpenTimestamps frente a cabeceras crudas de 80 bytes
//! de Bitcoin, con suelo de dificultad reciente y distincion estricta entre verificacion
//! local sin red y comprobacion real contra un nodo.

use crate::{ErrorHub, a_hex};
use sha2::{Digest, Sha256};
use x39_core::ots::{Atestacion, Prueba};

pub const CABECERA_BITCOIN_LEN: usize = 80;

/// Corte inferior de altura para permitir el modo local sin nodo.
/// Por debajo de 950_000 no hay modo sin red: solo BloqueIndicado o contraste con nodo.
pub const ALTURA_MINIMA_MODO_SIN_RED: u64 = 950_000;

/// Suelo de dificultad para alturas desde 950_000 en adelante: nBits = 0x17083de4
/// (dificultad aproximada 3.4e13).
/// Origen: bloque 950_381 de Bitcoin mainnet (nBits = 0x17020f79, minado el 21/05/2026),
/// medido desde el nodo propio el 11/11/2026 (con punta en 975_436, nBits = 0x1701e5ac),
/// fijando el objetivo maximo en 4 veces el objetivo del bloque 950_381 (0x020f79 * 4 = 0x083de4).
pub const SUELO_NBITS_RECIENTE: u32 = 0x1708_3de4;

/// Techo historico de mainnet (dificultad 1) para rechazar cabeceras regtest en alturas
/// anteriores a 950_000 cuando se contrastan contra un nodo.
const NBITS_DIFICULTAD_UNO_MAINNET: u32 = 0x1d00_ffff;

/// Nodo contra el que se ha comprobado el hash canonico del bloque para una altura dada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodoContraste {
    /// Nodo operado por X39 (valor por defecto si el usuario no configura uno propio).
    X39,
    /// Nodo propio configurado por el usuario (nombre o direccion identificativa).
    Propio(String),
}

impl NodoContraste {
    pub fn validar(&self) -> Result<(), ErrorHub> {
        match self {
            NodoContraste::X39 => Ok(()),
            NodoContraste::Propio(etiqueta) => {
                let limpia = etiqueta.trim();
                if limpia.is_empty() || etiqueta.len() > 128 || etiqueta.chars().any(|c| c.is_control()) {
                    return Err(ErrorHub::Formato);
                }
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for NodoContraste {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodoContraste::X39 => f.write_str("nodo X39"),
            NodoContraste::Propio(etiqueta) => write!(f, "nodo propio ({etiqueta})"),
        }
    }
}

/// Estado honesto de una prueba OpenTimestamps vinculada a la huella SHA-256 de un archivo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EstadoSelloBitcoin {
    /// El archivo coincide con el .ots y existen calendarios pendientes, sin bloque aun.
    CalendarioRecibido {
        huella_archivo: [u8; 32],
        calendarios_pendientes: usize,
    },
    /// El .ots declara una altura y su merkle_root derivada, sin haber comprobado cabecera.
    BloqueIndicado {
        huella_archivo: [u8; 32],
        altura: u64,
        merkle_root_esperada: [u8; 32],
    },
    /// Modo sin red (solo alturas >= 950_000): supera el suelo reciente y cuadra la merkle_root,
    /// pero NO se ha contrastado con ningun nodo.
    TrabajoLocalSinContrastarNodo {
        huella_archivo: [u8; 32],
        altura: u64,
        hash_cabecera: [u8; 32],
        merkle_root: [u8; 32],
        tiempo_bloque: u32,
    },
    /// Comprobado: el hash de la cabecera coincide con el devuelto por el nodo para esa altura.
    BloqueComprobado {
        huella_archivo: [u8; 32],
        altura: u64,
        block_hash: [u8; 32],
        merkle_root: [u8; 32],
        tiempo_bloque: u32,
        nodo: NodoContraste,
    },
}

impl std::fmt::Display for EstadoSelloBitcoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstadoSelloBitcoin::CalendarioRecibido { calendarios_pendientes, .. } => {
                write!(f, "calendario recibido ({calendarios_pendientes} pendiente(s), sin bloque)")
            }
            EstadoSelloBitcoin::BloqueIndicado { altura, .. } => {
                write!(f, "bloque {altura} indicado en el sello (sin cabecera comprobada)")
            }
            EstadoSelloBitcoin::TrabajoLocalSinContrastarNodo { altura, hash_cabecera, .. } => {
                write!(
                    f,
                    "trabajo local suficiente en altura {altura} ({}) SIN contrastar con ningun nodo",
                    a_hex(hash_cabecera)
                )
            }
            EstadoSelloBitcoin::BloqueComprobado { altura, block_hash, nodo, .. } => {
                write!(f, "bloque {altura} ({}) comprobado contra {nodo}", a_hex(block_hash))
            }
        }
    }
}

/// Campos extraidos y verificados de una cabecera cruda de 80 bytes de Bitcoin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CabeceraBitcoin {
    pub block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub tiempo_bloque: u32,
    pub nbits: u32,
    pub objetivo: [u8; 32],
}

/// Decodifica el formato compacto nBits de Bitcoin (SetCompact) a 256 bits big-endian.
pub fn objetivo_compacto_bitcoin(bits: u32) -> Option<[u8; 32]> {
    let tam = (bits >> 24) as usize;
    let mantisa = bits & 0x007f_ffff;
    if mantisa == 0 || (bits & 0x0080_0000) != 0 || tam == 0 || tam > 32 {
        return None;
    }
    let b0 = ((mantisa >> 16) & 0xff) as u8;
    let b1 = ((mantisa >> 8) & 0xff) as u8;
    let b2 = (mantisa & 0xff) as u8;
    let mut target = [0u8; 32];
    match tam {
        1 => target[31] = b0,
        2 => {
            target[30] = b0;
            target[31] = b1;
        }
        3..=32 => {
            let inicio = 32 - tam;
            target[inicio] = b0;
            target[inicio + 1] = b1;
            target[inicio + 2] = b2;
        }
        _ => unreachable!(),
    }
    if target == [0u8; 32] {
        return None;
    }
    Some(target)
}

pub fn nbits_cabecera(cabecera: &[u8; CABECERA_BITCOIN_LEN]) -> u32 {
    u32::from_le_bytes(cabecera[72..76].try_into().expect("4 bytes"))
}

/// Comprueba que nBits no permita un objetivo mayor (mas facil) que SUELO_NBITS_RECIENTE.
pub fn validar_nbits_suelo_reciente(nbits: u32) -> Result<[u8; 32], ErrorHub> {
    let objetivo = objetivo_compacto_bitcoin(nbits).ok_or(ErrorHub::TrabajoInsuficiente)?;
    let suelo = objetivo_compacto_bitcoin(SUELO_NBITS_RECIENTE).expect("suelo constante valido");
    if objetivo > suelo {
        return Err(ErrorHub::TrabajoInsuficiente);
    }
    Ok(suelo)
}

/// Verifica el doble SHA-256 de una cabecera cruda de 80 bytes contra su propio nBits.
pub fn verificar_pow_cabecera(
    cabecera: &[u8; CABECERA_BITCOIN_LEN],
) -> Result<CabeceraBitcoin, ErrorHub> {
    let nbits = nbits_cabecera(cabecera);
    let objetivo = objetivo_compacto_bitcoin(nbits).ok_or(ErrorHub::TrabajoInsuficiente)?;
    let h1 = Sha256::digest(cabecera);
    let mut block_hash: [u8; 32] = Sha256::digest(h1).into();
    block_hash.reverse();
    if block_hash > objetivo {
        return Err(ErrorHub::TrabajoInsuficiente);
    }
    let merkle_root: [u8; 32] = cabecera[36..68].try_into().expect("32 bytes");
    let tiempo_bloque = u32::from_le_bytes(cabecera[68..72].try_into().expect("4 bytes"));
    Ok(CabeceraBitcoin {
        block_hash,
        merkle_root,
        tiempo_bloque,
        nbits,
        objetivo,
    })
}

/// Extrae todos los pares (altura, merkle_root_32_bytes) de un sello OpenTimestamps.
pub fn raices_bitcoin_ots(prueba: &Prueba) -> Vec<(u64, [u8; 32])> {
    let mut pares: Vec<(u64, [u8; 32])> = prueba
        .timestamp
        .todas_las_atestaciones()
        .into_iter()
        .filter_map(|(msg, atestacion)| match atestacion {
            Atestacion::Bitcoin(altura) => {
                let raiz: [u8; 32] = msg.as_slice().try_into().ok()?;
                Some((altura, raiz))
            }
            _ => None,
        })
        .collect();
    pares.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    pares.dedup();
    pares
}

/// Clasifica un .ots frente a la huella SHA-256 del archivo sin consultar cabeceras ni nodo.
/// Si hay varias atestaciones Bitcoin, informa de la altura más baja. `raices_bitcoin_ots` las devuelve todas.
pub fn inspeccionar_ots_sin_cabecera(
    prueba: &Prueba,
    huella_archivo: &[u8; 32],
) -> Result<EstadoSelloBitcoin, ErrorHub> {
    if &prueba.huella() != huella_archivo {
        return Err(ErrorHub::Ots);
    }
    if let Some(&(altura, merkle_root_esperada)) = raices_bitcoin_ots(prueba).first() {
        return Ok(EstadoSelloBitcoin::BloqueIndicado {
            huella_archivo: *huella_archivo,
            altura,
            merkle_root_esperada,
        });
    }
    let calendarios_pendientes = prueba.pendientes().len();
    if calendarios_pendientes > 0 {
        return Ok(EstadoSelloBitcoin::CalendarioRecibido {
            huella_archivo: *huella_archivo,
            calendarios_pendientes,
        });
    }
    Err(ErrorHub::Ots)
}

/// Verifica una cabecera en modo local sin red (solo alturas >= 950_000 y superando 0x17083de4).
/// Nunca devuelve BloqueComprobado.
pub fn verificar_cabecera_sin_nodo(
    prueba: &Prueba,
    huella_archivo: &[u8; 32],
    altura: u64,
    cabecera_80b: &[u8; CABECERA_BITCOIN_LEN],
) -> Result<EstadoSelloBitcoin, ErrorHub> {
    if &prueba.huella() != huella_archivo {
        return Err(ErrorHub::Ots);
    }
    let raices = raices_bitcoin_ots(prueba);
    if !raices.iter().any(|(h, _)| *h == altura) {
        return Err(ErrorHub::Ots);
    }
    if altura < ALTURA_MINIMA_MODO_SIN_RED {
        return Err(ErrorHub::AlturaSinModoSinRed);
    }
    let suelo = validar_nbits_suelo_reciente(nbits_cabecera(cabecera_80b))?;
    let cab = verificar_pow_cabecera(cabecera_80b)?;
    if cab.block_hash > suelo {
        return Err(ErrorHub::TrabajoInsuficiente);
    }
    if !raices.iter().any(|(h, esp)| *h == altura && esp == &cab.merkle_root) {
        return Err(ErrorHub::Ots);
    }
    Ok(EstadoSelloBitcoin::TrabajoLocalSinContrastarNodo {
        huella_archivo: *huella_archivo,
        altura,
        hash_cabecera: cab.block_hash,
        merkle_root: cab.merkle_root,
        tiempo_bloque: cab.tiempo_bloque,
    })
}

/// Unica via para obtener BloqueComprobado: exige que el hash de la cabecera coincida con
/// el devuelto por el nodo indicado para esa altura y que la merkle_root coincida con el .ots.
/// `hash_bloque_segun_nodo` usa el orden de bytes que muestra `getblockhash`, inverso al interno de la cabecera.
pub fn comprobar_bloque_con_nodo(
    prueba: &Prueba,
    huella_archivo: &[u8; 32],
    altura: u64,
    cabecera_80b: &[u8; CABECERA_BITCOIN_LEN],
    hash_bloque_segun_nodo: &[u8; 32],
    nodo: NodoContraste,
) -> Result<EstadoSelloBitcoin, ErrorHub> {
    nodo.validar()?;
    if &prueba.huella() != huella_archivo {
        return Err(ErrorHub::Ots);
    }
    let raices = raices_bitcoin_ots(prueba);
    if !raices.iter().any(|(h, _)| *h == altura) {
        return Err(ErrorHub::Ots);
    }
    let nbits_limite = if altura >= ALTURA_MINIMA_MODO_SIN_RED {
        SUELO_NBITS_RECIENTE
    } else {
        NBITS_DIFICULTAD_UNO_MAINNET
    };
    let limite = objetivo_compacto_bitcoin(nbits_limite).expect("límite de dificultad válido");
    let cab = verificar_pow_cabecera(cabecera_80b)?;
    if cab.objetivo > limite || cab.block_hash > limite {
        return Err(ErrorHub::TrabajoInsuficiente);
    }
    if !raices.iter().any(|(h, esp)| *h == altura && esp == &cab.merkle_root) {
        return Err(ErrorHub::Ots);
    }
    if &cab.block_hash != hash_bloque_segun_nodo {
        return Err(ErrorHub::CabeceraNoCoincideConNodo);
    }
    Ok(EstadoSelloBitcoin::BloqueComprobado {
        huella_archivo: *huella_archivo,
        altura,
        block_hash: cab.block_hash,
        merkle_root: cab.merkle_root,
        tiempo_bloque: cab.tiempo_bloque,
        nodo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{de_hex_32, de_hex_exacto};

    const HASH_950381: &str = "00000000000000000000250ec4552d1dbb441416f4409e50b9531528c8ec310c";
    const CABECERA_950381: &str = "000000381c91e621324316979a5ea5900de864a2d6fe0412e32e00000000000000000000525f2bef6af79431c187eb8de8db9f2e08e33f5a493425317ec33f5f7864fe5e86180f6a790f0217fed3be59";
    const MERKLE_950381: &str = "525f2bef6af79431c187eb8de8db9f2e08e33f5a493425317ec33f5f7864fe5e";

    #[test]
    fn objetivo_compacto_rechaza_mantisa_nula_signo_y_tamanos_invalidos() {
        assert_eq!(objetivo_compacto_bitcoin(0x17000000), None);
        assert_eq!(objetivo_compacto_bitcoin(0x17800001), None);
        assert_eq!(objetivo_compacto_bitcoin(0x00123456), None);
        assert_eq!(objetivo_compacto_bitcoin(0x21000001), None);
    }

    #[test]
    fn objetivo_compacto_de_dificultad_uno_tiene_los_bytes_esperados() {
        let mut esperado = [0u8; 32];
        esperado[4] = 0xff;
        esperado[5] = 0xff;
        assert_eq!(objetivo_compacto_bitcoin(0x1d00ffff), Some(esperado));
    }

    #[test]
    fn nodo_de_contraste_valida_las_etiquetas() {
        use NodoContraste::{Propio, X39};

        assert_eq!(X39.validar(), Ok(()));
        assert_eq!(Propio("".into()).validar(), Err(ErrorHub::Formato));
        assert_eq!(Propio("   ".into()).validar(), Err(ErrorHub::Formato));
        assert_eq!(Propio("€".repeat(43)).validar(), Err(ErrorHub::Formato));
        assert_eq!(Propio("mi-nodo\n".into()).validar(), Err(ErrorHub::Formato));
        assert_eq!(Propio("mi-nodo".into()).validar(), Ok(()));
    }

    #[test]
    fn cabecera_real_950381_pasa_suelo_y_umbrales_inferiores_se_rechazan() {
        let raw = de_hex_exacto::<80>(CABECERA_950381).unwrap();
        let cab = verificar_pow_cabecera(&raw).unwrap();
        assert_eq!(cab.block_hash, de_hex_32(HASH_950381).unwrap());
        assert_eq!(cab.merkle_root, de_hex_32(MERKLE_950381).unwrap());
        assert_eq!(cab.nbits, 0x1702_0f79);
        assert_eq!(cab.tiempo_bloque, 1_779_374_214);
        assert!(validar_nbits_suelo_reciente(cab.nbits).is_ok());
        assert!(validar_nbits_suelo_reciente(0x1701_e5ac).is_ok());
        assert!(validar_nbits_suelo_reciente(SUELO_NBITS_RECIENTE).is_ok());

        assert_eq!(validar_nbits_suelo_reciente(0x207f_ffff).unwrap_err(), ErrorHub::TrabajoInsuficiente);
        assert_eq!(validar_nbits_suelo_reciente(0x1d00_ffff).unwrap_err(), ErrorHub::TrabajoInsuficiente);
        assert_eq!(validar_nbits_suelo_reciente(0x1708_3de5).unwrap_err(), ErrorHub::TrabajoInsuficiente);
    }
}
