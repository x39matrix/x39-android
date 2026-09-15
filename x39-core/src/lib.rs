//! x39-core — formato de cápsula Paris v3, compatible byte a byte con `paris_seal.py` / `paris_open.py` 3.10+.
//!
//! ```text
//! header(40) = MAGIC(8) | VERSION(1)=3 | flags(1) | reserved(6) | cid(16) | ts(8, BE)
//! cápsula    = header | ct_kem(1568, ML-KEM-1024) | nonce(12) | AES-256-GCM(pt, aad = header || aad_usuario)
//! clave      = HKDF-SHA256(secreto_compartido, salt = ninguno, info = "x39-paris-sealed-v1", 32 bytes)
//! ```
//!
//! Esta capa es la cápsula anónima de Paris (sin forward secrecy ni identidad del emisor).
//! El handshake y el ratchet de la app se construyen encima en fases posteriores.
#![forbid(unsafe_code)]

pub mod directorio;
pub mod firma;
pub mod invitacion;
pub mod ots;
pub mod share;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use sha2::Sha256;
use std::collections::HashSet;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"X39PARIS";
pub const VERSION: u8 = 3;
pub const CTX: &[u8] = b"x39-paris-sealed-v1";
pub const HEADER_LEN: usize = 40;
pub const PK_LEN: usize = 1568;
pub const SK_LEN: usize = 3168;
pub const CT_KEM_LEN: usize = 1568;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const CID_LEN: usize = 16;
/// Longitud mínima de una cápsula válida (plaintext vacío).
pub const MIN_LEN: usize = HEADER_LEN + CT_KEM_LEN + NONCE_LEN + TAG_LEN;
/// Tolerancia de reloj hacia el futuro, igual que Paris (300 s).
pub const MAX_FUTURE_SKEW: i64 = 300;

const OFF_CTKEM: usize = HEADER_LEN;
const OFF_NONCE: usize = OFF_CTKEM + CT_KEM_LEN;
const OFF_CT: usize = OFF_NONCE + NONCE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Magic,
    Version,
    Length,
    Ttl,
    /// Fallo de autenticación: cabecera, AAD, ct_kem, nonce o cuerpo manipulados, o clave equivocada.
    Aead,
    Replay,
    Rng,
    InvalidKey,
    /// Texto compartido corrupto, truncado o con prefijo equivocado.
    Formato,
    /// Firma del remitente ausente, manipulada, de otra persona o dirigida a otro destinatario.
    Firma,
    /// Prueba OpenTimestamps (.ots) o respuesta de calendario mal formada.
    Ots,
    /// Invitación del Ayuntamiento con la fecha de validez ya pasada.
    Caducada,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Error::Magic => "magic inválido",
            Error::Version => "versión no soportada (solo v3)",
            Error::Length => "longitud inválida",
            Error::Ttl => "cápsula fuera de la ventana temporal",
            Error::Aead => "descifrado o autenticación fallidos",
            Error::Replay => "replay detectado: cid ya consumido",
            Error::Rng => "fallo del generador aleatorio del sistema",
            Error::InvalidKey => "clave pública inválida",
            Error::Formato => "texto corrupto o de otro tipo (revisa que se copió entero)",
            Error::Firma => "la firma del remitente no es válida",
            Error::Ots => "prueba OpenTimestamps no válida",
            Error::Caducada => "la invitación ha caducado",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

pub struct KeyPair {
    pub public: [u8; PK_LEN],
    pub secret: Zeroizing<[u8; SK_LEN]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub cid: [u8; CID_LEN],
    pub ts: u64,
}

/// Ventana temporal obligatoria al abrir (Paris MESO2 exige `--ttl > 0`).
#[derive(Debug, Clone, Copy)]
pub struct TtlPolicy {
    pub now: u64,
    pub ttl: u64,
}

#[cfg(feature = "rng")]
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

/// Compilado sin `rng` (canister): nada que necesite aleatoriedad funciona; verificar sí.
#[cfg(not(feature = "rng"))]
fn random<const N: usize>() -> Result<[u8; N], Error> {
    Err(Error::Rng)
}

fn derive_key(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(CTX, key.as_mut())
        .expect("32 bytes está dentro del límite de HKDF");
    key
}

fn build_header(cid: &[u8; CID_LEN], ts: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8] = VERSION;
    h[16..32].copy_from_slice(cid);
    h[32..40].copy_from_slice(&ts.to_be_bytes());
    h
}

pub fn generate_keypair() -> Result<KeyPair, Error> {
    let seed = Zeroizing::new(random::<64>()?);
    let kp = mlkem1024::generate_key_pair(*seed);
    Ok(KeyPair {
        public: *kp.public_key().as_slice(),
        secret: Zeroizing::new(*kp.private_key().as_slice()),
    })
}

/// Sella `plaintext` para el destinatario. `cid = None` genera uno aleatorio.
pub fn seal(
    recipient_pk: &[u8; PK_LEN],
    plaintext: &[u8],
    aad: &[u8],
    cid: Option<[u8; CID_LEN]>,
    ts: u64,
) -> Result<Vec<u8>, Error> {
    let pk = mlkem1024::MlKem1024PublicKey::from(recipient_pk);
    if !mlkem1024::validate_public_key(&pk) {
        return Err(Error::InvalidKey);
    }
    let (ct_kem, shared) = mlkem1024::encapsulate(&pk, random::<32>()?);
    let shared = Zeroizing::new(shared);
    let key = derive_key(&shared);
    let nonce = random::<NONCE_LEN>()?;
    let cid = match cid {
        Some(c) => c,
        None => random::<CID_LEN>()?,
    };
    let header = build_header(&cid, ts);

    let mut aad_full = Vec::with_capacity(HEADER_LEN + aad.len());
    aad_full.extend_from_slice(&header);
    aad_full.extend_from_slice(aad);

    let cipher = Aes256Gcm::new(&(*key).into());
    let mut body = plaintext.to_vec();
    cipher
        .encrypt_in_place(&nonce.into(), &aad_full, &mut body)
        .map_err(|_| Error::Aead)?;

    let mut out = Vec::with_capacity(MIN_LEN + plaintext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(ct_kem.as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Abre una cápsula v3 sin estado de replay. Para uso real, [`ReplayGuard::open`].
pub fn open(
    recipient_sk: &[u8; SK_LEN],
    capsule: &[u8],
    aad: &[u8],
    ttl: Option<TtlPolicy>,
) -> Result<(Header, Zeroizing<Vec<u8>>), Error> {
    if capsule.len() < 8 || &capsule[..8] != MAGIC {
        return Err(Error::Magic);
    }
    if capsule.len() < 9 || capsule[8] != VERSION {
        return Err(Error::Version);
    }
    if capsule.len() < MIN_LEN {
        return Err(Error::Length);
    }
    let header_bytes = &capsule[..HEADER_LEN];
    let header = Header {
        flags: header_bytes[9],
        cid: header_bytes[16..32].try_into().expect("16 bytes"),
        ts: u64::from_be_bytes(header_bytes[32..40].try_into().expect("8 bytes")),
    };

    if let Some(p) = ttl {
        let age = p.now as i128 - header.ts as i128;
        if age > p.ttl as i128 || age < -(MAX_FUTURE_SKEW as i128) {
            return Err(Error::Ttl);
        }
    }

    let sk = mlkem1024::MlKem1024PrivateKey::from(recipient_sk);
    let ct = mlkem1024::MlKem1024Ciphertext::try_from(&capsule[OFF_CTKEM..OFF_NONCE])
        .map_err(|_| Error::Length)?;
    // ML-KEM usa rechazo implícito: un ct_kem manipulado da un secreto pseudoaleatorio y falla en AEAD.
    let shared = Zeroizing::new(mlkem1024::decapsulate(&sk, &ct));
    let key = derive_key(&shared);

    let nonce: [u8; NONCE_LEN] = capsule[OFF_NONCE..OFF_CT].try_into().expect("12 bytes");
    let mut aad_full = Vec::with_capacity(HEADER_LEN + aad.len());
    aad_full.extend_from_slice(header_bytes);
    aad_full.extend_from_slice(aad);

    let cipher = Aes256Gcm::new(&(*key).into());
    let mut body = Zeroizing::new(capsule[OFF_CT..].to_vec());
    cipher
        .decrypt_in_place(&nonce.into(), &aad_full, &mut *body)
        .map_err(|_| Error::Aead)?;
    Ok((header, body))
}

/// Anti-replay por `cid`, comprobado solo tras autenticar (igual que Paris).
/// Sustituye al fichero `.seen`; en la app vivirá en la base de datos cifrada.
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashSet<[u8; CID_LEN]>,
}

impl ReplayGuard {
    pub fn open(
        &mut self,
        recipient_sk: &[u8; SK_LEN],
        capsule: &[u8],
        aad: &[u8],
        ttl: Option<TtlPolicy>,
    ) -> Result<(Header, Zeroizing<Vec<u8>>), Error> {
        let (header, pt) = open(recipient_sk, capsule, aad, ttl)?;
        if !self.seen.insert(header.cid) {
            return Err(Error::Replay);
        }
        Ok((header, pt))
    }
}
