//! tunel — X39-TUNEL-PSK-v1: acuerdo post-cuántico de la clave precompartida (PSK) de WireGuard.
//!
//! El x39tunel es un túnel WireGuard entre el móvil y el servidor. WireGuard acuerda su
//! clave con Curve25519, que un ordenador cuántico rompe; pero admite una PSK de 32 bytes
//! por par que se mezcla en el apretón de manos. Si esa PSK viaja dentro de una cápsula
//! Paris (ML-KEM-1024) firmada con la identidad del móvil (ML-DSA-87), el túnel pasa a
//! ser híbrido: para abrirlo hay que romper Curve25519 **y** ML-KEM-1024.
//!
//! ```text
//! cadena   = "X39-TUNEL-PSK-v1|srv=<sha256 hex de la clave ML-KEM del servidor>|bh=<huella del móvil>"
//!            "|wg=<clave pública WireGuard del móvil, base64>|psk=<32 bytes hex>|hasta=<unix>"
//! cuerpo   = firma ML-DSA-87(cadena, ctx "x39-tunel-v1")(4627) || cadena
//! petición = cápsula Paris v3 hacia la clave del servidor, aad = "x39-tunel-psk-v1"
//! ```
//!
//! El servidor abre la cápsula con su clave secreta, busca la clave de firma del móvil
//! por su huella (lista de pares autorizados), verifica la firma, comprueba que `srv`
//! es él mismo (nadie puede desviar la petición a otro servidor) y que `hasta` no ha
//! pasado, y solo entonces aplica la PSK al par WireGuard `wg`. El `cid` y el `ts` de la
//! cápsula cortan la repetición. La PSK nunca viaja en claro ni se apunta en ningún log.
use crate::firma::{self, DSA_PK_LEN, DSA_SEED_LEN, SIG_LEN};
use crate::{Error, PK_LEN, ReplayGuard, SK_LEN, TtlPolicy};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const VERSION_PSK: &str = "X39-TUNEL-PSK-v1";
/// Contexto de dominio de la firma (separa este uso de mensajes, llamadas e invitaciones).
pub const CTX_TUNEL: &[u8] = b"x39-tunel-v1";
/// AAD de la cápsula: una cápsula de otro uso no se acepta como petición de PSK.
pub const AAD_PSK: &[u8] = b"x39-tunel-psk-v1";
pub const PSK_LEN: usize = 32;
pub const WG_PK_LEN: usize = 32;
/// Ventana en la que el servidor acepta una petición (igual que Paris: 5 minutos).
pub const TTL_PETICION_S: u64 = 300;
/// Vida máxima de una PSK: pasada, el móvil pide otra (rotación diaria por defecto).
pub const VIDA_MAX_S: u64 = 7 * 24 * 3600;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// base64 estándar CON relleno: es lo que WireGuard espera en `PresharedKey` y `PublicKey`.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn de_b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Huella del servidor: SHA-256 (hex) de su clave pública ML-KEM. Es lo que la app lleva fijado.
pub fn huella_servidor(kem_pk: &[u8; PK_LEN]) -> String {
    hex(&Sha256::digest(kem_pk))
}

/// Huella (binding hash) de una identidad: SHA-256 hex de su clave pública ML-DSA-87,
/// igual que `Identidad.huellaDe` en la app.
pub fn huella_identidad(dsa_pk: &[u8; DSA_PK_LEN]) -> String {
    hex(&Sha256::digest(dsa_pk))
}

/// La línea canónica que se firma.
pub fn cadena(srv: &str, bh: &str, wg_pk: &[u8; WG_PK_LEN], psk: &[u8; PSK_LEN], hasta: u64) -> String {
    format!("{VERSION_PSK}|srv={srv}|bh={bh}|wg={}|psk={}|hasta={hasta}", b64(wg_pk), hex(psk))
}

/// Lo que el servidor obtiene de una petición válida.
pub struct Peticion {
    /// Huella del móvil (ya verificada contra su clave de firma).
    pub bh: String,
    /// Clave pública WireGuard del par al que aplicar la PSK.
    pub wg_pk: [u8; WG_PK_LEN],
    /// La PSK. Aplicarla y olvidarla; nunca apuntarla.
    pub psk: Zeroizing<[u8; PSK_LEN]>,
    /// Hasta cuándo vale (unix). Pasado, el servidor la retira si no llega otra.
    pub hasta: u64,
}

impl Peticion {
    /// `PresharedKey = …` tal como lo entiende `wg set … preshared-key`.
    pub fn psk_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(b64(self.psk.as_ref()))
    }
    pub fn wg_pk_base64(&self) -> String {
        b64(&self.wg_pk)
    }
}

/// Lado móvil: genera una PSK fresca, la firma y la sella para el servidor.
/// Devuelve `(cápsula, psk)`: la cápsula se manda; la psk se pone en el par WireGuard local.
pub fn pedir_psk(
    servidor_kem_pk: &[u8; PK_LEN],
    mldsa_seed: &[u8; DSA_SEED_LEN],
    wg_pk: &[u8; WG_PK_LEN],
    hasta: u64,
    ahora: u64,
) -> Result<(Vec<u8>, Zeroizing<[u8; PSK_LEN]>), Error> {
    if hasta <= ahora || hasta - ahora > VIDA_MAX_S {
        return Err(Error::Caducada);
    }
    let psk = Zeroizing::new(crate::random::<PSK_LEN>()?);
    let bh = huella_identidad(&firma::public_key(mldsa_seed));
    let srv = huella_servidor(servidor_kem_pk);
    let cad = cadena(&srv, &bh, wg_pk, &psk, hasta);
    let sig = firma::sign(mldsa_seed, cad.as_bytes(), CTX_TUNEL)?;
    let mut cuerpo = Zeroizing::new(Vec::with_capacity(SIG_LEN + cad.len()));
    cuerpo.extend_from_slice(&sig);
    cuerpo.extend_from_slice(cad.as_bytes());
    let capsula = crate::seal(servidor_kem_pk, &cuerpo, AAD_PSK, None, ahora)?;
    Ok((capsula, psk))
}

fn campo<'a>(cad: &'a str, clave: &str) -> Option<&'a str> {
    cad.split('|').find_map(|p| p.strip_prefix(clave))
}

/// Lado servidor: abre la petición, verifica y devuelve lo que hay que aplicar.
/// `clave_de` busca la clave de firma ML-DSA-87 de una huella en la lista de pares
/// autorizados; una huella desconocida se rechaza como firma inválida (no se distingue,
/// para no dar pistas).
pub fn abrir_psk(
    servidor_kem_sk: &[u8; SK_LEN],
    servidor_kem_pk: &[u8; PK_LEN],
    capsula: &[u8],
    ahora: u64,
    guardia: &mut ReplayGuard,
    clave_de: impl Fn(&str) -> Option<[u8; DSA_PK_LEN]>,
) -> Result<Peticion, Error> {
    let ttl = TtlPolicy { now: ahora, ttl: TTL_PETICION_S };
    let (_h, cuerpo) = guardia.open(servidor_kem_sk, capsula, AAD_PSK, Some(ttl))?;
    if cuerpo.len() <= SIG_LEN {
        return Err(Error::Formato);
    }
    let sig = &cuerpo[..SIG_LEN];
    let cad = std::str::from_utf8(&cuerpo[SIG_LEN..]).map_err(|_| Error::Formato)?;
    if !cad.starts_with(&format!("{VERSION_PSK}|")) {
        return Err(Error::Formato);
    }
    let srv = campo(cad, "srv=").ok_or(Error::Formato)?;
    let bh = campo(cad, "bh=").ok_or(Error::Formato)?;
    let wg = campo(cad, "wg=").ok_or(Error::Formato)?;
    let psk_hex = campo(cad, "psk=").ok_or(Error::Formato)?;
    let hasta: u64 = campo(cad, "hasta=").ok_or(Error::Formato)?.parse().map_err(|_| Error::Formato)?;
    // ¿Es para mí? Una petición sellada para otro servidor no se aplica aquí.
    if srv != huella_servidor(servidor_kem_pk) {
        return Err(Error::Formato);
    }
    let pk = clave_de(bh).ok_or(Error::Firma)?;
    if huella_identidad(&pk) != bh {
        return Err(Error::Firma);
    }
    if !firma::verify(&pk, cad.as_bytes(), CTX_TUNEL, sig) {
        return Err(Error::Firma);
    }
    if hasta <= ahora || hasta - ahora > VIDA_MAX_S {
        return Err(Error::Caducada);
    }
    let wg_v = de_b64(wg).ok_or(Error::Formato)?;
    let wg_pk: [u8; WG_PK_LEN] = wg_v.try_into().map_err(|_| Error::Formato)?;
    let psk_v = de_hex(psk_hex).ok_or(Error::Formato)?;
    let psk: [u8; PSK_LEN] = psk_v.try_into().map_err(|_| Error::Formato)?;
    Ok(Peticion { bh: bh.to_string(), wg_pk, psk: Zeroizing::new(psk), hasta })
}

fn de_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escenario() -> (crate::KeyPair, Zeroizing<[u8; DSA_SEED_LEN]>, [u8; DSA_PK_LEN], [u8; WG_PK_LEN]) {
        let srv = crate::generate_keypair().unwrap();
        let seed = firma::generate_seed().unwrap();
        let pk = firma::public_key(&seed);
        let wg = [7u8; WG_PK_LEN];
        (srv, seed, pk, wg)
    }

    #[test]
    fn ida_y_vuelta() {
        let (srv, seed, pk, wg) = escenario();
        let ahora = 1_789_000_000;
        let (cap, psk) = pedir_psk(&srv.public, &seed, &wg, ahora + 86_400, ahora).unwrap();
        let mut g = ReplayGuard::default();
        let bh = huella_identidad(&pk);
        let p = abrir_psk(&srv.secret, &srv.public, &cap, ahora + 10, &mut g, |h| (h == bh).then_some(pk)).unwrap();
        assert_eq!(p.bh, bh);
        assert_eq!(p.wg_pk, wg);
        assert_eq!(p.psk.as_ref(), psk.as_ref());
        assert_eq!(p.hasta, ahora + 86_400);
        assert_eq!(p.psk_base64().len(), 44);
        assert_eq!(p.wg_pk_base64(), b64(&wg));
        // Repetir la misma cápsula: rechazada.
        assert_eq!(
            abrir_psk(&srv.secret, &srv.public, &cap, ahora + 11, &mut g, |h| (h == bh).then_some(pk)).err(),
            Some(Error::Replay)
        );
    }

    #[test]
    fn huella_desconocida_o_clave_ajena() {
        let (srv, seed, pk, wg) = escenario();
        let ahora = 1_789_000_000;
        let (cap, _) = pedir_psk(&srv.public, &seed, &wg, ahora + 3600, ahora).unwrap();
        let mut g = ReplayGuard::default();
        assert_eq!(abrir_psk(&srv.secret, &srv.public, &cap, ahora, &mut g, |_| None).err(), Some(Error::Firma));
        let otra = firma::public_key(&firma::generate_seed().unwrap());
        let mut g = ReplayGuard::default();
        assert_eq!(abrir_psk(&srv.secret, &srv.public, &cap, ahora, &mut g, |_| Some(otra)).err(), Some(Error::Firma));
        let _ = pk;
    }

    #[test]
    fn otro_servidor_no_la_acepta() {
        let (srv, seed, pk, wg) = escenario();
        let otro = crate::generate_keypair().unwrap();
        let ahora = 1_789_000_000;
        let (cap, _) = pedir_psk(&srv.public, &seed, &wg, ahora + 3600, ahora).unwrap();
        let mut g = ReplayGuard::default();
        // Con la clave secreta de otro servidor ni siquiera se abre.
        assert_eq!(abrir_psk(&otro.secret, &otro.public, &cap, ahora, &mut g, |_| Some(pk)).err(), Some(Error::Aead));
        // Si un servidor tuviera la secreta pero otra pública declarada, tampoco: `srv` no cuadra.
        let mut g = ReplayGuard::default();
        assert_eq!(abrir_psk(&srv.secret, &otro.public, &cap, ahora, &mut g, |_| Some(pk)).err(), Some(Error::Formato));
    }

    #[test]
    fn manipulada_vieja_o_caducada() {
        let (srv, seed, pk, wg) = escenario();
        let ahora = 1_789_000_000;
        let (mut cap, _) = pedir_psk(&srv.public, &seed, &wg, ahora + 3600, ahora).unwrap();
        let mut g = ReplayGuard::default();
        assert_eq!(abrir_psk(&srv.secret, &srv.public, &cap, ahora + 301, &mut g, |_| Some(pk)).err(), Some(Error::Ttl));
        let ultimo = cap.len() - 1;
        cap[ultimo] ^= 1;
        assert_eq!(abrir_psk(&srv.secret, &srv.public, &cap, ahora, &mut g, |_| Some(pk)).err(), Some(Error::Aead));
        assert_eq!(pedir_psk(&srv.public, &seed, &wg, ahora, ahora).err(), Some(Error::Caducada));
        assert_eq!(pedir_psk(&srv.public, &seed, &wg, ahora + VIDA_MAX_S + 1, ahora).err(), Some(Error::Caducada));
    }

    #[test]
    fn base64_wireguard() {
        let k = [0u8; 32];
        assert_eq!(b64(&k), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let v: Vec<u8> = (0..32).collect();
        assert_eq!(de_b64(&b64(&v)).unwrap(), v);
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(de_b64("YWI=").unwrap(), b"ab");
    }
}
