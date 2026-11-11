use super::{
    HuellaDsa, Nonce, NoncesBloqueados, SemillaDsa, campos, entero_positivo,
    firmar_mensaje, hex_fijo, verificar_mensaje,
};
use crate::{ErrorHub, a_hex};
use std::{fmt, str::FromStr};
use x39_core::firma::{self, DSA_PK_LEN, SIG_LEN};

const PREFIJO: &str = "X39-COBRO-BTC-v1";
const CONTEXTO: &[u8] = b"x39-cobro-btc-v1";
const MAX_SATOSHIS: u64 = 2_100_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedCobro {
    Bitcoin,
    Testnet,
    Signet,
}

impl fmt::Display for RedCobro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bitcoin => "bitcoin",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
        })
    }
}

impl FromStr for RedCobro {
    type Err = ErrorHub;

    fn from_str(texto: &str) -> Result<Self, ErrorHub> {
        match texto {
            "bitcoin" => Ok(Self::Bitcoin),
            "testnet" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            _ => Err(ErrorHub::Formato),
        }
    }
}

// Este filtro comprueba la forma y el prefijo. No sustituye la validación completa
// que la billetera debe hacer con su propia biblioteca antes de preparar el pago.
fn direccion_admitida(red: RedCobro, direccion: &str) -> bool {
    let bytes = direccion.as_bytes();
    if !(14..=90).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let (prefijo, tradicional) = match red {
        RedCobro::Bitcoin => ("bc1", matches!(bytes[0], b'1' | b'3')),
        RedCobro::Testnet | RedCobro::Signet => {
            ("tb1", matches!(bytes[0], b'm' | b'n' | b'2'))
        }
    };
    tradicional || (direccion.starts_with(prefijo) && !bytes.iter().any(u8::is_ascii_uppercase))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolicitudCobroBtc {
    pub red: RedCobro,
    pub direccion: String,
    pub satoshis: u64,
    pub caduca_unix_s: u64,
    pub nonce: Nonce,
    pub beneficiario_fp: HuellaDsa,
    pub beneficiario_pk: [u8; DSA_PK_LEN],
    pub firma: [u8; SIG_LEN],
}

impl SolicitudCobroBtc {
    fn validar_campos(&self) -> Result<(), ErrorHub> {
        if !direccion_admitida(self.red, &self.direccion)
            || !(1..=MAX_SATOSHIS).contains(&self.satoshis)
            || self.caduca_unix_s == 0
        {
            return Err(ErrorHub::Formato);
        }
        Ok(())
    }

    fn mensaje(&self) -> String {
        format!(
            "{PREFIJO}|{}|{}|{}|{}|{}|{}",
            self.red, self.direccion, self.satoshis, self.caduca_unix_s,
            self.nonce.como_str(), self.beneficiario_fp
        )
    }

    pub fn texto_canonico(&self) -> Result<String, ErrorHub> {
        self.validar_campos()?;
        Ok(self.mensaje())
    }

    pub fn texto_portable(&self) -> Result<String, ErrorHub> {
        Ok(format!(
            "{}|{}|{}", self.texto_canonico()?,
            a_hex(&self.beneficiario_pk), a_hex(&self.firma)
        ))
    }

    pub fn firmar(
        semilla_beneficiario: &SemillaDsa,
        red: RedCobro,
        direccion: &str,
        satoshis: u64,
        caduca_unix_s: u64,
        nonce: Nonce,
    ) -> Result<Self, ErrorHub> {
        let beneficiario_pk = firma::public_key(semilla_beneficiario);
        let mut solicitud = Self {
            red,
            direccion: direccion.to_owned(),
            satoshis,
            caduca_unix_s,
            nonce,
            beneficiario_fp: HuellaDsa::de_clave(&beneficiario_pk),
            beneficiario_pk,
            firma: [0; SIG_LEN],
        };
        solicitud.firma =
            firmar_mensaje(semilla_beneficiario, &solicitud.texto_canonico()?, CONTEXTO)?;
        Ok(solicitud)
    }

    #[cfg(feature = "rng")]
    pub fn firmar_con_nonce_aleatorio(
        semilla_beneficiario: &SemillaDsa,
        red: RedCobro,
        direccion: &str,
        satoshis: u64,
        caduca_unix_s: u64,
    ) -> Result<Self, ErrorHub> {
        let nonce = Nonce::de_hex(&a_hex(&crate::azar::<16>()?))?;
        Self::firmar(semilla_beneficiario, red, direccion, satoshis, caduca_unix_s, nonce)
    }

    /// Lee la estructura del sobre. La autorización de pago requiere verificarlo.
    pub fn leer_portable(entrada: &[u8]) -> Result<Self, ErrorHub> {
        let [prefijo, red, direccion, sats, caduca, nonce, huella, pk, firma] = campos(entrada)?;
        if prefijo != PREFIJO {
            return Err(ErrorHub::Formato);
        }
        let solicitud = Self {
            red: red.parse()?,
            direccion: direccion.to_owned(),
            satoshis: entero_positivo(sats)?,
            caduca_unix_s: entero_positivo(caduca)?,
            nonce: Nonce::de_hex(nonce)?,
            beneficiario_fp: HuellaDsa::de_hex(huella)?,
            beneficiario_pk: hex_fijo(pk)?,
            firma: hex_fijo(firma)?,
        };
        if solicitud.texto_portable()?.as_bytes() != entrada {
            return Err(ErrorHub::Formato);
        }
        Ok(solicitud)
    }

    /// La huella esperada procede del contacto elegido por quien paga.
    /// Tras Ok, la billetera debe reservar atómicamente el nonce de ese beneficiario.
    /// Solo quien consigue la reserva prepara el pago. La caja no guarda estado.
    pub fn verificar_antes_de_pagar(
        &self,
        beneficiario_esperado: &HuellaDsa,
        red_esperada: RedCobro,
        ahora_unix_s: u64,
        bloqueados: &dyn NoncesBloqueados,
    ) -> Result<(), ErrorHub> {
        // Se autentican los campos recibidos antes de consultar el reloj o los nonces.
        verificar_mensaje(
            beneficiario_esperado, &self.beneficiario_fp, &self.beneficiario_pk,
            &self.mensaje(), CONTEXTO, &self.firma,
        )?;
        if self.red != red_esperada {
            return Err(ErrorHub::Formato);
        }
        self.validar_campos()?;
        if ahora_unix_s > self.caduca_unix_s {
            return Err(ErrorHub::Caducado);
        }
        if bloqueados.contiene(&self.nonce) {
            return Err(ErrorHub::Replay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recibos::ReciboCustodia;
    use sha2::{Digest, Sha256};

    const VECTOR: &str = include_str!("../../tests/fixtures/cobro_v1.txt");
    const CUSTODIA: &str = include_str!("../../tests/fixtures/custodia_v1.txt");
    const DIRECCION: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const NONCE: &str = "00112233445566778899aabbccddeeff";
    const CADUCA: u64 = 2_000_000_000;

    struct Vista<'a>(Option<&'a Nonce>);

    impl NoncesBloqueados for Vista<'_> {
        fn contiene(&self, nonce: &Nonce) -> bool {
            self.0 == Some(nonce)
        }
    }

    struct NoConsultar;

    impl NoncesBloqueados for NoConsultar {
        fn contiene(&self, _: &Nonce) -> bool {
            panic!("se consultó el nonce antes de terminar las comprobaciones previas")
        }
    }

    fn datos(vector: &str) -> [&str; 6] {
        assert!(vector.is_ascii() && !vector.contains('\r'));
        let mut lineas = vector.strip_suffix('\n').expect("falta LF final").split('\n');
        let nombres = ["mensaje", "contexto", "huella_esperada", "clave_publica_hex", "firma_hex", "portable"];
        let valores = nombres.map(|nombre| {
            let (campo, valor) = lineas.next().unwrap().split_once('=').unwrap();
            assert_eq!(campo, nombre);
            assert!(!valor.is_empty());
            valor
        });
        assert!(lineas.next().is_none());
        valores
    }

    fn muestra() -> (SolicitudCobroBtc, HuellaDsa) {
        let [_, _, huella, _, _, portable] = datos(VECTOR);
        (
            SolicitudCobroBtc::leer_portable(portable.as_bytes()).unwrap(),
            HuellaDsa::de_hex(huella).unwrap(),
        )
    }

    #[test]
    fn vector_congelado_texto_exacto_y_portable_verificable() {
        assert_eq!(a_hex(&Sha256::digest(VECTOR.as_bytes())), SHA256_VECTOR);
        let [mensaje, contexto, huella, pk, firma_hex, portable] = datos(VECTOR);
        let esperado = format!(
            "X39-COBRO-BTC-v1|bitcoin|{DIRECCION}|24000|2000000000|{NONCE}|{huella}"
        );
        assert_eq!(mensaje.as_bytes(), esperado.as_bytes());
        assert_eq!(contexto, "x39-cobro-btc-v1");
        assert_eq!(portable, format!("{mensaje}|{pk}|{firma_hex}"));

        let (r, fp) = muestra();
        assert_eq!(a_hex(&Sha256::digest(r.beneficiario_pk)), huella);
        assert_eq!(a_hex(&r.beneficiario_pk), pk);
        assert_eq!(a_hex(&r.firma), firma_hex);
        assert_eq!(r.texto_canonico().unwrap().as_bytes(), esperado.as_bytes());
        assert_eq!(r.texto_portable().unwrap(), portable);
        assert_eq!(r.verificar_antes_de_pagar(&fp, RedCobro::Bitcoin, CADUCA, &Vista(None)), Ok(()));
    }

    #[test]
    fn lector_estricto_y_limites_de_importe() {
        let portable = datos(VECTOR)[5];
        let partes: Vec<&str> = portable.split('|').collect();
        for (i, valor) in [
            (0, "x39-cobro-btc-v1"), (1, "mainnet"), (1, "regtest"), (1, "Bitcoin"),
            (2, "tb1aaaaaaaaaaaa"), (3, "024000"), (3, "0"), (3, "2100000000000001"),
            (4, "0"), (4, "02000000000"), (5, "00112233445566778899AABBCCDDEEFF"),
        ] {
            let mut copia = partes.clone();
            copia[i] = valor;
            assert_eq!(SolicitudCobroBtc::leer_portable(copia.join("|").as_bytes()).unwrap_err(),
                ErrorHub::Formato);
        }
        for (i, longitud) in [(6, 32), (7, DSA_PK_LEN), (8, SIG_LEN)] {
            let mayusculas = "AB".repeat(longitud);
            let mut copia = partes.clone();
            copia[i] = &mayusculas;
            assert_eq!(SolicitudCobroBtc::leer_portable(copia.join("|").as_bytes()).unwrap_err(),
                ErrorHub::Formato);
        }
        for entrada in [format!("{portable}|extra"), partes[..8].join("|"), format!("{portable}\n")] {
            assert_eq!(SolicitudCobroBtc::leer_portable(entrada.as_bytes()).unwrap_err(),
                ErrorHub::Formato);
        }
        for importe in ["1", "2100000000000000"] {
            let mut copia = partes.clone();
            copia[3] = importe;
            assert!(SolicitudCobroBtc::leer_portable(copia.join("|").as_bytes()).is_ok());
        }
    }

    #[test]
    fn direcciones_por_red_alfabeto_y_longitud() {
        use RedCobro::{Bitcoin, Signet, Testnet};

        for (red, prefijos) in [
            (Bitcoin, &["bc1", "1", "3"][..]),
            (Testnet, &["tb1", "m", "n", "2"][..]),
            (Signet, &["tb1", "m", "n", "2"][..]),
        ] {
            for prefijo in prefijos {
                for longitud in [14, 90] {
                    let direccion = format!("{prefijo}{}", "a".repeat(longitud - prefijo.len()));
                    assert!(direccion_admitida(red, &direccion));
                }
            }
        }
        for red in [Testnet, Signet] {
            assert!(!direccion_admitida(red, DIRECCION));
            assert!(!direccion_admitida(red, "tb1aaaaAaaaaaaa"));
            assert!(direccion_admitida(red, "mABCDE123456789"));
        }
        for direccion in ["tb1aaaaaaaaaaaa", "bc1aaaaAaaaaaaa", "BC1aaaaaaaaaaaa",
                          "1abcdefghijk_lm", "1abcdefghijkñlm"] {
            assert!(!direccion_admitida(Bitcoin, direccion));
        }
        assert!(direccion_admitida(Bitcoin, "1ABCDE123456789"));
        for longitud in [13, 91] {
            assert!(!direccion_admitida(Bitcoin, &format!("1{}", "a".repeat(longitud - 1))));
        }
    }

    #[test]
    fn tres_desajustes_de_huella() {
        let (r, esperada) = muestra();
        let mut otra_pk = r.beneficiario_pk;
        otra_pk[0] ^= 1;
        let otra_fp = HuellaDsa::de_clave(&otra_pk);
        let rechazo = Err(ErrorHub::HuellaNoCoincide);

        assert_eq!(r.verificar_antes_de_pagar(&otra_fp, r.red, CADUCA, &NoConsultar), rechazo);

        let mut declarada = r.clone();
        declarada.beneficiario_fp = otra_fp;
        assert_eq!(declarada.verificar_antes_de_pagar(&esperada, r.red, CADUCA, &NoConsultar), rechazo);

        let mut adjunta = r.clone();
        adjunta.beneficiario_pk = otra_pk;
        assert_eq!(adjunta.verificar_antes_de_pagar(&esperada, r.red, CADUCA, &NoConsultar), rechazo);
    }

    #[test]
    fn red_caducidad_nonce_y_orden_de_errores() {
        let (mut r, fp) = muestra();
        let red = RedCobro::Bitcoin;
        for ahora in [CADUCA - 1, CADUCA] {
            assert_eq!(r.verificar_antes_de_pagar(&fp, red, ahora, &Vista(None)), Ok(()));
        }
        assert_eq!(r.verificar_antes_de_pagar(&fp, red, CADUCA, &Vista(Some(&r.nonce))),
            Err(ErrorHub::Replay));
        assert_eq!(r.verificar_antes_de_pagar(&fp, red, CADUCA + 1, &NoConsultar),
            Err(ErrorHub::Caducado));
        assert_eq!(r.verificar_antes_de_pagar(&fp, RedCobro::Signet, CADUCA + 1, &NoConsultar),
            Err(ErrorHub::Formato));

        r.firma[0] ^= 1;
        assert_eq!(r.verificar_antes_de_pagar(&fp, red, CADUCA + 1, &NoConsultar),
            Err(ErrorHub::Firma));
        assert_eq!(r.verificar_antes_de_pagar(&fp, RedCobro::Signet, CADUCA + 1, &NoConsultar),
            Err(ErrorHub::Firma));
    }

    #[test]
    fn alterar_direccion_o_importe_invalida_la_firma() {
        let (r, fp) = muestra();
        let mut otra = r.clone();
        otra.direccion = "1ABCDE123456789".into();
        assert_eq!(otra.verificar_antes_de_pagar(&fp, r.red, CADUCA, &NoConsultar), Err(ErrorHub::Firma));

        let mut otra = r.clone();
        otra.satoshis += 1;
        assert_eq!(otra.verificar_antes_de_pagar(&fp, r.red, CADUCA, &NoConsultar), Err(ErrorHub::Firma));
    }

    #[test]
    fn contextos_separados_y_firma_real_de_custodia() {
        let (mut r, _) = muestra();
        let mensaje = r.texto_canonico().unwrap();
        assert!(firma::verify(&r.beneficiario_pk, mensaje.as_bytes(), b"x39-cobro-btc-v1", &r.firma));
        for ctx in ["", "x39-msg-v1", "x39-custodia-v1", "x39-rotacion-v1", "x39-entrega-v1"] {
            assert!(!firma::verify(&r.beneficiario_pk, mensaje.as_bytes(), ctx.as_bytes(), &r.firma));
        }

        let [_, _, huella, _, _, portable] = datos(CUSTODIA);
        let custodio = HuellaDsa::de_hex(huella).unwrap();
        let c = ReciboCustodia::leer_portable(portable.as_bytes()).unwrap();
        assert_eq!(c.verificar(&custodio), Ok(()));
        r.beneficiario_fp = custodio;
        r.beneficiario_pk = c.custodio_pk;
        r.firma = c.firma_custodio;
        assert_eq!(r.verificar_antes_de_pagar(&custodio, r.red, CADUCA, &NoConsultar),
            Err(ErrorHub::Firma));
    }

    #[cfg(feature = "rng")]
    #[test]
    fn emision_con_nonce_aleatorio_y_redes_con_prefijo_compartido() {
        let semilla = [7; 32];
        let fp = HuellaDsa::de_clave(&firma::public_key(&semilla));
        let r = SolicitudCobroBtc::firmar_con_nonce_aleatorio(
            &semilla, RedCobro::Testnet, "tb1aaaaaaaaaaaa", 1, CADUCA,
        ).unwrap();
        assert_eq!(r.nonce.como_str().len(), 32);
        let releido = SolicitudCobroBtc::leer_portable(r.texto_portable().unwrap().as_bytes()).unwrap();
        assert_eq!(releido, r);
        assert_eq!(r.verificar_antes_de_pagar(&fp, RedCobro::Testnet, CADUCA, &Vista(None)), Ok(()));
        assert_eq!(r.verificar_antes_de_pagar(&fp, RedCobro::Signet, CADUCA, &NoConsultar),
            Err(ErrorHub::Formato));
    }

    #[cfg(not(feature = "rng"))]
    #[test]
    fn emitir_sin_rng_devuelve_rng() {
        let resultado = SolicitudCobroBtc::firmar(
            &[7; 32], RedCobro::Bitcoin, DIRECCION, 24_000, CADUCA, Nonce::de_hex(NONCE).unwrap(),
        );
        assert_eq!(resultado.unwrap_err(), ErrorHub::Rng);
    }
}

#[cfg(test)]
const SHA256_VECTOR: &str = "62f2e100a4d1334c05272c632db095f3cc31ced7c1345a4b34e6f099389b9ab5";
