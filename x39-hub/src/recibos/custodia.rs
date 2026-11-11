use super::{
    Hash32, HuellaDsa, Id, SemillaDsa, campos, entero_positivo, firmar_mensaje, hex_fijo,
    verificar_mensaje,
};
use crate::{ErrorHub, a_hex};
use sha2::{Digest, Sha256};
use std::fmt;
use x39_core::firma::{self, DSA_PK_LEN, SIG_LEN};

const PREFIJO: &str = "X39-CUSTODIA-v1";
const CONTEXTO: &[u8] = b"x39-custodia-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Previo {
    Raiz,
    /// SHA-256 del texto portable exacto del eslabón anterior, sin salto de línea.
    Eslabon(Hash32),
}

impl fmt::Display for Previo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raiz => f.write_str("raiz"),
            Self::Eslabon(hash) => f.write_str(&a_hex(hash)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReciboCustodia {
    pub id_entrega: Id,
    pub sha256_original: Hash32,
    pub emisor_fp: HuellaDsa,
    pub custodio_fp: HuellaDsa,
    pub recibo_previo: Previo,
    /// Segundos Unix declarados por el custodio. La firma acredita su declaración.
    /// La hora efectiva de recepción requiere evidencia independiente.
    pub hora_declarada_unix_s: u64,
    pub custodio_pk: [u8; DSA_PK_LEN],
    pub firma_custodio: [u8; SIG_LEN],
}

impl ReciboCustodia {
    pub fn firmar(
        semilla_custodio: &SemillaDsa,
        id_entrega: Id,
        sha256_original: Hash32,
        emisor_fp: HuellaDsa,
        recibo_previo: Previo,
        hora_declarada_unix_s: u64,
    ) -> Result<Self, ErrorHub> {
        let custodio_pk = firma::public_key(semilla_custodio);
        let mut recibo = Self {
            id_entrega,
            sha256_original,
            emisor_fp,
            custodio_fp: HuellaDsa::de_clave(&custodio_pk),
            recibo_previo,
            hora_declarada_unix_s,
            custodio_pk,
            firma_custodio: [0; SIG_LEN],
        };
        recibo.firma_custodio =
            firmar_mensaje(semilla_custodio, &recibo.texto_canonico()?, CONTEXTO)?;
        Ok(recibo)
    }

    pub fn texto_canonico(&self) -> Result<String, ErrorHub> {
        if self.hora_declarada_unix_s == 0 {
            return Err(ErrorHub::Formato);
        }
        Ok(format!(
            "{PREFIJO}|{}|{}|{}|{}|{}|{}",
            self.id_entrega.como_str(),
            a_hex(&self.sha256_original),
            self.emisor_fp,
            self.custodio_fp,
            self.recibo_previo,
            self.hora_declarada_unix_s
        ))
    }

    pub fn texto_portable(&self) -> Result<String, ErrorHub> {
        Ok(format!(
            "{}|{}|{}",
            self.texto_canonico()?,
            a_hex(&self.custodio_pk),
            a_hex(&self.firma_custodio)
        ))
    }

    /// Lee el formato. La autenticación requiere verificar con la huella esperada.
    pub fn leer_portable(entrada: &[u8]) -> Result<Self, ErrorHub> {
        let [prefijo, id, original, emisor, custodio, previo, hora, clave, firma] =
            campos(entrada)?;
        if prefijo != PREFIJO {
            return Err(ErrorHub::Formato);
        }
        let recibo = Self {
            id_entrega: Id::de_hex(id)?,
            sha256_original: hex_fijo(original)?,
            emisor_fp: HuellaDsa::de_hex(emisor)?,
            custodio_fp: HuellaDsa::de_hex(custodio)?,
            recibo_previo: if previo == "raiz" {
                Previo::Raiz
            } else {
                Previo::Eslabon(hex_fijo(previo)?)
            },
            hora_declarada_unix_s: entero_positivo(hora)?,
            custodio_pk: hex_fijo(clave)?,
            firma_custodio: hex_fijo(firma)?,
        };
        if recibo.texto_portable()?.as_bytes() != entrada {
            return Err(ErrorHub::Formato);
        }
        Ok(recibo)
    }

    /// La huella esperada procede del contacto o de la operación de custodia.
    pub fn verificar(&self, custodio_esperado: &HuellaDsa) -> Result<(), ErrorHub> {
        verificar_mensaje(
            custodio_esperado,
            &self.custodio_fp,
            &self.custodio_pk,
            &self.texto_canonico()?,
            CONTEXTO,
            &self.firma_custodio,
        )
    }

    /// Identifica este sobre completo para enlazarlo desde el siguiente recibo.
    pub fn huella_portable(&self) -> Result<Hash32, ErrorHub> {
        Ok(Sha256::digest(self.texto_portable()?.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00b2c3d4e5f60718";

    fn emitir(
        semilla: &SemillaDsa,
        previo: Previo,
        hora: u64,
    ) -> Result<ReciboCustodia, ErrorHub> {
        ReciboCustodia::firmar(
            semilla, Id::de_hex(ID)?, [0xab; 32],
            HuellaDsa::de_hex(&"cd".repeat(32))?, previo, hora,
        )
    }

    fn campos_de_muestra() -> Vec<String> {
        [
            "X39-CUSTODIA-v1".into(),
            ID.into(),
            "ab".repeat(32),
            "cd".repeat(32),
            HuellaDsa::de_clave(&[0xef; DSA_PK_LEN]).to_string(),
            "raiz".into(),
            "1800000000".into(),
            "ef".repeat(DSA_PK_LEN),
            "00".repeat(SIG_LEN),
        ].into()
    }

    #[test]
    fn el_lector_reproduce_el_portable_sin_autenticarlo() {
        let partes = campos_de_muestra();
        let texto = partes.join("|");
        let recibo = ReciboCustodia::leer_portable(texto.as_bytes()).unwrap();
        assert_eq!(recibo.texto_canonico().unwrap(), partes[..7].join("|"));
        assert_eq!(recibo.texto_portable().unwrap(), texto);
        let esperada = HuellaDsa::de_clave(&[0xef; DSA_PK_LEN]);
        assert_eq!(recibo.verificar(&esperada), Err(ErrorHub::Firma));
    }

    #[test]
    fn el_lector_rechaza_grafias_y_sobres_alternativos() {
        let base = campos_de_muestra();
        for (i, valor) in [
            (0, "x39-custodia-v1".into()),
            (1, "00B2c3d4e5f60718".into()),
            (2, "AB".repeat(32)),
            (3, "CD".repeat(32)),
            (4, "EF".repeat(32)),
            (5, "RAIZ".into()),
            (5, "AB".repeat(32)),
            (5, "ab".repeat(31)),
            (6, "01800000000".into()),
            (6, "+1800000000".into()),
            (6, "0".into()),
            (7, "EF".repeat(DSA_PK_LEN)),
            (7, "ef".repeat(DSA_PK_LEN - 1)),
            (8, "AA".repeat(SIG_LEN)),
            (8, "00".repeat(SIG_LEN - 1)),
        ] {
            let mut partes = base.clone();
            partes[i] = valor;
            assert_eq!(
                ReciboCustodia::leer_portable(partes.join("|").as_bytes()).unwrap_err(),
                ErrorHub::Formato
            );
        }
        let texto = base.join("|");
        for entrada in [
            format!("{texto}|"),
            format!("{texto}\n"),
            format!("{texto}\r\n"),
            format!(" {texto}"),
            format!("\u{feff}{texto}"),
            texto.replace("|raiz|", "||"),
            texto.replace("|raiz|", "|raíz|"),
            base[..8].join("|"),
        ] {
            assert_eq!(
                ReciboCustodia::leer_portable(entrada.as_bytes()).unwrap_err(),
                ErrorHub::Formato
            );
        }
        assert_eq!(ReciboCustodia::leer_portable(&[0xff]).unwrap_err(), ErrorHub::Formato);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn custodia_autentica_exige_el_contexto_y_la_huella_del_contacto() {
        let semilla = [7; 32];
        let esperada = HuellaDsa::de_clave(&firma::public_key(&semilla));
        let recibo = emitir(&semilla, Previo::Raiz, 1_800_000_000).unwrap();
        let texto = recibo.texto_portable().unwrap();
        let releido = ReciboCustodia::leer_portable(texto.as_bytes()).unwrap();
        assert_eq!(releido.verificar(&esperada), Ok(()));

        let mensaje = releido.texto_canonico().unwrap();
        let comprobar = |ctx: &[u8]| {
            firma::verify(&releido.custodio_pk, mensaje.as_bytes(), ctx, &releido.firma_custodio)
        };
        assert!(comprobar(b"x39-custodia-v1"));
        for ctx in ["", "x39-msg-v1", "x39-cobro-btc-v1", "x39-rotacion-v1", "x39-entrega-v1"] {
            assert!(!comprobar(ctx.as_bytes()));
        }

        let otra_pk = firma::public_key(&[9; 32]);
        let otra_fp = HuellaDsa::de_clave(&otra_pk);
        assert_eq!(releido.verificar(&otra_fp), Err(ErrorHub::HuellaNoCoincide));

        let mut cambiado = releido.clone();
        cambiado.custodio_fp = otra_fp;
        assert_eq!(cambiado.verificar(&esperada), Err(ErrorHub::HuellaNoCoincide));
        cambiado.custodio_fp = esperada;
        cambiado.custodio_pk = otra_pk;
        assert_eq!(cambiado.verificar(&esperada), Err(ErrorHub::HuellaNoCoincide));

        let mut alterado = releido;
        alterado.hora_declarada_unix_s += 1;
        assert_eq!(alterado.verificar(&esperada), Err(ErrorHub::Firma));
    }

    #[cfg(feature = "rng")]
    #[test]
    fn el_segundo_eslabon_enlaza_el_portable_exacto_del_primero() {
        let clave_a = [3; 32];
        let clave_b = [5; 32];
        let a = emitir(&clave_a, Previo::Raiz, 1).unwrap();
        assert_eq!(
            a.verificar(&HuellaDsa::de_clave(&firma::public_key(&clave_a))),
            Ok(())
        );

        let portable = a.texto_portable().unwrap();
        let esperado: Hash32 = Sha256::digest(portable.as_bytes()).into();
        assert_eq!(a.huella_portable().unwrap(), esperado);
        let con_salto: Hash32 = Sha256::digest(format!("{portable}\n").as_bytes()).into();
        assert_ne!(esperado, con_salto);

        let b = ReciboCustodia::firmar(
            &clave_b, a.id_entrega.clone(), a.sha256_original,
            a.custodio_fp, Previo::Eslabon(esperado), 2,
        ).unwrap();
        let b = ReciboCustodia::leer_portable(b.texto_portable().unwrap().as_bytes()).unwrap();
        assert_eq!(
            b.verificar(&HuellaDsa::de_clave(&firma::public_key(&clave_b))),
            Ok(())
        );
        assert_eq!(b.recibo_previo, Previo::Eslabon(esperado));

        let mut otro = a;
        otro.firma_custodio[0] ^= 1;
        assert_ne!(b.recibo_previo, Previo::Eslabon(otro.huella_portable().unwrap()));
    }

    #[cfg(not(feature = "rng"))]
    #[test]
    fn sin_rng_la_emision_devuelve_el_error_previsto() {
        assert_eq!(emitir(&[7; 32], Previo::Raiz, 1).unwrap_err(), ErrorHub::Rng);
    }
}
