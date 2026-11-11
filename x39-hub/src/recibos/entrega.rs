//! El aparato del receptor firma haber recibido los bytes identificados por su SHA-256.
//! La firma no acredita que una persona los leyera. RECHAZADO también requiere
//! haber recibido bytes. No existe una variante para «no llegó nada».
//!
//! El recibo carece de caducidad y nonce. La aplicación identifica la transferencia
//! por receptor e id_transferencia y registra su cierre una sola vez, de forma
//! atómica. Una segunda presentación del mismo recibo solo sirve para consultarlo.

use super::{
    Hash32, HuellaDsa, Id, SemillaDsa, campos, firmar_mensaje, hex_fijo, verificar_mensaje,
};
use crate::{ErrorHub, a_hex};
use std::{fmt, str::FromStr};
use x39_core::firma::{self, DSA_PK_LEN, SIG_LEN};

const PREFIJO: &str = "X39-ENTREGA-v1";
const CONTEXTO: &[u8] = b"x39-entrega-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaseAdjunto {
    Original,
    CopiaProcesada,
    CapsulaEvidencia,
}

impl fmt::Display for ClaseAdjunto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Original => "ORIGINAL",
            Self::CopiaProcesada => "COPIA_PROCESADA",
            Self::CapsulaEvidencia => "CAPSULA_EVIDENCIA",
        })
    }
}

impl FromStr for ClaseAdjunto {
    type Err = ErrorHub;

    fn from_str(texto: &str) -> Result<Self, ErrorHub> {
        match texto {
            "ORIGINAL" => Ok(Self::Original),
            "COPIA_PROCESADA" => Ok(Self::CopiaProcesada),
            "CAPSULA_EVIDENCIA" => Ok(Self::CapsulaEvidencia),
            _ => Err(ErrorHub::Formato),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultadoEntrega {
    Integro,
    Rechazado,
}

impl fmt::Display for ResultadoEntrega {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Integro => "INTEGRO",
            Self::Rechazado => "RECHAZADO",
        })
    }
}

impl FromStr for ResultadoEntrega {
    type Err = ErrorHub;

    fn from_str(texto: &str) -> Result<Self, ErrorHub> {
        match texto {
            "INTEGRO" => Ok(Self::Integro),
            "RECHAZADO" => Ok(Self::Rechazado),
            _ => Err(ErrorHub::Formato),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReciboEntregaAdjunto {
    pub id_transferencia: Id,
    pub receptor_fp: HuellaDsa,
    pub sha256_recibido: Hash32,
    pub clase: ClaseAdjunto,
    pub resultado: ResultadoEntrega,
    pub receptor_pk: [u8; DSA_PK_LEN],
    pub firma_receptor: [u8; SIG_LEN],
}

impl ReciboEntregaAdjunto {
    pub fn firmar(
        semilla_receptor: &SemillaDsa,
        id_transferencia: Id,
        sha256_recibido: Hash32,
        clase: ClaseAdjunto,
        resultado: ResultadoEntrega,
    ) -> Result<Self, ErrorHub> {
        let receptor_pk = firma::public_key(semilla_receptor);
        let mut recibo = Self {
            id_transferencia,
            receptor_fp: HuellaDsa::de_clave(&receptor_pk),
            sha256_recibido,
            clase,
            resultado,
            receptor_pk,
            firma_receptor: [0; SIG_LEN],
        };
        recibo.firma_receptor =
            firmar_mensaje(semilla_receptor, &recibo.texto_canonico()?, CONTEXTO)?;
        Ok(recibo)
    }

    pub fn texto_canonico(&self) -> Result<String, ErrorHub> {
        Ok(format!(
            "{PREFIJO}|{}|{}|{}|{}|{}",
            self.id_transferencia.como_str(),
            self.receptor_fp,
            a_hex(&self.sha256_recibido),
            self.clase,
            self.resultado
        ))
    }

    pub fn texto_portable(&self) -> Result<String, ErrorHub> {
        Ok(format!(
            "{}|{}|{}",
            self.texto_canonico()?,
            a_hex(&self.receptor_pk),
            a_hex(&self.firma_receptor)
        ))
    }

    /// Lee el sobre canónico. La autenticidad se comprueba con la huella del contacto.
    pub fn leer_portable(entrada: &[u8]) -> Result<Self, ErrorHub> {
        let [prefijo, id, huella, hash, clase, resultado, clave, firma] = campos(entrada)?;
        if prefijo != PREFIJO {
            return Err(ErrorHub::Formato);
        }
        Ok(Self {
            id_transferencia: Id::de_hex(id)?,
            receptor_fp: HuellaDsa::de_hex(huella)?,
            sha256_recibido: hex_fijo(hash)?,
            clase: clase.parse()?,
            resultado: resultado.parse()?,
            receptor_pk: hex_fijo(clave)?,
            firma_receptor: hex_fijo(firma)?,
        })
    }

    /// Autentica la declaración del receptor, incluso cuando declara RECHAZADO.
    pub fn verificar(&self, receptor_esperado: &HuellaDsa) -> Result<(), ErrorHub> {
        verificar_mensaje(
            receptor_esperado,
            &self.receptor_fp,
            &self.receptor_pk,
            &self.texto_canonico()?,
            CONTEXTO,
            &self.firma_receptor,
        )
    }

    /// Un recibo auténtico de otra transferencia o de otro archivo no cierra esta.
    /// El emisor aporta los datos de su envío. La aplicación solo lo marca como
    /// entregado si esta función devuelve Ok.
    pub fn verificar_cierre(
        &self,
        receptor_esperado: &HuellaDsa,
        id_esperado: &Id,
        sha256_enviado: &Hash32,
        clase_esperada: ClaseAdjunto,
    ) -> Result<(), ErrorHub> {
        self.verificar(receptor_esperado)?;
        if &self.id_transferencia != id_esperado
            || self.clase != clase_esperada
            || self.resultado == ResultadoEntrega::Rechazado
        {
            return Err(ErrorHub::Formato);
        }
        if &self.sha256_recibido != sha256_enviado {
            return Err(ErrorHub::HuellaNoCoincide);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const VECTOR: &str = include_str!("../../tests/fixtures/entrega_v1.txt");
    const CUSTODIA: &str = include_str!("../../tests/fixtures/custodia_v1.txt");
    const COBRO: &str = include_str!("../../tests/fixtures/cobro_v1.txt");
    const ROTACION: &str = include_str!("../../tests/fixtures/rotacion_v1.txt");
    const ID: &str = "1234567890abcdef";
    const SELLO: &str = "08e9db781dc79c9fbbe77a56cd0120d2830650d4bcf52a2dae9acb73091d449c";
    const CAPSULA: ClaseAdjunto = ClaseAdjunto::CapsulaEvidencia;

    fn dato<'a>(vector: &'a str, nombre: &str) -> &'a str {
        vector
            .lines()
            .filter_map(|linea| linea.split_once('='))
            .find(|(campo, _)| *campo == nombre)
            .expect("falta un campo del vector")
            .1
    }

    fn muestra() -> (ReciboEntregaAdjunto, HuellaDsa) {
        (
            ReciboEntregaAdjunto::leer_portable(dato(VECTOR, "portable").as_bytes()).unwrap(),
            HuellaDsa::de_hex(dato(VECTOR, "huella_esperada")).unwrap(),
        )
    }

    #[test]
    fn vector_congelado_y_textos_exactos() {
        assert_eq!(a_hex(&Sha256::digest(VECTOR.as_bytes())), SHA256_VECTOR);
        let (r, esperada) = muestra();
        let huella = dato(VECTOR, "huella_esperada");
        let mensaje = format!("X39-ENTREGA-v1|{ID}|{huella}|{SELLO}|CAPSULA_EVIDENCIA|INTEGRO");
        let pk = a_hex(&r.receptor_pk);
        let firma = a_hex(&r.firma_receptor);
        let portable = format!("{mensaje}|{pk}|{firma}");
        let exacto = format!(
            "mensaje={mensaje}\ncontexto=x39-entrega-v1\nhuella_esperada={huella}\n\
             clave_publica_hex={pk}\nfirma_hex={firma}\nportable={portable}\n"
        );
        assert_eq!(VECTOR.as_bytes(), exacto.as_bytes());
        assert_eq!(r.texto_canonico().unwrap(), mensaje);
        assert_eq!(r.texto_portable().unwrap(), portable);
        assert_eq!(r.verificar(&esperada), Ok(()));
    }

    #[test]
    fn lector_estricto_y_seis_combinaciones_canonicas() {
        let portable = dato(VECTOR, "portable");
        let partes: [&str; 8] = campos(portable.as_bytes()).unwrap();
        let rechaza = |s: &str| {
            assert_eq!(
                ReciboEntregaAdjunto::leer_portable(s.as_bytes()).unwrap_err(),
                ErrorHub::Formato
            );
        };
        for (i, valor) in [
            (0, "x39-entrega-v1"),
            (4, "original"),
            (4, "DOCUMENTO"),
            (5, "integro"),
            (5, "PENDIENTE"),
            (1, ""),
            (3, "ab"),
        ] {
            let mut p = partes;
            p[i] = valor;
            rechaza(&p.join("|"));
        }
        for i in [1, 2, 3, 6, 7] {
            let mut p = partes;
            let mayuscula = format!("A{}", &p[i][1..]);
            p[i] = &mayuscula;
            rechaza(&p.join("|"));
        }
        rechaza(&format!("{portable}|00"));
        rechaza(&partes[..7].join("|"));
        rechaza(&format!("{portable}\n"));
        for clase in ["ORIGINAL", "COPIA_PROCESADA", "CAPSULA_EVIDENCIA"] {
            for resultado in ["INTEGRO", "RECHAZADO"] {
                let mut p = partes;
                p[4] = clase;
                p[5] = resultado;
                let texto = p.join("|");
                let r = ReciboEntregaAdjunto::leer_portable(texto.as_bytes()).unwrap();
                assert_eq!(r.texto_portable().unwrap(), texto);
            }
        }
    }

    #[test]
    fn tres_desajustes_de_huella_y_firma_alterada() {
        let (r, esperada) = muestra();
        let mut otra_pk = r.receptor_pk;
        otra_pk[0] ^= 1;
        let otra = HuellaDsa::de_clave(&otra_pk);
        assert_ne!(otra, esperada);
        assert_eq!(r.verificar(&otra), Err(ErrorHub::HuellaNoCoincide));
        let mut cambiada = r.clone();
        cambiada.receptor_fp = otra;
        assert_eq!(
            cambiada.verificar(&esperada),
            Err(ErrorHub::HuellaNoCoincide)
        );
        let mut cambiada = r.clone();
        cambiada.receptor_pk = otra_pk;
        assert_eq!(
            cambiada.verificar(&esperada),
            Err(ErrorHub::HuellaNoCoincide)
        );
        let mut cambiada = r;
        cambiada.firma_receptor[0] ^= 1;
        assert_eq!(cambiada.verificar(&esperada), Err(ErrorHub::Firma));
    }

    #[test]
    fn cierre_de_la_transferencia_del_emisor_y_orden_de_errores() {
        let (mut r, esperada) = muestra();
        let id = Id::de_hex(ID).unwrap();
        let archivo: Hash32 = hex_fijo(SELLO).unwrap();
        let otro_id = Id::de_hex("1234567890abcdee").unwrap();
        let mut otro_archivo = archivo;
        otro_archivo[0] ^= 1;
        assert_eq!(
            r.verificar_cierre(&esperada, &id, &archivo, CAPSULA),
            Ok(())
        );
        assert_eq!(
            r.verificar_cierre(&esperada, &otro_id, &archivo, CAPSULA),
            Err(ErrorHub::Formato)
        );
        assert_eq!(
            r.verificar_cierre(&esperada, &id, &archivo, ClaseAdjunto::Original),
            Err(ErrorHub::Formato)
        );
        assert_eq!(
            r.verificar_cierre(&esperada, &id, &otro_archivo, CAPSULA),
            Err(ErrorHub::HuellaNoCoincide)
        );
        r.firma_receptor[0] ^= 1;
        assert_eq!(
            r.verificar_cierre(&esperada, &id, &otro_archivo, CAPSULA),
            Err(ErrorHub::Firma)
        );
    }

    #[test]
    fn el_hash_la_clase_y_el_resultado_estan_firmados() {
        let (r, esperada) = muestra();
        let mut modificada = r.clone();
        modificada.sha256_recibido[0] ^= 1;
        assert_eq!(modificada.verificar(&esperada), Err(ErrorHub::Firma));
        let mut modificada = r.clone();
        modificada.clase = ClaseAdjunto::CopiaProcesada;
        assert_eq!(modificada.verificar(&esperada), Err(ErrorHub::Firma));
        let mut modificada = r;
        modificada.resultado = ResultadoEntrega::Rechazado;
        assert_eq!(modificada.verificar(&esperada), Err(ErrorHub::Firma));
    }

    #[test]
    fn contexto_de_entrega_y_firmas_de_los_otros_tres_recibos() {
        let (r, _) = muestra();
        let m = dato(VECTOR, "mensaje").as_bytes();
        assert!(firma::verify(
            &r.receptor_pk,
            m,
            b"x39-entrega-v1",
            &r.firma_receptor
        ));
        for ctx in [
            "",
            "x39-msg-v1",
            "x39-custodia-v1",
            "x39-cobro-btc-v1",
            "x39-rotacion-v1",
        ] {
            assert!(!firma::verify(
                &r.receptor_pk,
                m,
                ctx.as_bytes(),
                &r.firma_receptor
            ));
        }
        for (vector, clave, firma_hex) in [
            (CUSTODIA, "clave_publica_hex", "firma_hex"),
            (COBRO, "clave_publica_hex", "firma_hex"),
            (ROTACION, "nueva_pk_hex", "firma_nueva_hex"),
            (ROTACION, "anterior_pk_hex", "firma_anterior_hex"),
        ] {
            let pk = hex_fijo(dato(vector, clave)).unwrap();
            let firma = hex_fijo(dato(vector, firma_hex)).unwrap();
            let original = dato(vector, "mensaje").as_bytes();
            let contexto = dato(vector, "contexto").as_bytes();
            assert!(firma::verify(&pk, original, contexto, &firma));
            assert!(!firma::verify(&pk, original, CONTEXTO, &firma));
            let mut trasplante = r.clone();
            let esperada = HuellaDsa::de_clave(&pk);
            trasplante.receptor_fp = esperada;
            trasplante.receptor_pk = pk;
            trasplante.firma_receptor = firma;
            assert_eq!(trasplante.verificar(&esperada), Err(ErrorHub::Firma));
        }
    }

    #[test]
    fn emision_de_un_rechazo_y_disponibilidad_de_rng() {
        let id = Id::de_hex(ID).unwrap();
        let archivo: Hash32 = hex_fijo(SELLO).unwrap();
        #[cfg(feature = "rng")]
        let semilla = firma::generate_seed().unwrap();
        #[cfg(not(feature = "rng"))]
        let semilla = [0; firma::DSA_SEED_LEN];
        let emitido = ReciboEntregaAdjunto::firmar(
            &semilla,
            id.clone(),
            archivo,
            CAPSULA,
            ResultadoEntrega::Rechazado,
        );
        #[cfg(not(feature = "rng"))]
        assert_eq!(emitido.unwrap_err(), ErrorHub::Rng);
        #[cfg(feature = "rng")]
        {
            let esperada = HuellaDsa::de_clave(&firma::public_key(&semilla));
            let portable = emitido.unwrap().texto_portable().unwrap();
            let r = ReciboEntregaAdjunto::leer_portable(portable.as_bytes()).unwrap();
            assert_eq!(r.verificar(&esperada), Ok(()));
            assert_eq!(
                r.verificar_cierre(&esperada, &id, &archivo, CAPSULA),
                Err(ErrorHub::Formato)
            );
            let mut otro = archivo;
            otro[0] ^= 1;
            assert_eq!(
                r.verificar_cierre(&esperada, &id, &otro, CAPSULA),
                Err(ErrorHub::Formato)
            );
        }
    }
}

#[cfg(test)]
const SHA256_VECTOR: &str = "3033145ee3290a6042aa1ff46b7dc88b81e0b017ece8fde0d9658e85187fe66a";
