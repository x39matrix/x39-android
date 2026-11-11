use super::{
    Hash32, HuellaDsa, Nonce, NoncesBloqueados, SemillaDsa, campos, entero_positivo,
    firmar_mensaje, hex_fijo,
};
use crate::{ErrorHub, a_hex};
use sha2::{Digest, Sha256};
use x39_core::firma::{self, DSA_PK_LEN, SIG_LEN};
use x39_core::{PK_LEN, share};

const PREFIJO: &str = "X39-ROTACION-v1";
const CONTEXTO: &[u8] = b"x39-rotacion-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentidadNueva {
    pub huella_dsa: HuellaDsa,
    pub clave_dsa: [u8; DSA_PK_LEN],
    pub clave_kem: [u8; PK_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaracionRotacionClave {
    pub anterior_fp: HuellaDsa,
    pub nueva_fp: HuellaDsa,
    pub emitida_unix_s: u64,
    pub nonce: Nonce,
    pub sha256_kem_nueva: Hash32,
    pub kem_nueva: [u8; PK_LEN],
    pub nueva_pk: [u8; DSA_PK_LEN],
    pub firma_nueva: [u8; SIG_LEN],
    /// Clave pública anterior y su firma, siempre juntas.
    pub anterior: Option<([u8; DSA_PK_LEN], [u8; SIG_LEN])>,
}

fn validar_kem(clave: &[u8; PK_LEN]) -> Result<[u8; PK_LEN], ErrorHub> {
    share::decode_public_key(&share::encode_public_key(clave))
        .map_err(|_| ErrorHub::ClaveCifradoInvalida)
}

impl DeclaracionRotacionClave {
    pub fn texto_canonico(&self) -> Result<String, ErrorHub> {
        if self.anterior_fp == self.nueva_fp || self.emitida_unix_s == 0 {
            return Err(ErrorHub::Formato);
        }
        Ok(format!(
            "{PREFIJO}|{}|{}|{}|{}|{}",
            self.anterior_fp, self.nueva_fp, self.emitida_unix_s,
            self.nonce.como_str(), a_hex(&self.sha256_kem_nueva)
        ))
    }

    pub fn texto_portable(&self) -> Result<String, ErrorHub> {
        let mut texto = format!(
            "{}|{}|{}|{}", self.texto_canonico()?, a_hex(&self.kem_nueva),
            a_hex(&self.nueva_pk), a_hex(&self.firma_nueva)
        );
        if let Some((clave, firma)) = &self.anterior {
            texto.push('|');
            texto.push_str(&a_hex(clave));
            texto.push('|');
            texto.push_str(&a_hex(firma));
        }
        Ok(texto)
    }

    /// Comprueba el formato de las dos variantes del sobre.
    pub fn leer_portable(entrada: &[u8]) -> Result<Self, ErrorHub> {
        let (base, anterior) = match entrada.iter().filter(|&&b| b == b'|').count() {
            8 => (campos::<9>(entrada)?, None),
            10 => {
                let [p, a, n, t, nonce, h, k, pk, s, pk_a, s_a] = campos::<11>(entrada)?;
                ([p, a, n, t, nonce, h, k, pk, s], Some((hex_fijo(pk_a)?, hex_fijo(s_a)?)))
            }
            _ => return Err(ErrorHub::Formato),
        };
        let [prefijo, antigua, nueva, hora, nonce, compromiso, kem, pk, firma] = base;
        if prefijo != PREFIJO {
            return Err(ErrorHub::Formato);
        }
        let declaracion = Self {
            anterior_fp: HuellaDsa::de_hex(antigua)?,
            nueva_fp: HuellaDsa::de_hex(nueva)?,
            emitida_unix_s: entero_positivo(hora)?,
            nonce: Nonce::de_hex(nonce)?,
            sha256_kem_nueva: hex_fijo(compromiso)?,
            kem_nueva: hex_fijo(kem)?,
            nueva_pk: hex_fijo(pk)?,
            firma_nueva: hex_fijo(firma)?,
            anterior,
        };
        if declaracion.texto_portable()?.as_bytes() != entrada {
            return Err(ErrorHub::Formato);
        }
        Ok(declaracion)
    }

    pub fn firmar_sin_anterior(
        anterior_fp: HuellaDsa,
        semilla_nueva: &SemillaDsa,
        kem_nueva: &[u8; PK_LEN],
        emitida_unix_s: u64,
        nonce: Nonce,
    ) -> Result<Self, ErrorHub> {
        let kem_nueva = validar_kem(kem_nueva)?;
        let nueva_pk = firma::public_key(semilla_nueva);
        let mut r = Self {
            anterior_fp,
            nueva_fp: HuellaDsa::de_clave(&nueva_pk),
            emitida_unix_s,
            nonce,
            sha256_kem_nueva: Sha256::digest(kem_nueva).into(),
            kem_nueva,
            nueva_pk,
            firma_nueva: [0; SIG_LEN],
            anterior: None,
        };
        r.firma_nueva = firmar_mensaje(semilla_nueva, &r.texto_canonico()?, CONTEXTO)?;
        Ok(r)
    }

    pub fn firmar_con_ambas(
        semilla_anterior: &SemillaDsa,
        semilla_nueva: &SemillaDsa,
        kem_nueva: &[u8; PK_LEN],
        emitida_unix_s: u64,
        nonce: Nonce,
    ) -> Result<Self, ErrorHub> {
        let pk = firma::public_key(semilla_anterior);
        let mut r = Self::firmar_sin_anterior(
            HuellaDsa::de_clave(&pk), semilla_nueva, kem_nueva, emitida_unix_s, nonce,
        )?;
        let firma = firmar_mensaje(semilla_anterior, &r.texto_canonico()?, CONTEXTO)?;
        r.anterior = Some((pk, firma));
        Ok(r)
    }

    /// La clave anterior autoriza la identidad nueva mediante la doble firma.
    /// En ambos caminos la agenda comprueba que anterior_fp sigue vigente para ese
    /// contacto y consume el nonce y sustituye la identidad en una única operación
    /// atómica. La caja solo consulta los nonces que le proporciona la agenda.
    pub fn verificar_con_firma_anterior(
        &self,
        anterior_esperada: &HuellaDsa,
        bloqueados: &dyn NoncesBloqueados,
    ) -> Result<IdentidadNueva, ErrorHub> {
        if self.anterior.is_none() {
            return Err(ErrorHub::Firma);
        }
        self.comprobar(anterior_esperada, None, bloqueados)
    }

    /// La huella nueva tiene que venir de fuera del recibo, por ejemplo, al volver a
    /// comparar el código en persona. Copiarla del propio recibo anula la comprobación.
    pub fn verificar_recuperacion(
        &self,
        anterior_esperada: &HuellaDsa,
        nueva_esperada_por_canal_externo: &HuellaDsa,
        bloqueados: &dyn NoncesBloqueados,
    ) -> Result<IdentidadNueva, ErrorHub> {
        self.comprobar(anterior_esperada, Some(nueva_esperada_por_canal_externo), bloqueados)
    }

    fn comprobar(
        &self,
        anterior_esperada: &HuellaDsa,
        nueva_externa: Option<&HuellaDsa>,
        bloqueados: &dyn NoncesBloqueados,
    ) -> Result<IdentidadNueva, ErrorHub> {
        let mensaje = self.texto_canonico()?;
        if anterior_esperada != &self.anterior_fp
            || nueva_externa.is_some_and(|fp| fp != &self.nueva_fp)
            || HuellaDsa::de_clave(&self.nueva_pk) != self.nueva_fp
            || self.anterior.as_ref().is_some_and(|(pk, _)| {
                HuellaDsa::de_clave(pk) != self.anterior_fp
            })
        {
            return Err(ErrorHub::HuellaNoCoincide);
        }

        if !firma::verify(&self.nueva_pk, mensaje.as_bytes(), CONTEXTO, &self.firma_nueva) {
            return Err(ErrorHub::Firma);
        }
        if let Some((pk, firma)) = &self.anterior {
            if !firma::verify(pk, mensaje.as_bytes(), CONTEXTO, firma) {
                return Err(ErrorHub::Firma);
            }
        }

        let clave_kem = validar_kem(&self.kem_nueva)?;
        let compromiso: Hash32 = Sha256::digest(clave_kem).into();
        if compromiso != self.sha256_kem_nueva {
            return Err(ErrorHub::HuellaNoCoincide);
        }
        if bloqueados.contiene(&self.nonce) {
            return Err(ErrorHub::Replay);
        }
        Ok(IdentidadNueva {
            huella_dsa: self.nueva_fp,
            clave_dsa: self.nueva_pk,
            clave_kem,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = include_str!("../../tests/fixtures/rotacion_v1.txt");
    const CUSTODIA: &str = include_str!("../../tests/fixtures/custodia_v1.txt");
    const COBRO: &str = include_str!("../../tests/fixtures/cobro_v1.txt");
    const NONCE: &str = "ffeeddccbbaa99887766554433221100";
    const NOMBRES: [&str; 10] = [
        "mensaje", "contexto", "anterior_esperada", "nueva_esperada",
        "kem_nueva_hex", "nueva_pk_hex", "firma_nueva_hex",
        "anterior_pk_hex", "firma_anterior_hex", "portable",
    ];

    fn datos<'a, const N: usize>(vector: &'a str, nombres: [&str; N]) -> [&'a str; N] {
        assert!(vector.is_ascii() && !vector.contains('\r'));
        let mut lineas = vector.strip_suffix('\n').unwrap().split('\n');
        let valores = nombres.map(|nombre| {
            let (campo, valor) = lineas.next().unwrap().split_once('=').unwrap();
            assert_eq!(campo, nombre);
            assert!(!valor.is_empty());
            valor
        });
        assert!(lineas.next().is_none());
        valores
    }

    fn muestra() -> (DeclaracionRotacionClave, HuellaDsa, HuellaDsa) {
        let v = datos(VECTOR, NOMBRES);
        (
            DeclaracionRotacionClave::leer_portable(v[9].as_bytes()).unwrap(),
            HuellaDsa::de_hex(v[2]).unwrap(),
            HuellaDsa::de_hex(v[3]).unwrap(),
        )
    }

    struct Vista<'a>(Option<&'a Nonce>);
    impl NoncesBloqueados for Vista<'_> {
        fn contiene(&self, nonce: &Nonce) -> bool { self.0 == Some(nonce) }
    }

    struct NoConsultar;
    impl NoncesBloqueados for NoConsultar {
        fn contiene(&self, _: &Nonce) -> bool {
            panic!("consulta de nonce prematura")
        }
    }

    #[test]
    fn vector_doble_y_sobre_sin_par_anterior() {
        assert_eq!(a_hex(&Sha256::digest(VECTOR.as_bytes())), SHA256_VECTOR);
        let [m, ctx, antigua, nueva, kem, pk_n, sig_n, pk_a, sig_a, portable] =
            datos(VECTOR, NOMBRES);
        let (r, a, n) = muestra();
        assert_eq!(ctx, "x39-rotacion-v1");
        assert_eq!(kem, a_hex(&r.kem_nueva));
        assert_eq!(pk_n, a_hex(&r.nueva_pk));
        assert_eq!(sig_n, a_hex(&r.firma_nueva));
        let (pk, sig) = r.anterior.as_ref().unwrap();
        assert_eq!(pk_a, a_hex(pk));
        assert_eq!(sig_a, a_hex(sig));
        assert_eq!(antigua, a_hex(&Sha256::digest(pk)));
        assert_eq!(nueva, a_hex(&Sha256::digest(r.nueva_pk)));

        let hash = a_hex(&Sha256::digest(r.kem_nueva));
        assert_eq!(m, format!("X39-ROTACION-v1|{antigua}|{nueva}|1900000100|{NONCE}|{hash}"));
        assert_eq!(r.texto_canonico().unwrap().as_bytes(), m.as_bytes());
        let solo = format!("{m}|{kem}|{pk_n}|{sig_n}");
        assert_eq!(portable, format!("{solo}|{pk_a}|{sig_a}"));
        assert_eq!(r.texto_portable().unwrap(), portable);

        let identidad = IdentidadNueva {
            huella_dsa: n, clave_dsa: r.nueva_pk, clave_kem: r.kem_nueva,
        };
        assert_eq!(r.verificar_con_firma_anterior(&a, &Vista(None)), Ok(identidad.clone()));
        assert_eq!(r.verificar_recuperacion(&a, &n, &Vista(None)), Ok(identidad.clone()));

        let recortado = DeclaracionRotacionClave::leer_portable(solo.as_bytes()).unwrap();
        assert!(recortado.anterior.is_none());
        assert_eq!(recortado.texto_portable().unwrap(), solo);
        assert_eq!(recortado.verificar_con_firma_anterior(&a, &NoConsultar), Err(ErrorHub::Firma));
        assert_eq!(recortado.verificar_recuperacion(&a, &n, &Vista(None)), Ok(identidad));
        assert_eq!(recortado.verificar_recuperacion(&n, &n, &NoConsultar),
            Err(ErrorHub::HuellaNoCoincide));
        assert_eq!(recortado.verificar_recuperacion(&a, &a, &NoConsultar),
            Err(ErrorHub::HuellaNoCoincide));
    }

    #[test]
    fn lector_estricto_campos_y_longitudes() {
        let partes: Vec<_> = datos(VECTOR, NOMBRES)[9].split('|').collect();
        let rechazo = |texto: String| {
            assert_eq!(DeclaracionRotacionClave::leer_portable(texto.as_bytes()).unwrap_err(),
                ErrorHub::Formato);
        };
        rechazo(partes[..10].join("|"));
        rechazo(format!("{}|extra", partes.join("|")));
        rechazo(format!("{}\n", partes.join("|")));
        for (i, valor) in [(1, partes[2]), (3, "0"), (3, "01900000100"), (4, "FF"), (5, "")] {
            let mut copia = partes.clone();
            copia[i] = valor;
            rechazo(copia.join("|"));
        }
        for i in [1, 2, 4, 5, 6, 7, 8, 9, 10] {
            let mut copia = partes.clone();
            let mayusculas = "A".repeat(copia[i].len());
            copia[i] = &mayusculas;
            rechazo(copia.join("|"));
            copia[i] = &partes[i][2..];
            rechazo(copia.join("|"));
            copia[i] = "";
            rechazo(copia.join("|"));
        }
    }

    fn error_en_ambas(
        r: &DeclaracionRotacionClave, a: &HuellaDsa, n: &HuellaDsa, error: ErrorHub,
    ) {
        assert_eq!(r.verificar_con_firma_anterior(a, &NoConsultar), Err(error));
        assert_eq!(r.verificar_recuperacion(a, n, &NoConsultar), Err(error));
    }

    #[test]
    fn huellas_firmas_y_precedencia() {
        let (r, a, n) = muestra();
        error_en_ambas(&r, &n, &n, ErrorHub::HuellaNoCoincide);

        let mut alterada = r.clone();
        alterada.nueva_pk = r.anterior.as_ref().unwrap().0;
        error_en_ambas(&alterada, &a, &n, ErrorHub::HuellaNoCoincide);
        let mut alterada = r.clone();
        alterada.anterior.as_mut().unwrap().0[0] ^= 1;
        error_en_ambas(&alterada, &a, &n, ErrorHub::HuellaNoCoincide);

        let mut alterada = r.clone();
        alterada.firma_nueva[0] ^= 1;
        error_en_ambas(&alterada, &a, &n, ErrorHub::Firma);
        let mut alterada = r;
        alterada.anterior.as_mut().unwrap().1[0] ^= 1;
        error_en_ambas(&alterada, &a, &n, ErrorHub::Firma);
        assert_eq!(alterada.verificar_recuperacion(&a, &n, &Vista(Some(&alterada.nonce))),
            Err(ErrorHub::Firma));
    }

    #[test]
    fn kem_invalida_kem_ajena_y_compromiso_alterado() {
        let (r, a, n) = muestra();
        let mut ajena = r.clone();
        // Cambiar la semilla pública final conserva la codificación de los coeficientes.
        ajena.kem_nueva[PK_LEN - 1] ^= 1;
        assert!(validar_kem(&ajena.kem_nueva).is_ok());
        error_en_ambas(&ajena, &a, &n, ErrorHub::HuellaNoCoincide);

        let mut invalida = r.clone();
        invalida.kem_nueva = [0xff; PK_LEN];
        assert_eq!(validar_kem(&invalida.kem_nueva), Err(ErrorHub::ClaveCifradoInvalida));
        error_en_ambas(&invalida, &a, &n, ErrorHub::ClaveCifradoInvalida);

        let mut alterada = r;
        alterada.sha256_kem_nueva[0] ^= 1;
        error_en_ambas(&alterada, &a, &n, ErrorHub::Firma);
    }

    #[test]
    fn el_nonce_bloqueado_se_rechaza_en_los_dos_caminos() {
        let (mut r, a, n) = muestra();
        assert_eq!(r.verificar_con_firma_anterior(&a, &Vista(Some(&r.nonce))), Err(ErrorHub::Replay));
        r.anterior = None;
        assert_eq!(r.verificar_recuperacion(&a, &n, &Vista(Some(&r.nonce))), Err(ErrorHub::Replay));
    }

    #[test]
    fn contextos_y_firmas_de_otros_recibos() {
        let (r, a, _) = muestra();
        let mensaje = r.texto_canonico().unwrap();
        let (pk_a, sig_a) = r.anterior.as_ref().unwrap();
        for (pk, sig) in [(pk_a, sig_a), (&r.nueva_pk, &r.firma_nueva)] {
            assert!(firma::verify(pk, mensaje.as_bytes(), b"x39-rotacion-v1", sig));
            for ctx in ["", "x39-msg-v1", "x39-custodia-v1", "x39-cobro-btc-v1", "x39-entrega-v1"] {
                assert!(!firma::verify(pk, mensaje.as_bytes(), ctx.as_bytes(), sig));
            }
        }

        for (vector, esperado) in [(CUSTODIA, "x39-custodia-v1"), (COBRO, "x39-cobro-btc-v1")] {
            let [msg, ctx, fp, pk, sig, _] = datos(vector, [
                "mensaje", "contexto", "huella_esperada", "clave_publica_hex", "firma_hex", "portable",
            ]);
            let mut otra = r.clone();
            otra.anterior = None;
            otra.nueva_pk = hex_fijo(pk).unwrap();
            otra.firma_nueva = hex_fijo(sig).unwrap();
            otra.nueva_fp = HuellaDsa::de_hex(fp).unwrap();
            assert_eq!(ctx, esperado);
            assert_eq!(HuellaDsa::de_clave(&otra.nueva_pk), otra.nueva_fp);
            assert!(firma::verify(&otra.nueva_pk, msg.as_bytes(), ctx.as_bytes(), &otra.firma_nueva));
            assert_eq!(otra.verificar_recuperacion(&a, &otra.nueva_fp, &NoConsultar),
                Err(ErrorHub::Firma));
        }
    }

    #[test]
    fn emision_con_clave_anterior_perdida_y_disponibilidad_de_rng() {
        let (r, a, _) = muestra();
        let semilla = [7; 32];
        let resultado = DeclaracionRotacionClave::firmar_sin_anterior(
            a, &semilla, &r.kem_nueva, 1, r.nonce.clone(),
        );
        #[cfg(feature = "rng")]
        {
            let nueva = HuellaDsa::de_clave(&firma::public_key(&semilla));
            let emitida = resultado.unwrap();
            assert!(emitida.anterior.is_none());
            let releida = DeclaracionRotacionClave::leer_portable(
                emitida.texto_portable().unwrap().as_bytes(),
            ).unwrap();
            assert_eq!(releida.verificar_recuperacion(&a, &nueva, &Vista(None)).unwrap().huella_dsa,
                nueva);
        }
        #[cfg(not(feature = "rng"))]
        {
            assert_eq!(resultado.unwrap_err(), ErrorHub::Rng);
            assert_eq!(DeclaracionRotacionClave::firmar_con_ambas(
                &[8; 32], &semilla, &r.kem_nueva, 1, r.nonce,
            ).unwrap_err(), ErrorHub::Rng);
        }
    }
}

#[cfg(test)]
const SHA256_VECTOR: &str = "fef218b105b1798c4e0100605e40c1de4c4427172d7ce8047ca1293557eba035";
