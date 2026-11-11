//! Cobros para Comunicaciones. Este módulo se puede probar sin una JVM.
#![forbid(unsafe_code)]

use x39_core::firma::DSA_SEED_LEN;
use x39_hub::ErrorHub;
use x39_hub::recibos::{HuellaDsa, Nonce, NoncesBloqueados, SolicitudCobroBtc};

/// Valores estables del entero que recibe la aplicación al verificar un cobro.
pub mod codigos {
    /// Se ha verificado el cobro.
    pub const CORRECTO: i32 = 0;
    /// Formato o argumento inválido, o red distinta de la esperada.
    pub const FORMATO: i32 = 1;
    /// Firma inválida.
    pub const FIRMA: i32 = 2;
    /// Las huellas comparadas no coinciden.
    pub const HUELLA_NO_COINCIDE: i32 = 3;
    /// Clave pública de cifrado inválida.
    pub const CLAVE_CIFRADO_INVALIDA: i32 = 4;
    /// Ha vencido el plazo del cobro.
    pub const CADUCADO: i32 = 5;
    /// El nonce ya está registrado.
    pub const REPLAY: i32 = 6;
    /// Prueba de inclusión Merkle inválida.
    pub const INCLUSION_MERKLE: i32 = 7;
    /// Error al comprobar un sello OpenTimestamps.
    pub const OTS: i32 = 8;
    /// Altura fuera del modo sin red.
    pub const ALTURA_SIN_MODO_SIN_RED: i32 = 9;
    /// Trabajo de la cabecera insuficiente.
    pub const TRABAJO_INSUFICIENTE: i32 = 10;
    /// El hash de la cabecera difiere del que declara el nodo.
    pub const CABECERA_NO_COINCIDE_CON_NODO: i32 = 11;
    /// Generador aleatorio no disponible.
    pub const RNG: i32 = 12;
}

fn codigo(resultado: Result<(), ErrorHub>) -> i32 {
    match resultado {
        Ok(()) => codigos::CORRECTO,
        Err(ErrorHub::Formato) => codigos::FORMATO,
        Err(ErrorHub::Firma) => codigos::FIRMA,
        Err(ErrorHub::HuellaNoCoincide) => codigos::HUELLA_NO_COINCIDE,
        Err(ErrorHub::ClaveCifradoInvalida) => codigos::CLAVE_CIFRADO_INVALIDA,
        Err(ErrorHub::Caducado) => codigos::CADUCADO,
        Err(ErrorHub::Replay) => codigos::REPLAY,
        Err(ErrorHub::InclusionMerkle) => codigos::INCLUSION_MERKLE,
        Err(ErrorHub::Ots) => codigos::OTS,
        Err(ErrorHub::AlturaSinModoSinRed) => codigos::ALTURA_SIN_MODO_SIN_RED,
        Err(ErrorHub::TrabajoInsuficiente) => codigos::TRABAJO_INSUFICIENTE,
        Err(ErrorHub::CabeceraNoCoincideConNodo) => codigos::CABECERA_NO_COINCIDE_CON_NODO,
        Err(ErrorHub::Rng) => codigos::RNG,
    }
}

/// Lectura sin autenticar. Sirve para consultar el registro de nonces de la app.
pub fn cobro_leer(portable: &[u8]) -> Result<String, ErrorHub> {
    let c = SolicitudCobroBtc::leer_portable(portable)?;
    Ok(format!(
        "{}|{}|{}|{}|{}|{}",
        c.red,
        c.direccion,
        c.satoshis,
        c.caduca_unix_s,
        c.nonce.como_str(),
        c.beneficiario_fp
    ))
}

/// Respuesta de la aplicación para el nonce del portable de esta llamada.
struct ConsultaNonce {
    ya_registrado: bool,
}

impl NoncesBloqueados for ConsultaNonce {
    fn contiene(&self, _: &Nonce) -> bool {
        self.ya_registrado
    }
}

/// La huella y la red esperadas proceden de la aplicación. Esta consulta el nonce
/// para la misma secuencia de bytes que pasa aquí y, tras CORRECTO, lo reserva
/// atómicamente antes de preparar el pago.
pub fn cobro_verificar(
    portable: &[u8],
    huella_esperada_hex: &str,
    red: &str,
    ahora_unix_s: i64,
    nonce_ya_registrado: bool,
) -> i32 {
    let resultado = SolicitudCobroBtc::leer_portable(portable).and_then(|c| {
        let esperada = HuellaDsa::de_hex(huella_esperada_hex)?;
        let red_esperada = red.parse()?;
        let ahora = u64::try_from(ahora_unix_s).map_err(|_| ErrorHub::Formato)?;
        c.verificar_antes_de_pagar(
            &esperada,
            red_esperada,
            ahora,
            &ConsultaNonce {
                ya_registrado: nonce_ya_registrado,
            },
        )
    });
    codigo(resultado)
}

/// Emite el portable con un nonce aleatorio. Toma prestados los bytes de la semilla.
pub fn cobro_firmar(
    semilla: &[u8],
    red: &str,
    direccion: &str,
    satoshis: i64,
    caduca_unix_s: i64,
) -> Result<Vec<u8>, ErrorHub> {
    let semilla: &[u8; DSA_SEED_LEN] = semilla.try_into().map_err(|_| ErrorHub::Formato)?;
    let importe = u64::try_from(satoshis).map_err(|_| ErrorHub::Formato)?;
    let caduca = u64::try_from(caduca_unix_s).map_err(|_| ErrorHub::Formato)?;
    let cobro = SolicitudCobroBtc::firmar_con_nonce_aleatorio(
        semilla,
        red.parse()?,
        direccion,
        importe,
        caduca,
    )?;
    Ok(cobro.texto_portable()?.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x39_core::firma;

    const VECTOR: &str = include_str!("../../x39-hub/tests/fixtures/cobro_v1.txt");
    const FP: &str = "1bbfdeac7aea3dce0c7be5903d8a5c3445c0f0f77dbeb428853c7db0b5e15d51";
    const DIRECCION: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const LIMITE: i64 = 2_000_000_000;

    fn portable() -> &'static [u8] {
        VECTOR
            .lines()
            .find_map(|linea| linea.strip_prefix("portable="))
            .expect("falta el portable congelado")
            .as_bytes()
    }

    #[test]
    fn lectura_exacta_y_verificacion_en_el_segundo_limite() {
        let esperado =
            format!("bitcoin|{DIRECCION}|24000|2000000000|00112233445566778899aabbccddeeff|{FP}");
        assert_eq!(cobro_leer(portable()).unwrap(), esperado);
        assert_eq!(cobro_verificar(portable(), FP, "bitcoin", LIMITE, false), 0);
    }

    #[test]
    fn caducidad_repeticion_red_y_huella() {
        let verificar =
            |fp, red, ahora, registrado| cobro_verificar(portable(), fp, red, ahora, registrado);
        assert_eq!(
            verificar(FP, "bitcoin", LIMITE + 1, false),
            codigos::CADUCADO
        );
        assert_eq!(verificar(FP, "bitcoin", LIMITE, true), codigos::REPLAY);
        assert_eq!(verificar(FP, "signet", LIMITE, false), codigos::FORMATO);
        assert_eq!(
            verificar(&"00".repeat(32), "bitcoin", LIMITE, false),
            codigos::HUELLA_NO_COINCIDE
        );
    }

    #[test]
    fn la_lectura_no_autentica_y_la_firma_se_juzga_antes_del_plazo_y_el_nonce() {
        let mut cobro = SolicitudCobroBtc::leer_portable(portable()).unwrap();
        cobro.firma[0] ^= 1;
        let alterado = cobro.texto_portable().unwrap();
        assert_eq!(cobro_leer(alterado.as_bytes()), cobro_leer(portable()));
        for (ahora, registrado) in [(LIMITE, false), (LIMITE + 1, true)] {
            assert_eq!(
                cobro_verificar(alterado.as_bytes(), FP, "bitcoin", ahora, registrado),
                codigos::FIRMA
            );
        }
    }

    #[test]
    fn emitir_leer_y_verificar_con_la_huella_del_firmante() {
        let semilla = firma::generate_seed().unwrap();
        let fp = HuellaDsa::de_clave(&firma::public_key(&semilla)).to_string();
        let portable =
            cobro_firmar(semilla.as_slice(), "bitcoin", DIRECCION, 24_000, LIMITE).unwrap();
        let lectura = cobro_leer(&portable).unwrap();
        let partes: [&str; 6] = lectura.split('|').collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(&partes[..4], &["bitcoin", DIRECCION, "24000", "2000000000"]);
        assert_eq!(partes[4].len(), 32);
        assert!(Nonce::de_hex(partes[4]).is_ok());
        assert_eq!(partes[5], fp);
        assert_eq!(cobro_verificar(&portable, &fp, "bitcoin", LIMITE, false), 0);
    }

    #[test]
    fn argumentos_invalidos_se_rechazan_sin_reinterpretar_el_signo() {
        assert_eq!(
            cobro_verificar(b"", FP, "bitcoin", LIMITE, false),
            codigos::FORMATO
        );
        assert_eq!(
            cobro_verificar(portable(), "ab", "bitcoin", LIMITE, false),
            codigos::FORMATO
        );
        assert_eq!(
            cobro_verificar(portable(), FP, "Bitcoin", LIMITE, false),
            codigos::FORMATO
        );
        assert_eq!(
            cobro_verificar(portable(), FP, "bitcoin", -1, false),
            codigos::FORMATO
        );
        let semilla = [0_u8; DSA_SEED_LEN];
        for (clave, sats, caduca) in [
            (&semilla[..31], 1, LIMITE),
            (&semilla[..], -1, LIMITE),
            (&semilla[..], 1, -1),
        ] {
            assert_eq!(
                cobro_firmar(clave, "bitcoin", DIRECCION, sats, caduca).err(),
                Some(ErrorHub::Formato)
            );
        }
    }

    #[test]
    fn codigos_estables_y_distintos_para_todas_las_variantes() {
        use ErrorHub::*;
        let resultados = [
            Ok(()),
            Err(Formato),
            Err(Firma),
            Err(HuellaNoCoincide),
            Err(ClaveCifradoInvalida),
            Err(Caducado),
            Err(Replay),
            Err(InclusionMerkle),
            Err(Ots),
            Err(AlturaSinModoSinRed),
            Err(TrabajoInsuficiente),
            Err(CabeceraNoCoincideConNodo),
            Err(Rng),
        ];
        assert_eq!(
            resultados.map(codigo),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        );
    }
}
