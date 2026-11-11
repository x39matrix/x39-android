const SHA256_VECTOR: &str = "a68e727e38bc43a75acd8e6bd958fab235379a498a0e5f480800071ef3d65557";

use sha2::{Digest, Sha256};
use x39_core::firma;
use x39_hub::recibos::{HuellaDsa, ReciboCustodia};
use x39_hub::{ErrorHub, a_hex, de_hex_32};

const VECTOR: &str = include_str!("fixtures/custodia_v1.txt");

fn dato<'a>(lineas: &mut impl Iterator<Item = &'a str>, nombre: &str) -> &'a str {
    let (campo, valor) = lineas
        .next()
        .and_then(|linea| linea.split_once('='))
        .expect("falta una línea nombre=valor");
    assert_eq!(campo, nombre);
    assert!(!valor.is_empty(), "campo vacío: {nombre}");
    valor
}

#[test]
fn vector_congelado_de_custodia_y_cinco_rechazos() {
    assert_eq!(a_hex(&Sha256::digest(VECTOR.as_bytes())), SHA256_VECTOR);
    assert!(VECTOR.is_ascii());
    assert!(!VECTOR.contains('\r'));

    let mut lineas = VECTOR.strip_suffix('\n').expect("falta el LF final").split('\n');
    let mensaje = dato(&mut lineas, "mensaje");
    let contexto = dato(&mut lineas, "contexto");
    let huella = dato(&mut lineas, "huella_esperada");
    let clave_hex = dato(&mut lineas, "clave_publica_hex");
    let firma_hex = dato(&mut lineas, "firma_hex");
    let portable = dato(&mut lineas, "portable");
    assert!(lineas.next().is_none(), "sobran líneas en el vector");

    assert_eq!(contexto, "x39-custodia-v1");
    assert_eq!(
        mensaje,
        format!(
            "X39-CUSTODIA-v1|00b2c3d4e5f60718|{}|{}|{huella}|raiz|1800000000",
            "ab".repeat(32), "cd".repeat(32)
        )
    );
    assert_eq!(portable, format!("{mensaje}|{clave_hex}|{firma_hex}"));

    let esperada = HuellaDsa::de_hex(huella).unwrap();
    let recibo = ReciboCustodia::leer_portable(portable.as_bytes()).unwrap();
    assert_eq!(recibo.texto_canonico().unwrap(), mensaje);
    assert_eq!(recibo.texto_portable().unwrap(), portable);
    assert_eq!(a_hex(&recibo.custodio_pk), clave_hex);
    assert_eq!(a_hex(&recibo.firma_custodio), firma_hex);
    assert_eq!(a_hex(&Sha256::digest(recibo.custodio_pk)), huella);
    assert_eq!(recibo.verificar(&esperada), Ok(()));

    let comprobar = |datos: &[u8], ctx: &[u8]| {
        firma::verify(&recibo.custodio_pk, datos, ctx, &recibo.firma_custodio)
    };
    assert!(comprobar(mensaje.as_bytes(), contexto.as_bytes()));

    // Cambiar el mensaje, manteniendo los bytes originales de la firma.
    let con_salto = format!("{mensaje}\n");
    assert!(!comprobar(con_salto.as_bytes(), contexto.as_bytes()));
    assert!(!comprobar(mensaje.as_bytes(), b""));
    assert!(!comprobar(mensaje.as_bytes(), b"x39-msg-v1"));

    // Cambiar la huella que el verificador esperaba por un canal independiente.
    let mut otra_huella = de_hex_32(huella).unwrap();
    otra_huella[0] ^= 1;
    let otra_esperada = HuellaDsa::de_hex(&a_hex(&otra_huella)).unwrap();
    assert_eq!(recibo.verificar(&otra_esperada), Err(ErrorHub::HuellaNoCoincide));

    // Cambiar un byte de la firma sin alterar el mensaje, la clave ni el contexto.
    let mut alterado = recibo;
    alterado.firma_custodio[0] ^= 1;
    assert_eq!(alterado.verificar(&esperada), Err(ErrorHub::Firma));
}
