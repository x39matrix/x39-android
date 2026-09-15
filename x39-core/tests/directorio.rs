use x39_core::Error;
use x39_core::directorio::{self, PREFIX_DIR};
use x39_core::firma;
use x39_core::invitacion;

fn titular() -> ([u8; 32], [u8; 1568]) {
    let seed = firma::generate_seed().unwrap();
    let kem = x39_core::generate_keypair().unwrap();
    (*seed, kem.public)
}

#[test]
fn codigo_estable_y_legible() {
    let (seed, _) = titular();
    let pk = firma::public_key(&seed);
    let c = directorio::codigo(&pk);
    assert_eq!(c.len(), 12);
    assert_eq!(c, directorio::codigo(&pk), "determinista");
    assert!(c.bytes().all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b)));
    let visible = directorio::codigo_visible(&c);
    assert_eq!(visible.len(), 14);
    assert_eq!(directorio::normalizar_codigo(&visible).unwrap(), c);
    // Lo que teclea una persona: minúsculas, espacios, O por 0, l por 1.
    let tecleado = visible.to_lowercase().replace('-', " ").replace('0', "o").replace('1', "l");
    assert_eq!(directorio::normalizar_codigo(&tecleado).unwrap(), c);
    assert_eq!(directorio::normalizar_codigo("ABCD"), Err(Error::Formato));
    assert_eq!(directorio::normalizar_codigo("ABCD-EFGH-JK!M"), Err(Error::Formato));
}

#[test]
fn entrada_sin_acreditacion() {
    let (seed, kem) = titular();
    let texto = directorio::publicar(&seed, &kem, None).unwrap();
    assert!(texto.starts_with(PREFIX_DIR));
    let e = directorio::leer(&texto).unwrap();
    assert_eq!(e.kem_pk, kem);
    assert_eq!(e.dsa_pk, firma::public_key(&seed));
    assert_eq!(e.acreditacion, None);
    assert_eq!(e.codigo, directorio::codigo(&e.dsa_pk));
    assert!(directorio::leer_para_codigo(&texto, &e.codigo).is_ok());
    assert_eq!(directorio::leer_para_codigo(&texto, "000000000000").unwrap_err(), Error::Firma);
}

#[test]
fn entrada_con_acreditacion_y_manipulaciones() {
    let autoridad = firma::generate_seed().unwrap();
    let pk_autoridad = firma::public_key(&autoridad);
    let (seed, kem) = titular();
    let inv = invitacion::emitir(&autoridad, "2026-12-31", "María López · Cultura").unwrap();
    let acr = invitacion::acreditar(&seed, &inv).unwrap();
    let texto = directorio::publicar(&seed, &kem, Some(&acr)).unwrap();
    let e = directorio::leer(&texto).unwrap();
    assert_eq!(e.acreditacion.as_deref(), Some(acr.as_str()));
    let v = invitacion::verificar_acreditacion(&pk_autoridad, &e.dsa_pk, e.acreditacion.as_deref().unwrap(), "2026-09-15").unwrap();
    assert_eq!(v.nombre, "María López · Cultura");

    // Otra clave no puede publicar bajo este código: la firma de la entrada no cuadra con la clave que lleva.
    let (otra, _) = titular();
    let ajena = directorio::publicar(&otra, &kem, Some(&acr)).unwrap();
    assert_ne!(directorio::leer(&ajena).unwrap().codigo, e.codigo);
    // Un solo carácter cambiado dentro del cuerpo rompe el check (o la firma).
    let mut roto: Vec<char> = texto.chars().collect();
    let i = texto.len() / 2;
    roto[i] = if roto[i] == 'A' { 'B' } else { 'A' };
    let roto: String = roto.into_iter().collect();
    assert!(matches!(directorio::leer(&roto), Err(Error::Formato) | Err(Error::Firma)));
    // Una acreditación mal formada no se admite ni al publicar.
    assert_eq!(directorio::publicar(&seed, &kem, Some("hola")).unwrap_err(), Error::Formato);
}

#[test]
fn direccion_coincide_con_la_app() {
    let (_, kem) = titular();
    let d = directorio::direccion(&kem);
    assert_eq!(d.len(), 64);
    assert!(d.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}
