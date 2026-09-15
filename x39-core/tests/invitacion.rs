use x39_core::Error;
use x39_core::firma;
use x39_core::invitacion::{self, PREFIX_INV};

fn autoridad() -> ([u8; 32], [u8; 2592]) {
    let seed = firma::generate_seed().unwrap();
    let pk = firma::public_key(&seed);
    (*seed, pk)
}

#[test]
fn ida_y_vuelta() {
    let (seed, pk) = autoridad();
    let texto = invitacion::emitir(&seed, "2026-12-31", "Concejalía de Cultura").unwrap();
    assert!(texto.starts_with(PREFIX_INV));
    let inv = invitacion::verificar(&pk, &texto, "2026-09-15").unwrap();
    assert_eq!(inv.caduca, "2026-12-31");
    assert_eq!(inv.nombre, "Concejalía de Cultura");
    // El último día de validez todavía vale.
    assert!(invitacion::verificar(&pk, &texto, "2026-12-31").is_ok());
}

#[test]
fn acepta_saltos_de_linea_de_los_chats() {
    let (seed, pk) = autoridad();
    let texto = invitacion::emitir(&seed, "2027-01-01", "Secretaría").unwrap();
    let partido: String = texto
        .chars()
        .enumerate()
        .flat_map(|(i, c)| if i % 60 == 59 { vec![c, '\n', ' '] } else { vec![c] })
        .collect();
    assert!(invitacion::verificar(&pk, &partido, "2026-09-15").is_ok());
}

#[test]
fn caducada() {
    let (seed, pk) = autoridad();
    let texto = invitacion::emitir(&seed, "2026-09-14", "Alguien").unwrap();
    assert_eq!(invitacion::verificar(&pk, &texto, "2026-09-15"), Err(Error::Caducada));
}

#[test]
fn otra_autoridad_no_vale() {
    let (seed, _) = autoridad();
    let (_, otra_pk) = autoridad();
    let texto = invitacion::emitir(&seed, "2026-12-31", "Alguien").unwrap();
    assert_eq!(invitacion::verificar(&otra_pk, &texto, "2026-09-15"), Err(Error::Firma));
}

#[test]
fn texto_alterado_se_rechaza() {
    let (seed, pk) = autoridad();
    let texto = invitacion::emitir(&seed, "2026-12-31", "Alguien").unwrap();
    // Cambiar un carácter del cuerpo rompe el check o la firma; nunca da una invitación válida.
    let mut chars: Vec<char> = texto.chars().collect();
    let i = chars.len() - 10;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let alterado: String = chars.into_iter().collect();
    assert!(invitacion::verificar(&pk, &alterado, "2026-09-15").is_err());
    assert_eq!(invitacion::verificar(&pk, "X39MSG1:abcd", "2026-09-15"), Err(Error::Formato));
}

#[test]
fn entradas_invalidas_al_emitir() {
    let (seed, _) = autoridad();
    assert_eq!(invitacion::emitir(&seed, "31-12-2026", "Alguien"), Err(Error::Formato));
    assert_eq!(invitacion::emitir(&seed, "2026-13-01", "Alguien"), Err(Error::Formato));
    assert_eq!(invitacion::emitir(&seed, "2026-12-31", ""), Err(Error::Formato));
    assert_eq!(invitacion::emitir(&seed, "2026-12-31", "con|barra"), Err(Error::Formato));
}
