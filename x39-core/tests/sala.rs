use x39_core::Error;
use x39_core::firma;
use x39_core::sala;

#[test]
fn ids_de_sala() {
    assert!(sala::sala_valida("general"));
    assert!(sala::sala_valida("los-remedios"));
    assert!(!sala::sala_valida("Los Remedios"));
    assert!(!sala::sala_valida("-a"));
    assert!(!sala::sala_valida(""));
}

#[test]
fn cifrar_descifrar_atado_a_sala_y_epoca() {
    let clave = sala::nueva_clave().unwrap();
    let m = sala::cifrar(&clave, "amate", 0, "hola sala".as_bytes()).unwrap();
    assert!(m.starts_with(sala::PREFIX_MSG));
    assert_eq!(sala::descifrar(&clave, "amate", 0, &m).unwrap(), b"hola sala");
    assert_eq!(sala::descifrar(&clave, "general", 0, &m).unwrap_err(), Error::Aead, "otra sala");
    assert_eq!(sala::descifrar(&clave, "amate", 1, &m).unwrap_err(), Error::Aead, "otra época");
    let otra = sala::nueva_clave().unwrap();
    assert_eq!(sala::descifrar(&otra, "amate", 0, &m).unwrap_err(), Error::Aead, "otra clave");
}

#[test]
fn firma_de_publicaciones() {
    let seed = firma::generate_seed().unwrap();
    let pk = firma::public_key(&seed);
    let clave = sala::nueva_clave().unwrap();
    let m = sala::cifrar(&clave, "amate", 0, b"x").unwrap();
    let f = sala::firmar(&seed, "amate", 0, &m).unwrap();
    assert!(f.starts_with(sala::PREFIX_FIRMA));
    assert!(sala::verificar(&pk, "amate", 0, &m, &f).is_ok());
    assert_eq!(sala::verificar(&pk, "general", 0, &m, &f).unwrap_err(), Error::Firma, "movida de sala");
    assert_eq!(sala::verificar(&pk, "amate", 1, &m, &f).unwrap_err(), Error::Firma);
    let otra = firma::public_key(&firma::generate_seed().unwrap());
    assert_eq!(sala::verificar(&otra, "amate", 0, &m, &f).unwrap_err(), Error::Firma);
    // Sobres y altas de miembro usan la misma firma con otra acción.
    let acc = sala::accion_sobre("abcd", "X39MSG1:zzz");
    let f2 = sala::firmar(&seed, "amate", 0, &acc).unwrap();
    assert!(sala::verificar(&pk, "amate", 0, &acc, &f2).is_ok());
    assert_eq!(sala::verificar(&pk, "amate", 0, &sala::accion_sobre("abce", "X39MSG1:zzz"), &f2).unwrap_err(), Error::Firma);
}

#[test]
fn cadena_de_eslabones() {
    let cero = [0u8; 32];
    let e1 = sala::eslabon(&cero, "amate", 1, "de1", "m1", "f1");
    let e2 = sala::eslabon(&e1, "amate", 2, "de2", "m2", "f2");
    assert_ne!(e1, e2);
    assert_eq!(sala::eslabon(&e1, "amate", 2, "de2", "m2", "f2"), e2, "determinista");
    assert_ne!(sala::eslabon(&cero, "amate", 2, "de2", "m2", "f2"), e2, "sin el anterior no cuadra");
    let h = sala::hex(&e2);
    assert_eq!(h.len(), 64);
    assert_eq!(sala::de_hex(&h).unwrap(), e2);
    assert!(sala::de_hex("zz").is_none());
}
