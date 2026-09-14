use x39_core::share::*;
use x39_core::*;

#[test]
fn clave_publica_texto_ida_y_vuelta() {
    let kp = generate_keypair().unwrap();
    let txt = encode_public_key(&kp.public);
    assert!(txt.starts_with(PREFIX_PK));
    assert_eq!(decode_public_key(&txt).unwrap(), kp.public);

    // Un chat que parte líneas o añade espacios no rompe nada.
    let partido: String = txt
        .chars()
        .enumerate()
        .flat_map(|(i, c)| if i > 0 && i % 60 == 0 { vec!['\n', ' ', c] } else { vec![c] })
        .collect();
    assert_eq!(decode_public_key(&partido).unwrap(), kp.public);
}

#[test]
fn mensaje_texto_abre_con_la_capsula() {
    let kp = generate_keypair().unwrap();
    let cap = seal(&kp.public, b"hola desde el bolsillo", b"", None, 1_790_000_000).unwrap();
    let txt = encode_capsule(&cap);
    let recuperada = decode_capsule(&txt).unwrap();
    let (_, pt) = open(&kp.secret, &recuperada, b"", Some(TtlPolicy { now: 1_790_000_000, ttl: 60 })).unwrap();
    assert_eq!(pt.as_slice(), b"hola desde el bolsillo");
}

#[test]
fn texto_corrupto_o_equivocado_se_rechaza() {
    let kp = generate_keypair().unwrap();
    let pk_txt = encode_public_key(&kp.public);
    let cap_txt = encode_capsule(&seal(&kp.public, b"x", b"", None, 0).unwrap());

    // Cambiar un solo carácter en cualquier posición del cuerpo.
    for pos in [PREFIX_PK.len(), pk_txt.len() / 2, pk_txt.len() - 1] {
        let mut chars: Vec<char> = pk_txt.chars().collect();
        chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
        let malo: String = chars.into_iter().collect();
        assert!(decode_public_key(&malo).is_err(), "carácter {pos} cambiado fue aceptado");
    }
    assert_eq!(decode_public_key(&pk_txt[..pk_txt.len() - 10]).unwrap_err(), Error::Formato);
    assert_eq!(decode_public_key(&cap_txt).unwrap_err(), Error::Formato, "mensaje pegado como clave");
    assert_eq!(decode_capsule(&pk_txt).unwrap_err(), Error::Formato, "clave pegada como mensaje");
    assert_eq!(decode_capsule("hola").unwrap_err(), Error::Formato);
}

#[test]
fn huella_de_seguridad() {
    let a = generate_keypair().unwrap();
    let b = generate_keypair().unwrap();
    let fa = fingerprint(&a.public);
    assert_eq!(fa, fingerprint(&a.public), "determinista");
    assert_ne!(fa, fingerprint(&b.public));
    let grupos: Vec<&str> = fa.split(' ').collect();
    assert_eq!(grupos.len(), 12);
    assert!(grupos.iter().all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    println!("huella de ejemplo: {fa}");
}

#[test]
fn cabe_en_un_qr() {
    let kp = generate_keypair().unwrap();
    let pk_txt = encode_public_key(&kp.public);
    assert!(pk_txt.len() <= QR_MAX_BYTES, "clave pública: {} > {}", pk_txt.len(), QR_MAX_BYTES);

    let max = max_plaintext_for_qr();
    let cap = seal(&kp.public, &vec![b'a'; max], b"", None, 0).unwrap();
    assert!(encode_capsule(&cap).len() <= QR_MAX_BYTES);
    let cap_mas = seal(&kp.public, &vec![b'a'; max + 1], b"", None, 0).unwrap();
    assert!(encode_capsule(&cap_mas).len() > QR_MAX_BYTES);
    println!("QR: clave pública = {} caracteres · mensaje máximo = {max} bytes de texto", pk_txt.len());
}
