use x39_core::firma::*;
use x39_core::share::*;
use x39_core::*;

struct Persona {
    kem: KeyPair,
    semilla: zeroize::Zeroizing<[u8; DSA_SEED_LEN]>,
    firma_pk: [u8; DSA_PK_LEN],
}

fn persona() -> Persona {
    let semilla = generate_seed().unwrap();
    let firma_pk = public_key(&semilla);
    Persona { kem: generate_keypair().unwrap(), semilla, firma_pk }
}

#[test]
fn tamanos_ml_dsa_87() {
    let p = persona();
    assert_eq!(p.firma_pk.len(), 2592);
    let cuerpo = sign_for(&p.semilla, &p.kem.public, b"").unwrap();
    assert_eq!(cuerpo.len(), 1 + 4627);
    assert!(is_signed(&cuerpo));
}

#[test]
fn mensaje_firmado_de_extremo_a_extremo() {
    let alicia = persona();
    let bruno = persona();
    let carga = br#"{"v":1,"de":"a1","t":"hola Bruno","ts":1}"#;

    let cuerpo = sign_for(&alicia.semilla, &bruno.kem.public, carga).unwrap();
    let texto = encode_capsule(&seal(&bruno.kem.public, &cuerpo, b"", None, 1_790_000_000).unwrap());

    let (_, abierto) = open(&bruno.kem.secret, &decode_capsule(&texto).unwrap(), b"", Some(TtlPolicy { now: 1_790_000_000, ttl: 60 })).unwrap();
    assert_eq!(unverified_payload(&abierto).unwrap(), carga);
    assert_eq!(verify_from(&alicia.firma_pk, &bruno.kem.public, &abierto).unwrap(), carga);
}

#[test]
fn suplantacion_manipulacion_y_reenvio_se_rechazan() {
    let alicia = persona();
    let bruno = persona();
    let carla = persona();
    let malvado = persona();
    let carga = b"transferencia aprobada";
    let cuerpo = sign_for(&alicia.semilla, &bruno.kem.public, carga).unwrap();

    // Otra persona firmando en nombre de Alicia.
    let falso = sign_for(&malvado.semilla, &bruno.kem.public, carga).unwrap();
    assert_eq!(verify_from(&alicia.firma_pk, &bruno.kem.public, &falso).unwrap_err(), Error::Firma);

    // Bruno reenvía a Carla el mensaje que Alicia firmó para él.
    assert_eq!(verify_from(&alicia.firma_pk, &carla.kem.public, &cuerpo).unwrap_err(), Error::Firma);

    // Un bit cambiado en la firma o en la carga.
    for pos in [1, 2000, cuerpo.len() - 1] {
        let mut malo = cuerpo.to_vec();
        malo[pos] ^= 1;
        assert!(verify_from(&alicia.firma_pk, &bruno.kem.public, &malo).is_err(), "byte {pos}");
    }

    // Mensajes sin firma (x39 0.2) y cuerpos truncados.
    let v02 = br#"{"v":1,"de":"a1","t":"hola"}"#;
    assert!(!is_signed(v02));
    assert!(unverified_payload(v02).is_none());
    assert_eq!(verify_from(&alicia.firma_pk, &bruno.kem.public, v02).unwrap_err(), Error::Firma);
    assert!(verify_from(&alicia.firma_pk, &bruno.kem.public, &cuerpo[..100]).is_err());
}

#[test]
fn identidad_texto_y_huella() {
    let p = persona();
    let txt = encode_identity(&p.kem.public, &p.firma_pk);
    assert!(txt.starts_with(PREFIX_ID));
    let (kem, dsa) = decode_identity(&txt).unwrap();
    assert_eq!(kem, p.kem.public);
    assert_eq!(dsa, p.firma_pk);

    let partido: String = txt.chars().enumerate().flat_map(|(i, c)| if i > 0 && i % 76 == 0 { vec!['\n', c] } else { vec![c] }).collect();
    assert!(decode_identity(&partido).is_ok(), "saltos de línea del chat");

    let mut chars: Vec<char> = txt.chars().collect();
    let medio = chars.len() / 2;
    chars[medio] = if chars[medio] == 'A' { 'B' } else { 'A' };
    assert!(decode_identity(&chars.into_iter().collect::<String>()).is_err());

    let pk1 = encode_public_key(&p.kem.public);
    assert_eq!(decode_identity(&pk1).unwrap_err(), Error::Formato, "X39PK1 no es una identidad");
    assert_eq!(decode_public_key(&txt).unwrap_err(), Error::Formato, "X39ID1 no es un X39PK1");

    let h = fingerprint_identity(&p.kem.public, &p.firma_pk);
    assert_eq!(h, fingerprint_identity(&p.kem.public, &p.firma_pk));
    assert_ne!(h, fingerprint(&p.kem.public), "v2 distinta de v1");
    assert_ne!(h, fingerprint_identity(&p.kem.public, &persona().firma_pk), "cambia si cambia la clave de firma");
    assert_eq!(h.split(' ').count(), 12);
    println!("identidad X39ID1: {} caracteres", txt.len());
}
