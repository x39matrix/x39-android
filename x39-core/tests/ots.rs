use sha2::{Digest, Sha256};
use x39_core::ots::*;
use x39_core::Error;

// Pruebas reales generadas por el cliente oficial `ots` y ya ancladas en Bitcoin (datos públicos).
const SELLO_DORADO: &[u8] = include_bytes!("fixtures/MASTER_GOLDEN_SEAL.txt.ots");
const BUNDLE_PQC: &[u8] = include_bytes!("fixtures/x39_cert_pqc_bundle.tar.gz.ots");

#[test]
fn lee_y_reescribe_byte_a_byte_pruebas_reales() {
    let casos: [(&[u8], &str, &[u64]); 2] = [
        (SELLO_DORADO, "08e9db781dc79c9fbbe77a56cd0120d2830650d4bcf52a2dae9acb73091d449c", &[950381, 950398, 950408]),
        (BUNDLE_PQC, "f6f8ccff11b39e2d0a251eabef5581b6aee56994e581a6207e32264bef72781d", &[953819, 953820, 953827, 953842]),
    ];
    for (bytes, huella, bloques) in casos {
        let p = Prueba::leer(bytes).unwrap();
        assert_eq!(hex::encode(p.huella()), huella);
        assert_eq!(p.bloques_bitcoin(), bloques);
        assert_eq!(p.serializar().unwrap(), bytes, "reescritura distinta del original");
    }
}

#[test]
fn pruebas_corruptas_se_rechazan() {
    assert_eq!(Prueba::leer(&SELLO_DORADO[..SELLO_DORADO.len() - 1]).unwrap_err(), Error::Ots, "truncada");
    let mut con_basura = SELLO_DORADO.to_vec();
    con_basura.push(0);
    assert_eq!(Prueba::leer(&con_basura).unwrap_err(), Error::Ots, "basura al final");
    let mut mala_magia = SELLO_DORADO.to_vec();
    mala_magia[1] ^= 1;
    assert_eq!(Prueba::leer(&mala_magia).unwrap_err(), Error::Ots, "magia");
    assert_eq!(Prueba::leer(b"").unwrap_err(), Error::Ots);
}

fn respuesta_simulada(compromiso: &[u8], prefijo: u8, uri: &str) -> Vec<u8> {
    let mut t = Timestamp::new(compromiso.to_vec());
    let nodo = t.anadir_op(Op::Prepend(vec![prefijo; 4])).unwrap().anadir_op(Op::Append(vec![0xbb; 8])).unwrap().anadir_op(Op::Sha256).unwrap();
    nodo.atestaciones.insert(Atestacion::Pendiente(uri.to_string()));
    t.serializar().unwrap()
}

#[test]
fn sello_nuevo_con_dos_calendarios_y_actualizacion() {
    let huella: [u8; 32] = Sha256::digest(b"foto de prueba").into();
    let nonce = [7u8; 16];
    let (mut p, compromiso) = Prueba::nueva(huella, nonce).unwrap();
    let esperado: Vec<u8> = Sha256::digest([huella.as_slice(), nonce.as_slice()].concat()).to_vec();
    assert_eq!(compromiso, esperado, "compromiso = sha256(huella || nonce), como `ots stamp`");
    assert_eq!(p.serializar().unwrap_err(), Error::Ots, "sin atestaciones no hay prueba que guardar");

    p.incorporar(&compromiso, &respuesta_simulada(&compromiso, 0xaa, "https://alice.btc.calendar.opentimestamps.org")).unwrap();
    p.incorporar(&compromiso, &respuesta_simulada(&compromiso, 0xcc, "https://bob.btc.calendar.opentimestamps.org")).unwrap();
    let pendientes = p.pendientes();
    assert_eq!(pendientes.len(), 2);

    // El calendario de Alice confirma: su nodo pendiente recibe una atestación de bloque.
    let (_, nodo_alice) = pendientes.iter().find(|(u, _)| u.contains("alice")).unwrap().clone();
    let mut mejora = Timestamp::new(nodo_alice.clone());
    mejora.anadir_op(Op::Prepend(vec![0x11; 32])).unwrap().anadir_op(Op::Sha256).unwrap().atestaciones.insert(Atestacion::Bitcoin(967_500));
    p.incorporar(&nodo_alice, &mejora.serializar().unwrap()).unwrap();
    assert_eq!(p.bloques_bitcoin(), vec![967_500]);

    let bytes = p.serializar().unwrap();
    let releida = Prueba::leer(&bytes).unwrap();
    assert_eq!(releida, p);
    assert_eq!(releida.serializar().unwrap(), bytes);

    // Una respuesta para otro compromiso no se puede colar en la prueba.
    let ajeno = [9u8; 32];
    assert_eq!(p.incorporar(&ajeno, &respuesta_simulada(&ajeno, 1, "https://x.example")).unwrap_err(), Error::Ots);
    std::fs::write(std::env::temp_dir().join("x39_ots_simulada.ots"), &bytes).unwrap();
}

#[test]
fn uri_con_caracteres_no_permitidos_se_rechaza() {
    let c = [3u8; 32];
    let mala = respuesta_simulada(&c, 1, "https://calendario.example/?q=1");
    assert_eq!(Timestamp::desde_respuesta(&c, &mala).unwrap_err(), Error::Ots);
}
