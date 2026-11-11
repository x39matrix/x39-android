use x39_core::ots::{Atestacion, Op, Prueba, Timestamp};
use x39_hub::ots_nodo::{
    CABECERA_BITCOIN_LEN, EstadoSelloBitcoin, NodoContraste, comprobar_bloque_con_nodo,
    inspeccionar_ots_sin_cabecera, raices_bitcoin_ots, verificar_cabecera_sin_nodo,
    verificar_pow_cabecera,
};
use x39_hub::{ErrorHub, de_hex_32, de_hex_exacto};

const SELLO_REAL: &[u8] = include_bytes!("../../x39-core/tests/fixtures/MASTER_GOLDEN_SEAL.txt.ots");
const HUELLA_REAL: &str = "08e9db781dc79c9fbbe77a56cd0120d2830650d4bcf52a2dae9acb73091d449c";
const HASH_950381: &str = "00000000000000000000250ec4552d1dbb441416f4409e50b9531528c8ec310c";
const CABECERA_950381: &str = "000000381c91e621324316979a5ea5900de864a2d6fe0412e32e00000000000000000000525f2bef6af79431c187eb8de8db9f2e08e33f5a493425317ec33f5f7864fe5e86180f6a790f0217fed3be59";
const HUELLA_SINTETICA: [u8; 32] = [0x42; 32];

struct Caso {
    sello: Prueba,
    huella: [u8; 32],
    cabecera: [u8; CABECERA_BITCOIN_LEN],
    hash_segun_nodo: [u8; 32],
}

impl Caso {
    fn sin_nodo(&self, altura: u64) -> Result<EstadoSelloBitcoin, ErrorHub> {
        verificar_cabecera_sin_nodo(&self.sello, &self.huella, altura, &self.cabecera)
    }

    fn con_nodo(&self, altura: u64, nodo: NodoContraste) -> Result<EstadoSelloBitcoin, ErrorHub> {
        comprobar_bloque_con_nodo(
            &self.sello,
            &self.huella,
            altura,
            &self.cabecera,
            &self.hash_segun_nodo,
            nodo,
        )
    }
}

fn caso_real() -> Caso {
    Caso {
        sello: Prueba::leer(SELLO_REAL).unwrap(),
        huella: de_hex_32(HUELLA_REAL).unwrap(),
        cabecera: de_hex_exacto::<CABECERA_BITCOIN_LEN>(CABECERA_950381).unwrap(),
        hash_segun_nodo: de_hex_32(HASH_950381).unwrap(),
    }
}

#[test]
fn inspeccion_del_sello_real_indica_el_bloque_950381() {
    let caso = caso_real();
    assert_eq!(caso.sello.huella(), caso.huella);
    assert_eq!(caso.sello.bloques_bitcoin(), [950_381, 950_398, 950_408]);

    let estado = inspeccionar_ots_sin_cabecera(&caso.sello, &caso.huella).unwrap();
    assert!(matches!(
        estado,
        EstadoSelloBitcoin::BloqueIndicado { altura: 950_381, .. }
    ));
}

#[test]
fn cabecera_real_sin_nodo_informa_trabajo_local() {
    let caso = caso_real();
    let estado = caso.sin_nodo(950_381).unwrap();

    assert!(estado.to_string().contains("SIN contrastar"));
    assert!(matches!(
        estado,
        EstadoSelloBitcoin::TrabajoLocalSinContrastarNodo {
            altura: 950_381,
            hash_cabecera,
            ..
        } if hash_cabecera == caso.hash_segun_nodo
    ));
}

#[test]
fn cabecera_real_con_nodo_x39_informa_bloque_comprobado() {
    let caso = caso_real();
    let estado = caso.con_nodo(950_381, NodoContraste::X39).unwrap();

    let texto = estado.to_string();
    assert!(texto.contains("nodo X39"));
    assert!(texto.contains(HASH_950381));
    assert!(matches!(
        estado,
        EstadoSelloBitcoin::BloqueComprobado {
            altura: 950_381,
            block_hash,
            nodo: NodoContraste::X39,
            ..
        } if block_hash == caso.hash_segun_nodo
    ));
}

#[test]
fn un_bit_distinto_en_el_hash_del_nodo_se_rechaza() {
    let mut caso = caso_real();
    caso.hash_segun_nodo[31] ^= 1;

    assert_eq!(
        caso.con_nodo(950_381, NodoContraste::X39),
        Err(ErrorHub::CabeceraNoCoincideConNodo)
    );
}

#[test]
fn huella_de_archivo_distinta_se_rechaza_en_las_tres_funciones() {
    let mut caso = caso_real();
    caso.huella[0] ^= 1;

    assert_eq!(
        inspeccionar_ots_sin_cabecera(&caso.sello, &caso.huella),
        Err(ErrorHub::Ots)
    );
    assert_eq!(caso.sin_nodo(950_381), Err(ErrorHub::Ots));
    assert_eq!(caso.con_nodo(950_381, NodoContraste::X39), Err(ErrorHub::Ots));
}

#[test]
fn cabecera_del_950381_se_rechaza_para_la_altura_atestada_950398() {
    let caso = caso_real();
    assert!(caso.sello.bloques_bitcoin().contains(&950_398));

    assert_eq!(caso.sin_nodo(950_398), Err(ErrorHub::Ots));
    assert_eq!(caso.con_nodo(950_398, NodoContraste::X39), Err(ErrorHub::Ots));
}

#[test]
fn altura_ausente_del_sello_se_rechaza() {
    let caso = caso_real();
    assert!(!caso.sello.bloques_bitcoin().contains(&950_382));

    assert_eq!(caso.sin_nodo(950_382), Err(ErrorHub::Ots));
    assert_eq!(caso.con_nodo(950_382, NodoContraste::X39), Err(ErrorHub::Ots));
}

#[test]
fn nodo_propio_con_nombre_vacio_se_rechaza() {
    let caso = caso_real();

    assert_eq!(
        caso.con_nodo(950_381, NodoContraste::Propio(String::new())),
        Err(ErrorHub::Formato)
    );
}

fn sello_sintetico(atestaciones: impl IntoIterator<Item = Atestacion>) -> Prueba {
    let (mut sello, compromiso) = Prueba::nueva(HUELLA_SINTETICA, [7; 16]).unwrap();
    let mut respuesta = Timestamp::new(compromiso.clone());
    let hoja = respuesta.anadir_op(Op::Sha256).unwrap();
    for atestacion in atestaciones {
        hoja.atestaciones.insert(atestacion);
    }
    sello.incorporar(&compromiso, &respuesta.serializar().unwrap()).unwrap();
    sello
}

fn caso_con_trabajo_facil(altura: u64) -> Caso {
    let sello = sello_sintetico([Atestacion::Bitcoin(altura)]);
    let raices = raices_bitcoin_ots(&sello);
    let [(altura_atestada, raiz)] = raices.as_slice() else {
        panic!("se esperaba una única raíz Bitcoin en el sello sintético");
    };
    assert_eq!(*altura_atestada, altura);

    let mut cabecera = [0u8; CABECERA_BITCOIN_LEN];
    cabecera[36..68].copy_from_slice(raiz);
    cabecera[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());

    for nonce in 0..1024_u32 {
        cabecera[76..80].copy_from_slice(&nonce.to_le_bytes());
        if let Ok(verificada) = verificar_pow_cabecera(&cabecera) {
            assert_eq!(&verificada.merkle_root, raiz);
            return Caso {
                sello,
                huella: HUELLA_SINTETICA,
                cabecera,
                hash_segun_nodo: verificada.block_hash,
            };
        }
    }
    panic!("ningún nonce de prueba ha satisfecho el objetivo 0x207fffff");
}

#[test]
fn trabajo_facil_en_960000_se_rechaza_con_y_sin_nodo() {
    let caso = caso_con_trabajo_facil(960_000);

    assert_eq!(caso.sin_nodo(960_000), Err(ErrorHub::TrabajoInsuficiente));
    assert_eq!(
        caso.con_nodo(960_000, NodoContraste::X39),
        Err(ErrorHub::TrabajoInsuficiente)
    );
}

#[test]
fn trabajo_facil_en_949999_se_rechaza_segun_el_modo() {
    let caso = caso_con_trabajo_facil(949_999);

    assert_eq!(caso.sin_nodo(949_999), Err(ErrorHub::AlturaSinModoSinRed));
    assert_eq!(
        caso.con_nodo(949_999, NodoContraste::X39),
        Err(ErrorHub::TrabajoInsuficiente)
    );
}

#[test]
fn sello_con_dos_calendarios_pendientes_informa_ambos() {
    let sello = sello_sintetico([
        Atestacion::Pendiente("https://uno.example".into()),
        Atestacion::Pendiente("https://dos.example".into()),
    ]);

    assert_eq!(
        inspeccionar_ots_sin_cabecera(&sello, &HUELLA_SINTETICA),
        Ok(EstadoSelloBitcoin::CalendarioRecibido {
            huella_archivo: HUELLA_SINTETICA,
            calendarios_pendientes: 2,
        })
    );
}
