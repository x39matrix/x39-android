use serde_json::{Value, json};
use x39_core::*;

const DIR_VECTORES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectores");

fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex válido")
}

/// Los 59 vectores generados por Python con la lógica de Paris v3.
#[test]
fn vectores_paris_v3() {
    let raw = std::fs::read_to_string(format!("{DIR_VECTORES}/paris_v3.json"))
        .expect("falta vectores/paris_v3.json: ejecuta gen_paris_v3.py");
    let doc: Value = serde_json::from_str(&raw).unwrap();
    let sk: [u8; SK_LEN] = hexb(&doc["recipient_sk"]).try_into().unwrap();
    let base = hexb(&doc["plaintext_base"]);

    let mut guard = ReplayGuard::default();
    let mut ok = 0;
    let mut fallos = Vec::new();
    for v in doc["vectores"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let cap = hexb(&v["capsule"]);
        let aad = hexb(&v["aad"]);
        let ttl = v["ttl"].as_u64().unwrap();
        let pol = (ttl > 0).then(|| TtlPolicy { now: v["now"].as_u64().unwrap(), ttl });
        let expect = v["expect"].as_str().unwrap();

        let res = if v["cat"] == "REPLAY" {
            guard.open(&sk, &cap, &aad, pol)
        } else {
            open(&sk, &cap, &aad, pol)
        };
        let pass = match (expect, &res) {
            ("accept", Ok((_, pt))) => id != "C01" || pt.as_slice() == base.as_slice(),
            ("reject", Err(_)) => true,
            ("reject_si_R01_consumido", Err(Error::Replay)) => true,
            _ => false,
        };
        if pass {
            ok += 1;
        } else {
            let got = match &res {
                Ok(_) => "accept".to_string(),
                Err(e) => format!("reject({e:?})"),
            };
            fallos.push(format!("{id} {} expect={expect} got={got}", v["name"]));
        }
    }
    println!("vectores Paris v3 OK: {ok}/{}", doc["vectores"].as_array().unwrap().len());
    assert!(fallos.is_empty(), "fallos: {fallos:#?}");
}

#[test]
fn ida_y_vuelta_y_manipulacion() {
    let kp = generate_keypair().unwrap();
    let otra = generate_keypair().unwrap();
    let pt = b"x39: hola desde Rust";
    let cap = seal(&kp.public, pt, b"ctx", None, 1_790_000_000).unwrap();
    let pol = Some(TtlPolicy { now: 1_790_000_010, ttl: 60 });

    let (h, abierto) = open(&kp.secret, &cap, b"ctx", pol).unwrap();
    assert_eq!(abierto.as_slice(), pt);
    assert_eq!(h.ts, 1_790_000_000);

    for i in [0, 9, 20, 35, HEADER_LEN, HEADER_LEN + CT_KEM_LEN, cap.len() - 1] {
        let mut m = cap.clone();
        m[i] ^= 1;
        assert!(open(&kp.secret, &m, b"ctx", pol).is_err(), "bit {i} manipulado fue aceptado");
    }
    assert_eq!(open(&otra.secret, &cap, b"ctx", pol).unwrap_err(), Error::Aead);
    assert_eq!(open(&kp.secret, &cap, b"otro", pol).unwrap_err(), Error::Aead);

    let mut g = ReplayGuard::default();
    assert!(g.open(&kp.secret, &cap, b"ctx", pol).is_ok());
    assert_eq!(g.open(&kp.secret, &cap, b"ctx", pol).unwrap_err(), Error::Replay);
}

/// Deja cápsulas selladas por Rust para que `verificar_rust.py` las abra con la lógica de Paris.
#[test]
fn exporta_capsulas_para_python() {
    let kp = generate_keypair().unwrap();
    let grande = [7u8; 4096];
    let casos: [(&[u8], &[u8]); 3] = [(b"", b""), (b"hola Paris", b"x39-ctx"), (&grande, b"")];
    let capsulas: Vec<Value> = casos
        .iter()
        .map(|(pt, aad)| {
            let c = seal(&kp.public, pt, aad, None, 1_790_000_000).unwrap();
            json!({ "pt": hex::encode(pt), "aad": hex::encode(aad), "capsule": hex::encode(c) })
        })
        .collect();
    let doc = json!({
        "test_only": true,
        "recipient_sk": hex::encode(kp.secret.as_slice()),
        "capsulas": capsulas,
    });
    std::fs::write(
        format!("{DIR_VECTORES}/rust_sealed.json"),
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
}
