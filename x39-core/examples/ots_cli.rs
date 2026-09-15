//! Herramienta de validación del cliente OpenTimestamps del motor contra calendarios reales.
//! La red la hace `curl` en scripts/probar_ots_calendarios.sh; esto solo monta y lee pruebas.
//!
//!   ots_cli compromiso <huella_hex> <nonce_hex>
//!   ots_cli montar <huella_hex> <nonce_hex> <salida.ots> <respuesta.bin>...
//!   ots_cli pendientes <prueba.ots>          → "uri mensaje_hex" por línea
//!   ots_cli actualizar <prueba.ots> <mensaje_hex> <respuesta.bin>
//!   ots_cli bloques <prueba.ots>

use std::process::exit;
use x39_core::ots::Prueba;

fn fijo<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).ok().and_then(|v| v.try_into().ok()).unwrap_or_else(|| {
        eprintln!("hex de {N} bytes esperado: {h}");
        exit(2)
    })
}

fn fallo<T>(r: Result<T, x39_core::Error>, que: &str) -> T {
    r.unwrap_or_else(|e| {
        eprintln!("{que}: {e}");
        exit(1)
    })
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("compromiso") if a.len() == 3 => {
            let (_, c) = fallo(Prueba::nueva(fijo(&a[1]), fijo(&a[2])), "compromiso");
            println!("{}", hex::encode(c));
        }
        Some("montar") if a.len() >= 5 => {
            let (mut p, c) = fallo(Prueba::nueva(fijo(&a[1]), fijo(&a[2])), "compromiso");
            for r in &a[4..] {
                let bytes = std::fs::read(r).expect("leer respuesta");
                fallo(p.incorporar(&c, &bytes), r);
            }
            std::fs::write(&a[3], fallo(p.serializar(), "serializar")).expect("escribir .ots");
            println!("{} · {} calendarios pendientes", a[3], p.pendientes().len());
        }
        Some("pendientes") if a.len() == 2 => {
            let p = fallo(Prueba::leer(&std::fs::read(&a[1]).expect("leer .ots")), "leer");
            for (uri, msg) in p.pendientes() {
                println!("{uri} {}", hex::encode(msg));
            }
        }
        Some("actualizar") if a.len() == 4 => {
            let mut p = fallo(Prueba::leer(&std::fs::read(&a[1]).expect("leer .ots")), "leer");
            let msg = hex::decode(&a[2]).expect("hex");
            fallo(p.incorporar(&msg, &std::fs::read(&a[3]).expect("leer respuesta")), "incorporar");
            std::fs::write(&a[1], fallo(p.serializar(), "serializar")).expect("escribir .ots");
            println!("bloques: {:?}", p.bloques_bitcoin());
        }
        Some("bloques") if a.len() == 2 => {
            let p = fallo(Prueba::leer(&std::fs::read(&a[1]).expect("leer .ots")), "leer");
            println!("{:?}", p.bloques_bitcoin());
        }
        _ => {
            eprintln!("uso: compromiso | montar | pendientes | actualizar | bloques (ver cabecera)");
            exit(2);
        }
    }
}
