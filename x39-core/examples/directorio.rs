//! Herramienta de prueba del directorio (canister/buzon): crea una identidad de mentira y su entrada
//! `X39DIR1:…`, o lee una entrada y dice su código. Solo para probar el canister desde el PC.
//!
//! ```text
//! directorio nueva [invitacion.txt]    crea claves nuevas (se descartan), las acredita si se da la
//!                                      invitación, e imprime: código, dirección y la entrada
//! directorio leer <entrada.txt>        verifica la entrada e imprime código, dirección y acreditación
//! ```
use std::fs;
use std::process;
use x39_core::directorio;
use x39_core::firma;
use x39_core::invitacion;

const USO: &str = "uso:\n  directorio nueva [invitacion.txt]\n  directorio leer <entrada.txt>";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [_, "nueva"] => nueva(None),
        [_, "nueva", inv] => nueva(Some(inv)),
        [_, "leer", ruta] => leer(ruta),
        _ => {
            eprintln!("{USO}");
            process::exit(2);
        }
    }
}

fn fallo(msg: String) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn nueva(invitacion: Option<&str>) {
    let seed = firma::generate_seed().unwrap_or_else(|e| fallo(e.to_string()));
    let kem = x39_core::generate_keypair().unwrap_or_else(|e| fallo(e.to_string()));
    let acr = invitacion.map(|ruta| {
        let inv = fs::read_to_string(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {ruta}: {e}")));
        invitacion::acreditar(&seed, &inv).unwrap_or_else(|e| fallo(e.to_string()))
    });
    let entrada = directorio::publicar(&seed, &kem.public, acr.as_deref()).unwrap_or_else(|e| fallo(e.to_string()));
    let e = directorio::leer(&entrada).unwrap_or_else(|e| fallo(e.to_string()));
    println!("codigo    : {}", directorio::codigo_visible(&e.codigo));
    println!("direccion : {}", directorio::direccion(&e.kem_pk));
    println!("{entrada}");
}

fn leer(ruta: &str) {
    let texto = fs::read_to_string(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {ruta}: {e}")));
    match directorio::leer(texto.trim()) {
        Ok(e) => {
            println!("VÁLIDA");
            println!("codigo    : {}", directorio::codigo_visible(&e.codigo));
            println!("direccion : {}", directorio::direccion(&e.kem_pk));
            println!("acreditacion: {}", e.acreditacion.map_or("ninguna".into(), |a| format!("{} caracteres", a.len())));
        }
        Err(e) => {
            println!("NO VÁLIDA: {e}");
            process::exit(1);
        }
    }
}
