//! Monta el texto de identidad «X39ID1:…» a partir de las dos claves públicas de un móvil
//! (clave_publica.bin ML-KEM-1024 de 1568 bytes y firma_publica.bin ML-DSA-87 de 2592 bytes).
//! Uso: cargo run -q --example identidad -- <kem.bin> <dsa.bin>
use std::{env, fs, process};
use x39_core::PK_LEN;
use x39_core::firma::DSA_PK_LEN;
use x39_core::share;

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() != 3 {
        eprintln!("uso: identidad <kem.bin> <dsa.bin>");
        process::exit(2);
    }
    let kem: [u8; PK_LEN] = fs::read(&a[1])
        .unwrap_or_else(|e| fallo(&e.to_string()))
        .try_into()
        .unwrap_or_else(|_| fallo(&format!("{} no mide {PK_LEN} bytes", a[1])));
    let dsa: [u8; DSA_PK_LEN] = fs::read(&a[2])
        .unwrap_or_else(|e| fallo(&e.to_string()))
        .try_into()
        .unwrap_or_else(|_| fallo(&format!("{} no mide {DSA_PK_LEN} bytes", a[2])));
    eprintln!("huella: {}", share::fingerprint_identity(&kem, &dsa));
    println!("{}", share::encode_identity(&kem, &dsa));
}

fn fallo(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}
