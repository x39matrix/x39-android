//! Herramienta de la autoridad (el Ayuntamiento): crea su clave ML-DSA-87 y emite invitaciones
//! para activar el modo personal de la app x39. Uso normal a través de scripts/invitaciones.sh.
//!
//! ```text
//! invitacion nueva-autoridad <semilla.bin>                 crea <semilla.bin> (0600) y <semilla.bin>.pk
//! invitacion emitir <semilla.bin> <AAAA-MM-DD> <nombre>    imprime el texto X39INV1:…
//! invitacion verificar <clave.pk> <AAAA-MM-DD hoy> <texto> comprueba una invitación
//! ```
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process;
use x39_core::firma::{self, DSA_PK_LEN, DSA_SEED_LEN};
use x39_core::invitacion;
use zeroize::Zeroizing;

const USO: &str = "uso:\n  invitacion nueva-autoridad <semilla.bin>\n  invitacion emitir <semilla.bin> <AAAA-MM-DD> <nombre o cargo>\n  invitacion verificar <clave.pk> <AAAA-MM-DD hoy> <texto X39INV1:...>";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [_, "nueva-autoridad", semilla] => nueva_autoridad(semilla),
        [_, "emitir", semilla, caduca, nombre] => emitir(semilla, caduca, nombre),
        [_, "verificar", clave, hoy, texto] => verificar(clave, hoy, texto),
        _ => {
            eprintln!("{USO}");
            process::exit(2);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fallo(msg: String) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn nueva_autoridad(ruta: &str) {
    let seed = firma::generate_seed().unwrap_or_else(|e| fallo(e.to_string()));
    let pk = firma::public_key(&seed);
    // Solo el propietario puede leer la semilla; nunca se sobrescribe una existente.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(ruta)
        .unwrap_or_else(|e| fallo(format!("no se pudo crear {ruta}: {e}")));
    f.write_all(&*seed).unwrap_or_else(|e| fallo(e.to_string()));
    let ruta_pk = format!("{ruta}.pk");
    fs::write(&ruta_pk, pk).unwrap_or_else(|e| fallo(format!("no se pudo escribir {ruta_pk}: {e}")));
    println!("semilla secreta : {ruta}  (solo la autoridad; sin ella no se pueden emitir invitaciones)");
    println!("clave pública   : {ruta_pk}  ({DSA_PK_LEN} bytes; va dentro de la app)");
    println!("huella SHA-256  : {}", hex(&Sha256::digest(pk)));
}

fn leer_semilla(ruta: &str) -> Zeroizing<[u8; DSA_SEED_LEN]> {
    let datos = Zeroizing::new(fs::read(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {ruta}: {e}"))));
    if datos.len() != DSA_SEED_LEN {
        fallo(format!("{ruta} no es una semilla de {DSA_SEED_LEN} bytes"));
    }
    let mut seed = Zeroizing::new([0u8; DSA_SEED_LEN]);
    seed.copy_from_slice(&datos);
    seed
}

fn emitir(semilla: &str, caduca: &str, nombre: &str) {
    let seed = leer_semilla(semilla);
    let texto = invitacion::emitir(&seed, caduca, nombre).unwrap_or_else(|e| fallo(e.to_string()));
    println!("{texto}");
}

fn verificar(clave: &str, hoy: &str, texto: &str) {
    let datos = fs::read(clave).unwrap_or_else(|e| fallo(format!("no se pudo leer {clave}: {e}")));
    let pk: [u8; DSA_PK_LEN] = datos
        .try_into()
        .unwrap_or_else(|_| fallo(format!("{clave} no es una clave pública ML-DSA-87 de {DSA_PK_LEN} bytes")));
    match invitacion::verificar(&pk, texto, hoy) {
        Ok(inv) => println!("VÁLIDA · para: {} · caduca: {}", inv.nombre, inv.caduca),
        Err(e) => {
            println!("NO VÁLIDA: {e}");
            process::exit(1);
        }
    }
}
