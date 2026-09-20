//! x39-tunel — herramienta de línea de comandos del acuerdo de PSK del x39tunel.
//!
//! En el VPS (lo llama x39_signaling.py):
//!   tunel claves <dir>                      crea <dir>/tunel.sk y <dir>/tunel.pk (ML-KEM-1024)
//!   tunel huella <tunel.pk>                 huella SHA-256 de la clave pública (la que lleva la app)
//!   tunel abrir <tunel.sk> <tunel.pk> <pk_mldsa_b64> <ahora>   lee la cápsula (base64) por stdin
//!        → JSON {"bh","wg","psk","hasta","cid"}  · salida 1 y motivo por stderr si no vale
//! En el PC (pruebas):
//!   tunel pedir <tunel.pk> <semilla.hex> <wg_pk_b64> <horas> <ahora>   → cápsula base64 por stdout,
//!        la PSK en base64 por stderr (para compararla con la que aplica el servidor)
//!
//! Las claves se leen crudas (1568 / 3168 bytes) o en hex. La PSK sale solo por la
//! salida estándar del comando que la pide; no se escribe en ningún fichero.
use std::io::{Read, Write};
use x39_core::tunel;
use x39_core::{PK_LEN, SK_LEN};

fn leer_clave<const N: usize>(ruta: &str) -> [u8; N] {
    let datos = std::fs::read(ruta).unwrap_or_else(|e| fallo(&format!("no puedo leer {ruta}: {e}")));
    if datos.len() == N {
        return datos.try_into().unwrap();
    }
    let texto = String::from_utf8_lossy(&datos);
    let hexs: String = texto.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hexs.len() == N * 2 {
        let v: Vec<u8> = (0..N).map(|i| u8::from_str_radix(&hexs[2 * i..2 * i + 2], 16).unwrap()).collect();
        return v.try_into().unwrap();
    }
    fallo(&format!("{ruta}: esperaba {N} bytes crudos o {} hex", N * 2))
}

fn fallo(m: &str) -> ! {
    eprintln!("{m}");
    std::process::exit(1)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("claves") if a.len() == 3 => {
            let kp = x39_core::generate_keypair().unwrap_or_else(|e| fallo(&e.to_string()));
            let dir = std::path::Path::new(&a[2]);
            std::fs::create_dir_all(dir).unwrap_or_else(|e| fallo(&e.to_string()));
            let sk = dir.join("tunel.sk");
            let pk = dir.join("tunel.pk");
            std::fs::write(&sk, kp.secret.as_ref()).unwrap_or_else(|e| fallo(&e.to_string()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o600)).ok();
            }
            std::fs::write(&pk, kp.public).unwrap_or_else(|e| fallo(&e.to_string()));
            println!("secreta: {} (solo root)\npública: {}\nhuella: {}", sk.display(), pk.display(), tunel::huella_servidor(&kp.public));
        }
        Some("huella") if a.len() == 3 => {
            let pk = leer_clave::<PK_LEN>(&a[2]);
            println!("{}", tunel::huella_servidor(&pk));
        }
        // Clave pública ML-DSA-87 (base64) y huella de una semilla: para pruebas en el PC.
        Some("publica") if a.len() == 3 => {
            let seed = leer_clave::<32>(&a[2]);
            let pk = x39_core::firma::public_key(&seed);
            println!("{}", tunel::b64(&pk));
            eprintln!("huella {}", tunel::huella_identidad(&pk));
        }
        Some("pedir") if a.len() == 7 => {
            let pk = leer_clave::<PK_LEN>(&a[2]);
            let seed = leer_clave::<32>(&a[3]);
            let wg: [u8; 32] = tunel::de_b64(&a[4]).and_then(|v| v.try_into().ok()).unwrap_or_else(|| fallo("clave WireGuard: 32 bytes en base64"));
            let horas: u64 = a[5].parse().unwrap_or_else(|_| fallo("horas"));
            let ahora: u64 = a[6].parse().unwrap_or_else(|_| fallo("ahora (unix)"));
            let (cap, psk) = tunel::pedir_psk(&pk, &seed, &wg, ahora + horas * 3600, ahora).unwrap_or_else(|e| fallo(&e.to_string()));
            println!("{}", tunel::b64(&cap));
            eprintln!("{}", tunel::b64(psk.as_ref()));
        }
        Some("abrir") if a.len() == 6 => {
            let sk = leer_clave::<SK_LEN>(&a[2]);
            let pk = leer_clave::<PK_LEN>(&a[3]);
            let pk_dsa: [u8; x39_core::firma::DSA_PK_LEN] = tunel::de_b64(&a[4]).and_then(|v| v.try_into().ok()).unwrap_or_else(|| fallo("clave ML-DSA-87: 2592 bytes en base64"));
            let ahora: u64 = a[5].parse().unwrap_or_else(|_| fallo("ahora (unix)"));
            let mut entrada = String::new();
            std::io::stdin().read_to_string(&mut entrada).unwrap_or_else(|e| fallo(&e.to_string()));
            let cap = tunel::de_b64(entrada.trim()).unwrap_or_else(|| fallo("cápsula: base64 inválido"));
            let mut g = x39_core::ReplayGuard::default();
            let p = tunel::abrir_psk(&sk, &pk, &cap, ahora, &mut g, |_| Some(pk_dsa)).unwrap_or_else(|e| fallo(&e.to_string()));
            let cid: String = cap[16..32].iter().map(|b| format!("{b:02x}")).collect();
            let salida = format!(
                "{{\"bh\":\"{}\",\"wg\":\"{}\",\"psk\":\"{}\",\"hasta\":{},\"cid\":\"{}\"}}\n",
                p.bh, p.wg_pk_base64(), p.psk_base64().as_str(), p.hasta, cid
            );
            std::io::stdout().write_all(salida.as_bytes()).ok();
        }
        _ => fallo("uso: tunel claves <dir> | huella <pk> | pedir <pk> <semilla.hex> <wg_b64> <horas> <ahora> | abrir <sk> <pk> <pk_mldsa_b64> <ahora> < capsula.b64"),
    }
}
