//! Verificador de recibos de x39 Evidencia desde el PC (lo que haría cualquiera con el recibo y la clave).
//!
//! ```text
//! recibo verificar <recibo.json> [clave_publica.bin]
//! ```
//! Comprueba: tamaños (clave 2.592, firma 4.627), que SHA-256(clave) == signer_fp del recibo, y que la
//! firma ML-DSA-87 (contexto vacío) verifica sobre «X39-EVIDENCIA-v1|<sha256>|<captured_at_local>».
//! Si el recibo lleva `signer_pk` (desde 0.2), la clave sale del propio recibo y no hace falta el fichero.
use sha2::{Digest, Sha256};
use std::fs;
use std::process;
use x39_core::firma::{self, DSA_PK_LEN, SIG_LEN};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [_, "verificar", recibo] => verificar(recibo, None),
        [_, "verificar", recibo, clave] => verificar(recibo, Some(clave)),
        _ => {
            eprintln!("uso: recibo verificar <recibo.json> [clave_publica.bin]");
            process::exit(2);
        }
    }
}

fn fallo(msg: String) -> ! {
    eprintln!("NO VERIFICA: {msg}");
    process::exit(1);
}

fn b64(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    for ch in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, b) in ch.iter().enumerate() {
            let v = A.iter().position(|x| x == b).unwrap_or_else(|| fallo("base64 inválido".into())) as u32;
            n |= v << (18 - 6 * i);
        }
        for i in 0..ch.len().saturating_sub(1) {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn verificar(recibo: &str, clave: Option<&str>) {
    let texto = fs::read_to_string(recibo).unwrap_or_else(|e| fallo(format!("no se pudo leer {recibo}: {e}")));
    let j: serde_json::Value = serde_json::from_str(&texto).unwrap_or_else(|e| fallo(format!("JSON: {e}")));
    let campo = |k: &str| j.get(k).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| fallo(format!("falta {k}")));
    let sha = campo("sha256");
    let hora = campo("captured_at_local");
    let fp = campo("signer_fp");
    let sig = b64(&campo("sig"));
    let pk_bytes = match (clave, j.get("signer_pk").and_then(|v| v.as_str())) {
        (Some(ruta), _) => fs::read(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {ruta}: {e}"))),
        (None, Some(s)) => b64(s),
        (None, None) => fallo("el recibo no lleva signer_pk y no se dio el fichero de la clave".into()),
    };
    println!("firma: {} bytes {}", sig.len(), if sig.len() == SIG_LEN { "✓" } else { "✗ (esperados 4627)" });
    println!("clave: {} bytes {}", pk_bytes.len(), if pk_bytes.len() == DSA_PK_LEN { "✓" } else { "✗ (esperados 2592)" });
    let pk: [u8; DSA_PK_LEN] = pk_bytes.clone().try_into().unwrap_or_else(|_| fallo("clave con longitud incorrecta".into()));
    let huella_pk: String = Sha256::digest(&pk_bytes).iter().map(|b| format!("{b:02x}")).collect();
    println!("SHA-256(clave) = {huella_pk}");
    println!("signer_fp      = {fp} {}", if huella_pk == fp { "✓ coincide" } else { "✗ NO coincide" });
    let canonico = format!("X39-EVIDENCIA-v1|{sha}|{hora}");
    println!("mensaje canónico: {canonico}");
    let ok = firma::verify(&pk, canonico.as_bytes(), b"", &sig);
    println!("firma ML-DSA-87 sobre el mensaje canónico: {}", if ok { "✓ válida para la clave con huella ".to_string() + &huella_pk[..16] + "…" } else { "✗ NO válida".to_string() });
    if !(ok && huella_pk == fp && sig.len() == SIG_LEN && pk_bytes.len() == DSA_PK_LEN) {
        process::exit(1);
    }
    println!("Lo que esto NO dice: quién es la persona detrás de la clave, ni la hora real (la hora es la declarada por el móvil); el ancla en Bitcoin se comprueba aparte con `ots verify`.");
}
