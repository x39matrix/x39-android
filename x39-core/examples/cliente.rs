//! Cliente de pruebas de x39 desde el PC: hace lo mismo que la app (identidad, directorio y salas) con el
//! mismo motor, guardando su estado en una carpeta. Lo usa scripts/comprobar_salas.sh contra el canister real.
//!
//! ```text
//! cliente <carpeta> crear <invitacion.txt>              claves nuevas + acreditación → kem.pk kem.sk dsa.seed dsa.pk
//!                                                        acr.txt entrada.txt direccion.txt codigo.txt
//! cliente <carpeta> sobre <sala> <época> <para.kem.pk> <para.direccion>
//!                                                        entrega la clave de la sala (la crea si no existe) →
//!                                                        imprime el JSON de POST /sala/sobre
//! cliente <carpeta> abrir <sala> <época> <sobre.json> <remitente.dsa.pk>
//!                                                        abre un sobre recibido y guarda la clave de la sala
//! cliente <carpeta> mensaje <sala> <época> <texto>      imprime el JSON de POST /sala/mensaje
//! cliente <carpeta> miembro <sala> <direccion>          imprime el JSON de POST /sala/miembro
//! cliente <carpeta> leer <sala> <mensajes.json> <entrada.txt>...
//!                                                        comprueba cadena y firmas y descifra; imprime cada mensaje
//! ```
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use x39_core::firma::{self, DSA_PK_LEN, DSA_SEED_LEN};
use x39_core::{PK_LEN, SK_LEN, TtlPolicy, directorio, invitacion, sala, share};
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [_, dir, "crear", inv] => crear(dir, inv),
        [_, dir, "sobre", s, e, kem, para] => sobre(dir, s, e, kem, para),
        [_, dir, "abrir", s, e, json, pk] => abrir(dir, s, e, json, pk),
        [_, dir, "mensaje", s, e, texto] => mensaje(dir, s, e, texto),
        [_, dir, "miembro", s, direccion] => miembro(dir, s, direccion),
        [_, dir, "leer", s, json, entradas @ ..] if !entradas.is_empty() => leer(dir, s, json, entradas),
        [_, _, "kem-de", entrada, salida] => kem_de(entrada, salida),
        _ => {
            eprintln!("uso: ver cabecera de examples/cliente.rs");
            process::exit(2);
        }
    }
}

fn fallo(msg: String) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn ahora() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("reloj").as_secs()
}

fn escribir_privado(ruta: &Path, datos: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(ruta)
        .unwrap_or_else(|e| fallo(format!("no se pudo escribir {}: {e}", ruta.display())));
    f.write_all(datos).unwrap_or_else(|e| fallo(e.to_string()));
}

fn leer_bytes(ruta: &Path) -> Vec<u8> {
    fs::read(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {}: {e}", ruta.display())))
}

fn leer_texto(ruta: &Path) -> String {
    fs::read_to_string(ruta).unwrap_or_else(|e| fallo(format!("no se pudo leer {}: {e}", ruta.display()))).trim().to_string()
}

fn fijo<const N: usize>(datos: Vec<u8>, que: &str) -> [u8; N] {
    datos.try_into().unwrap_or_else(|_| fallo(format!("{que}: longitud incorrecta")))
}

struct Yo {
    dir: PathBuf,
    kem_pk: [u8; PK_LEN],
    seed: Zeroizing<[u8; DSA_SEED_LEN]>,
    direccion: String,
}

fn yo(dir: &str) -> Yo {
    let d = PathBuf::from(dir);
    let kem_pk: [u8; PK_LEN] = fijo(leer_bytes(&d.join("kem.pk")), "kem.pk");
    let seed = Zeroizing::new(fijo::<DSA_SEED_LEN>(leer_bytes(&d.join("dsa.seed")), "dsa.seed"));
    let direccion = directorio::direccion(&kem_pk);
    Yo { dir: d, kem_pk, seed, direccion }
}

fn crear(dir: &str, inv: &str) {
    let d = PathBuf::from(dir);
    fs::create_dir_all(&d).unwrap_or_else(|e| fallo(e.to_string()));
    let invitacion = leer_texto(Path::new(inv));
    let seed = firma::generate_seed().unwrap_or_else(|e| fallo(e.to_string()));
    let kem = x39_core::generate_keypair().unwrap_or_else(|e| fallo(e.to_string()));
    let acr = invitacion::acreditar(&seed, &invitacion).unwrap_or_else(|e| fallo(e.to_string()));
    let entrada = directorio::publicar(&seed, &kem.public, Some(&acr)).unwrap_or_else(|e| fallo(e.to_string()));
    let dsa_pk = firma::public_key(&seed);
    fs::write(d.join("kem.pk"), kem.public).unwrap();
    escribir_privado(&d.join("kem.sk"), kem.secret.as_slice());
    escribir_privado(&d.join("dsa.seed"), &*seed);
    fs::write(d.join("dsa.pk"), dsa_pk).unwrap();
    fs::write(d.join("acr.txt"), &acr).unwrap();
    fs::write(d.join("entrada.txt"), &entrada).unwrap();
    fs::write(d.join("direccion.txt"), directorio::direccion(&kem.public)).unwrap();
    fs::write(d.join("codigo.txt"), directorio::codigo_visible(&directorio::codigo(&dsa_pk))).unwrap();
    println!("direccion : {}", directorio::direccion(&kem.public));
    println!("codigo    : {}", directorio::codigo_visible(&directorio::codigo(&dsa_pk)));
}

fn ruta_clave(d: &Path, s: &str, epoca: u32) -> PathBuf {
    d.join(format!("sala-{s}-{epoca}.key"))
}

fn epoca(e: &str) -> u32 {
    e.parse().unwrap_or_else(|_| fallo("época no numérica".into()))
}

fn sobre(dir: &str, s: &str, e: &str, kem: &str, para: &str) {
    let yo = yo(dir);
    let ep = epoca(e);
    let ruta = ruta_clave(&yo.dir, s, ep);
    let clave: [u8; sala::CLAVE_LEN] = if ruta.exists() {
        fijo(leer_bytes(&ruta), "clave de sala")
    } else {
        let k = sala::nueva_clave().unwrap_or_else(|e| fallo(e.to_string()));
        escribir_privado(&ruta, &k);
        k
    };
    let para_kem: [u8; PK_LEN] = fijo(leer_bytes(Path::new(kem)), "clave KEM del destinatario");
    let carga = format!("{{\"sala\":\"{s}\",\"epoca\":{ep},\"clave\":\"{}\"}}", base64(&clave));
    let cuerpo = firma::sign_for(&yo.seed, &para_kem, carga.as_bytes()).unwrap_or_else(|e| fallo(e.to_string()));
    let capsula = x39_core::seal(&para_kem, &cuerpo, b"", None, ahora()).unwrap_or_else(|e| fallo(e.to_string()));
    let texto = share::encode_capsule(&capsula);
    let firma_txt = sala::firmar(&yo.seed, s, ep, &sala::accion_sobre(para, &texto)).unwrap_or_else(|e| fallo(e.to_string()));
    println!(
        "{{\"sala\":\"{s}\",\"epoca\":{ep},\"para\":\"{para}\",\"de\":\"{}\",\"sobre\":\"{texto}\",\"firma\":\"{firma_txt}\"}}",
        yo.direccion
    );
}

fn abrir(dir: &str, s: &str, e: &str, json: &str, pk: &str) {
    let yo = yo(dir);
    let ep = epoca(e);
    let j = leer_texto(Path::new(json));
    let texto = campo_json(&j, "sobre");
    let sk = Zeroizing::new(fijo::<SK_LEN>(leer_bytes(&yo.dir.join("kem.sk")), "kem.sk"));
    let remitente: [u8; DSA_PK_LEN] = fijo(leer_bytes(Path::new(pk)), "clave de firma del remitente");
    let capsula = share::decode_capsule(&texto).unwrap_or_else(|e| fallo(e.to_string()));
    let (_, pt) = x39_core::open(&sk, &capsula, b"", Some(TtlPolicy { now: ahora(), ttl: 10 * 365 * 24 * 3600 }))
        .unwrap_or_else(|e| fallo(e.to_string()));
    let carga = firma::verify_from(&remitente, &yo.kem_pk, &pt).unwrap_or_else(|e| fallo(format!("firma del sobre: {e}")));
    let carga = std::str::from_utf8(carga).unwrap_or_else(|_| fallo("carga no UTF-8".into()));
    if campo_json(carga, "sala") != s || campo_json(carga, "epoca") != ep.to_string() {
        fallo("el sobre es de otra sala o época".into());
    }
    let clave = de_base64(&campo_json(carga, "clave"));
    if clave.len() != sala::CLAVE_LEN {
        fallo("clave de sala con longitud incorrecta".into());
    }
    escribir_privado(&ruta_clave(&yo.dir, s, ep), &clave);
    println!("clave de la sala {s} (época {ep}) guardada");
}

fn mensaje(dir: &str, s: &str, e: &str, texto: &str) {
    let yo = yo(dir);
    let ep = epoca(e);
    let clave: [u8; sala::CLAVE_LEN] = fijo(leer_bytes(&ruta_clave(&yo.dir, s, ep)), "clave de sala");
    let m = sala::cifrar(&clave, s, ep, texto.as_bytes()).unwrap_or_else(|e| fallo(e.to_string()));
    let f = sala::firmar(&yo.seed, s, ep, &m).unwrap_or_else(|e| fallo(e.to_string()));
    println!("{{\"sala\":\"{s}\",\"epoca\":{ep},\"de\":\"{}\",\"msg\":\"{m}\",\"firma\":\"{f}\"}}", yo.direccion);
}

fn miembro(dir: &str, s: &str, direccion: &str) {
    let yo = yo(dir);
    let f = sala::firmar(&yo.seed, s, 0, &sala::accion_miembro(direccion)).unwrap_or_else(|e| fallo(e.to_string()));
    println!("{{\"sala\":\"{s}\",\"direccion\":\"{direccion}\",\"de\":\"{}\",\"firma\":\"{f}\"}}", yo.direccion);
}

fn leer(dir: &str, s: &str, json: &str, entradas: &[&str]) {
    let yo = yo(dir);
    let mut claves: Vec<(String, [u8; DSA_PK_LEN])> = Vec::new();
    for ruta in entradas {
        let e = directorio::leer(&leer_texto(Path::new(ruta))).unwrap_or_else(|e| fallo(format!("{ruta}: {e}")));
        claves.push((directorio::direccion(&e.kem_pk), e.dsa_pk));
    }
    let j = leer_texto(Path::new(json));
    // Lector mínimo: los mensajes vienen como objetos {"seq":..,"de":"..","epoca":..,"msg":"..","firma":"..","ts":..,"hash":".."}.
    let mut anterior = [0u8; 32];
    let mut ok = 0;
    for obj in objetos(&j, "mensajes") {
        let seq: u64 = campo_json(&obj, "seq").parse().unwrap_or_else(|_| fallo("seq".into()));
        let de = campo_json(&obj, "de");
        let ep: u32 = campo_json(&obj, "epoca").parse().unwrap_or_else(|_| fallo("epoca".into()));
        let msg = campo_json(&obj, "msg");
        let f = campo_json(&obj, "firma");
        let hash = campo_json(&obj, "hash");
        let calc = sala::hex(&sala::eslabon(&anterior, s, seq, &de, &msg, &f));
        let cadena = if calc == hash { "cadena ok" } else { "CADENA ROTA" };
        let firma_estado = match claves.iter().find(|(d, _)| *d == de) {
            Some((_, pk)) => match sala::verificar(pk, s, ep, &msg, &f) {
                Ok(()) => "firma ok",
                Err(_) => "FIRMA MAL",
            },
            None => "autor desconocido",
        };
        let ruta = ruta_clave(&yo.dir, s, ep);
        let texto = if ruta.exists() {
            let clave: [u8; sala::CLAVE_LEN] = fijo(leer_bytes(&ruta), "clave de sala");
            match sala::descifrar(&clave, s, ep, &msg) {
                Ok(t) => String::from_utf8_lossy(&t).into_owned(),
                Err(_) => "(no descifra)".into(),
            }
        } else {
            "(sin clave de esa época)".into()
        };
        println!("#{seq} de {}… · {firma_estado} · {cadena} · «{texto}»", &de[..8]);
        if cadena == "cadena ok" && firma_estado == "firma ok" {
            ok += 1;
        }
        anterior = sala::de_hex(&hash).unwrap_or([0u8; 32]);
    }
    println!("mensajes correctos: {ok}");
}

/// Saca la clave ML-KEM de una entrada del directorio (para entregarle un sobre a esa persona).
fn kem_de(entrada: &str, salida: &str) {
    let e = directorio::leer(&leer_texto(Path::new(entrada))).unwrap_or_else(|e| fallo(e.to_string()));
    fs::write(salida, e.kem_pk).unwrap_or_else(|e| fallo(e.to_string()));
    println!("{}", directorio::direccion(&e.kem_pk));
}

// ---- JSON mínimo (los cuerpos del canister son planos y sin escapes raros)

fn campo_json(j: &str, clave: &str) -> String {
    let pat = format!("\"{clave}\":");
    let i = j.find(&pat).unwrap_or_else(|| fallo(format!("falta {clave}"))) + pat.len();
    let resto = j[i..].trim_start();
    if let Some(r) = resto.strip_prefix('"') {
        let fin = r.find('"').unwrap_or(r.len());
        r[..fin].to_string()
    } else {
        let fin = resto.find([',', '}', ']']).unwrap_or(resto.len());
        resto[..fin].trim().to_string()
    }
}

fn objetos(j: &str, clave: &str) -> Vec<String> {
    let pat = format!("\"{clave}\":[");
    let Some(i) = j.find(&pat) else { return Vec::new() };
    let mut out = Vec::new();
    let mut prof = 0;
    let mut ini = 0;
    for (k, c) in j[i + pat.len()..].char_indices() {
        match c {
            '{' => {
                if prof == 0 {
                    ini = k;
                }
                prof += 1;
            }
            '}' => {
                prof -= 1;
                if prof == 0 {
                    out.push(j[i + pat.len() + ini..=i + pat.len() + k].to_string());
                }
            }
            ']' if prof == 0 => break,
            _ => {}
        }
    }
    out
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= ch.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn de_base64(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    for ch in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, b) in ch.iter().enumerate() {
            let v = A.iter().position(|x| x == b).unwrap_or_else(|| fallo("base64 inválido".into())) as u32;
            n |= v << (18 - 6 * i);
        }
        for i in 0..ch.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}
