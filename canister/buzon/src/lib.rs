//! x39 · buzón del Ayuntamiento: relé mínimo para los mensajes cifrados de la app, y directorio de claves.
//!
//! Solo guarda y entrega cápsulas `X39MSG1:…` (cifradas ML-KEM-1024 + AES-256-GCM y firmadas ML-DSA-87
//! en los móviles). El buzón NO puede leerlas; sí ve la dirección de destino (SHA-256 de la clave
//! pública del destinatario), el tamaño y la hora. Eso es lo que hay que decir de él.
//!
//! Se usa por HTTP a través de la pasarela `https://<canister>.raw.icp0.io`:
//!   POST /poner            cuerpo JSON {"para": <64 hex>, "msg": "X39MSG1:…"}   → {"seq": n}
//!   GET  /recoger?para=<64 hex>&desde=<seq>                                      → {"mensajes":[{"seq","ts","msg"}],"ultimo":n}
//!   GET  /estado                                                                 → {"mensajes": n, "ultimo": n, "directorio": n}
//! Límites: 16 000 caracteres por mensaje, 300 por destinatario, 20 000 en total, 14 días de vida.
//!
//! Directorio (desde 0.10): cada móvil publica su entrada `X39DIR1:…` (claves públicas + acreditación,
//! firmada por su propia clave; ver x39-core/src/directorio.rs) y los demás la piden por el código corto
//! de 12 símbolos o por la dirección de buzón. El canister solo guarda entradas que verifican, y el código
//! sale de la clave firmada: nadie puede publicar bajo el código de otro.
//!   POST /publicar         cuerpo JSON {"entrada": "X39DIR1:…"}                 → {"codigo": "XXXX-XXXX-XXXX", "direccion": <64 hex>}
//!   GET  /buscar?codigo=XXXX-XXXX-XXXX   o   /buscar?dir=<16..64 hex>            → {"entrada": "X39DIR1:…", "codigo", "direccion", "ts"}
//! Límites: 40 000 caracteres por entrada, 2 000 entradas, 365 días sin renovar. Lo que revela: claves
//! públicas y acreditación (nombre, fecha) de quien publica, a quien sepa su código o su dirección.
//! No hay control de quién escribe: cualquiera con la URL puede dejar mensajes (la app descarta los que no
//! vengan firmados por un contacto). Pendiente para después del 30/09: exigir invitación o firma al poner.

use candid::CandidType;
use ic_cdk::api::time;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use x39_core::directorio;

const MAX_MSG: usize = 16_000;
const MAX_POR_DESTINO: usize = 300;
const MAX_TOTAL: usize = 20_000;
const VIDA_NS: u64 = 14 * 24 * 3600 * 1_000_000_000;
const LOTE: usize = 30;
const MAX_ENTRADA: usize = 40_000;
const MAX_FICHAS: usize = 2_000;
const VIDA_FICHA_NS: u64 = 365 * 24 * 3600 * 1_000_000_000;
/// Mínimo de caracteres de dirección para buscar: el identificador de contacto de la app (16 hex).
const MIN_DIR: usize = 16;

#[derive(CandidType, Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: ByteBuf,
}

#[derive(CandidType, Deserialize)]
struct HttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: ByteBuf,
    upgrade: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, CandidType)]
struct Entrada {
    seq: u64,
    para: String,
    msg: String,
    ts: u64,
}

/// Una entrada del directorio ya verificada.
#[derive(Clone, Serialize, Deserialize, CandidType)]
struct Ficha {
    codigo: String,
    direccion: String,
    entrada: String,
    ts: u64,
}

#[derive(Default, Serialize, Deserialize, CandidType)]
struct Estado {
    ultimo: u64,
    entradas: Vec<Entrada>,
    /// `opt` para poder restaurar el estado guardado por la versión sin directorio.
    directorio: Option<Vec<Ficha>>,
}

thread_local! {
    static ESTADO: RefCell<Estado> = RefCell::new(Estado::default());
}

#[derive(Serialize)]
struct Salida<'a> {
    seq: u64,
    ts: u64,
    msg: &'a str,
}

fn json(status: u16, cuerpo: String) -> HttpResponse {
    HttpResponse {
        status_code: status,
        headers: vec![
            ("Content-Type".into(), "application/json; charset=utf-8".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: ByteBuf::from(cuerpo.into_bytes()),
        upgrade: None,
    }
}

fn error(status: u16, msg: &str) -> HttpResponse {
    json(status, format!("{{\"error\":{}}}", serde_json::to_string(msg).unwrap_or_default()))
}

fn ruta_y_consulta(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((r, q)) => (r, q),
        None => (url, ""),
    }
}

fn parametro<'a>(consulta: &'a str, nombre: &str) -> Option<&'a str> {
    consulta
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == nombre)
        .map(|(_, v)| v)
}

fn direccion_valida(d: &str) -> bool {
    d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit())
}

fn purgar(e: &mut Estado, ahora: u64) {
    e.entradas.retain(|x| ahora.saturating_sub(x.ts) < VIDA_NS);
    if e.entradas.len() > MAX_TOTAL {
        let sobra = e.entradas.len() - MAX_TOTAL;
        e.entradas.drain(0..sobra);
    }
    if let Some(d) = e.directorio.as_mut() {
        d.retain(|f| ahora.saturating_sub(f.ts) < VIDA_FICHA_NS);
        if d.len() > MAX_FICHAS {
            let sobra = d.len() - MAX_FICHAS;
            d.drain(0..sobra);
        }
    }
}

fn ficha_json(f: &Ficha) -> String {
    serde_json::json!({
        "entrada": f.entrada,
        "codigo": directorio::codigo_visible(&f.codigo),
        "direccion": f.direccion,
        "ts": f.ts,
    })
    .to_string()
}

fn buscar(consulta: &str) -> HttpResponse {
    ESTADO.with(|s| buscar_en(&s.borrow(), consulta))
}

fn buscar_en(s: &Estado, consulta: &str) -> HttpResponse {
    // El parámetro llega tal cual se escribió en la URL: los guiones no se codifican.
    let por_codigo = parametro(consulta, "codigo").map(|c| c.replace("%2D", "-"));
    let por_dir = parametro(consulta, "dir").map(str::to_ascii_lowercase);
    let codigo = match por_codigo.as_deref() {
        Some(c) => match directorio::normalizar_codigo(c) {
            Ok(n) => Some(n),
            Err(_) => return error(400, "codigo invalido: son 12 letras o numeros"),
        },
        None => None,
    };
    if let Some(d) = por_dir.as_deref() {
        if d.len() < MIN_DIR || d.len() > 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
            return error(400, "dir invalida");
        }
    }
    if codigo.is_none() && por_dir.is_none() {
        return error(400, "falta codigo o dir");
    }
    let vacio = Vec::new();
    let d = s.directorio.as_ref().unwrap_or(&vacio);
    let hallada = d.iter().rev().find(|f| {
        codigo.as_deref().is_none_or(|c| f.codigo == c) && por_dir.as_deref().is_none_or(|p| f.direccion.starts_with(p))
    });
    match hallada {
        Some(f) => json(200, ficha_json(f)),
        None => error(404, "no esta en el directorio"),
    }
}

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.method == "POST" {
        // La pasarela vuelve a llamar a http_request_update, que sí puede escribir.
        return HttpResponse {
            status_code: 200,
            headers: vec![],
            body: ByteBuf::new(),
            upgrade: Some(true),
        };
    }
    let (ruta, consulta) = ruta_y_consulta(&req.url);
    match (req.method.as_str(), ruta) {
        ("GET", "/estado") => ESTADO.with(|s| {
            let s = s.borrow();
            let fichas = s.directorio.as_ref().map_or(0, Vec::len);
            json(200, format!("{{\"mensajes\":{},\"ultimo\":{},\"directorio\":{}}}", s.entradas.len(), s.ultimo, fichas))
        }),
        ("GET", "/recoger") => {
            let Some(para) = parametro(consulta, "para") else {
                return error(400, "falta para");
            };
            if !direccion_valida(para) {
                return error(400, "direccion invalida");
            }
            let desde: u64 = parametro(consulta, "desde").and_then(|d| d.parse().ok()).unwrap_or(0);
            ESTADO.with(|s| {
                let s = s.borrow();
                let lote: Vec<Salida> = s
                    .entradas
                    .iter()
                    .filter(|e| e.para == para && e.seq > desde)
                    .take(LOTE)
                    .map(|e| Salida { seq: e.seq, ts: e.ts, msg: &e.msg })
                    .collect();
                let cuerpo = serde_json::json!({ "mensajes": lote, "ultimo": s.ultimo });
                json(200, cuerpo.to_string())
            })
        }
        ("GET", "/buscar") => buscar(consulta),
        _ => error(404, "no existe"),
    }
}

#[derive(Deserialize)]
struct Peticion {
    para: String,
    msg: String,
}

#[derive(Deserialize)]
struct Publicacion {
    entrada: String,
}

fn poner_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: Peticion = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if !direccion_valida(&p.para) {
        return error(400, "direccion invalida");
    }
    if !p.msg.starts_with("X39MSG1:") || p.msg.len() > MAX_MSG || p.msg.chars().any(char::is_whitespace) {
        return error(400, "mensaje invalido");
    }
    purgar(s, ahora);
    let del_destino = s.entradas.iter().filter(|e| e.para == p.para).count();
    if del_destino >= MAX_POR_DESTINO {
        if let Some(i) = s.entradas.iter().position(|e| e.para == p.para) {
            s.entradas.remove(i);
        }
    }
    s.ultimo += 1;
    let seq = s.ultimo;
    s.entradas.push(Entrada { seq, para: p.para, msg: p.msg, ts: ahora });
    json(200, format!("{{\"seq\":{seq}}}"))
}

fn publicar_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: Publicacion = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if p.entrada.len() > MAX_ENTRADA || p.entrada.chars().any(char::is_whitespace) {
        return error(400, "entrada demasiado grande o con espacios");
    }
    // Aquí está la garantía del directorio: solo entra lo que firma la clave que lleva dentro.
    let e = match directorio::leer(&p.entrada) {
        Ok(e) => e,
        Err(err) => return error(400, &format!("entrada no valida: {err}")),
    };
    let ficha = Ficha {
        codigo: e.codigo.clone(),
        direccion: directorio::direccion(&e.kem_pk),
        entrada: p.entrada,
        ts: ahora,
    };
    purgar(s, ahora);
    let d = s.directorio.get_or_insert_with(Vec::new);
    // Una entrada nueva del mismo titular sustituye a la anterior (renovación o acreditación nueva).
    d.retain(|f| f.codigo != ficha.codigo);
    let respuesta = format!(
        "{{\"codigo\":\"{}\",\"direccion\":\"{}\"}}",
        directorio::codigo_visible(&ficha.codigo),
        ficha.direccion
    );
    d.push(ficha);
    json(200, respuesta)
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let (ruta, _) = ruta_y_consulta(&req.url);
    ESTADO.with(|s| {
        let mut s = s.borrow_mut();
        match (req.method.as_str(), ruta) {
            ("POST", "/poner") => poner_en(&mut s, &req.body, time()),
            ("POST", "/publicar") => publicar_en(&mut s, &req.body, time()),
            _ => error(404, "no existe"),
        }
    })
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    ESTADO.with(|s| {
        let s = s.borrow();
        ic_cdk::storage::stable_save((&*s,)).expect("no se pudo guardar el buzón");
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    if let Ok((estado,)) = ic_cdk::storage::stable_restore::<(Estado,)>() {
        ESTADO.with(|s| *s.borrow_mut() = estado);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x39_core::firma;

    fn cuerpo(r: &HttpResponse) -> String {
        String::from_utf8(r.body.to_vec()).unwrap()
    }

    fn entrada(acreditacion: Option<&str>) -> (String, String, String) {
        let seed = firma::generate_seed().unwrap();
        let kem = x39_core::generate_keypair().unwrap();
        let e = directorio::publicar(&seed, &kem.public, acreditacion).unwrap();
        let leida = directorio::leer(&e).unwrap();
        (e, directorio::codigo_visible(&leida.codigo), directorio::direccion(&kem.public))
    }

    fn publicacion(e: &str) -> Vec<u8> {
        serde_json::json!({ "entrada": e }).to_string().into_bytes()
    }

    #[test]
    fn publicar_y_buscar_por_codigo_y_direccion() {
        let mut s = Estado::default();
        let (e, codigo, dir) = entrada(None);
        let r = publicar_en(&mut s, &publicacion(&e), 1_000);
        assert_eq!(r.status_code, 200, "{}", cuerpo(&r));
        assert!(cuerpo(&r).contains(&format!("\"codigo\":\"{codigo}\"")));

        // Con guiones, en minúsculas, con espacios y con O por 0: todo lleva a la misma entrada.
        for c in [codigo.clone(), codigo.to_lowercase(), codigo.replace('-', ""), codigo.replace('0', "O")] {
            let r = buscar_en(&s, &format!("codigo={c}"));
            assert_eq!(r.status_code, 200, "codigo {c}: {}", cuerpo(&r));
            assert!(cuerpo(&r).contains(&e));
        }
        let r = buscar_en(&s, &format!("dir={}", &dir[..16]));
        assert_eq!(r.status_code, 200);
        assert!(cuerpo(&r).contains(&e));
        assert_eq!(buscar_en(&s, "codigo=0000-0000-0000").status_code, 404);
        assert_eq!(buscar_en(&s, "codigo=hola").status_code, 400);
        assert_eq!(buscar_en(&s, "dir=abc").status_code, 400);
        assert_eq!(buscar_en(&s, "").status_code, 400);
    }

    #[test]
    fn solo_entra_lo_que_verifica_y_renovar_no_duplica() {
        let mut s = Estado::default();
        let (e, codigo, _) = entrada(None);
        let mut rota: Vec<char> = e.chars().collect();
        let i = e.len() / 2;
        rota[i] = if rota[i] == 'A' { 'B' } else { 'A' };
        let rota: String = rota.into_iter().collect();
        assert_eq!(publicar_en(&mut s, &publicacion(&rota), 1).status_code, 400);
        assert_eq!(publicar_en(&mut s, b"{\"entrada\":\"X39DIR1:AAAA\"}", 1).status_code, 400);
        assert_eq!(publicar_en(&mut s, b"nada", 1).status_code, 400);
        assert!(s.directorio.as_ref().is_none_or(Vec::is_empty));

        assert_eq!(publicar_en(&mut s, &publicacion(&e), 1).status_code, 200);
        assert_eq!(publicar_en(&mut s, &publicacion(&e), 2).status_code, 200);
        assert_eq!(s.directorio.as_ref().unwrap().len(), 1);
        assert_eq!(s.directorio.as_ref().unwrap()[0].ts, 2);
        assert_eq!(buscar_en(&s, &format!("codigo={codigo}")).status_code, 200);
    }

    #[test]
    fn caduca_al_ano_sin_renovar_y_los_mensajes_siguen_igual() {
        let mut s = Estado::default();
        let (e, codigo, dir) = entrada(None);
        assert_eq!(publicar_en(&mut s, &publicacion(&e), 0).status_code, 200);
        let msg = format!("{{\"para\":\"{dir}\",\"msg\":\"X39MSG1:abc\"}}");
        assert_eq!(poner_en(&mut s, msg.as_bytes(), VIDA_FICHA_NS - 1).status_code, 200);
        assert_eq!(buscar_en(&s, &format!("codigo={codigo}")).status_code, 200);
        assert_eq!(poner_en(&mut s, msg.as_bytes(), VIDA_FICHA_NS + 1).status_code, 200);
        assert_eq!(buscar_en(&s, &format!("codigo={codigo}")).status_code, 404, "purgada al año");
        assert_eq!(s.entradas.len(), 2, "los mensajes (2 ns entre ellos) tienen su propia vida de 14 días");
        assert_eq!(poner_en(&mut s, msg.as_bytes(), VIDA_FICHA_NS + VIDA_NS + 1).status_code, 200);
        assert_eq!(s.entradas.len(), 1, "los dos primeros ya pasaron de 14 días");
    }

    #[test]
    fn el_estado_antiguo_sin_directorio_se_restaura() {
        // Lo que guardó la versión 0.8 (sin campo directorio) tiene que poder leerse tras la actualización.
        #[derive(CandidType)]
        struct EstadoViejo {
            ultimo: u64,
            entradas: Vec<Entrada>,
        }
        let viejo = EstadoViejo { ultimo: 7, entradas: vec![Entrada { seq: 7, para: "a".into(), msg: "X39MSG1:x".into(), ts: 1 }] };
        let bytes = candid::encode_one(&viejo).unwrap();
        let nuevo: Estado = candid::decode_one(&bytes).unwrap();
        assert_eq!(nuevo.ultimo, 7);
        assert_eq!(nuevo.entradas.len(), 1);
        assert!(nuevo.directorio.is_none());
    }
}
