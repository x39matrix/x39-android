//! x39 · buzón del Ayuntamiento: relé mínimo para los mensajes cifrados de la app.
//!
//! Solo guarda y entrega cápsulas `X39MSG1:…` (cifradas ML-KEM-1024 + AES-256-GCM y firmadas ML-DSA-87
//! en los móviles). El buzón NO puede leerlas; sí ve la dirección de destino (SHA-256 de la clave
//! pública del destinatario), el tamaño y la hora. Eso es lo que hay que decir de él.
//!
//! Se usa por HTTP a través de la pasarela `https://<canister>.raw.icp0.io`:
//!   POST /poner            cuerpo JSON {"para": <64 hex>, "msg": "X39MSG1:…"}   → {"seq": n}
//!   GET  /recoger?para=<64 hex>&desde=<seq>                                      → {"mensajes":[{"seq","ts","msg"}],"ultimo":n}
//!   GET  /estado                                                                 → {"mensajes": n, "ultimo": n}
//! Límites: 16 000 caracteres por mensaje, 300 por destinatario, 20 000 en total, 14 días de vida.
//! No hay control de quién escribe: cualquiera con la URL puede dejar mensajes (la app descarta los que no
//! vengan firmados por un contacto). Pendiente para después del 30/09: exigir invitación o firma al poner.

use candid::CandidType;
use ic_cdk::api::time;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::cell::RefCell;

const MAX_MSG: usize = 16_000;
const MAX_POR_DESTINO: usize = 300;
const MAX_TOTAL: usize = 20_000;
const VIDA_NS: u64 = 14 * 24 * 3600 * 1_000_000_000;
const LOTE: usize = 30;

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

#[derive(Default, Serialize, Deserialize, CandidType)]
struct Estado {
    ultimo: u64,
    entradas: Vec<Entrada>,
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

fn purgar(e: &mut Estado) {
    let ahora = time();
    e.entradas.retain(|x| ahora.saturating_sub(x.ts) < VIDA_NS);
    if e.entradas.len() > MAX_TOTAL {
        let sobra = e.entradas.len() - MAX_TOTAL;
        e.entradas.drain(0..sobra);
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
            json(200, format!("{{\"mensajes\":{},\"ultimo\":{}}}", s.entradas.len(), s.ultimo))
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
        _ => error(404, "no existe"),
    }
}

#[derive(Deserialize)]
struct Peticion {
    para: String,
    msg: String,
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let (ruta, _) = ruta_y_consulta(&req.url);
    if req.method != "POST" || ruta != "/poner" {
        return error(404, "no existe");
    }
    let p: Peticion = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if !direccion_valida(&p.para) {
        return error(400, "direccion invalida");
    }
    if !p.msg.starts_with("X39MSG1:") || p.msg.len() > MAX_MSG || p.msg.chars().any(char::is_whitespace) {
        return error(400, "mensaje invalido");
    }
    ESTADO.with(|s| {
        let mut s = s.borrow_mut();
        purgar(&mut s);
        let del_destino = s.entradas.iter().filter(|e| e.para == p.para).count();
        if del_destino >= MAX_POR_DESTINO {
            if let Some(i) = s.entradas.iter().position(|e| e.para == p.para) {
                s.entradas.remove(i);
            }
        }
        s.ultimo += 1;
        let seq = s.ultimo;
        s.entradas.push(Entrada { seq, para: p.para, msg: p.msg, ts: time() });
        json(200, format!("{{\"seq\":{seq}}}"))
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
