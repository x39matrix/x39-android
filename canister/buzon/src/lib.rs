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
//!   GET  /agenda?desde=<ts>              (fichas acreditadas más nuevas que ts)  → {"fichas":[…], "hasta": ts, "quedan": bool}
//!
//! Salas por departamento (desde 0.12; ver x39-core/src/sala.rs). Solo publica quien está acreditado en el
//! directorio: cada POST lleva la firma ML-DSA-87 del remitente y el canister la comprueba con su clave del
//! directorio. Los mensajes van cifrados con la clave de la sala (el canister no la tiene), encadenados por
//! hash, y NUNCA se borran.
//!   GET  /sala/estado?sala=<id>                         → {"epoca","ultimo","ultimo_hash","con_sobre":[dir…],"miembros":[…]}
//!   GET  /sala/sobres?sala=<id>&para=<dir>              → {"epoca","sobres":[{"epoca","de","sobre","firma","ts"}]}
//!   GET  /sala/mensajes?sala=<id>&desde=<seq>           → {"mensajes":[{"seq","de","epoca","msg","firma","ts","hash"}],"ultimo","epoca"}
//!   GET  /sala/mias?para=<dir>                          → {"salas":[id…]}  (a las que le añadieron a mano)
//!   POST /sala/sobre    {sala,epoca,para,de,sobre,firma}   entrega la clave a un miembro (la época 0 la crea el primero)
//!   POST /sala/mensaje  {sala,epoca,de,msg,firma}          → {"seq","hash"}
//!   POST /sala/miembro  {sala,direccion,de,firma}          añade a alguien de otra área
//!
//! Revocación (desde 0.13): la autoridad (clave pública en autoridad.pk, la misma que lleva la app) firma
//! «X39REV1:…» con el código de contacto; la ficha se conserva marcada como revocada, sale de la agenda,
//! sus publicaciones se rechazan y las salas en las que tenía clave pasan a la época siguiente.
//!   POST /revocar {revocacion}                          → {"codigo","fichas","salas_rotadas"}
//!   GET  /revocadas?desde=<ts>                          → {"revocaciones":[{"codigo","ts","motivo","texto"}],"hasta"}
//! Cambio de clave de una sala: un miembro con la clave de la época N puede abrir la N+1 entregando el
//! primer sobre; en cada época solo entrega sobres quien ya tiene esa clave (una sola clave por época).
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
use x39_core::invitacion;
use x39_core::sala;

/// Clave pública de la autoridad (el Ayuntamiento): la misma que lleva la app en assets/autoridad.pk.
/// Con ella el canister comprueba las revocaciones firmadas por el alcalde.
const AUTORIDAD: &[u8; 2592] = include_bytes!("../autoridad.pk");

#[cfg(test)]
thread_local! {
    static AUTORIDAD_PRUEBA: RefCell<Option<[u8; 2592]>> = const { RefCell::new(None) };
}

fn autoridad_pk() -> [u8; 2592] {
    #[cfg(test)]
    if let Some(pk) = AUTORIDAD_PRUEBA.with(|a| *a.borrow()) {
        return pk;
    }
    *AUTORIDAD
}

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
/// Fichas por respuesta de /agenda (unos 31 000 caracteres cada una con acreditación).
const LOTE_AGENDA: usize = 10;
const MAX_SALAS: usize = 500;
/// Un sobre real (cápsula ML-KEM con cuerpo firmado ML-DSA-87 de ~6,4 kB) ronda los 8 500 caracteres.
const MAX_SOBRE: usize = 12_000;
const MAX_FIRMA: usize = 7_000;
const LOTE_SALA: usize = 30;

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
    /// Lleva acreditación (X39ACR1). `opt` por las fichas guardadas antes de existir el campo.
    acreditada: Option<bool>,
    /// Momento en que la autoridad revocó esta acreditación (la ficha se conserva, pero deja de valer).
    revocada: Option<u64>,
}

/// Revocación firmada por la autoridad, tal como se publicó (la app vuelve a comprobar la firma).
#[derive(Clone, Serialize, Deserialize, CandidType)]
struct Revocacion {
    codigo: String,
    ts: u64,
    motivo: String,
    texto: String,
}

/// Un mensaje de sala: cifrado con la clave de la sala, firmado por su autor, encadenado por hash.
#[derive(Clone, Serialize, Deserialize, CandidType)]
struct MensajeSala {
    seq: u64,
    de: String,
    epoca: u32,
    msg: String,
    firma: String,
    ts: u64,
    hash: String,
}

/// La clave de la sala entregada a un miembro (cápsula X39MSG1 firmada por quien la entrega).
#[derive(Clone, Serialize, Deserialize, CandidType)]
struct Sobre {
    epoca: u32,
    para: String,
    de: String,
    sobre: String,
    firma: String,
    ts: u64,
}

/// Miembro añadido a mano por otro miembro (los de la propia área entran solos por su acreditación).
#[derive(Clone, Serialize, Deserialize, CandidType)]
struct Miembro {
    direccion: String,
    por: String,
    ts: u64,
}

#[derive(Default, Clone, Serialize, Deserialize, CandidType)]
struct Sala {
    /// None hasta que el primer miembro entrega la primera clave (época 0).
    epoca: Option<u32>,
    mensajes: Vec<MensajeSala>,
    sobres: Vec<Sobre>,
    miembros: Vec<Miembro>,
}

#[derive(Default, Serialize, Deserialize, CandidType)]
struct Estado {
    ultimo: u64,
    entradas: Vec<Entrada>,
    /// `opt` para poder restaurar el estado guardado por la versión sin directorio.
    directorio: Option<Vec<Ficha>>,
    /// Salas por departamento (desde 0.12). Nada se borra nunca de aquí.
    salas: Option<std::collections::BTreeMap<String, Sala>>,
    /// Revocaciones de acreditación (desde 0.13), en orden de llegada.
    revocaciones: Option<Vec<Revocacion>>,
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

/// Agenda: las fichas acreditadas publicadas después de `desde` (marca de tiempo), en lotes.
/// La app comprueba cada acreditación con la clave del Ayuntamiento antes de añadir a nadie.
fn agenda_en(s: &Estado, consulta: &str) -> HttpResponse {
    let desde: u64 = parametro(consulta, "desde").and_then(|d| d.parse().ok()).unwrap_or(0);
    let vacio = Vec::new();
    let d = s.directorio.as_ref().unwrap_or(&vacio);
    let mut fichas: Vec<&Ficha> = d.iter().filter(|f| f.ts > desde && f.acreditada != Some(false) && f.revocada.is_none()).collect();
    fichas.sort_by_key(|f| f.ts);
    let quedan = fichas.len() > LOTE_AGENDA;
    fichas.truncate(LOTE_AGENDA);
    let hasta = fichas.last().map_or(desde, |f| f.ts);
    let lote: Vec<serde_json::Value> = fichas
        .iter()
        .map(|f| {
            serde_json::json!({
                "entrada": f.entrada,
                "codigo": directorio::codigo_visible(&f.codigo),
                "direccion": f.direccion,
                "ts": f.ts,
            })
        })
        .collect();
    json(200, serde_json::json!({ "fichas": lote, "hasta": hasta, "quedan": quedan }).to_string())
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
        f.revocada.is_none()
            && codigo.as_deref().is_none_or(|c| f.codigo == c)
            && por_dir.as_deref().is_none_or(|p| f.direccion.starts_with(p))
    });
    match hallada {
        Some(f) => json(200, ficha_json(f)),
        None => error(404, "no esta en el directorio"),
    }
}

// ---------------------------------------------------------------- salas

fn sala_de(consulta: &str) -> Result<String, HttpResponse> {
    match parametro(consulta, "sala") {
        Some(s) if sala::sala_valida(s) => Ok(s.to_string()),
        _ => Err(error(400, "sala invalida")),
    }
}

fn sala_estado_en(s: &Estado, consulta: &str) -> HttpResponse {
    let id = match sala_de(consulta) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let vacia = Sala::default();
    let sala = s.salas.as_ref().and_then(|m| m.get(&id)).unwrap_or(&vacia);
    let con_sobre: Vec<&str> = sala
        .sobres
        .iter()
        .filter(|x| Some(x.epoca) == sala.epoca)
        .map(|x| x.para.as_str())
        .collect();
    let miembros: Vec<serde_json::Value> = sala
        .miembros
        .iter()
        .map(|m| serde_json::json!({ "direccion": m.direccion, "por": m.por, "ts": m.ts }))
        .collect();
    let ultimo = sala.mensajes.last();
    json(
        200,
        serde_json::json!({
            "epoca": sala.epoca,
            "ultimo": ultimo.map_or(0, |m| m.seq),
            "ultimo_hash": ultimo.map_or("", |m| m.hash.as_str()),
            "con_sobre": con_sobre,
            "miembros": miembros,
        })
        .to_string(),
    )
}

fn sala_sobres_en(s: &Estado, consulta: &str) -> HttpResponse {
    let id = match sala_de(consulta) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(para) = parametro(consulta, "para") else {
        return error(400, "falta para");
    };
    let vacia = Sala::default();
    let sala = s.salas.as_ref().and_then(|m| m.get(&id)).unwrap_or(&vacia);
    let lote: Vec<serde_json::Value> = sala
        .sobres
        .iter()
        .filter(|x| x.para == para)
        .map(|x| serde_json::json!({ "epoca": x.epoca, "de": x.de, "sobre": x.sobre, "firma": x.firma, "ts": x.ts }))
        .collect();
    json(200, serde_json::json!({ "epoca": sala.epoca, "sobres": lote }).to_string())
}

fn sala_mensajes_en(s: &Estado, consulta: &str) -> HttpResponse {
    let id = match sala_de(consulta) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let desde: u64 = parametro(consulta, "desde").and_then(|d| d.parse().ok()).unwrap_or(0);
    let vacia = Sala::default();
    let sala = s.salas.as_ref().and_then(|m| m.get(&id)).unwrap_or(&vacia);
    let lote: Vec<&MensajeSala> = sala.mensajes.iter().filter(|m| m.seq > desde).take(LOTE_SALA).collect();
    json(
        200,
        serde_json::json!({
            "mensajes": lote,
            "ultimo": sala.mensajes.last().map_or(0, |m| m.seq),
            "epoca": sala.epoca,
        })
        .to_string(),
    )
}

/// Salas a las que `para` fue añadido a mano (las de su área las sabe por su acreditación).
fn sala_mias_en(s: &Estado, consulta: &str) -> HttpResponse {
    let Some(para) = parametro(consulta, "para") else {
        return error(400, "falta para");
    };
    let ids: Vec<&str> = s
        .salas
        .as_ref()
        .map(|m| m.iter().filter(|(_, sala)| sala.miembros.iter().any(|x| x.direccion == para)).map(|(id, _)| id.as_str()).collect())
        .unwrap_or_default();
    json(200, serde_json::json!({ "salas": ids }).to_string())
}

/// Clave de firma de un remitente acreditado del directorio. None si no está o no está acreditado.
fn clave_firma_de(s: &Estado, de: &str) -> Option<[u8; 2592]> {
    let ficha = s.directorio.as_ref()?.iter().rev().find(|f| f.direccion == de && f.acreditada != Some(false) && f.revocada.is_none())?;
    let e = directorio::leer(&ficha.entrada).ok()?;
    e.acreditacion.as_ref()?;
    Some(e.dsa_pk)
}

/// Comprueba que la publicación la firma un remitente acreditado. Devuelve la respuesta de error si no.
fn autorizar(s: &Estado, de: &str, sala: &str, epoca: u32, accion: &str, firma: &str) -> Result<(), HttpResponse> {
    if !direccion_valida(de) {
        return Err(error(400, "remitente invalido"));
    }
    if firma.len() > MAX_FIRMA {
        return Err(error(400, "firma demasiado grande"));
    }
    let Some(pk) = clave_firma_de(s, de) else {
        return Err(error(403, "el remitente no esta acreditado en el directorio"));
    };
    match sala::verificar(&pk, sala, epoca, accion, firma) {
        Ok(()) => Ok(()),
        Err(_) => Err(error(403, "la firma de la publicacion no es del remitente")),
    }
}

fn sala_mut<'a>(s: &'a mut Estado, id: &str) -> Result<&'a mut Sala, HttpResponse> {
    let m = s.salas.get_or_insert_with(Default::default);
    if !m.contains_key(id) && m.len() >= MAX_SALAS {
        return Err(error(507, "demasiadas salas"));
    }
    Ok(m.entry(id.to_string()).or_default())
}

#[derive(Deserialize)]
struct PeticionSobre {
    sala: String,
    epoca: u32,
    para: String,
    de: String,
    sobre: String,
    firma: String,
}

fn sala_sobre_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: PeticionSobre = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if !sala::sala_valida(&p.sala) || !direccion_valida(&p.para) {
        return error(400, "sala o destinatario invalidos");
    }
    if !p.sobre.starts_with("X39MSG1:") || p.sobre.len() > MAX_SOBRE || p.sobre.chars().any(char::is_whitespace) {
        return error(400, "sobre invalido");
    }
    if let Err(e) = autorizar(s, &p.de, &p.sala, p.epoca, &sala::accion_sobre(&p.para, &p.sobre), &p.firma) {
        return e;
    }
    let sala = match sala_mut(s, &p.sala) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let tiene_sobre = |sala: &Sala, epoca: u32, quien: &str| sala.sobres.iter().any(|x| x.epoca == epoca && x.para == quien);
    match sala.epoca {
        // La primera clave la fija quien llega primero; los demás la reciben por su sobre.
        None if p.epoca == 0 => sala.epoca = Some(0),
        None => return error(409, "la sala aun no tiene clave: la primera epoca es la 0"),
        Some(actual) if actual == p.epoca => {
            // Una sola clave por época: solo quien ya la tiene puede entregarla (el primero la crea).
            if sala.sobres.iter().any(|x| x.epoca == actual) && !tiene_sobre(sala, actual, &p.de) {
                return error(403, "solo quien ya tiene la clave de esta epoca puede entregarla");
            }
        }
        // Cambio de clave voluntario: un miembro con la clave actual abre la época siguiente.
        Some(actual) if p.epoca == actual + 1 && tiene_sobre(sala, actual, &p.de) => sala.epoca = Some(p.epoca),
        Some(actual) => return error(409, &format!("la sala va por la epoca {actual}")),
    }
    // Un sobre por destinatario y época; el más reciente sustituye al anterior.
    sala.sobres.retain(|x| !(x.epoca == p.epoca && x.para == p.para));
    sala.sobres.push(Sobre { epoca: p.epoca, para: p.para, de: p.de, sobre: p.sobre, firma: p.firma, ts: ahora });
    json(200, format!("{{\"epoca\":{}}}", p.epoca))
}

#[derive(Deserialize)]
struct PeticionMensajeSala {
    sala: String,
    epoca: u32,
    de: String,
    msg: String,
    firma: String,
}

fn sala_mensaje_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: PeticionMensajeSala = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if !sala::sala_valida(&p.sala) {
        return error(400, "sala invalida");
    }
    if !p.msg.starts_with(sala::PREFIX_MSG) || p.msg.len() > MAX_MSG || p.msg.chars().any(char::is_whitespace) {
        return error(400, "mensaje invalido");
    }
    if let Err(e) = autorizar(s, &p.de, &p.sala, p.epoca, &p.msg, &p.firma) {
        return e;
    }
    let sala = match sala_mut(s, &p.sala) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match sala.epoca {
        None => return error(409, "la sala aun no tiene clave"),
        Some(actual) if actual != p.epoca => return error(409, &format!("la sala va por la epoca {actual}")),
        Some(_) => {}
    }
    let seq = sala.mensajes.last().map_or(0, |m| m.seq) + 1;
    let anterior = sala.mensajes.last().and_then(|m| sala::de_hex(&m.hash)).unwrap_or([0u8; 32]);
    let hash = sala::hex(&sala::eslabon(&anterior, &p.sala, seq, &p.de, &p.msg, &p.firma));
    sala.mensajes.push(MensajeSala { seq, de: p.de, epoca: p.epoca, msg: p.msg, firma: p.firma, ts: ahora, hash: hash.clone() });
    json(200, format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}"))
}

#[derive(Deserialize)]
struct PeticionMiembro {
    sala: String,
    direccion: String,
    de: String,
    firma: String,
}

fn sala_miembro_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: PeticionMiembro = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if !sala::sala_valida(&p.sala) || !direccion_valida(&p.direccion) {
        return error(400, "sala o miembro invalidos");
    }
    if let Err(e) = autorizar(s, &p.de, &p.sala, 0, &sala::accion_miembro(&p.direccion), &p.firma) {
        return e;
    }
    let sala = match sala_mut(s, &p.sala) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if !sala.miembros.iter().any(|m| m.direccion == p.direccion) {
        sala.miembros.push(Miembro { direccion: p.direccion, por: p.de, ts: ahora });
    }
    json(200, "{\"ok\":true}".into())
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
            let salas = s.salas.as_ref().map_or(0, |m| m.len());
            let en_salas: usize = s.salas.as_ref().map_or(0, |m| m.values().map(|x| x.mensajes.len()).sum());
            let revocadas = s.revocaciones.as_ref().map_or(0, Vec::len);
            json(200, format!("{{\"mensajes\":{},\"ultimo\":{},\"directorio\":{},\"salas\":{},\"mensajes_en_salas\":{},\"revocadas\":{}}}", s.entradas.len(), s.ultimo, fichas, salas, en_salas, revocadas))
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
        ("GET", "/agenda") => ESTADO.with(|s| agenda_en(&s.borrow(), consulta)),
        ("GET", "/sala/estado") => ESTADO.with(|s| sala_estado_en(&s.borrow(), consulta)),
        ("GET", "/sala/sobres") => ESTADO.with(|s| sala_sobres_en(&s.borrow(), consulta)),
        ("GET", "/sala/mensajes") => ESTADO.with(|s| sala_mensajes_en(&s.borrow(), consulta)),
        ("GET", "/sala/mias") => ESTADO.with(|s| sala_mias_en(&s.borrow(), consulta)),
        ("GET", "/revocadas") => ESTADO.with(|s| revocadas_en(&s.borrow(), consulta)),
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
        acreditada: Some(e.acreditacion.is_some()),
        revocada: None,
    };
    purgar(s, ahora);
    let d = s.directorio.get_or_insert_with(Vec::new);
    if d.iter().any(|f| f.codigo == ficha.codigo && f.revocada.is_some()) {
        return error(403, "acreditacion revocada por la autoridad");
    }
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

#[derive(Deserialize)]
struct PeticionRevocacion {
    revocacion: String,
}

/// Revocación firmada por la autoridad: la ficha deja de valer (agenda, búsqueda, publicaciones) y todas
/// las salas en las que esa persona tenía la clave pasan a la época siguiente: lo nuevo ya no lo lee.
fn revocar_en(s: &mut Estado, cuerpo: &[u8], ahora: u64) -> HttpResponse {
    let p: PeticionRevocacion = match serde_json::from_slice(cuerpo) {
        Ok(p) => p,
        Err(_) => return error(400, "cuerpo JSON invalido"),
    };
    if p.revocacion.len() > MAX_FIRMA || p.revocacion.chars().any(char::is_whitespace) {
        return error(400, "revocacion invalida");
    }
    let r = match invitacion::verificar_revocacion(&autoridad_pk(), &p.revocacion) {
        Ok(r) => r,
        Err(e) => return error(403, &format!("revocacion no valida: {e}")),
    };
    // Repetir una revocación ya aplicada no cambia nada (ni vuelve a rotar las salas).
    let ya = s.revocaciones.as_ref().is_some_and(|l| l.iter().any(|x| x.codigo == r.codigo));
    let mut direcciones = Vec::new();
    let mut salas_rotadas = 0;
    if !ya {
        if let Some(d) = s.directorio.as_mut() {
            for f in d.iter_mut().filter(|f| f.codigo == r.codigo) {
                f.revocada = Some(ahora);
                direcciones.push(f.direccion.clone());
            }
        }
        if let Some(m) = s.salas.as_mut() {
            for sala in m.values_mut() {
                let estaba = sala.sobres.iter().any(|x| direcciones.contains(&x.para));
                if estaba {
                    if let Some(e) = sala.epoca {
                        sala.epoca = Some(e + 1);
                        salas_rotadas += 1;
                    }
                }
            }
        }
        s.revocaciones.get_or_insert_with(Vec::new).push(Revocacion {
            codigo: r.codigo.clone(),
            ts: ahora,
            motivo: r.motivo.clone(),
            texto: p.revocacion,
        });
    }
    json(
        200,
        serde_json::json!({
            "codigo": directorio::codigo_visible(&r.codigo),
            "fichas": direcciones.len(),
            "salas_rotadas": salas_rotadas,
        })
        .to_string(),
    )
}

fn revocadas_en(s: &Estado, consulta: &str) -> HttpResponse {
    let desde: u64 = parametro(consulta, "desde").and_then(|d| d.parse().ok()).unwrap_or(0);
    let vacio = Vec::new();
    let lista: Vec<serde_json::Value> = s
        .revocaciones
        .as_ref()
        .unwrap_or(&vacio)
        .iter()
        .filter(|r| r.ts > desde)
        .map(|r| serde_json::json!({ "codigo": directorio::codigo_visible(&r.codigo), "ts": r.ts, "motivo": r.motivo, "texto": r.texto }))
        .collect();
    let hasta = s.revocaciones.as_ref().and_then(|l| l.last()).map_or(desde, |r| r.ts.max(desde));
    json(200, serde_json::json!({ "revocaciones": lista, "hasta": hasta }).to_string())
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let (ruta, _) = ruta_y_consulta(&req.url);
    ESTADO.with(|s| {
        let mut s = s.borrow_mut();
        match (req.method.as_str(), ruta) {
            ("POST", "/poner") => poner_en(&mut s, &req.body, time()),
            ("POST", "/publicar") => publicar_en(&mut s, &req.body, time()),
            ("POST", "/revocar") => revocar_en(&mut s, &req.body, time()),
            ("POST", "/sala/sobre") => sala_sobre_en(&mut s, &req.body, time()),
            ("POST", "/sala/mensaje") => sala_mensaje_en(&mut s, &req.body, time()),
            ("POST", "/sala/miembro") => sala_miembro_en(&mut s, &req.body, time()),
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
    fn agenda_solo_acreditadas_por_lotes_y_desde() {
        let autoridad = firma::generate_seed().unwrap();
        let inv = x39_core::invitacion::emitir(&autoridad, "2027-12-31", "Prueba").unwrap();
        let mut s = Estado::default();
        // 12 acreditadas y 1 sin acreditar.
        for i in 0..12u64 {
            let seed = firma::generate_seed().unwrap();
            let kem = x39_core::generate_keypair().unwrap();
            let acr = x39_core::invitacion::acreditar(&seed, &inv).unwrap();
            let e = directorio::publicar(&seed, &kem.public, Some(&acr)).unwrap();
            assert_eq!(publicar_en(&mut s, &publicacion(&e), 100 + i).status_code, 200);
        }
        let (sin, _, _) = entrada(None);
        assert_eq!(publicar_en(&mut s, &publicacion(&sin), 200).status_code, 200);

        let r: serde_json::Value = serde_json::from_str(&cuerpo(&agenda_en(&s, ""))).unwrap();
        assert_eq!(r["fichas"].as_array().unwrap().len(), LOTE_AGENDA);
        assert_eq!(r["quedan"], true);
        assert_eq!(r["hasta"], 109);
        let r: serde_json::Value = serde_json::from_str(&cuerpo(&agenda_en(&s, "desde=109"))).unwrap();
        assert_eq!(r["fichas"].as_array().unwrap().len(), 2, "la sin acreditar no sale");
        assert_eq!(r["quedan"], false);
        assert_eq!(r["hasta"], 111);
        let r: serde_json::Value = serde_json::from_str(&cuerpo(&agenda_en(&s, "desde=111"))).unwrap();
        assert_eq!(r["fichas"].as_array().unwrap().len(), 0);
        assert_eq!(r["hasta"], 111);
    }

    #[test]
    fn salas_solo_acreditados_cadena_y_epocas() {
        let autoridad = firma::generate_seed().unwrap();
        let inv = x39_core::invitacion::emitir(&autoridad, "2027-12-31", "Ana Ruiz · Técnica · Amate").unwrap();
        let mut s = Estado::default();
        // Ana: acreditada y publicada. Beto: publicado sin acreditación.
        let ana = firma::generate_seed().unwrap();
        let ana_kem = x39_core::generate_keypair().unwrap();
        let ana_dir = directorio::direccion(&ana_kem.public);
        let acr = x39_core::invitacion::acreditar(&ana, &inv).unwrap();
        let e = directorio::publicar(&ana, &ana_kem.public, Some(&acr)).unwrap();
        assert_eq!(publicar_en(&mut s, &publicacion(&e), 1).status_code, 200);
        let beto = firma::generate_seed().unwrap();
        let beto_kem = x39_core::generate_keypair().unwrap();
        let beto_dir = directorio::direccion(&beto_kem.public);
        let e = directorio::publicar(&beto, &beto_kem.public, None).unwrap();
        assert_eq!(publicar_en(&mut s, &publicacion(&e), 2).status_code, 200);

        let clave = sala::nueva_clave().unwrap();
        // Sin clave todavía: un mensaje no entra.
        let m = sala::cifrar(&clave, "amate", 0, b"hola").unwrap();
        let f = sala::firmar(&ana, "amate", 0, &m).unwrap();
        let cuerpo = serde_json::json!({"sala":"amate","epoca":0,"de":ana_dir,"msg":m,"firma":f}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, cuerpo.as_bytes(), 10).status_code, 409);

        // Ana se entrega la clave a sí misma: nace la época 0. El sobre es uno REAL (cápsula con cuerpo
        // firmado), para que el límite de tamaño del canister se compruebe con el tamaño verdadero.
        let carga = format!("{{\"sala\":\"amate\",\"epoca\":0,\"clave\":\"{}\"}}", "A".repeat(44));
        let cuerpo_sobre = firma::sign_for(&ana, &ana_kem.public, carga.as_bytes()).unwrap();
        let capsula = x39_core::seal(&ana_kem.public, &cuerpo_sobre, b"", None, 1).unwrap();
        let sobre = x39_core::share::encode_capsule(&capsula);
        assert!(sobre.len() > 8_000 && sobre.len() <= MAX_SOBRE, "sobre real de {} caracteres", sobre.len());
        let fs = sala::firmar(&ana, "amate", 0, &sala::accion_sobre(&ana_dir, &sobre)).unwrap();
        let cs = serde_json::json!({"sala":"amate","epoca":0,"para":ana_dir,"de":ana_dir,"sobre":sobre,"firma":fs}).to_string();
        assert_eq!(sala_sobre_en(&mut s, cs.as_bytes(), 11).status_code, 200);
        // Saltarse una época (la 2 cuando la sala va por la 0) no vale; abrir la siguiente (1) sí lo puede hacer
        // quien tiene la clave actual, pero aquí no se hace para seguir probando la 0.
        let fs2 = sala::firmar(&ana, "amate", 2, &sala::accion_sobre(&ana_dir, &sobre)).unwrap();
        let cs2 = serde_json::json!({"sala":"amate","epoca":2,"para":ana_dir,"de":ana_dir,"sobre":sobre,"firma":fs2}).to_string();
        assert_eq!(sala_sobre_en(&mut s, cs2.as_bytes(), 12).status_code, 409);

        // Ahora sí: dos mensajes encadenados.
        let r = sala_mensaje_en(&mut s, cuerpo.as_bytes(), 13);
        assert_eq!(r.status_code, 200, "{}", cuerpo_de(&r));
        let m2 = sala::cifrar(&clave, "amate", 0, b"segundo").unwrap();
        let f2 = sala::firmar(&ana, "amate", 0, &m2).unwrap();
        let c2 = serde_json::json!({"sala":"amate","epoca":0,"de":ana_dir,"msg":m2,"firma":f2}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, c2.as_bytes(), 14).status_code, 200);
        let sala_amate = &s.salas.as_ref().unwrap()["amate"];
        assert_eq!(sala_amate.mensajes.len(), 2);
        let h1 = sala::eslabon(&[0u8; 32], "amate", 1, &ana_dir, &m, &f);
        let h2 = sala::eslabon(&h1, "amate", 2, &ana_dir, &m2, &f2);
        assert_eq!(sala_amate.mensajes[1].hash, sala::hex(&h2), "la cadena se puede recomputar fuera");

        // Beto (sin acreditar) no puede escribir; una firma de otro tampoco.
        let mb = sala::cifrar(&clave, "amate", 0, b"intruso").unwrap();
        let fb = sala::firmar(&beto, "amate", 0, &mb).unwrap();
        let cb = serde_json::json!({"sala":"amate","epoca":0,"de":beto_dir,"msg":mb,"firma":fb}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, cb.as_bytes(), 15).status_code, 403);
        let cf = serde_json::json!({"sala":"amate","epoca":0,"de":ana_dir,"msg":mb,"firma":fb}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, cf.as_bytes(), 16).status_code, 403);
        assert_eq!(s.salas.as_ref().unwrap()["amate"].mensajes.len(), 2, "nada entró");

        // Ana añade a Beto a la sala; /sala/mias lo refleja; lectura por lotes desde seq.
        let fm = sala::firmar(&ana, "amate", 0, &sala::accion_miembro(&beto_dir)).unwrap();
        let cm = serde_json::json!({"sala":"amate","direccion":beto_dir,"de":ana_dir,"firma":fm}).to_string();
        assert_eq!(sala_miembro_en(&mut s, cm.as_bytes(), 17).status_code, 200);
        assert_eq!(sala_miembro_en(&mut s, cm.as_bytes(), 18).status_code, 200, "repetir no duplica");
        assert_eq!(s.salas.as_ref().unwrap()["amate"].miembros.len(), 1);
        assert!(cuerpo_de(&sala_mias_en(&s, &format!("para={beto_dir}"))).contains("\"amate\""));
        let r: serde_json::Value = serde_json::from_str(&cuerpo_de(&sala_mensajes_en(&s, "sala=amate&desde=1"))).unwrap();
        assert_eq!(r["mensajes"].as_array().unwrap().len(), 1);
        assert_eq!(r["ultimo"], 2);
        let r: serde_json::Value = serde_json::from_str(&cuerpo_de(&sala_estado_en(&s, "sala=amate"))).unwrap();
        assert_eq!(r["epoca"], 0);
        assert_eq!(r["con_sobre"].as_array().unwrap().len(), 1);
        let r: serde_json::Value = serde_json::from_str(&cuerpo_de(&sala_estado_en(&s, "sala=nueva"))).unwrap();
        assert!(r["epoca"].is_null());
    }

    fn cuerpo_de(r: &HttpResponse) -> String {
        cuerpo(r)
    }

    #[test]
    fn revocar_saca_de_la_agenda_rechaza_publicaciones_y_rota_las_salas() {
        let autoridad = firma::generate_seed().unwrap();
        AUTORIDAD_PRUEBA.with(|a| *a.borrow_mut() = Some(firma::public_key(&autoridad)));
        let inv = x39_core::invitacion::emitir(&autoridad, "2027-12-31", "Ana Ruiz · Técnica · Amate").unwrap();
        let mut s = Estado::default();
        let mut personas = Vec::new();
        for _ in 0..2 {
            let seed = firma::generate_seed().unwrap();
            let kem = x39_core::generate_keypair().unwrap();
            let acr = x39_core::invitacion::acreditar(&seed, &inv).unwrap();
            let e = directorio::publicar(&seed, &kem.public, Some(&acr)).unwrap();
            assert_eq!(publicar_en(&mut s, &publicacion(&e), 1).status_code, 200);
            let dir = directorio::direccion(&kem.public);
            let cod = directorio::codigo(&firma::public_key(&seed));
            personas.push((seed, kem, dir, cod));
        }
        let (ana, _, ana_dir, _) = &personas[0];
        let (beto, beto_kem, beto_dir, _) = &personas[1];
        // Sala con clave de Ana entregada a Beto (época 0).
        let sobre = |de: &[u8; 32], para: &str, kem: &[u8; 1568], epoca: u32| {
            let cuerpo = firma::sign_for(de, kem, b"{}").unwrap();
            let c = x39_core::share::encode_capsule(&x39_core::seal(kem, &cuerpo, b"", None, 1).unwrap());
            let f = sala::firmar(de, "amate", epoca, &sala::accion_sobre(para, &c)).unwrap();
            (c, f)
        };
        let (c, f) = sobre(ana, ana_dir, &personas[0].1.public, 0);
        let cs = serde_json::json!({"sala":"amate","epoca":0,"para":ana_dir,"de":ana_dir,"sobre":c,"firma":f}).to_string();
        assert_eq!(sala_sobre_en(&mut s, cs.as_bytes(), 2).status_code, 200);
        // Beto, sin la clave, no puede entregar sobres de la época 0 (una sola clave por época).
        let (c, f) = sobre(beto, beto_dir, &beto_kem.public, 0);
        let cb = serde_json::json!({"sala":"amate","epoca":0,"para":beto_dir,"de":beto_dir,"sobre":c,"firma":f}).to_string();
        assert_eq!(sala_sobre_en(&mut s, cb.as_bytes(), 3).status_code, 403);
        let (c, f) = sobre(ana, beto_dir, &beto_kem.public, 0);
        let cab = serde_json::json!({"sala":"amate","epoca":0,"para":beto_dir,"de":ana_dir,"sobre":c,"firma":f}).to_string();
        assert_eq!(sala_sobre_en(&mut s, cab.as_bytes(), 4).status_code, 200);

        // Revocación de Beto firmada por la autoridad; una firmada por otro no vale.
        let otra = firma::generate_seed().unwrap();
        let falsa = x39_core::invitacion::revocar(&otra, &personas[1].3, "2026-09-16", "x").unwrap();
        let cf = serde_json::json!({ "revocacion": falsa }).to_string();
        assert_eq!(revocar_en(&mut s, cf.as_bytes(), 5).status_code, 403);
        let rev = x39_core::invitacion::revocar(&autoridad, &personas[1].3, "2026-09-16", "Cese").unwrap();
        let cr = serde_json::json!({ "revocacion": rev }).to_string();
        let r = revocar_en(&mut s, cr.as_bytes(), 6);
        assert_eq!(r.status_code, 200, "{}", cuerpo(&r));
        assert!(cuerpo(&r).contains("\"salas_rotadas\":1"));
        assert_eq!(revocar_en(&mut s, cr.as_bytes(), 7).status_code, 200, "repetir es inocuo");
        assert_eq!(s.revocaciones.as_ref().unwrap().len(), 1);

        // Fuera de la agenda y de la búsqueda; no puede publicar ni escribir; Ana sí.
        let r: serde_json::Value = serde_json::from_str(&cuerpo(&agenda_en(&s, ""))).unwrap();
        assert_eq!(r["fichas"].as_array().unwrap().len(), 1);
        assert_eq!(buscar_en(&s, &format!("dir={}", &beto_dir[..16])).status_code, 404);
        let e = directorio::publicar(beto, &beto_kem.public, None).unwrap();
        assert_eq!(publicar_en(&mut s, &publicacion(&e), 8).status_code, 403);
        assert_eq!(s.salas.as_ref().unwrap()["amate"].epoca, Some(1), "la sala pasó a la época 1");
        let clave = sala::nueva_clave().unwrap();
        let m = sala::cifrar(&clave, "amate", 0, b"tarde").unwrap();
        let fm = sala::firmar(beto, "amate", 0, &m).unwrap();
        let cm = serde_json::json!({"sala":"amate","epoca":0,"de":beto_dir,"msg":m,"firma":fm}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, cm.as_bytes(), 9).status_code, 403);
        // Ana, que tenía la clave de la época 0, abre la época 1 y ya puede escribir en ella.
        let (c, f) = sobre(ana, ana_dir, &personas[0].1.public, 1);
        let c1 = serde_json::json!({"sala":"amate","epoca":1,"para":ana_dir,"de":ana_dir,"sobre":c,"firma":f}).to_string();
        assert_eq!(sala_sobre_en(&mut s, c1.as_bytes(), 10).status_code, 200);
        let m1 = sala::cifrar(&clave, "amate", 1, b"nueva epoca").unwrap();
        let f1 = sala::firmar(ana, "amate", 1, &m1).unwrap();
        let cm1 = serde_json::json!({"sala":"amate","epoca":1,"de":ana_dir,"msg":m1,"firma":f1}).to_string();
        assert_eq!(sala_mensaje_en(&mut s, cm1.as_bytes(), 11).status_code, 200);
        let r: serde_json::Value = serde_json::from_str(&cuerpo(&revocadas_en(&s, "desde=0"))).unwrap();
        assert_eq!(r["revocaciones"].as_array().unwrap().len(), 1);
        assert_eq!(r["revocaciones"][0]["motivo"], "Cese");
        assert_eq!(revocadas_en(&s, "desde=6").status_code, 200);
        let r: serde_json::Value = serde_json::from_str(&cuerpo(&revocadas_en(&s, "desde=6"))).unwrap();
        assert_eq!(r["revocaciones"].as_array().unwrap().len(), 0);
        AUTORIDAD_PRUEBA.with(|a| *a.borrow_mut() = None);
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

        // Y lo que guardó 0.10 (fichas sin el campo acreditada) también.
        #[derive(CandidType)]
        struct FichaVieja {
            codigo: String,
            direccion: String,
            entrada: String,
            ts: u64,
        }
        #[derive(CandidType)]
        struct EstadoDiez {
            ultimo: u64,
            entradas: Vec<Entrada>,
            directorio: Option<Vec<FichaVieja>>,
        }
        let diez = EstadoDiez {
            ultimo: 1,
            entradas: vec![],
            directorio: Some(vec![FichaVieja { codigo: "A".repeat(12), direccion: "b".repeat(64), entrada: "X39DIR1:x".into(), ts: 5 }]),
        };
        let nuevo: Estado = candid::decode_one(&candid::encode_one(&diez).unwrap()).unwrap();
        let f = &nuevo.directorio.unwrap()[0];
        assert_eq!(f.ts, 5);
        assert_eq!(f.acreditada, None, "sin dato: la agenda la incluye y la app decide");
    }
}
