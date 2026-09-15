//! Cliente mínimo de OpenTimestamps: formato `.ots` compatible byte a byte con
//! python-opentimestamps 0.4.5 (la librería del cliente oficial `ots`).
//!
//! ```text
//! archivo  = MAGIA(31) | varuint(1) | 0x08 (sha256) | huella(32) | árbol
//! árbol    = [0xff (0x00 atestación | op árbol)]* (0x00 atestación | op árbol)
//! op       = 0x08 sha256 | 0xf0 append varbytes | 0xf1 prepend varbytes
//! atest.   = tag(8) | varbytes(payload)     pendiente: varbytes(uri) · bitcoin: varuint(altura)
//! ```
//! Aquí solo vive el formato y el árbol de la prueba. La red la pone la app:
//! `POST <calendario>/digest` con el compromiso y `GET <calendario>/timestamp/<hex>` para actualizar.
//! Al aplicar operaciones solo se admiten sha256, append y prepend (las que usan los calendarios);
//! cualquier otra se rechaza en lugar de adivinarla.

use crate::Error;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const MAGIA: &[u8; 31] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
pub const VERSION_MAYOR: u64 = 1;
pub const MAX_MSG: usize = 4096;
/// Tamaño máximo de una respuesta de calendario, igual que el cliente oficial.
pub const MAX_RESPUESTA: usize = 10_000;
const MAX_PAYLOAD: usize = 8192;
const MAX_URI: usize = 1000;
const LIMITE_RECURSION: usize = 256;
const TAG_PENDIENTE: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const URI_PERMITIDOS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:";

// ------------------------------------------------------------------ lectura y escritura

struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    fn new(datos: &'a [u8]) -> Self {
        Lector { datos, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let fin = self.pos.checked_add(n).ok_or(Error::Ots)?;
        let s = self.datos.get(self.pos..fin).ok_or(Error::Ots)?;
        self.pos = fin;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    /// LEB128 sin signo, como `read_varuint`.
    fn varuint(&mut self) -> Result<u64, Error> {
        let mut valor = 0u64;
        let mut desplazamiento = 0u32;
        loop {
            let b = self.byte()?;
            if desplazamiento > 63 {
                return Err(Error::Ots);
            }
            valor |= u64::from(b & 0x7f) << desplazamiento;
            if b & 0x80 == 0 {
                return Ok(valor);
            }
            desplazamiento += 7;
        }
    }

    fn varbytes(&mut self, max: usize, min: usize) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.varuint()?).map_err(|_| Error::Ots)?;
        if n > max || n < min {
            return Err(Error::Ots);
        }
        self.bytes(n)
    }

    fn fin(&self) -> Result<(), Error> {
        if self.pos == self.datos.len() { Ok(()) } else { Err(Error::Ots) }
    }
}

fn escribir_varuint(out: &mut Vec<u8>, mut valor: u64) {
    if valor == 0 {
        out.push(0);
        return;
    }
    while valor != 0 {
        let mut b = (valor & 0x7f) as u8;
        if valor > 0x7f {
            b |= 0x80;
        }
        out.push(b);
        if valor <= 0x7f {
            break;
        }
        valor >>= 7;
    }
}

fn escribir_varbytes(out: &mut Vec<u8>, datos: &[u8]) {
    escribir_varuint(out, datos.len() as u64);
    out.extend_from_slice(datos);
}

// ------------------------------------------------------------------ operaciones

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Sha256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha256 => 0x08,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
        }
    }

    fn argumento(&self) -> &[u8] {
        match self {
            Op::Sha256 => &[],
            Op::Append(a) | Op::Prepend(a) => a,
        }
    }

    pub fn aplicar(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.len() > MAX_MSG {
            return Err(Error::Ots);
        }
        let r = match self {
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Append(a) => [msg, a.as_slice()].concat(),
            Op::Prepend(a) => [a.as_slice(), msg].concat(),
        };
        if r.is_empty() || r.len() > MAX_MSG {
            return Err(Error::Ots);
        }
        Ok(r)
    }

    fn escribir(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        if !matches!(self, Op::Sha256) {
            escribir_varbytes(out, self.argumento());
        }
    }

    fn leer(lector: &mut Lector, tag: u8) -> Result<Op, Error> {
        match tag {
            0x08 => Ok(Op::Sha256),
            0xf0 => Ok(Op::Append(lector.varbytes(MAX_MSG, 1)?.to_vec())),
            0xf1 => Ok(Op::Prepend(lector.varbytes(MAX_MSG, 1)?.to_vec())),
            // sha1, ripemd160, keccak, reverse, hexlify: no los usan los calendarios de Bitcoin.
            _ => Err(Error::Ots),
        }
    }
}

/// Mismo orden que python-opentimestamps: por tag y, a igual tag, por argumento.
impl Ord for Op {
    fn cmp(&self, otra: &Self) -> Ordering {
        self.tag().cmp(&otra.tag()).then_with(|| self.argumento().cmp(otra.argumento()))
    }
}

impl PartialOrd for Op {
    fn partial_cmp(&self, otra: &Self) -> Option<Ordering> {
        Some(self.cmp(otra))
    }
}

// ------------------------------------------------------------------ atestaciones

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Atestacion {
    /// Pendiente en un calendario: la URI donde pedir la actualización.
    Pendiente(String),
    /// Anclada: el mensaje de ese nodo es la raíz Merkle del bloque a esa altura.
    Bitcoin(u64),
    Desconocida([u8; 8], Vec<u8>),
}

impl Atestacion {
    fn tag(&self) -> [u8; 8] {
        match self {
            Atestacion::Pendiente(_) => TAG_PENDIENTE,
            Atestacion::Bitcoin(_) => TAG_BITCOIN,
            Atestacion::Desconocida(t, _) => *t,
        }
    }

    fn escribir(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tag());
        let mut payload = Vec::new();
        match self {
            Atestacion::Pendiente(uri) => escribir_varbytes(&mut payload, uri.as_bytes()),
            Atestacion::Bitcoin(altura) => escribir_varuint(&mut payload, *altura),
            Atestacion::Desconocida(_, p) => payload.extend_from_slice(p),
        }
        escribir_varbytes(out, &payload);
    }

    fn leer(lector: &mut Lector) -> Result<Atestacion, Error> {
        let tag: [u8; 8] = lector.bytes(8)?.try_into().expect("8 bytes");
        let payload = lector.varbytes(MAX_PAYLOAD, 0)?;
        let mut sub = Lector::new(payload);
        let a = match tag {
            TAG_PENDIENTE => {
                let uri = sub.varbytes(MAX_URI, 0)?;
                if !uri.iter().all(|c| URI_PERMITIDOS.contains(c)) {
                    return Err(Error::Ots);
                }
                Atestacion::Pendiente(String::from_utf8(uri.to_vec()).map_err(|_| Error::Ots)?)
            }
            TAG_BITCOIN => Atestacion::Bitcoin(sub.varuint()?),
            _ => return Ok(Atestacion::Desconocida(tag, payload.to_vec())),
        };
        sub.fin()?;
        Ok(a)
    }
}

/// Orden de python-opentimestamps: por tag; a igual tag, por URI, altura o payload.
impl Ord for Atestacion {
    fn cmp(&self, otra: &Self) -> Ordering {
        self.tag().cmp(&otra.tag()).then_with(|| match (self, otra) {
            (Atestacion::Pendiente(a), Atestacion::Pendiente(b)) => a.as_bytes().cmp(b.as_bytes()),
            (Atestacion::Bitcoin(a), Atestacion::Bitcoin(b)) => a.cmp(b),
            (Atestacion::Desconocida(_, a), Atestacion::Desconocida(_, b)) => a.cmp(b),
            _ => Ordering::Equal,
        })
    }
}

impl PartialOrd for Atestacion {
    fn partial_cmp(&self, otra: &Self) -> Option<Ordering> {
        Some(self.cmp(otra))
    }
}

// ------------------------------------------------------------------ árbol

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub msg: Vec<u8>,
    pub atestaciones: BTreeSet<Atestacion>,
    pub ops: BTreeMap<Op, Timestamp>,
}

impl Timestamp {
    pub fn new(msg: Vec<u8>) -> Self {
        Timestamp { msg, atestaciones: BTreeSet::new(), ops: BTreeMap::new() }
    }

    /// Añade la operación (si no estaba) y devuelve el nodo resultante.
    pub fn anadir_op(&mut self, op: Op) -> Result<&mut Timestamp, Error> {
        if !self.ops.contains_key(&op) {
            let resultado = op.aplicar(&self.msg)?;
            self.ops.insert(op.clone(), Timestamp::new(resultado));
        }
        Ok(self.ops.get_mut(&op).expect("recién insertado"))
    }

    pub fn fusionar(&mut self, otro: Timestamp) -> Result<(), Error> {
        if self.msg != otro.msg {
            return Err(Error::Ots);
        }
        self.atestaciones.extend(otro.atestaciones);
        for (op, sub) in otro.ops {
            self.anadir_op(op)?.fusionar(sub)?;
        }
        Ok(())
    }

    /// Primer nodo del árbol cuyo mensaje es `msg`.
    pub fn nodo_mut(&mut self, msg: &[u8]) -> Option<&mut Timestamp> {
        if self.msg == msg {
            return Some(self);
        }
        for sub in self.ops.values_mut() {
            if let Some(n) = sub.nodo_mut(msg) {
                return Some(n);
            }
        }
        None
    }

    pub fn todas_las_atestaciones(&self) -> Vec<(Vec<u8>, Atestacion)> {
        let mut v: Vec<(Vec<u8>, Atestacion)> = self.atestaciones.iter().map(|a| (self.msg.clone(), a.clone())).collect();
        for sub in self.ops.values() {
            v.extend(sub.todas_las_atestaciones());
        }
        v
    }

    fn escribir(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.atestaciones.is_empty() && self.ops.is_empty() {
            return Err(Error::Ots);
        }
        let atest: Vec<&Atestacion> = self.atestaciones.iter().collect();
        if atest.len() > 1 {
            for a in &atest[..atest.len() - 1] {
                out.extend_from_slice(&[0xff, 0x00]);
                a.escribir(out);
            }
        }
        if self.ops.is_empty() {
            out.push(0x00);
            atest[atest.len() - 1].escribir(out);
            return Ok(());
        }
        if let Some(ultima) = atest.last() {
            out.extend_from_slice(&[0xff, 0x00]);
            ultima.escribir(out);
        }
        let ops: Vec<(&Op, &Timestamp)> = self.ops.iter().collect();
        for (op, sub) in &ops[..ops.len() - 1] {
            out.push(0xff);
            op.escribir(out);
            sub.escribir(out)?;
        }
        let (op, sub) = ops[ops.len() - 1];
        op.escribir(out);
        sub.escribir(out)
    }

    pub fn serializar(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.escribir(&mut out)?;
        Ok(out)
    }

    fn leer(lector: &mut Lector, msg: Vec<u8>, limite: usize) -> Result<Timestamp, Error> {
        if limite == 0 || msg.len() > MAX_MSG {
            return Err(Error::Ots);
        }
        let mut t = Timestamp::new(msg);
        let mut tag = lector.byte()?;
        while tag == 0xff {
            let siguiente = lector.byte()?;
            t.leer_elemento(lector, siguiente, limite)?;
            tag = lector.byte()?;
        }
        t.leer_elemento(lector, tag, limite)?;
        Ok(t)
    }

    fn leer_elemento(&mut self, lector: &mut Lector, tag: u8, limite: usize) -> Result<(), Error> {
        if tag == 0x00 {
            self.atestaciones.insert(Atestacion::leer(lector)?);
        } else {
            let op = Op::leer(lector, tag)?;
            let resultado = op.aplicar(&self.msg)?;
            let sub = Timestamp::leer(lector, resultado, limite - 1)?;
            self.ops.insert(op, sub);
        }
        Ok(())
    }

    /// Lee una respuesta de calendario para `compromiso`, como `Timestamp.deserialize`.
    pub fn desde_respuesta(compromiso: &[u8], respuesta: &[u8]) -> Result<Timestamp, Error> {
        if respuesta.len() > MAX_RESPUESTA {
            return Err(Error::Ots);
        }
        Timestamp::leer(&mut Lector::new(respuesta), compromiso.to_vec(), LIMITE_RECURSION)
    }
}

// ------------------------------------------------------------------ archivo .ots

/// Prueba OpenTimestamps separada del documento (`documento.ots`), siempre con SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prueba {
    pub timestamp: Timestamp,
}

impl Prueba {
    /// Empieza un sello: huella del documento → append nonce(16) → sha256 = compromiso que se envía.
    /// El nonce aleatorio evita que los calendarios puedan relacionar huellas entre sí.
    pub fn nueva(huella: [u8; 32], nonce: [u8; 16]) -> Result<(Prueba, Vec<u8>), Error> {
        let mut raiz = Timestamp::new(huella.to_vec());
        let compromiso = raiz.anadir_op(Op::Append(nonce.to_vec()))?.anadir_op(Op::Sha256)?.msg.clone();
        Ok((Prueba { timestamp: raiz }, compromiso))
    }

    pub fn huella(&self) -> [u8; 32] {
        self.timestamp.msg.as_slice().try_into().expect("32 bytes")
    }

    /// Incorpora la respuesta de un calendario (a `/digest` o a `/timestamp/<hex>`) en el nodo del compromiso.
    pub fn incorporar(&mut self, compromiso: &[u8], respuesta: &[u8]) -> Result<(), Error> {
        let sub = Timestamp::desde_respuesta(compromiso, respuesta)?;
        self.timestamp.nodo_mut(compromiso).ok_or(Error::Ots)?.fusionar(sub)
    }

    /// Calendarios pendientes: (URI, mensaje del nodo que hay que pedir en `/timestamp/<hex>`).
    pub fn pendientes(&self) -> Vec<(String, Vec<u8>)> {
        self.timestamp
            .todas_las_atestaciones()
            .into_iter()
            .filter_map(|(msg, a)| match a {
                Atestacion::Pendiente(uri) => Some((uri, msg)),
                _ => None,
            })
            .collect()
    }

    /// Alturas de bloque de Bitcoin que atestiguan la prueba, ordenadas y sin repetir.
    pub fn bloques_bitcoin(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .timestamp
            .todas_las_atestaciones()
            .into_iter()
            .filter_map(|(_, a)| match a {
                Atestacion::Bitcoin(h) => Some(h),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    pub fn serializar(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(MAGIA);
        escribir_varuint(&mut out, VERSION_MAYOR);
        Op::Sha256.escribir(&mut out);
        out.extend_from_slice(&self.timestamp.msg);
        self.timestamp.escribir(&mut out)?;
        Ok(out)
    }

    pub fn leer(bytes: &[u8]) -> Result<Prueba, Error> {
        let mut l = Lector::new(bytes);
        if l.bytes(MAGIA.len())? != MAGIA || l.varuint()? != VERSION_MAYOR || l.byte()? != 0x08 {
            return Err(Error::Ots);
        }
        let huella = l.bytes(32)?.to_vec();
        let timestamp = Timestamp::leer(&mut l, huella, LIMITE_RECURSION)?;
        l.fin()?;
        Ok(Prueba { timestamp })
    }
}
