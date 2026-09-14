//! Puente JNI entre la app Android (`org.x39.bolsillo.X39Core`) y `x39-core`.
//!
//! Todos los métodos son estáticos. Los errores llegan a Kotlin como `RuntimeException`
//! con un mensaje en español. Los secretos se borran de la memoria nativa al terminar.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use x39_core::{CID_LEN, PK_LEN, SK_LEN, TtlPolicy, share};
use zeroize::Zeroizing;

#[derive(Debug)]
enum PuenteError {
    Jni(jni::errors::Error),
    X39(x39_core::Error),
    Datos(&'static str),
}

impl From<jni::errors::Error> for PuenteError {
    fn from(e: jni::errors::Error) -> Self {
        PuenteError::Jni(e)
    }
}

impl From<x39_core::Error> for PuenteError {
    fn from(e: x39_core::Error) -> Self {
        PuenteError::X39(e)
    }
}

impl std::fmt::Display for PuenteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PuenteError::Jni(e) => write!(f, "error interno JNI: {e}"),
            PuenteError::X39(e) => write!(f, "{e}"),
            PuenteError::Datos(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for PuenteError {}

type Res<T> = Result<T, PuenteError>;

fn public_key_from(env: &jni::Env, array: &JByteArray) -> Res<[u8; PK_LEN]> {
    env.convert_byte_array(array)?
        .try_into()
        .map_err(|_| PuenteError::Datos("clave pública con longitud incorrecta"))
}

fn secret_key_from(env: &jni::Env, array: &JByteArray) -> Res<Zeroizing<[u8; SK_LEN]>> {
    let raw = Zeroizing::new(env.convert_byte_array(array)?);
    if raw.len() != SK_LEN {
        return Err(PuenteError::Datos("clave secreta con longitud incorrecta"));
    }
    let mut sk = Zeroizing::new([0u8; SK_LEN]);
    sk.copy_from_slice(&raw);
    Ok(sk)
}

fn seconds(value: jlong, what: &'static str) -> Res<u64> {
    u64::try_from(value).map_err(|_| PuenteError::Datos(what))
}

/// Devuelve `clave_pública(1568) || clave_secreta(3168)`. Kotlin la parte y cifra la secreta con Android Keystore.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_generateKeypair<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let kp = x39_core::generate_keypair()?;
            let mut out = Zeroizing::new(Vec::with_capacity(PK_LEN + SK_LEN));
            out.extend_from_slice(&kp.public);
            out.extend_from_slice(kp.secret.as_slice());
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_publicKeyToText<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    public_key: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &public_key)?;
            Ok(env.new_string(share::encode_public_key(&pk))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_publicKeyFromText<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    text: JString<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = share::decode_public_key(&text.to_string())?;
            Ok(env.byte_array_from_slice(&pk)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_fingerprint<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    public_key: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &public_key)?;
            Ok(env.new_string(share::fingerprint(&pk))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Cifra `plaintext` para `public_key` y devuelve el texto `X39MSG1:…` listo para compartir.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_seal<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    public_key: JByteArray<'c>,
    plaintext: JByteArray<'c>,
    now_secs: jlong,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &public_key)?;
            let pt = Zeroizing::new(env.convert_byte_array(&plaintext)?);
            let now = seconds(now_secs, "hora del sistema inválida")?;
            let capsule = x39_core::seal(&pk, &pt, b"", None, now)?;
            Ok(env.new_string(share::encode_capsule(&capsule))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Abre un texto `X39MSG1:…`. Devuelve `cid(16) || plaintext`; Kotlin guarda el cid para el anti-replay.
/// El TTL es obligatorio (> 0), igual que Paris tras MESO2.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_open<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    secret_key: JByteArray<'c>,
    text: JString<'c>,
    now_secs: jlong,
    ttl_secs: jlong,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let sk = secret_key_from(env, &secret_key)?;
            let now = seconds(now_secs, "hora del sistema inválida")?;
            let ttl = seconds(ttl_secs, "ttl inválido")?;
            if ttl == 0 {
                return Err(PuenteError::Datos("el ttl debe ser mayor que 0"));
            }
            let capsule = share::decode_capsule(&text.to_string())?;
            let (header, pt) = x39_core::open(&sk, &capsule, b"", Some(TtlPolicy { now, ttl }))?;
            let mut out = Zeroizing::new(Vec::with_capacity(CID_LEN + pt.len()));
            out.extend_from_slice(&header.cid);
            out.extend_from_slice(&pt);
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_maxPlaintextForQr<'c>(
    _unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
) -> jint {
    share::max_plaintext_for_qr() as jint
}
