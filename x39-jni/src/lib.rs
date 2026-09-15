//! Puente JNI entre la app Android (`org.x39.bolsillo.X39Core`) y `x39-core`.
//!
//! Todos los métodos son estáticos. Los errores llegan a Kotlin como `RuntimeException`
//! con un mensaje en español. Los secretos se borran de la memoria nativa al terminar.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use x39_core::firma::{self, DSA_PK_LEN, DSA_SEED_LEN};
use x39_core::invitacion;
use x39_core::ots::Prueba;
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

fn signing_public_key_from(env: &jni::Env, array: &JByteArray) -> Res<[u8; DSA_PK_LEN]> {
    env.convert_byte_array(array)?
        .try_into()
        .map_err(|_| PuenteError::Datos("clave de firma con longitud incorrecta"))
}

fn seed_from(env: &jni::Env, array: &JByteArray) -> Res<Zeroizing<[u8; DSA_SEED_LEN]>> {
    let raw = Zeroizing::new(env.convert_byte_array(array)?);
    if raw.len() != DSA_SEED_LEN {
        return Err(PuenteError::Datos("semilla de firma con longitud incorrecta"));
    }
    let mut seed = Zeroizing::new([0u8; DSA_SEED_LEN]);
    seed.copy_from_slice(&raw);
    Ok(seed)
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

/// Semilla ML-DSA-87 de 32 bytes. Kotlin la cifra con Android Keystore; la clave se deriva al firmar.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_generateSigningSeed<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = firma::generate_seed()?;
            Ok(env.byte_array_from_slice(seed.as_slice())?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_signingPublicKey<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    seed: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &seed)?;
            Ok(env.byte_array_from_slice(&firma::public_key(&seed))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_identityToText<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    kem_public_key: JByteArray<'c>,
    signing_public_key: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let kem = public_key_from(env, &kem_public_key)?;
            let dsa = signing_public_key_from(env, &signing_public_key)?;
            Ok(env.new_string(share::encode_identity(&kem, &dsa))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Devuelve `clave_ml_kem(1568) || clave_ml_dsa(2592)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_identityFromText<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    text: JString<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let (kem, dsa) = share::decode_identity(&text.to_string())?;
            let mut out = Vec::with_capacity(PK_LEN + DSA_PK_LEN);
            out.extend_from_slice(&kem);
            out.extend_from_slice(&dsa);
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_identityFingerprint<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    kem_public_key: JByteArray<'c>,
    signing_public_key: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let kem = public_key_from(env, &kem_public_key)?;
            let dsa = signing_public_key_from(env, &signing_public_key)?;
            Ok(env.new_string(share::fingerprint_identity(&kem, &dsa))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Firma `payload` con ML-DSA-87 para el destinatario, lo sella y devuelve el texto `X39MSG1:…`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_sealSigned<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    recipient_public_key: JByteArray<'c>,
    seed: JByteArray<'c>,
    payload: JByteArray<'c>,
    now_secs: jlong,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &recipient_public_key)?;
            let seed = seed_from(env, &seed)?;
            let payload = Zeroizing::new(env.convert_byte_array(&payload)?);
            let now = seconds(now_secs, "hora del sistema inválida")?;
            let body = firma::sign_for(&seed, &pk, &payload)?;
            let capsule = x39_core::seal(&pk, &body, b"", None, now)?;
            Ok(env.new_string(share::encode_capsule(&capsule))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Carga de un cuerpo firmado SIN verificar, para leer el remitente declarado. Lanza si no está firmado.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_unverifiedPayload<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    body: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let body = Zeroizing::new(env.convert_byte_array(&body)?);
            let payload = firma::unverified_payload(&body).ok_or(PuenteError::Datos("mensaje sin firma"))?;
            Ok(env.byte_array_from_slice(payload)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica la firma del remitente sobre un cuerpo abierto y devuelve la carga. Lanza si no es válida.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_verifySigned<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    sender_signing_key: JByteArray<'c>,
    my_public_key: JByteArray<'c>,
    body: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let sender = signing_public_key_from(env, &sender_signing_key)?;
            let mine = public_key_from(env, &my_public_key)?;
            let body = Zeroizing::new(env.convert_byte_array(&body)?);
            let payload = firma::verify_from(&sender, &mine, &body)?;
            Ok(env.byte_array_from_slice(payload)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

fn fijo<const N: usize>(env: &jni::Env, array: &JByteArray, que: &'static str) -> Res<[u8; N]> {
    env.convert_byte_array(array)?.try_into().map_err(|_| PuenteError::Datos(que))
}

/// Firma ML-DSA-87 estándar (contexto vacío) de `message` con la semilla. Devuelve 4627 bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_signMessage<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    seed: JByteArray<'c>,
    message: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &seed)?;
            let msg = env.convert_byte_array(&message)?;
            Ok(env.byte_array_from_slice(&firma::sign(&seed, &msg, b"")?)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Devuelve 1 si la firma ML-DSA-87 (contexto vacío) es válida; si no, lanza.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_verifyMessage<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    signing_public_key: JByteArray<'c>,
    message: JByteArray<'c>,
    signature: JByteArray<'c>,
) -> jint {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = signing_public_key_from(env, &signing_public_key)?;
            let msg = env.convert_byte_array(&message)?;
            let sig = env.convert_byte_array(&signature)?;
            if firma::verify(&pk, &msg, b"", &sig) { Ok(1) } else { Err(PuenteError::X39(x39_core::Error::Firma)) }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Compromiso OpenTimestamps que se envía a los calendarios: sha256(huella || nonce).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_otsCommitment<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    digest: JByteArray<'c>,
    nonce: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let (_, compromiso) = Prueba::nueva(fijo(env, &digest, "huella de 32 bytes")?, fijo(env, &nonce, "nonce de 16 bytes")?)?;
            Ok(env.byte_array_from_slice(&compromiso)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Incorpora una respuesta de calendario. Con `ots` nulo empieza la prueba desde huella y nonce.
/// Devuelve el `.ots` completo actualizado.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_otsIncorporate<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    ots: JByteArray<'c>,
    digest: JByteArray<'c>,
    nonce: JByteArray<'c>,
    commitment: JByteArray<'c>,
    response: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let mut prueba = if ots.is_null() {
                Prueba::nueva(fijo(env, &digest, "huella de 32 bytes")?, fijo(env, &nonce, "nonce de 16 bytes")?)?.0
            } else {
                Prueba::leer(&env.convert_byte_array(&ots)?)?
            };
            prueba.incorporar(&env.convert_byte_array(&commitment)?, &env.convert_byte_array(&response)?)?;
            Ok(env.byte_array_from_slice(&prueba.serializar()?)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Matriz QR (corrección L, modo binario) de unos bytes: ancho en u16 big-endian seguido de un byte
/// por módulo, fila a fila (1 = oscuro). Una clave ML-DSA-87 (2.592 bytes) cabe en la versión 40.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_qrMatrix<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    data: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let datos = env.convert_byte_array(&data)?;
            let qr = qrcode::QrCode::with_error_correction_level(&datos, qrcode::EcLevel::L)
                .map_err(|_| PuenteError::Datos("los datos no caben en un código QR"))?;
            let ancho = qr.width();
            let mut salida = Vec::with_capacity(2 + ancho * ancho);
            salida.extend_from_slice(&(ancho as u16).to_be_bytes());
            salida.extend(qr.to_colors().iter().map(|c| u8::from(*c == qrcode::Color::Dark)));
            Ok(env.byte_array_from_slice(&salida)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica una invitación «X39INV1:…» con la clave pública de la autoridad (el Ayuntamiento).
/// `today` es AAAA-MM-DD. Devuelve "caduca|nombre"; si no verifica o ha caducado, lanza la excepción.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_invitationVerify<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    authority_key: JByteArray<'c>,
    text: JString<'c>,
    today: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = signing_public_key_from(env, &authority_key)?;
            let inv = invitacion::verificar(&pk, &text.to_string(), &today.to_string())?;
            Ok(env.new_string(format!("{}|{}", inv.caduca, inv.nombre))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Calendarios pendientes, una línea por cada uno: "uri mensaje_hex".
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_otsPending<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    ots: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let prueba = Prueba::leer(&env.convert_byte_array(&ots)?)?;
            let lineas: Vec<String> = prueba
                .pendientes()
                .into_iter()
                .map(|(uri, msg)| format!("{uri} {}", msg.iter().map(|b| format!("{b:02x}")).collect::<String>()))
                .collect();
            Ok(env.new_string(lineas.join("\n"))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Alturas de bloque de Bitcoin que atestiguan la prueba, separadas por comas (vacío si ninguna).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_otsBlocks<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    ots: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let prueba = Prueba::leer(&env.convert_byte_array(&ots)?)?;
            let bloques: Vec<String> = prueba.bloques_bitcoin().iter().map(u64::to_string).collect();
            Ok(env.new_string(bloques.join(","))?)
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
