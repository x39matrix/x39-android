//! Puente JNI entre la app Android (`org.x39.bolsillo.X39Core`) y `x39-core`.
//!
//! Todos los métodos son estáticos. Los errores llegan a Kotlin como `RuntimeException`
//! con un mensaje en español. Los secretos se borran de la memoria nativa al terminar.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use x39_core::directorio;
use x39_core::firma::{self, DSA_PK_LEN, DSA_SEED_LEN};
use x39_core::invitacion;
use x39_core::ots::Prueba;
use x39_core::sala;
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

/// Verifica una revocación «X39REV1:…» firmada por la autoridad. Devuelve "codigo|fecha|motivo"
/// (código canónico de 12 símbolos) o lanza.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_revocationVerify<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    authority_key: JByteArray<'c>,
    text: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = signing_public_key_from(env, &authority_key)?;
            let r = invitacion::verificar_revocacion(&pk, &text.to_string())?;
            Ok(env.new_string(format!("{}|{}|{}", r.codigo, r.fecha, r.motivo))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Acreditación: firma la invitación con la semilla ML-DSA-87 del titular. Devuelve «X39ACR1:…».
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_accreditationCreate<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    seed: JByteArray<'c>,
    invitation: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &seed)?;
            let acr = invitacion::acreditar(&seed, &invitation.to_string())?;
            Ok(env.new_string(acr)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica una acreditación «X39ACR1:…» con la clave de la autoridad y la clave de firma del titular.
/// Devuelve "caduca|nombre"; si alguna firma falla o ha caducado, lanza la excepción.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_accreditationVerify<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    authority_key: JByteArray<'c>,
    holder_signing_key: JByteArray<'c>,
    text: JString<'c>,
    today: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let aut = signing_public_key_from(env, &authority_key)?;
            let titular = signing_public_key_from(env, &holder_signing_key)?;
            let inv = invitacion::verificar_acreditacion(&aut, &titular, &text.to_string(), &today.to_string())?;
            Ok(env.new_string(format!("{}|{}", inv.caduca, inv.nombre))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Código corto de contacto («XXXX-XXXX-XXXX») de una clave de firma ML-DSA-87.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_directoryCode<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    signing_public_key: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = signing_public_key_from(env, &signing_public_key)?;
            Ok(env.new_string(directorio::codigo_visible(&directorio::codigo(&pk)))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Código tal como lo tecleó alguien → canónico (12 símbolos, sin guiones). Lanza si no es un código.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_directoryNormalizeCode<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    text: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let c = directorio::normalizar_codigo(&text.to_string())
                .map_err(|_| PuenteError::Datos("El código son 12 letras o números, como XXXX-XXXX-XXXX."))?;
            Ok(env.new_string(c)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Entrada del directorio «X39DIR1:…» firmada con la semilla del titular: sus claves y su acreditación (o vacía).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_directoryEntryCreate<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    seed: JByteArray<'c>,
    kem_public_key: JByteArray<'c>,
    accreditation: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &seed)?;
            let kem = public_key_from(env, &kem_public_key)?;
            let acr = if accreditation.is_null() { String::new() } else { accreditation.to_string() };
            let acr = acr.trim();
            let entrada = directorio::publicar(&seed, &kem, (!acr.is_empty()).then_some(acr))?;
            Ok(env.new_string(entrada)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica una entrada del directorio y la devuelve como texto de contacto: «X39ID1:… X39ACR1:…»
/// (lo mismo que se pega en Añadir contacto). Con `expectedCode` no vacío exige además que sea el de ese código.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_directoryEntryRead<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    text: JString<'c>,
    expected_code: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let esperado = if expected_code.is_null() { String::new() } else { expected_code.to_string() };
            let e = if esperado.is_empty() {
                directorio::leer(&text.to_string())?
            } else {
                let canonico = directorio::normalizar_codigo(&esperado)
                    .map_err(|_| PuenteError::Datos("El código son 12 letras o números, como XXXX-XXXX-XXXX."))?;
                directorio::leer_para_codigo(&text.to_string(), &canonico)
                    .map_err(|_| PuenteError::Datos("El directorio devolvió una clave que no corresponde a ese código."))?
            };
            let mut salida = share::encode_identity(&e.kem_pk, &e.dsa_pk);
            if let Some(acr) = e.acreditacion {
                salida.push(' ');
                salida.push_str(&acr);
            }
            Ok(env.new_string(salida)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

// ---- Salas por departamento (x39-core/src/sala.rs)

fn clave_sala_from(env: &jni::Env, array: &JByteArray) -> Res<Zeroizing<[u8; sala::CLAVE_LEN]>> {
    let raw = Zeroizing::new(env.convert_byte_array(array)?);
    if raw.len() != sala::CLAVE_LEN {
        return Err(PuenteError::Datos("clave de sala con longitud incorrecta"));
    }
    let mut k = Zeroizing::new([0u8; sala::CLAVE_LEN]);
    k.copy_from_slice(&raw);
    Ok(k)
}

fn epoca_from(value: jint) -> Res<u32> {
    u32::try_from(value).map_err(|_| PuenteError::Datos("época negativa"))
}

/// Clave nueva de sala (32 bytes). El llamante la guarda cifrada.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomNewKey<'c>(mut unowned: EnvUnowned<'c>, _class: JClass<'c>) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let k = Zeroizing::new(sala::nueva_clave()?);
            Ok(env.byte_array_from_slice(&*k)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Cifra un mensaje para la sala. Devuelve «X39SALA1:…».
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomEncrypt<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    key: JByteArray<'c>,
    room: JString<'c>,
    epoch: jint,
    plaintext: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let k = clave_sala_from(env, &key)?;
            let texto = Zeroizing::new(env.convert_byte_array(&plaintext)?);
            let m = sala::cifrar(&k, &room.to_string(), epoca_from(epoch)?, &texto)?;
            Ok(env.new_string(m)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomDecrypt<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    key: JByteArray<'c>,
    room: JString<'c>,
    epoch: jint,
    message: JString<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let k = clave_sala_from(env, &key)?;
            let texto = Zeroizing::new(sala::descifrar(&k, &room.to_string(), epoca_from(epoch)?, &message.to_string())?);
            Ok(env.byte_array_from_slice(&texto)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Firma una publicación en la sala (mensaje, sobre o alta). Devuelve «X39FIRMA1:…».
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomSign<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    seed: JByteArray<'c>,
    room: JString<'c>,
    epoch: jint,
    action: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &seed)?;
            let f = sala::firmar(&seed, &room.to_string(), epoca_from(epoch)?, &action.to_string())?;
            Ok(env.new_string(f)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// 1 si la firma de la publicación es de esa clave; si no, lanza.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomVerify<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    signing_public_key: JByteArray<'c>,
    room: JString<'c>,
    epoch: jint,
    action: JString<'c>,
    signature: JString<'c>,
) -> jint {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = signing_public_key_from(env, &signing_public_key)?;
            sala::verificar(&pk, &room.to_string(), epoca_from(epoch)?, &action.to_string(), &signature.to_string())?;
            Ok(1)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Eslabón de la cadena (hex) a partir del anterior (hex o vacío para el primero).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_roomChainLink<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    previous_hex: JString<'c>,
    room: JString<'c>,
    seq: jlong,
    sender: JString<'c>,
    message: JString<'c>,
    signature: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let prev = previous_hex.to_string();
            let anterior = if prev.is_empty() {
                [0u8; 32]
            } else {
                sala::de_hex(&prev).ok_or(PuenteError::Datos("eslabón anterior mal formado"))?
            };
            let seq = seconds(seq, "seq negativo")?;
            let h = sala::eslabon(&anterior, &room.to_string(), seq, &sender.to_string(), &message.to_string(), &signature.to_string());
            Ok(env.new_string(sala::hex(&h))?)
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

// ============================================================================
// X39-CALL-KEY — puente para las llamadas cifradas (app «x39» / Comunicaciones).
// La criptografía está en x39_core::call_key (la que pasa los vectores byte a byte).
// El bridge es sin estado: los secretos efímeros (dk, ss) viajan a Kotlin como
// bytes y la app los guarda (Keystore) entre pasos; nunca salen del aparato.
// ============================================================================
use x39_core::CT_KEM_LEN;
use x39_core::call_key;

/// Oferta de llamada: par efímero ML-KEM + firma ML-DSA-87 de la cadena canónica.
/// Devuelve `ek(1568) || dk(3168) || firma(4627)`. Kotlin guarda `dk` (secreto).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callOffer<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    call_hash: JString<'c>,
    from_bh: JString<'c>,
    to_bh: JString<'c>,
    epoch: jint,
    call_salt: JByteArray<'c>,
    mldsa_seed: JByteArray<'c>,
    ts: JString<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let seed = seed_from(env, &mldsa_seed)?;
            let salt = fijo::<32>(env, &call_salt, "call_salt con longitud incorrecta")?;
            let (of, dk) = call_key::hacer_oferta(
                &call_hash.to_string(),
                epoca_from(epoch)?,
                &from_bh.to_string(),
                &to_bh.to_string(),
                &salt,
                &seed,
                &ts.to_string(),
            )?;
            let mut out = Zeroizing::new(Vec::with_capacity(PK_LEN + SK_LEN + firma::SIG_LEN));
            out.extend_from_slice(&of.ek);
            out.extend_from_slice(dk.as_slice());
            out.extend_from_slice(&of.sig_mldsa);
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica una oferta recibida: reconstruye la cadena canónica con los campos
/// recibidos y comprueba la firma ML-DSA-87 del emisor. Devuelve 1, o lanza.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callVerifyOffer<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    call_hash: JString<'c>,
    from_bh: JString<'c>,
    to_bh: JString<'c>,
    epoch: jint,
    ek: JByteArray<'c>,
    call_salt: JByteArray<'c>,
    ts: JString<'c>,
    signature: JByteArray<'c>,
    emisor_pk: JByteArray<'c>,
) -> jint {
    unowned
        .with_env(|env| -> Res<_> {
            let ek = public_key_from(env, &ek)?;
            let salt = fijo::<32>(env, &call_salt, "call_salt con longitud incorrecta")?;
            let sig = env.convert_byte_array(&signature)?;
            let pk = signing_public_key_from(env, &emisor_pk)?;
            let canonical = call_key::cadena_oferta(
                &call_hash.to_string(),
                &from_bh.to_string(),
                &to_bh.to_string(),
                epoca_from(epoch)?,
                &ek,
                &salt,
                &ts.to_string(),
            );
            if firma::verify(&pk, canonical.as_bytes(), call_key::CALL_CTX, &sig) {
                Ok(1)
            } else {
                Err(PuenteError::X39(x39_core::Error::Firma))
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Firma el criptograma ML-KEM (`ct`) de esta llamada con la identidad del emisor.
/// Devuelve la firma ML-DSA-87 (4627 bytes), que se envía junto al `ct`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callKemSign<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    call_hash: JString<'c>,
    from_bh: JString<'c>,
    to_bh: JString<'c>,
    epoch: jint,
    ct: JByteArray<'c>,
    ts: JString<'c>,
    mldsa_seed: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let ct = fijo::<CT_KEM_LEN>(env, &ct, "criptograma ML-KEM con longitud incorrecta")?;
            let seed = seed_from(env, &mldsa_seed)?;
            let sig = call_key::firmar_kem(
                &call_hash.to_string(),
                &from_bh.to_string(),
                &to_bh.to_string(),
                epoca_from(epoch)?,
                &ct,
                &seed,
                &ts.to_string(),
            )?;
            Ok(env.byte_array_from_slice(&sig)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Verifica la firma del `ct` recibido contra la identidad del emisor. Devuelve 1, o lanza.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callKemVerify<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    call_hash: JString<'c>,
    from_bh: JString<'c>,
    to_bh: JString<'c>,
    epoch: jint,
    ct: JByteArray<'c>,
    ts: JString<'c>,
    signature: JByteArray<'c>,
    emisor_pk: JByteArray<'c>,
) -> jint {
    unowned
        .with_env(|env| -> Res<_> {
            let ct = fijo::<CT_KEM_LEN>(env, &ct, "criptograma ML-KEM con longitud incorrecta")?;
            let sig = env.convert_byte_array(&signature)?;
            let pk = signing_public_key_from(env, &emisor_pk)?;
            call_key::verificar_kem(
                &call_hash.to_string(),
                &from_bh.to_string(),
                &to_bh.to_string(),
                epoca_from(epoch)?,
                &ct,
                &ts.to_string(),
                &pk,
                &sig,
            )?;
            Ok(1)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Encapsula contra la `ek` efímera del otro. Devuelve `ct(1568) || ss(32)`.
/// Kotlin guarda `ss` (secreto) y envía `ct`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callEncapsulate<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    ek_otro: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let ek = public_key_from(env, &ek_otro)?;
            let (ct, ss) = call_key::encapsular(&ek)?;
            let mut out = Zeroizing::new(Vec::with_capacity(CT_KEM_LEN + 32));
            out.extend_from_slice(&ct);
            out.extend_from_slice(ss.as_slice());
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Desencapsula el `ct` que nos llegó con nuestra `dk` efímera. Devuelve `ss(32)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callDecapsulate<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    dk: JByteArray<'c>,
    ct: JByteArray<'c>,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let dk = secret_key_from(env, &dk)?;
            let ct = fijo::<CT_KEM_LEN>(env, &ct, "criptograma ML-KEM con longitud incorrecta")?;
            let ss = call_key::desencapsular(&dk, &ct)?;
            Ok(env.byte_array_from_slice(ss.as_slice())?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Deriva los 32 bytes de la clave de fotograma (lo que se entrega a LiveKit).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callDerive<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    bh_a: JString<'c>,
    bh_b: JString<'c>,
    ek_a: JByteArray<'c>,
    ek_b: JByteArray<'c>,
    ss_a: JByteArray<'c>,
    ss_b: JByteArray<'c>,
    call_hash: JString<'c>,
    call_salt: JByteArray<'c>,
    epoch: jint,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let eka = public_key_from(env, &ek_a)?;
            let ekb = public_key_from(env, &ek_b)?;
            let ssa = fijo::<32>(env, &ss_a, "secreto A con longitud incorrecta")?;
            let ssb = fijo::<32>(env, &ss_b, "secreto B con longitud incorrecta")?;
            let salt = fijo::<32>(env, &call_salt, "call_salt con longitud incorrecta")?;
            let key = call_key::derivar_material(
                &bh_a.to_string(),
                &bh_b.to_string(),
                &eka,
                &ekb,
                &ssa,
                &ssb,
                &call_hash.to_string(),
                &salt,
                epoca_from(epoch)?,
            );
            Ok(env.byte_array_from_slice(key.as_ref())?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Las seis palabras SAS para comparar por un canal aparte. Devuelve "p1 p2 ... p6".
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_callSas<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    frame_key: JByteArray<'c>,
    call_hash: JString<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let key = fijo::<32>(env, &frame_key, "clave de fotograma con longitud incorrecta")?;
            let palabras = call_key::sas(&key, &call_hash.to_string());
            Ok(env.new_string(palabras.join(" "))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

// ---------------------------------------------------------------- x39tunel v2 (x39-core/src/tunel.rs)

/// Petición de PSK de WireGuard: devuelve `psk(32) || cápsula`. La PSK va al par WireGuard
/// local; la cápsula, al servidor por la señalización (`{"type":"psk","capsula":base64}`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_tunelPedirPsk<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    servidor_kem_pk: JByteArray<'c>,
    mldsa_seed: JByteArray<'c>,
    wg_pk: JByteArray<'c>,
    hasta: jlong,
    ahora: jlong,
) -> JByteArray<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &servidor_kem_pk)?;
            let seed = seed_from(env, &mldsa_seed)?;
            let wg = fijo::<32>(env, &wg_pk, "clave WireGuard con longitud incorrecta")?;
            let (capsula, psk) = x39_core::tunel::pedir_psk(
                &pk,
                &seed,
                &wg,
                seconds(hasta, "fecha de caducidad inválida")?,
                seconds(ahora, "hora inválida")?,
            )?;
            let mut out = Zeroizing::new(Vec::with_capacity(32 + capsula.len()));
            out.extend_from_slice(psk.as_ref());
            out.extend_from_slice(&capsula);
            Ok(env.byte_array_from_slice(&out)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Huella SHA-256 (hex) de la clave ML-KEM del servidor: la que la app enseña y compara.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Core_tunelHuellaServidor<'c>(
    mut unowned: EnvUnowned<'c>,
    _class: JClass<'c>,
    servidor_kem_pk: JByteArray<'c>,
) -> JString<'c> {
    unowned
        .with_env(|env| -> Res<_> {
            let pk = public_key_from(env, &servidor_kem_pk)?;
            Ok(env.new_string(x39_core::tunel::huella_servidor(&pk))?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
