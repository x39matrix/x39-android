//! Puente de cobro para los métodos estáticos de org.x39.bolsillo.X39Hub.

pub mod cobro;

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jlong};
use x39_core::firma::DSA_SEED_LEN;
use x39_hub::ErrorHub;
use zeroize::Zeroizing;

#[derive(Debug)]
enum ErrorPuente {
    Jni(jni::errors::Error),
    Hub(ErrorHub),
}

impl From<jni::errors::Error> for ErrorPuente {
    fn from(error: jni::errors::Error) -> Self {
        Self::Jni(error)
    }
}

impl From<ErrorHub> for ErrorPuente {
    fn from(error: ErrorHub) -> Self {
        Self::Hub(error)
    }
}

impl std::fmt::Display for ErrorPuente {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jni(error) => write!(f, "error interno JNI: {error}"),
            Self::Hub(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ErrorPuente {}

type ResultadoJni<T> = Result<T, ErrorPuente>;

/// Lee los campos declarados sin autenticar al beneficiario.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Hub_cobroLeer<'c>(
    mut marco: EnvUnowned<'c>,
    _clase: JClass<'c>,
    portable: JByteArray<'c>,
) -> JString<'c> {
    marco
        .with_env(|env| -> ResultadoJni<_> {
            let bytes = env.convert_byte_array(&portable)?;
            Ok(env.new_string(cobro::cobro_leer(&bytes)?)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Todo rechazo del cobro se devuelve como código, incluido un argumento nulo.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Hub_cobroVerificar<'c>(
    mut marco: EnvUnowned<'c>,
    _clase: JClass<'c>,
    portable: JByteArray<'c>,
    huella_esperada_hex: JString<'c>,
    red: JString<'c>,
    ahora_unix_s: jlong,
    nonce_ya_registrado: jboolean,
) -> jint {
    marco
        .with_env(|env| -> jni::errors::Result<Option<jint>> {
            if portable.is_null() || huella_esperada_hex.is_null() || red.is_null() {
                return Ok(Some(cobro::codigos::FORMATO));
            }
            let bytes = env.convert_byte_array(&portable)?;
            let huella = huella_esperada_hex.try_to_string(env)?;
            let red = red.try_to_string(env)?;
            Ok(Some(cobro::cobro_verificar(
                &bytes,
                &huella,
                &red,
                ahora_unix_s,
                nonce_ya_registrado,
            )))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
        // El valor de respaldo de JNI tras una excepción tampoco puede autorizar un pago.
        .unwrap_or(cobro::codigos::FORMATO)
}

/// Emite un cobro. Los errores de emisión siguen la convención RuntimeException.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_x39_bolsillo_X39Hub_cobroFirmar<'c>(
    mut marco: EnvUnowned<'c>,
    _clase: JClass<'c>,
    semilla: JByteArray<'c>,
    red: JString<'c>,
    direccion: JString<'c>,
    satoshis: jlong,
    caduca_unix_s: jlong,
) -> JByteArray<'c> {
    marco
        .with_env(|env| -> ResultadoJni<_> {
            if semilla.len(env)? != DSA_SEED_LEN {
                return Err(ErrorHub::Formato.into());
            }
            let red = red.try_to_string(env)?;
            let direccion = direccion.try_to_string(env)?;
            let portable = {
                let copia = Zeroizing::new(env.convert_byte_array(&semilla)?);
                cobro::cobro_firmar(&copia, &red, &direccion, satoshis, caduca_unix_s)?
            };
            Ok(env.byte_array_from_slice(&portable)?)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
