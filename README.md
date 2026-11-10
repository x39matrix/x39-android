# x39 Mensajería

App de mensajería post-cuántica para Android. El diseño parte de Paris v3 y se valida contra la suite Mesopotamia.

## Qué hay en este repositorio

| Carpeta | Qué es |
|---|---|
| `android/evidencia/` | **X-39 Evidencia** (`org.x39matrix.evidencia`, versión 0.3.6): la app publicada en el repositorio F-Droid propio, en GitHub Releases y en el canister de Internet Computer. Este es su código fuente; su licencia está en `android/evidencia/LICENSE`. |
| `android/app/` | x39 Mensajería (versión 0.13.0), la app que describe el resto de este documento. |
| `android/comun/` | Código Android compartido por las dos apps. |
| `x39-core/` | Núcleo Rust del protocolo de mensajería: sellado y apertura Paris v3 y firma ML-DSA-87. |
| `x39-jni/` | Puente JNI entre Android y `x39-core`. |
| `canister/buzon/` | Código del canister `buzon` (Internet Computer). |
| `vectores/` | Vectores de prueba Paris v3 (Python) y su comprobación cruzada con Rust. |
| `tools/` | `x39_verify.py`, verificador en Python. |
| `scripts/` | Guiones de compilación y de actualización del registro. |
| `pruebas_ots/actas/` | Pruebas OpenTimestamps de las actas publicadas. |
| `docs/`, `diseno/` | Documento institucional y maquetas de pantallas. |

La billetera Bitcoin de autocustodia **no** vive aquí: se desarrolla en su propio repositorio, [`x39-wallet`](https://github.com/x39matrix/x39-wallet) (motor Rust con BDK y módulo Android), y se integra en la app de llamadas, vídeo y mensajes [X39 Enlace](https://github.com/x39matrix/x39-enlace) (`org.x39matrix.llamadas`, publicada en el repositorio F-Droid propio junto a Evidencia), que X-39 Evidencia enlaza desde su botón de comunicaciones. Los tres repositorios públicos del proyecto son este, `x39-wallet` y `x39-enlace`.

## Decisión de arquitectura (2026-09-14)
**Signal + x39. Descartados Element y Matrix.**
- **De Signal:** servidor central mínimo que no ve contenido y reduce metadatos (sealed sender), interfaz sencilla, números de seguridad y mensajes temporales. Se toma el diseño, no su código ni su marca.
- **De x39:** protocolo propio en Rust derivado de Paris (híbrido X25519 + ML-KEM-1024, ratchet con forward secrecy), suite de ataques estilo Mesopotamia, ubicación efímera sin capturas, bloqueo con clave y PIN de coacción, wallet BTC non-custodial.
- **Por qué no Matrix:** su servidor ve pertenencia a salas y tiempos, y su E2EE no es post-cuántico.
- **Coste asumido:** un protocolo propio exige audit externo antes de afirmar públicamente que es seguro.

## Principios (cero humo)
- Las claves del usuario se generan y viven en el móvil. Nunca pasan por un canister ni por un servidor.
- «Contenido cifrado post-cuántico» es la afirmación que se puede hacer. «Sin rastro» todavía no: el anonimato de metadatos está pendiente.
- Todo lo que se afirme debe tener un test que lo demuestre.

## Fases
| Fase | Qué | Criterio de hecho |
|---|---|---|
| 0 | Vectores Paris v3 generados en Python (`vectores/`) | Todas las cápsulas positivas abren y todas las negativas se rechazan |
| 1 | Núcleo Rust `x39-core`: seal/open Paris v3 | Pasa el 100 % de los vectores de la fase 0, y Python abre lo que sella Rust |
| 2 | Handshake híbrido X25519 + ML-KEM-1024 con pre-claves de un solo uso (idea de las burner keys) | Forward secrecy demostrada: una clave comprometida no abre mensajes pasados |
| 3 | Ratchet de sesión + contadores anti-replay (sustituye al `.seen`) | Vectores de replay, desorden y pérdida |
| 4 | Binding Android (UniFFI) + claves en Keystore/StrongBox | La app abre y sella en el móvil |
| 5 | Transporte con relay ciego y notificaciones sin Google | El relay no puede leer contenido ni emisor |

## APK v0.1 · «Paris de bolsillo»
App Android sin servidor: generar claves, compartir la clave pública (QR o texto `X39PK1:`), cifrar para otra persona, abrir mensajes `X39MSG1:` (con TTL y anti-replay), huella de seguridad de 60 dígitos y `FLAG_SECURE` en toda la app.
- Motor listo en `x39-core` (`share.rs`: formatos de texto, huella y límite de QR).
- **Google 0 en la app:** sin Play Services, Firebase, FCM, Google Maps ni analítica. El SDK/NDK de Google solo se usa para compilar en el PC.
- **Diseño:** tema oscuro con **rojo** como acento. **Prohibido el verde** en cualquier elemento. Como el rojo se asocia a «error», los errores se marcan con icono y texto, no solo con color.

## APK v0.4 · Plenos y modo ciudadano (2026-09-15)
Versión para el Ayuntamiento de Sevilla. **Sin wallet** y sin ninguna mención a dinero.
- **Portada con dos entradas:** «Ver plenos y comprobar documentos» (ciudadano: sin clave, sin cuenta, sin desbloqueo) y «Soy personal del Ayuntamiento» (crea ML-KEM-1024 + ML-DSA-87). El ciudadano puede activar el acceso de personal más tarde desde Plenos.
- **Plenos:** las 28 áreas del portal agrupadas (gobierno y contratación, 11 distritos, organismos y servicios, empresas municipales) con sus documentos anclados. Tocar uno abre el PDF congelado en el navegador; la app sigue sin permiso de internet.
- **Registro incluido en la app** (`assets/registro.json`): `scripts/actualizar_registro.sh` lo descarga de `https://api.x39matrix.org/registro/registro.json` en cada compilación. Solo incluye lo emitido y comprobado: descarta entradas con huella inválida, ruta de PDF fuera de `actas/`, PDF no publicado en el portal o PDF cuya SHA-256 no coincide. Sin conexión conserva la copia anterior.
- **Comprobar un documento:** SHA-256 calculado en el móvil y comparado con el registro incluido. No sustituye la verificación completa de los sellos, que se hace con las herramientas del portal.
- **Roles:** los ciudadanos solo consultan y comprueban. Chats y grupos son para el personal. Anclar actas nunca se hace desde la app ni desde la web: se prepara en el ordenador de Secretaría y la autorización la firma el móvil del responsable (pendiente).
- `scripts/comprobar_pdfs_registro.sh` descarga cada PDF del registro y confirma que existe en el portal y que su huella coincide.

## APK v0.3 · firma del remitente (2026-09-15)
Cada mensaje va firmado con **ML-DSA-87** (FIPS 204, crate `ml-dsa` 0.1.1, la misma que el canister Joseph) y la firma viaja dentro de la cápsula cifrada.
- **Formato:** `0x02 | firma(4627) | carga`; se firma `SHA-256(clave ML-KEM del destinatario) || carga` con contexto `x39-msg-v1`. Atar la firma al destinatario impide reenviar a un tercero un mensaje firmado para otro.
- **Identidad `X39ID1:`** = clave ML-KEM-1024 + clave ML-DSA-87 (≈5,6 kB de texto; ya no cabe en un QR). Huella v2 de 60 dígitos sobre ambas claves.
- **Semilla de firma** de 32 bytes cifrada con la clave de Android Keystore, igual que la secreta ML-KEM. Quien actualiza desde la 0.2 recibe su identidad de firma al abrir la app; su huella cambia y sus contactos deben volver a compararla.
- **Al recibir:** si el contacto tiene clave de firma, un mensaje sin firma o con firma inválida se **descarta** (anti-suplantación y anti-degradación). Los contactos con clave antigua `X39PK1` siguen funcionando, marcados como «remitente declarado, sin firma comprobada». No se acepta sustituir una clave con firma por una antigua.
- **Tests:** `tests/firma.rs` (extremo a extremo, suplantación, reenvío a otro destinatario, bit cambiado, mensajes 0.2) y un test que demuestra que el prefijo FIPS 204 coincide con la librería.
- **Pendiente:** forward secrecy, relé, auditoría externa. Probado en el PC con tests; en móvil falta la prueba manual entre dos teléfonos.

## Función: ubicación efímera (5 / 10 / 30 s)
1. El emisor elige 5, 10 o 30 s. La ubicación se toma una sola vez (nunca en segundo plano) y viaja cifrada como un mensaje más.
2. El receptor ve «📍 Ubicación · 10 s», toca para abrirla y **la cuenta atrás empieza al abrir** (se ve una sola vez).
3. La pantalla usa `FLAG_SECURE`: bloquea capturas, grabación de pantalla y la vista previa en «recientes».
4. Al terminar: se borran las coordenadas de la memoria, se destruye la clave de ese mensaje (crypto-erasure) y se elimina en **ambos** móviles.
5. El mapa es **offline** (MapLibre con mapa descargado). Pedir baldosas a Google u OSM revelaría la ubicación al servidor de mapas.

Límites honestos: no impide una foto con otro móvil ni la captura en móviles rooteados. Si el receptor no la abre, caduca a las 24 h sin mostrarse.

## Función: wallet Bitcoin non-custodial
> Estado (09/11/2026): lo que sigue es el diseño de septiembre de 2026, no el estado del código. La billetera se construye en el repositorio [`x39-wallet`](https://github.com/x39matrix/x39-wallet) y se usa desde la app de llamadas [X39 Enlace](https://github.com/x39matrix/x39-enlace), no desde esta app de mensajería; lo hecho y lo pendiente están documentados allí (`PRUEBAS.md`).

1. **Las claves son del usuario:** la semilla (BIP39) se genera en el móvil y se guarda cifrada con StrongBox. Nunca pasa por el servidor, el HUB ni ningún canister. x39 no puede mover fondos de nadie.
2. **Motor:** BDK (Bitcoin Dev Kit, Rust). Sin código de firma propio.
3. **Pagar en el chat:** «💸 Pedir 0.001 BTC» o «Enviar a este contacto». La dirección y el importe viajan cifrados dentro del mensaje, y cada pago usa una dirección nueva.
4. **Privacidad de consulta:** el saldo se consulta a un servidor Electrum propio o por Tor. Un servidor ajeno vería todas tus direcciones.
5. **Compatibilidad con cold wallets:** PSBT por QR con Coldcard y Sparrow, las mismas que usa la guía de Paris.
6. **Seguridad heredada de Paris:**
   - pantalla de la semilla con `FLAG_SECURE` y verificación del respaldo en papel;
   - **wallet de coacción:** el PIN falso abre una wallet con saldo pequeño.
7. **Alcance:** solo BTC al principio. Cada cripto adicional se decide aparte.

Límites honestos: si el usuario pierde la semilla, nadie puede recuperar los fondos. Las políticas de Google Play para wallets y la normativa (MiCA) deben revisarse antes de publicar.

## Fuera del núcleo (decisiones ya tomadas)
- Identidad: par de claves local, no b3c6l.
- Wallet: non-custodial en el móvil, nunca el HUB.
- Recibo verificable: opcional y firmado, nunca `cert_notarize`.
