# x39 Mensajería

App de mensajería post-cuántica para Android. El diseño parte de Paris v3 y se valida contra la suite Mesopotamia.

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

## Fuera del núcleo (decisiones ya tomadas)
- Identidad: par de claves local, no b3c6l.
- Wallet: non-custodial en el móvil, nunca el HUB.
- Recibo verificable: opcional y firmado, nunca `cert_notarize`.
