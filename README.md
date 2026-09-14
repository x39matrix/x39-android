# x39 Mensajería

App de mensajería post-cuántica para Android. El diseño parte de Paris v3 y se valida contra la suite Mesopotamia.

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

## Función: ubicación efímera (5 / 10 / 30 s)
1. El emisor elige 5, 10 o 30 s. La ubicación se toma una sola vez (nunca en segundo plano) y viaja cifrada como un mensaje más.
2. El receptor ve «📍 Ubicación · 10 s», toca para abrirla y **la cuenta atrás empieza al abrir** (se ve una sola vez).
3. La pantalla usa `FLAG_SECURE`: bloquea capturas, grabación de pantalla y la vista previa en «recientes».
4. Al terminar: se borran las coordenadas de la memoria, se destruye la clave de ese mensaje (crypto-erasure) y se elimina en **ambos** móviles.
5. El mapa es **offline** (MapLibre con mapa descargado). Pedir baldosas a Google u OSM revelaría la ubicación al servidor de mapas.

Límites honestos: no impide una foto con otro móvil ni la captura en móviles rooteados. Si el receptor no la abre, caduca a las 24 h sin mostrarse.

## Fuera del núcleo (decisiones ya tomadas)
- Identidad: par de claves local, no b3c6l.
- Wallet: non-custodial en el móvil, nunca el HUB.
- Recibo verificable: opcional y firmado, nunca `cert_notarize`.
