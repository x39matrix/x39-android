package org.x39.bolsillo;

/** Puente al motor Rust (libx39jni.so). Los errores llegan como RuntimeException con mensaje en español. */
final class X39Core {
    static {
        System.loadLibrary("x39jni");
    }

    static final int PK_LEN = 1568;
    static final int SK_LEN = 3168;
    static final int CID_LEN = 16;
    static final int DSA_PK_LEN = 2592;
    static final int DSA_SEED_LEN = 32;
    static final int SIG_LEN = 4627;
    static final byte SIGNED_TAG = 0x02;

    private X39Core() {}

    // API JNI del protocolo de llamadas existente; no modifica el motor criptográfico.
    static native byte[] callOffer(String callHash, String fromBh, int epoch, byte[] seed, String ts);
    static native int callVerifyOffer(String callHash, String fromBh, int epoch, byte[] ek, String ts, byte[] signature, byte[] emisorPk);
    static native byte[] callEncapsulate(byte[] ekOtro);
    static native byte[] callDecapsulate(byte[] dk, byte[] ct);
    static native byte[] callDerive(String bhA, String bhB, byte[] ekA, byte[] ekB, byte[] ssA, byte[] ssB, String callHash, byte[] callSalt, int epoch);
    static native String callSas(byte[] frameKey, String callHash);

    /** Cuerpo abierto con firma ML-DSA-87: 0x02 || firma(4627) || carga. */
    static boolean estaFirmado(byte[] cuerpo) {
        return cuerpo.length >= 1 + SIG_LEN && cuerpo[0] == SIGNED_TAG;
    }

    /** Semilla ML-DSA-87 de 32 bytes. El llamante la cifra y la borra de memoria. */
    static native byte[] generateSigningSeed();

    static native byte[] signingPublicKey(byte[] seed);

    static native String identityToText(byte[] kemPublicKey, byte[] signingPublicKey);

    /** clave_ml_kem(1568) || clave_ml_dsa(2592). */
    static native byte[] identityFromText(String text);

    static native String identityFingerprint(byte[] kemPublicKey, byte[] signingPublicKey);

    /** Firma con ML-DSA-87 para el destinatario y sella. Devuelve el texto X39MSG1. */
    static native String sealSigned(byte[] recipientPublicKey, byte[] seed, byte[] payload, long nowSecs);

    /** Carga sin verificar, solo para leer el remitente declarado. */
    static native byte[] unverifiedPayload(byte[] body);

    /** Devuelve la carga si la firma es del remitente y va dirigida a mí; si no, lanza. */
    static native byte[] verifySigned(byte[] senderSigningKey, byte[] myPublicKey, byte[] body);

    // ---- Evidencia: firma de mensajes y OpenTimestamps

    /** Firma ML-DSA-87 estándar (contexto vacío) con la semilla de 32 bytes. Devuelve 4627 bytes. */
    static native byte[] signMessage(byte[] seed, byte[] message);

    /** 1 si la firma es válida; si no, lanza. */
    static native int verifyMessage(byte[] signingPublicKey, byte[] message, byte[] signature);

    /** Compromiso que se envía a los calendarios: sha256(huella(32) || nonce(16)). */
    static native byte[] otsCommitment(byte[] digest, byte[] nonce);

    /** Incorpora la respuesta de un calendario; con ots == null empieza la prueba. Devuelve el .ots completo. */
    static native byte[] otsIncorporate(byte[] ots, byte[] digest, byte[] nonce, byte[] commitment, byte[] response);

    /** Pendientes, una línea por calendario: "uri mensaje_hex". */
    static native String otsPending(byte[] ots);

    /** Bloques de Bitcoin que atestiguan la prueba, separados por comas. */
    static native String otsBlocks(byte[] ots);

    /** Matriz QR (corrección L): ancho en u16 big-endian y un byte por módulo, fila a fila (1 = oscuro). */
    static native byte[] qrMatrix(byte[] data);

    /**
     * Invitación del Ayuntamiento («X39INV1:…») verificada con la clave pública de su autoridad.
     * {@code today} es AAAA-MM-DD. Devuelve "caduca|nombre"; si no verifica o ha caducado, lanza RuntimeException.
     */
    static native String invitationVerify(byte[] authorityKey, String text, String today);

    /** Revocación «X39REV1:…» firmada por la autoridad. Devuelve "codigo|fecha|motivo" (código canónico) o lanza. */
    static native String revocationVerify(byte[] authorityKey, String text);

    /** Acreditación: la invitación firmada con la semilla ML-DSA-87 del titular («X39ACR1:…»). */
    static native String accreditationCreate(byte[] seed, String invitation);

    /** Verifica una acreditación con la clave de la autoridad y la clave de firma del titular. Devuelve "caduca|nombre" o lanza. */
    static native String accreditationVerify(byte[] authorityKey, byte[] holderSigningKey, String text, String today);

    // ---- Directorio: añadir contactos con un código corto (canister/buzon, /publicar y /buscar)

    /** Código de contacto «XXXX-XXXX-XXXX» de una clave de firma ML-DSA-87 (60 bits de su SHA-256). */
    static native String directoryCode(byte[] signingPublicKey);

    /** Lo tecleado por una persona → código canónico de 12 símbolos. Lanza si no es un código. */
    static native String directoryNormalizeCode(String text);

    /** Entrada «X39DIR1:…» firmada con la semilla: claves públicas + acreditación (null o vacía si no hay). */
    static native String directoryEntryCreate(byte[] seed, byte[] kemPublicKey, String accreditation);

    /**
     * Verifica una entrada del directorio (firma de la clave que lleva dentro y, si se da expectedCode, que el
     * código coincida) y la devuelve como «X39ID1:… X39ACR1:…», listo para Almacen.leerTexto.
     */
    static native String directoryEntryRead(String text, String expectedCode);

    // ---- Salas por departamento (x39-core/src/sala.rs; canister /sala/*)

    static final int ROOM_KEY_LEN = 32;

    /** Clave nueva de sala (32 bytes). Se guarda cifrada en el almacén. */
    static native byte[] roomNewKey();

    /** Cifra un mensaje para la sala en esa época. Devuelve «X39SALA1:…». */
    static native String roomEncrypt(byte[] key, String room, int epoch, byte[] plaintext);

    static native byte[] roomDecrypt(byte[] key, String room, int epoch, String message);

    /** Firma una publicación (el texto X39SALA1 del mensaje, o la acción de sobre/miembro). Devuelve «X39FIRMA1:…». */
    static native String roomSign(byte[] seed, String room, int epoch, String action);

    /** 1 si la firma es de esa clave; si no, lanza. */
    static native int roomVerify(byte[] signingPublicKey, String room, int epoch, String action, String signature);

    /** Eslabón (hex) de la cadena de la sala; previousHex vacío para el primer mensaje. */
    static native String roomChainLink(String previousHex, String room, long seq, String sender, String message, String signature);

    /** Acción firmada al entregar la clave de la sala a `para`: igual que sala::accion_sobre. */
    static String roomActionEnvelope(String para, String sobre) {
        return "sobre:" + para + ":" + sobre;
    }

    /** Acción firmada al añadir a alguien: igual que sala::accion_miembro. */
    static String roomActionMember(String direccion) {
        return "miembro:" + direccion;
    }

    /** clave_pública(1568) || clave_secreta(3168). */
    static native byte[] generateKeypair();

    static native String publicKeyToText(byte[] publicKey);

    static native byte[] publicKeyFromText(String text);

    static native String fingerprint(byte[] publicKey);

    /** Devuelve el texto X39MSG1 listo para compartir. */
    static native String seal(byte[] publicKey, byte[] plaintext, long nowSecs);

    /** Devuelve cid(16) || plaintext. ttlSecs debe ser mayor que 0. */
    static native byte[] open(byte[] secretKey, String text, long nowSecs, long ttlSecs);

    static native int maxPlaintextForQr();
}
