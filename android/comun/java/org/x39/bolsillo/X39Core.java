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
