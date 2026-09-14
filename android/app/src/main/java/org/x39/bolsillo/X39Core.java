package org.x39.bolsillo;

/** Puente al motor Rust (libx39jni.so). Los errores llegan como RuntimeException con mensaje en español. */
final class X39Core {
    static {
        System.loadLibrary("x39jni");
    }

    static final int PK_LEN = 1568;
    static final int SK_LEN = 3168;
    static final int CID_LEN = 16;

    private X39Core() {}

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
