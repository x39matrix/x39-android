package org.x39.bolsillo;

import org.x39.chat.Motor;

/** El motor de Evidencia (su X39Core, en comun/) para el chat común. Solo pasa las llamadas. */
final class MotorEvidencia implements Motor {

    static final MotorEvidencia UNICO = new MotorEvidencia();

    private MotorEvidencia() { }

    @Override public byte[] firmar(byte[] semilla, byte[] mensaje) { return X39Core.signMessage(semilla, mensaje); }

    @Override public String sellarFirmado(byte[] kemPkDestino, byte[] semilla, byte[] carga, long ahoraS) {
        return X39Core.sealSigned(kemPkDestino, semilla, carga, ahoraS);
    }

    @Override public byte[] abrir(byte[] kemSk, String sobre, long ahoraS, long ventanaS) {
        return X39Core.open(kemSk, sobre, ahoraS, ventanaS);
    }

    @Override public byte[] verificarFirmado(byte[] sigPkRemitente, byte[] miKemPk, byte[] cuerpo) {
        return X39Core.verifySigned(sigPkRemitente, miKemPk, cuerpo);
    }

    @Override public byte[] nuevoParCifrado() { return X39Core.generateKeypair(); }

    @Override public String identidadATexto(byte[] kemPk, byte[] sigPk) { return X39Core.identityToText(kemPk, sigPk); }

    @Override public byte[] identidadDeTexto(String texto) { return X39Core.identityFromText(texto); }

    @Override public String huellaIdentidad(byte[] kemPk, byte[] sigPk) { return X39Core.identityFingerprint(kemPk, sigPk); }
}
