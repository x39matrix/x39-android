package org.x39.bolsillo;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Guarda las claves del usuario dentro de la app.
 * Una clave AES-256 que vive en Android Keystore (en el chip StrongBox si el móvil lo tiene)
 * cifra la clave secreta ML-KEM, la semilla de firma ML-DSA-87 y el almacén de contactos y mensajes.
 * Esa clave nunca sale del hardware.
 */
final class Boveda {
    private static final String ALIAS = "x39_bolsillo_envoltura_v1";
    private static final String PK_FILE = "clave_publica.bin";
    private static final String SK_FILE = "clave_secreta.enc";
    private static final String FIRMA_PK_FILE = "firma_publica.bin";
    private static final String FIRMA_SEMILLA_FILE = "firma_semilla.enc";
    private static final String SEEN_FILE = "cids_abiertos.txt";

    private final File dir;

    Boveda(Context context) {
        dir = context.getFilesDir();
    }

    boolean tieneClaves() {
        return new File(dir, PK_FILE).exists() && new File(dir, SK_FILE).exists();
    }

    void crearClaves() throws Exception {
        byte[] ambas = X39Core.generateKeypair();
        byte[] pk = Arrays.copyOfRange(ambas, 0, X39Core.PK_LEN);
        byte[] sk = Arrays.copyOfRange(ambas, X39Core.PK_LEN, ambas.length);
        Arrays.fill(ambas, (byte) 0);
        try {
            escribir(SK_FILE, cifrarDatos(sk));
            escribir(PK_FILE, pk);
        } finally {
            Arrays.fill(sk, (byte) 0);
        }
    }

    byte[] clavePublica() throws IOException {
        return Files.readAllBytes(new File(dir, PK_FILE).toPath());
    }

    /** El llamante DEBE borrar el array con Arrays.fill al terminar. */
    byte[] claveSecreta() throws Exception {
        return descifrarDatos(Files.readAllBytes(new File(dir, SK_FILE).toPath()));
    }

    boolean tieneFirma() {
        return new File(dir, FIRMA_PK_FILE).exists() && new File(dir, FIRMA_SEMILLA_FILE).exists();
    }

    /** Crea la identidad de firma ML-DSA-87. Quien venía de x39 0.2 la recibe al abrir la 0.3. */
    void crearFirma() throws Exception {
        byte[] semilla = X39Core.generateSigningSeed();
        try {
            byte[] pk = X39Core.signingPublicKey(semilla);
            escribir(FIRMA_SEMILLA_FILE, cifrarDatos(semilla));
            escribir(FIRMA_PK_FILE, pk);
        } finally {
            Arrays.fill(semilla, (byte) 0);
        }
    }

    byte[] clavePublicaFirma() throws IOException {
        return Files.readAllBytes(new File(dir, FIRMA_PK_FILE).toPath());
    }

    /** El llamante DEBE borrar el array con Arrays.fill al terminar. */
    byte[] semillaFirma() throws Exception {
        return descifrarDatos(Files.readAllBytes(new File(dir, FIRMA_SEMILLA_FILE).toPath()));
    }

    /** AES-256-GCM con la clave de Keystore. Formato: iv(12) || cifrado+etiqueta. */
    byte[] cifrarDatos(byte[] plano) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, claveEnvoltura());
        byte[] iv = cipher.getIV();
        byte[] cifrado = cipher.doFinal(plano);
        byte[] salida = new byte[iv.length + cifrado.length];
        System.arraycopy(iv, 0, salida, 0, iv.length);
        System.arraycopy(cifrado, 0, salida, iv.length, cifrado.length);
        return salida;
    }

    byte[] descifrarDatos(byte[] datos) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, claveEnvoltura(), new GCMParameterSpec(128, datos, 0, 12));
        return cipher.doFinal(datos, 12, datos.length - 12);
    }

    /** Dónde vive la clave de envoltura. Sin texto: cada app pone el suyo (Evidencia, desde sus strings.xml). */
    enum Nivel { STRONGBOX, TEE, HARDWARE_SEGURO, SOFTWARE, DESCONOCIDO }

    /** Dónde vive realmente la clave de envoltura, según el propio Keystore. */
    Nivel nivel() {
        try {
            SecretKey k = claveEnvoltura();
            SecretKeyFactory f = SecretKeyFactory.getInstance(k.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = (KeyInfo) f.getKeySpec(k, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= 31) {
                int nivel = info.getSecurityLevel();
                if (nivel == KeyProperties.SECURITY_LEVEL_STRONGBOX) return Nivel.STRONGBOX;
                if (nivel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return Nivel.TEE;
                return Nivel.SOFTWARE;
            }
            @SuppressWarnings("deprecation")
            boolean hw = info.isInsideSecureHardware();
            return hw ? Nivel.HARDWARE_SEGURO : Nivel.SOFTWARE;
        } catch (Exception e) {
            return Nivel.DESCONOCIDO;
        }
    }

    /** El nivel en español, como lo muestra bolsillo (mismo texto de siempre). Evidencia no lo usa. */
    String nivelHardware() {
        switch (nivel()) {
            case STRONGBOX: return "StrongBox";
            case TEE: return "Entorno seguro (TEE)";
            case HARDWARE_SEGURO: return "Hardware seguro";
            case SOFTWARE: return "Software";
            default: return "Desconocido";
        }
    }

    /** Anti-replay: devuelve false si ese mensaje ya se abrió antes. */
    synchronized boolean registrarApertura(byte[] cid) throws IOException {
        String hex = aHex(cid);
        Set<String> vistos = leerVistos();
        if (vistos.contains(hex)) {
            return false;
        }
        try (FileOutputStream out = new FileOutputStream(new File(dir, SEEN_FILE), true)) {
            out.write((hex + "\n").getBytes(StandardCharsets.US_ASCII));
        }
        return true;
    }

    synchronized int aperturasRegistradas() {
        try {
            return leerVistos().size();
        } catch (IOException e) {
            return 0;
        }
    }

    private Set<String> leerVistos() throws IOException {
        File f = new File(dir, SEEN_FILE);
        Set<String> vistos = new HashSet<>();
        if (f.exists()) {
            for (String l : new String(Files.readAllBytes(f.toPath()), StandardCharsets.US_ASCII).split("\n")) {
                if (!l.isEmpty()) vistos.add(l);
            }
        }
        return vistos;
    }

    private SecretKey claveEnvoltura() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return (SecretKey) ks.getKey(ALIAS, null);
        }
        try {
            return generar(true);
        } catch (StrongBoxUnavailableException e) {
            return generar(false);
        }
    }

    private static SecretKey generar(boolean enStrongBox) throws Exception {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(enStrongBox)
                .build();
        KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(spec);
        return gen.generateKey();
    }

    private void escribir(String nombre, byte[] datos) throws IOException {
        try (FileOutputStream out = new FileOutputStream(new File(dir, nombre))) {
            out.write(datos);
        }
    }

    static String aHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
