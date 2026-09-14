package org.x39.bolsillo;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
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
import javax.crypto.spec.GCMParameterSpec;

/**
 * Guarda las claves del usuario dentro de la app.
 * La clave secreta ML-KEM se cifra con una clave AES-256 que vive en Android Keystore
 * (en el chip StrongBox si el móvil lo tiene) y nunca sale del hardware.
 */
final class Boveda {
    private static final String ALIAS = "x39_bolsillo_envoltura_v1";
    private static final String PK_FILE = "clave_publica.bin";
    private static final String SK_FILE = "clave_secreta.enc";
    private static final String SEEN_FILE = "cids_abiertos.txt";

    private final File dir;
    private boolean strongBox;

    Boveda(Context context) {
        dir = context.getFilesDir();
    }

    boolean tieneClaves() {
        return new File(dir, PK_FILE).exists() && new File(dir, SK_FILE).exists();
    }

    boolean usaStrongBox() {
        return strongBox;
    }

    void crearClaves() throws Exception {
        byte[] ambas = X39Core.generateKeypair();
        byte[] pk = Arrays.copyOfRange(ambas, 0, X39Core.PK_LEN);
        byte[] sk = Arrays.copyOfRange(ambas, X39Core.PK_LEN, ambas.length);
        Arrays.fill(ambas, (byte) 0);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, claveEnvoltura());
            byte[] iv = cipher.getIV();
            byte[] cifrada = cipher.doFinal(sk);
            byte[] salida = new byte[iv.length + cifrada.length];
            System.arraycopy(iv, 0, salida, 0, iv.length);
            System.arraycopy(cifrada, 0, salida, iv.length, cifrada.length);
            escribir(SK_FILE, salida);
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
        byte[] datos = Files.readAllBytes(new File(dir, SK_FILE).toPath());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, claveEnvoltura(), new GCMParameterSpec(128, datos, 0, 12));
        return cipher.doFinal(datos, 12, datos.length - 12);
    }

    /** Anti-replay: devuelve false si ese mensaje ya se abrió antes. */
    synchronized boolean registrarApertura(byte[] cid) throws IOException {
        String hex = aHex(cid);
        File f = new File(dir, SEEN_FILE);
        Set<String> vistos = new HashSet<>();
        if (f.exists()) {
            vistos.addAll(Arrays.asList(new String(Files.readAllBytes(f.toPath()), StandardCharsets.US_ASCII).split("\n")));
        }
        if (vistos.contains(hex)) {
            return false;
        }
        try (FileOutputStream out = new FileOutputStream(f, true)) {
            out.write((hex + "\n").getBytes(StandardCharsets.US_ASCII));
        }
        return true;
    }

    private SecretKey claveEnvoltura() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return (SecretKey) ks.getKey(ALIAS, null);
        }
        try {
            SecretKey k = generar(true);
            strongBox = true;
            return k;
        } catch (StrongBoxUnavailableException e) {
            strongBox = false;
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
