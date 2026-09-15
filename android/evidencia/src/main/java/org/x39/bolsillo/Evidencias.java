package org.x39.bolsillo;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Almacén de evidencias (Evidencia v0.1, secciones 4 y 5 de la especificación).
 * <ul>
 * <li>Foto: JPEG tal cual sale de la cámara, cifrado con AES-256-GCM bajo una clave propia por foto,
 *     que a su vez va envuelta por la clave de Android Keystore. Nunca MediaStore ni galería.</li>
 * <li>Huella: SHA-256 de esos bytes exactos, antes de cifrar. El fichero no se modifica después.</li>
 * <li>Firma: ML-DSA-87 sobre «X39-EVIDENCIA-v1|huella|hora local» en UTF-8.</li>
 * <li>Prueba: .ots estándar de OpenTimestamps junto a la ficha.</li>
 * </ul>
 */
final class Evidencias {
    static final String PREFIJO_CANONICO = "X39-EVIDENCIA-v1|";
    private static final DateTimeFormatter HORA_LOCAL = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final Object CERROJO = new Object();
    private static final String INDICE = "fichas.enc";

    static final class Ficha {
        String id;
        String sha256;
        /** Hora del dispositivo con su zona. No es prueba de hora. */
        String capturada;
        /** SHA-256 de la clave pública ML-DSA-87 que firmó. */
        String firmante;
        /** Firma en base64. */
        String firma;
        /** pending → calendar → bitcoin. */
        String otsEstado = "pending";
        long bloque = -1;
        String nonce;
        String compromiso;
        long creada;

        String canonica() {
            return PREFIJO_CANONICO + sha256 + "|" + capturada;
        }

        JSONObject aJson() throws JSONException {
            return new JSONObject()
                    .put("id", id).put("sha256", sha256).put("capturada", capturada)
                    .put("firmante", firmante).put("firma", firma).put("ots_estado", otsEstado)
                    .put("bloque", bloque).put("nonce", nonce).put("compromiso", compromiso).put("creada", creada);
        }

        static Ficha deJson(JSONObject o) throws JSONException {
            Ficha f = new Ficha();
            f.id = o.getString("id");
            f.sha256 = o.getString("sha256");
            f.capturada = o.getString("capturada");
            f.firmante = o.getString("firmante");
            f.firma = o.getString("firma");
            f.otsEstado = o.optString("ots_estado", "pending");
            f.bloque = o.optLong("bloque", -1);
            f.nonce = o.getString("nonce");
            f.compromiso = o.getString("compromiso");
            f.creada = o.optLong("creada", 0);
            return f;
        }
    }

    private final Boveda boveda;
    private final File dir;

    Evidencias(Context contexto) {
        Context app = contexto.getApplicationContext();
        boveda = new Boveda(app);
        dir = new File(app.getFilesDir(), "evidencias");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
    }

    /** La identidad del usuario es su clave ML-DSA-87: nace aquí y no sale del móvil. */
    void asegurarIdentidad() throws Exception {
        synchronized (CERROJO) {
            if (!boveda.tieneFirma()) boveda.crearFirma();
        }
    }

    byte[] clavePublica() throws IOException {
        return boveda.clavePublicaFirma();
    }

    String huellaClave() throws IOException {
        return sha256Hex(clavePublica());
    }

    static String sha256Hex(byte[] datos) {
        try {
            return Boveda.aHex(MessageDigest.getInstance("SHA-256").digest(datos));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] deHex(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    // ------------------------------------------------------------------ índice

    List<Ficha> todas() throws Exception {
        synchronized (CERROJO) {
            return leer();
        }
    }

    Ficha porId(String id) throws Exception {
        for (Ficha f : todas()) if (f.id.equals(id)) return f;
        return null;
    }

    private List<Ficha> leer() throws Exception {
        List<Ficha> l = new ArrayList<>();
        File f = new File(dir, INDICE);
        if (!f.exists()) return l;
        byte[] plano = boveda.descifrarDatos(Files.readAllBytes(f.toPath()));
        try {
            JSONArray a = new JSONObject(new String(plano, StandardCharsets.UTF_8)).getJSONArray("fichas");
            for (int i = 0; i < a.length(); i++) l.add(Ficha.deJson(a.getJSONObject(i)));
        } finally {
            Arrays.fill(plano, (byte) 0);
        }
        l.sort((x, y) -> Long.compare(y.creada, x.creada));
        return l;
    }

    private void escribir(List<Ficha> l) throws Exception {
        JSONArray a = new JSONArray();
        for (Ficha f : l) a.put(f.aJson());
        byte[] plano = new JSONObject().put("version", 1).put("fichas", a).toString().getBytes(StandardCharsets.UTF_8);
        try {
            escribirAtomico(new File(dir, INDICE), boveda.cifrarDatos(plano));
        } finally {
            Arrays.fill(plano, (byte) 0);
        }
    }

    // ------------------------------------------------------------------ captura

    /** Guarda la foto cifrada, calcula su huella, la firma y prepara el compromiso de anclaje. */
    Ficha crear(byte[] jpeg) throws Exception {
        Ficha f = new Ficha();
        f.sha256 = sha256Hex(jpeg);
        f.id = f.sha256.substring(0, 16);
        f.capturada = HORA_LOCAL.format(ZonedDateTime.now());
        f.creada = System.currentTimeMillis();

        byte[] semilla = boveda.semillaFirma();
        try {
            f.firma = Base64.encodeToString(X39Core.signMessage(semilla, f.canonica().getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
        } finally {
            Arrays.fill(semilla, (byte) 0);
        }
        f.firmante = huellaClave();

        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        f.nonce = Boveda.aHex(nonce);
        f.compromiso = Boveda.aHex(X39Core.otsCommitment(deHex(f.sha256), nonce));

        escribirAtomico(new File(dir, f.id + ".foto"), cifrarFoto(jpeg));
        synchronized (CERROJO) {
            List<Ficha> l = leer();
            for (Ficha x : l) if (x.id.equals(f.id)) return x;
            l.add(f);
            escribir(l);
        }
        return f;
    }

    /**
     * Sobre: clave AES-256 aleatoria por foto (cifrado en software, rápido para varios MB)
     * envuelta por la clave de Keystore. Formato: len(2) || clave envuelta || iv(12) || cifrado+etiqueta.
     */
    private byte[] cifrarFoto(byte[] jpeg) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256, new SecureRandom());
        SecretKey clave = gen.generateKey();
        byte[] cruda = clave.getEncoded();
        try {
            byte[] envuelta = boveda.cifrarDatos(cruda);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cruda, "AES"), new SecureRandom());
            byte[] iv = c.getIV();
            byte[] cifrado = c.doFinal(jpeg);
            ByteBuffer out = ByteBuffer.allocate(2 + envuelta.length + iv.length + cifrado.length);
            out.putShort((short) envuelta.length).put(envuelta).put(iv).put(cifrado);
            return out.array();
        } finally {
            Arrays.fill(cruda, (byte) 0);
        }
    }

    /** El llamante DEBE borrar el array al terminar. */
    byte[] foto(Ficha f) throws Exception {
        ByteBuffer in = ByteBuffer.wrap(Files.readAllBytes(new File(dir, f.id + ".foto").toPath()));
        byte[] envuelta = new byte[in.getShort() & 0xffff];
        in.get(envuelta);
        byte[] iv = new byte[12];
        in.get(iv);
        byte[] cifrado = new byte[in.remaining()];
        in.get(cifrado);
        byte[] cruda = boveda.descifrarDatos(envuelta);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cruda, "AES"), new GCMParameterSpec(128, iv));
            return c.doFinal(cifrado);
        } finally {
            Arrays.fill(cruda, (byte) 0);
        }
    }

    // ------------------------------------------------------------------ prueba OpenTimestamps

    byte[] ots(Ficha f) throws IOException {
        File a = new File(dir, f.id + ".ots");
        return a.exists() ? Files.readAllBytes(a.toPath()) : null;
    }

    void guardarOts(Ficha f, byte[] ots) throws IOException {
        escribirAtomico(new File(dir, f.id + ".ots"), ots);
    }

    void actualizar(Ficha f) throws Exception {
        synchronized (CERROJO) {
            List<Ficha> l = leer();
            for (int i = 0; i < l.size(); i++) {
                if (l.get(i).id.equals(f.id)) {
                    l.set(i, f);
                    escribir(l);
                    return;
                }
            }
        }
    }

    void borrar(Ficha f) throws Exception {
        synchronized (CERROJO) {
            List<Ficha> l = leer();
            l.removeIf(x -> x.id.equals(f.id));
            escribir(l);
        }
        //noinspection ResultOfMethodCallIgnored
        new File(dir, f.id + ".foto").delete();
        //noinspection ResultOfMethodCallIgnored
        new File(dir, f.id + ".ots").delete();
    }

    /** Recibo exportable (sección 4): huella, firma y estado. Ni la foto ni su ruta. */
    static JSONObject recibo(Ficha f) throws JSONException {
        return new JSONObject()
                .put("v", 1)
                .put("id", f.id)
                .put("sha256", f.sha256)
                .put("captured_at_local", f.capturada)
                .put("signer_fp", f.firmante)
                .put("sig_alg", "ML-DSA-87")
                .put("sig", f.firma)
                .put("signed_message", f.canonica())
                .put("ots", f.id + ".ots")
                .put("ots_status", f.otsEstado)
                .put("bitcoin_block", f.bloque >= 0 ? f.bloque : JSONObject.NULL)
                .put("location_included", false)
                // Previstos para la etapa B (registro en canister y cofirma de Joseph); vacíos en la v0.1.
                .put("ic_seq", JSONObject.NULL)
                .put("ic_time", JSONObject.NULL)
                .put("ic_cert", JSONObject.NULL)
                .put("joseph_sig", JSONObject.NULL);
    }

    static void escribirAtomico(File destino, byte[] datos) throws IOException {
        File tmp = new File(destino.getParentFile(), destino.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(datos);
            out.getFD().sync();
        }
        if (!tmp.renameTo(destino)) throw new IOException("no se pudo guardar " + destino.getName());
    }
}
