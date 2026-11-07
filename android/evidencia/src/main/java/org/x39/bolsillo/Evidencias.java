package org.x39.bolsillo;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.x39matrix.evidencia.R;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Almacén de evidencias (Evidencia v0.1, secciones 4 y 5 de la especificación).
 * <ul>
 * <li>Contenido: una foto de la cámara propia o cualquier archivo elegido con el selector de Android. Se guarda
 *     cifrado en {@code filesDir} con nombre aleatorio; nunca MediaStore ni galería.</li>
 * <li>Cifrado por trozos de 1 MiB con AES-256-GCM (un vídeo de varios GB no se carga entero en memoria).
 *     Clave aleatoria por evidencia, envuelta por la clave de Android Keystore. Cada trozo lleva en el nonce
 *     su número y si es el último, así que cambiar, quitar o reordenar trozos rompe la etiqueta.</li>
 * <li>Huella: SHA-256 de los bytes exactos leídos, calculada mientras se cifran. El fichero no se modifica después.</li>
 * <li>Firma: ML-DSA-87 sobre «X39-EVIDENCIA-v1|huella|hora local» en UTF-8.</li>
 * <li>Prueba: .ots estándar de OpenTimestamps junto a la ficha.</li>
 * </ul>
 */
final class Evidencias {
    static final String PREFIJO_CANONICO = "X39-EVIDENCIA-v1|";
    static final String FOTO = "foto";
    static final String ARCHIVO = "archivo";
    /** Vídeo grabado con la cámara de la app (0.2). */
    static final String VIDEO = "video";
    /** Audio grabado con el micrófono desde la app (0.2.1). */
    static final String AUDIO = "audio";
    static final int PK_ESPERADA = 2592;
    static final int FIRMA_ESPERADA = 4627;
    private static final DateTimeFormatter HORA_LOCAL = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final Object CERROJO = new Object();
    private static final String INDICE = "fichas.enc";
    /** Almacén v2: «X39E» 0x02 · longitud (2) · clave envuelta · prefijo de nonce (7) · trozos cifrados. */
    private static final byte[] MAGIA = {'X', '3', '9', 'E', 2};
    private static final int TROZO = 1 << 20;
    private static final int ETIQUETA = 16;
    private static final int PREFIJO_NONCE = 7;
    private static final SecureRandom AZAR = new SecureRandom();

    interface Progreso {
        void bytes(long procesados);
    }

    static final class Sellado {
        final Ficha ficha;
        /** El mismo contenido ya estaba sellado: se devuelve la ficha existente y no se duplica. */
        final boolean yaExistia;

        Sellado(Ficha ficha, boolean yaExistia) {
            this.ficha = ficha;
            this.yaExistia = yaExistia;
        }
    }

    static final class Ficha {
        String id;
        String tipo = FOTO;
        /** Nombre original del archivo. Solo en el índice cifrado; nunca en el recibo. */
        String nombre = "";
        String mime = "image/jpeg";
        long bytes = -1;
        /** Nombre del fichero cifrado dentro del almacén. */
        String archivo;
        String sha256;
        /** Hora del dispositivo con su zona. Declarada, no verificable. */
        String capturada;
        /** SHA-256 de la clave pública ML-DSA-87 que firmó. */
        String firmante;
        /** Firma en base64. */
        String firma;
        /** pending → calendar → bitcoin. */
        String otsEstado = "pending";
        long bloque = -1;
        String tsrEstado = "none";
        long icSeq = -1;
        String icTime;
        String icCert;
        String josephSig;
        String nonce;
        String compromiso;
        long creada;

        boolean esFoto() {
            return FOTO.equals(tipo);
        }

        boolean esImagen() {
            return esFoto() || mime.startsWith("image/");
        }

        boolean esVideo() {
            return VIDEO.equals(tipo) || mime.startsWith("video/");
        }

        boolean esAudio() {
            return AUDIO.equals(tipo) || mime.startsWith("audio/");
        }

        String canonica() {
            return PREFIJO_CANONICO + sha256 + "|" + capturada;
        }

        JSONObject aJson() throws JSONException {
            return new JSONObject()
                    .put("id", id).put("tipo", tipo).put("nombre", nombre).put("mime", mime).put("bytes", bytes)
                    .put("archivo", archivo).put("sha256", sha256).put("capturada", capturada)
                    .put("firmante", firmante).put("firma", firma).put("ots_estado", otsEstado)
                    .put("bloque", bloque).put("tsr_estado", tsrEstado).put("ic_seq", icSeq)
                    .put("ic_time", icTime != null ? icTime : JSONObject.NULL)
                    .put("ic_cert", icCert != null ? icCert : JSONObject.NULL)
                    .put("joseph_sig", josephSig != null ? josephSig : JSONObject.NULL)
                    .put("nonce", nonce).put("compromiso", compromiso).put("creada", creada);
        }

        static Ficha deJson(JSONObject o) throws JSONException {
            Ficha f = new Ficha();
            f.id = o.getString("id");
            f.tipo = o.optString("tipo", FOTO);
            f.nombre = o.optString("nombre", "");
            f.mime = o.optString("mime", "image/jpeg");
            f.bytes = o.optLong("bytes", -1);
            // Las fichas de la 0.1.0 no tenían este campo: su foto está en «<id>.foto» con el formato antiguo.
            f.archivo = o.optString("archivo", f.id + ".foto");
            f.sha256 = o.getString("sha256");
            f.capturada = o.getString("capturada");
            f.firmante = o.getString("firmante");
            f.firma = o.getString("firma");
            f.otsEstado = o.optString("ots_estado", "pending");
            f.bloque = o.optLong("bloque", -1);
            f.tsrEstado = o.optString("tsr_estado", "none");
            f.icSeq = o.optLong("ic_seq", -1);
            f.icTime = o.isNull("ic_time") ? null : o.optString("ic_time", null);
            f.icCert = o.isNull("ic_cert") ? null : o.optString("ic_cert", null);
            f.josephSig = o.isNull("joseph_sig") ? null : o.optString("joseph_sig", null);
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
        limpiarTemporales();
    }

    // ------------------------------------------------------------------ identidad

    /** La identidad es la clave ML-DSA-87: se crea solo cuando el usuario pulsa «Crear identidad». */
    boolean tieneIdentidad() {
        return boveda.tieneFirma();
    }

    void crearIdentidad() throws Exception {
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

    /** Dónde vive la clave del Keystore. El texto lo pone la pantalla, desde strings.xml. */
    Boveda.Nivel nivel() {
        return boveda.nivel();
    }

    /** Mide en este móvil la clave pública y una firma de prueba recién hecha, y la verifica. {clave, firma}. */
    int[] comprobarTamanos() throws Exception {
        byte[] pk = clavePublica();
        byte[] mensaje = (PREFIJO_CANONICO + "comprobacion|" + HORA_LOCAL.format(ZonedDateTime.now())).getBytes(StandardCharsets.UTF_8);
        byte[] semilla = boveda.semillaFirma();
        byte[] firma;
        try {
            firma = X39Core.signMessage(semilla, mensaje);
        } finally {
            Arrays.fill(semilla, (byte) 0);
        }
        X39Core.verifyMessage(pk, mensaje, firma);
        return new int[]{pk.length, firma.length};
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

    long espacioLibre() {
        return dir.getUsableSpace();
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
        byte[] plano = new JSONObject().put("version", 2).put("fichas", a).toString().getBytes(StandardCharsets.UTF_8);
        try {
            escribirAtomico(new File(dir, INDICE), boveda.cifrarDatos(plano));
        } finally {
            Arrays.fill(plano, (byte) 0);
        }
    }

    // ------------------------------------------------------------------ sellado

    Sellado crearFoto(byte[] jpeg) throws Exception {
        return sellar(new ByteArrayInputStream(jpeg), FOTO, "", "image/jpeg", null);
    }

    /**
     * Cifra el contenido en el almacén calculando su huella a la vez, lo firma y prepara el compromiso de anclaje.
     * El flujo se lee una sola vez: lo que se hashea es exactamente lo que queda guardado.
     */
    Sellado sellar(InputStream in, String tipo, String nombre, String mime, Progreso progreso) throws Exception {
        if (!tieneIdentidad()) throw new FalloVisible(R.string.x39_motivo_sin_identidad);
        String archivo = "e-" + Boveda.aHex(aleatorio(8)) + ".dat";
        File destino = new File(dir, archivo);
        File tmp = new File(dir, archivo + ".tmp");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        long total;
        try {
            total = cifrarFlujo(in, tmp, sha, progreso);
        } catch (Exception e) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw e;
        }
        String huella = Boveda.aHex(sha.digest());

        synchronized (CERROJO) {
            for (Ficha x : leer()) {
                if (x.sha256.equals(huella)) {
                    //noinspection ResultOfMethodCallIgnored
                    tmp.delete();
                    return new Sellado(x, true);
                }
            }
        }

        Ficha f = new Ficha();
        f.tipo = tipo;
        f.nombre = nombre == null ? "" : nombre;
        f.mime = mime == null ? "application/octet-stream" : mime;
        f.bytes = total;
        f.archivo = archivo;
        f.sha256 = huella;
        f.id = huella.substring(0, 16);
        f.capturada = HORA_LOCAL.format(ZonedDateTime.now());
        f.creada = System.currentTimeMillis();

        byte[] semilla = boveda.semillaFirma();
        try {
            f.firma = Base64.encodeToString(X39Core.signMessage(semilla, f.canonica().getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
        } finally {
            Arrays.fill(semilla, (byte) 0);
        }
        f.firmante = huellaClave();

        byte[] nonce = aleatorio(16);
        f.nonce = Boveda.aHex(nonce);
        f.compromiso = Boveda.aHex(X39Core.otsCommitment(deHex(f.sha256), nonce));

        if (!tmp.renameTo(destino)) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw new FalloVisible(R.string.x39_motivo_no_guardar_evidencia);
        }
        synchronized (CERROJO) {
            List<Ficha> l = leer();
            l.add(f);
            escribir(l);
        }
        return new Sellado(f, false);
    }

    private long cifrarFlujo(InputStream in, File tmp, MessageDigest sha, Progreso progreso) throws Exception {
        byte[] clave = aleatorio(32);
        byte[] prefijo = aleatorio(PREFIJO_NONCE);
        long total = 0;
        try (FileOutputStream fos = new FileOutputStream(tmp); OutputStream out = new BufferedOutputStream(fos, 1 << 16)) {
            byte[] envuelta = boveda.cifrarDatos(clave);
            out.write(MAGIA);
            out.write(envuelta.length >>> 8);
            out.write(envuelta.length & 0xff);
            out.write(envuelta);
            out.write(prefijo);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec k = new SecretKeySpec(clave, "AES");
            byte[] actual = new byte[TROZO];
            byte[] siguiente = new byte[TROZO];
            int n = leerLleno(in, actual);
            for (int contador = 0; ; contador++) {
                // Se lee por adelantado para saber si este trozo es el último.
                int nSiguiente = n == TROZO ? leerLleno(in, siguiente) : 0;
                boolean ultimo = nSiguiente == 0;
                sha.update(actual, 0, n);
                c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, nonce(prefijo, contador, ultimo)));
                out.write(c.doFinal(actual, 0, n));
                total += n;
                if (progreso != null) progreso.bytes(total);
                if (ultimo) break;
                byte[] t = actual;
                actual = siguiente;
                siguiente = t;
                n = nSiguiente;
            }
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(siguiente, (byte) 0);
            out.flush();
            fos.getFD().sync();
        } finally {
            Arrays.fill(clave, (byte) 0);
        }
        return total;
    }

    // ------------------------------------------------------------------ lectura

    /**
     * Descifra lo guardado hacia {@code destino}. Si el contenido cifrado se ha alterado lanza
     * {@link GeneralSecurityException}: la etiqueta GCM del trozo afectado no cuadra.
     */
    void descifrarA(Ficha f, OutputStream destino) throws Exception {
        File a = new File(dir, f.archivo);
        if (f.archivo.endsWith(".foto")) {
            byte[] d = leerFormatoAntiguo(a);
            try {
                destino.write(d);
            } finally {
                Arrays.fill(d, (byte) 0);
            }
            return;
        }
        try (PushbackInputStream in = new PushbackInputStream(new BufferedInputStream(new FileInputStream(a), 1 << 16), 1)) {
            byte[] magia = new byte[MAGIA.length];
            if (leerLleno(in, magia) != MAGIA.length || !Arrays.equals(magia, MAGIA)) {
                throw new GeneralSecurityException("cabecera del almacén alterada");
            }
            int alto = in.read();
            int bajo = in.read();
            if (alto < 0 || bajo < 0) throw new GeneralSecurityException("almacén truncado");
            int longitud = (alto << 8) | bajo;
            if (longitud > 1024) throw new GeneralSecurityException("cabecera del almacén alterada");
            byte[] envuelta = new byte[longitud];
            byte[] prefijo = new byte[PREFIJO_NONCE];
            if (leerLleno(in, envuelta) != longitud || leerLleno(in, prefijo) != PREFIJO_NONCE) {
                throw new GeneralSecurityException("almacén truncado");
            }
            byte[] clave = boveda.descifrarDatos(envuelta);
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec k = new SecretKeySpec(clave, "AES");
                byte[] trozo = new byte[TROZO + ETIQUETA];
                for (int contador = 0; ; contador++) {
                    int n = leerLleno(in, trozo);
                    boolean ultimo;
                    if (n < trozo.length) {
                        ultimo = true;
                    } else {
                        int b = in.read();
                        ultimo = b < 0;
                        if (!ultimo) in.unread(b);
                    }
                    if (n < ETIQUETA) throw new GeneralSecurityException("almacén truncado");
                    c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, nonce(prefijo, contador, ultimo)));
                    byte[] claro = c.doFinal(trozo, 0, n);
                    destino.write(claro);
                    Arrays.fill(claro, (byte) 0);
                    if (ultimo) break;
                }
                Arrays.fill(trozo, (byte) 0);
            } finally {
                Arrays.fill(clave, (byte) 0);
            }
        }
    }

    /** Recalcula la huella de lo guardado sin escribirlo en claro en ningún sitio. */
    String huellaGuardada(Ficha f) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        descifrarA(f, new OutputStream() {
            @Override
            public void write(int b) {
                sha.update((byte) b);
            }

            @Override
            public void write(byte[] b, int off, int len) {
                sha.update(b, off, len);
            }
        });
        return Boveda.aHex(sha.digest());
    }

    /** Todo el contenido en memoria, solo para mostrar imágenes. El llamante DEBE borrar el array. */
    byte[] leerEntero(Ficha f, long maximo) throws Exception {
        if (f.bytes > maximo) throw new IOException("demasiado grande para mostrarlo");
        ByteArrayOutputStream b = new ByteArrayOutputStream(f.bytes > 0 ? (int) f.bytes : 1 << 16);
        descifrarA(f, b);
        return b.toByteArray();
    }

    /** Fotos guardadas por la 0.1.0: len(2) || clave envuelta || iv(12) || cifrado+etiqueta, de una vez. */
    private byte[] leerFormatoAntiguo(File a) throws Exception {
        ByteBuffer in = ByteBuffer.wrap(Files.readAllBytes(a.toPath()));
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

    byte[] tsr(Ficha f) throws IOException {
        File a = new File(dir, f.id + ".tsr");
        return a.exists() ? Files.readAllBytes(a.toPath()) : null;
    }

    void guardarTsr(Ficha f, byte[] tsr) throws IOException {
        escribirAtomico(new File(dir, f.id + ".tsr"), tsr);
        f.tsrEstado = "qualified";
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
        new File(dir, f.archivo).delete();
        //noinspection ResultOfMethodCallIgnored
        new File(dir, f.id + ".ots").delete();
        //noinspection ResultOfMethodCallIgnored
        new File(dir, f.id + ".tsr").delete();
    }

    /**
     * Recibo exportable, con los campos de la sección 4. Ni el contenido, ni su nombre, ni su ruta.
     * Desde 0.2 lleva también la clave pública (`signer_pk`, 2.592 bytes en base64): con el recibo solo,
     * cualquiera comprueba que SHA-256(signer_pk) == signer_fp y que la firma verifica, sin pedir la clave aparte.
     */
    static JSONObject recibo(Ficha f, byte[] clavePublicaFirma) throws JSONException {
        return new JSONObject()
                .put("v", 1)
                .put("id", f.id)
                .put("sha256", f.sha256)
                .put("captured_at_local", f.capturada)
                .put("signer_fp", f.firmante)
                .put("signer_pk", clavePublicaFirma == null ? JSONObject.NULL : Base64.encodeToString(clavePublicaFirma, Base64.NO_WRAP))
                .put("sig_alg", "ML-DSA-87")
                .put("sig", f.firma)
                .put("ots", f.id + ".ots")
                .put("ots_status", f.otsEstado)
                .put("bitcoin_block", f.bloque >= 0 ? f.bloque : JSONObject.NULL)
                .put("tsr", !"none".equals(f.tsrEstado) ? f.id + ".tsr" : JSONObject.NULL)
                .put("tsr_status", f.tsrEstado != null ? f.tsrEstado : "none")
                .put("location_included", false)
                .put("ic_seq", f.icSeq >= 0 ? f.icSeq : JSONObject.NULL)
                .put("ic_time", f.icTime != null ? f.icTime : JSONObject.NULL)
                .put("ic_cert", f.icCert != null ? f.icCert : JSONObject.NULL)
                .put("joseph_sig", f.josephSig != null ? f.josephSig : JSONObject.NULL);
    }

    // ------------------------------------------------------------------ utilidades

    static void escribirAtomico(File destino, byte[] datos) throws IOException {
        File tmp = new File(destino.getParentFile(), destino.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(datos);
            out.getFD().sync();
        }
        if (!tmp.renameTo(destino)) throw new FalloVisible(R.string.x39_motivo_no_guardar_fichero, destino.getName());
    }

    /** Restos de un sellado interrumpido (la app murió a mitad). Solo los de hace más de un día. */
    private void limpiarTemporales() {
        File[] restos = dir.listFiles((d, n) -> n.endsWith(".tmp"));
        if (restos == null) return;
        long limite = System.currentTimeMillis() - 24L * 3600 * 1000;
        for (File r : restos) {
            //noinspection ResultOfMethodCallIgnored
            if (r.lastModified() < limite) r.delete();
        }
    }

    private static int leerLleno(InputStream in, byte[] b) throws IOException {
        int total = 0;
        while (total < b.length) {
            int n = in.read(b, total, b.length - total);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    private static byte[] nonce(byte[] prefijo, int contador, boolean ultimo) {
        return ByteBuffer.allocate(12).put(prefijo).putInt(contador).put((byte) (ultimo ? 1 : 0)).array();
    }

    private static byte[] aleatorio(int n) {
        byte[] b = new byte[n];
        AZAR.nextBytes(b);
        return b;
    }
}
