package org.x39.bolsillo;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/**
 * Cliente del buzón del Ayuntamiento (canister/buzon): el ÚNICO uso de internet de la app.
 * Sube cápsulas ya cifradas y firmadas y recoge las dirigidas a este móvil; desde 0.10 también publica
 * la entrada de este móvil en el directorio y busca las de otros por código corto. Solo HTTPS, solo al
 * dominio configurado, sin redirecciones, respuestas de 256 kB como máximo. Cada conexión queda en
 * el registro que enseña Seguridad. El buzón ve direcciones, tamaños y horas; nunca el contenido.
 */
final class Buzon {
    static final String PREF_ACTIVO = "buzon_activo";
    static final String PREF_URL = "buzon_url";
    static final String PREF_DESDE = "buzon_desde";
    /** Canister buzon desplegado el 15/09/2026 (canister/buzon/canister_ids.json). Se puede cambiar en Seguridad. */
    static final String URL_POR_DEFECTO = "https://gx4ic-yqaaa-aaaah-qu43a-cai.raw.icp0.io";
    /** Un lote de la agenda son hasta 10 entradas de ~31 kB. */
    private static final int MAX_RESPUESTA = 1024 * 1024;
    private static final int MAX_REGISTRO = 30;
    private static final ArrayDeque<String> REGISTRO = new ArrayDeque<>();

    /** El directorio respondió, pero nadie ha publicado con ese código o dirección. */
    static final class NoEstaEnDirectorio extends IOException {
        NoEstaEnDirectorio() {
            super("No hay nadie con ese código en el directorio. Pídele que abra x39 con el buzón activado: su clave se publica sola.");
        }
    }

    static final class Recibido {
        final long seq;
        final String msg;

        Recibido(long seq, String msg) {
            this.seq = seq;
            this.msg = msg;
        }
    }

    private final SharedPreferences prefs;

    Buzon(Context c) {
        prefs = c.getApplicationContext().getSharedPreferences("x39", Context.MODE_PRIVATE);
    }

    boolean activo() {
        return prefs.getBoolean(PREF_ACTIVO, true) && !url().isEmpty();
    }

    String url() {
        return prefs.getString(PREF_URL, URL_POR_DEFECTO).trim();
    }

    long desde() {
        return prefs.getLong(PREF_DESDE, 0);
    }

    void guardarDesde(long seq) {
        prefs.edit().putLong(PREF_DESDE, seq).apply();
    }

    /** Dirección de buzón de una clave ML-KEM-1024: SHA-256 en hex. Pública y estable, como un apartado de correos. */
    static String direccion(byte[] clavePublica) {
        try {
            return Boveda.aHex(MessageDigest.getInstance("SHA-256").digest(clavePublica));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Solo se acepta un buzón en la pasarela de ICP o en un dominio propio de x39matrix. */
    static String validarUrl(String u) {
        String s = u.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        try {
            URL url = new URL(s);
            String h = url.getHost().toLowerCase(Locale.ROOT);
            boolean ok = "https".equals(url.getProtocol()) && url.getPort() == -1 && url.getQuery() == null
                    && (h.endsWith(".icp0.io") || h.endsWith(".ic0.app") || h.endsWith(".x39matrix.org"));
            if (!ok) throw new IllegalArgumentException("La dirección tiene que ser https y estar en icp0.io, ic0.app o x39matrix.org.");
        } catch (java.net.MalformedURLException e) {
            throw new IllegalArgumentException("Dirección no válida.");
        }
        return s;
    }

    void poner(String para, String capsula) throws IOException {
        JSONObject cuerpo = new JSONObject();
        try {
            cuerpo.put("para", para).put("msg", capsula);
        } catch (Exception e) {
            throw new IOException(e);
        }
        JSONObject r = pedir("POST", url() + "/poner", cuerpo.toString().getBytes(StandardCharsets.UTF_8));
        if (!r.has("seq")) throw new IOException("el buzón no confirmó el mensaje");
    }

    /**
     * Publica en el directorio la entrada «X39DIR1:…» de este móvil (claves públicas + acreditación, firmada).
     * El canister solo la guarda si verifica. Devuelve el código de contacto que confirma el buzón.
     */
    String publicar(String entrada) throws IOException {
        JSONObject cuerpo = new JSONObject();
        try {
            cuerpo.put("entrada", entrada);
        } catch (Exception e) {
            throw new IOException(e);
        }
        JSONObject r = pedir("POST", url() + "/publicar", cuerpo.toString().getBytes(StandardCharsets.UTF_8));
        if (!r.has("codigo")) throw new IOException("el directorio no confirmó la publicación");
        return r.optString("codigo");
    }

    /** Entrada del directorio de quien tiene ese código canónico (12 símbolos). IOException si no está. */
    String buscarPorCodigo(String codigoCanonico) throws IOException {
        return entradaDe(pedir("GET", url() + "/buscar?codigo=" + URLEncoder.encode(codigoCanonico, "UTF-8"), null));
    }

    /** Entrada del directorio de quien tiene esa dirección de buzón (o su prefijo de 16+ hex, el id de contacto). */
    String buscarPorDireccion(String prefijoHex) throws IOException {
        return entradaDe(pedir("GET", url() + "/buscar?dir=" + URLEncoder.encode(prefijoHex, "UTF-8"), null));
    }

    /** Un lote de la agenda del Ayuntamiento: entradas acreditadas publicadas después de `desde`. */
    static final class Agenda {
        final List<String> entradas = new ArrayList<>();
        long hasta;
        boolean quedan;
    }

    Agenda agenda(long desde) throws IOException {
        JSONObject r = pedir("GET", url() + "/agenda?desde=" + desde, null);
        Agenda a = new Agenda();
        a.hasta = r.optLong("hasta", desde);
        a.quedan = r.optBoolean("quedan", false);
        JSONArray fs = r.optJSONArray("fichas");
        if (fs != null) {
            for (int i = 0; i < fs.length(); i++) {
                JSONObject f = fs.optJSONObject(i);
                String e = f == null ? "" : f.optString("entrada", "");
                if (!e.isEmpty()) a.entradas.add(e);
            }
        }
        return a;
    }

    /** Revocaciones publicadas después de `desde`: [{codigo, ts, motivo, texto}] y «hasta». */
    JSONObject revocadas(long desde) throws IOException {
        return pedir("GET", url() + "/revocadas?desde=" + desde, null);
    }

    // ---- Salas por departamento (canister /sala/*)

    JSONObject salaEstado(String sala) throws IOException {
        return pedir("GET", url() + "/sala/estado?sala=" + sala, null);
    }

    /** Sobres (clave de la sala) dirigidos a `para`: [{epoca, de, sobre, firma, ts}]. */
    JSONArray salaSobres(String sala, String para) throws IOException {
        JSONArray a = pedir("GET", url() + "/sala/sobres?sala=" + sala + "&para=" + para, null).optJSONArray("sobres");
        return a == null ? new JSONArray() : a;
    }

    /** {mensajes:[{seq,de,epoca,msg,firma,ts,hash}], ultimo, epoca}. */
    JSONObject salaMensajes(String sala, long desde) throws IOException {
        return pedir("GET", url() + "/sala/mensajes?sala=" + sala + "&desde=" + desde, null);
    }

    /** Salas a las que añadieron a mano a `para`. */
    List<String> salaMias(String para) throws IOException {
        JSONArray a = pedir("GET", url() + "/sala/mias?para=" + para, null).optJSONArray("salas");
        List<String> l = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) l.add(a.optString(i));
        return l;
    }

    /** Entrega la clave de la sala a `para`. La época 0 la crea el primero; 409 si la sala va por otra época. */
    void salaSobre(String sala, int epoca, String para, String de, String sobre, String firma) throws IOException {
        JSONObject c = new JSONObject();
        try {
            c.put("sala", sala).put("epoca", epoca).put("para", para).put("de", de).put("sobre", sobre).put("firma", firma);
        } catch (Exception e) {
            throw new IOException(e);
        }
        pedir("POST", url() + "/sala/sobre", c.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** Publica un mensaje cifrado y firmado. Devuelve {seq, hash}. */
    JSONObject salaMensaje(String sala, int epoca, String de, String msg, String firma) throws IOException {
        JSONObject c = new JSONObject();
        try {
            c.put("sala", sala).put("epoca", epoca).put("de", de).put("msg", msg).put("firma", firma);
        } catch (Exception e) {
            throw new IOException(e);
        }
        return pedir("POST", url() + "/sala/mensaje", c.toString().getBytes(StandardCharsets.UTF_8));
    }

    void salaMiembro(String sala, String direccion, String de, String firma) throws IOException {
        JSONObject c = new JSONObject();
        try {
            c.put("sala", sala).put("direccion", direccion).put("de", de).put("firma", firma);
        } catch (Exception e) {
            throw new IOException(e);
        }
        pedir("POST", url() + "/sala/miembro", c.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** El canister rechazó la publicación porque la sala va por otra época (o aún no tiene clave). */
    static final class OtraEpoca extends IOException {
        OtraEpoca(String detalle) {
            super(detalle);
        }
    }

    private static String entradaDe(JSONObject r) throws IOException {
        String e = r.optString("entrada", "");
        if (e.isEmpty()) throw new IOException("el directorio no devolvió ninguna entrada");
        return e;
    }

    /** Mensajes para `direccion` con seq > desde, en orden. */
    List<Recibido> recoger(String direccion, long desde) throws IOException {
        JSONObject r = pedir("GET", url() + "/recoger?para=" + URLEncoder.encode(direccion, "UTF-8") + "&desde=" + desde, null);
        List<Recibido> l = new ArrayList<>();
        JSONArray a = r.optJSONArray("mensajes");
        if (a == null) return l;
        for (int i = 0; i < a.length(); i++) {
            JSONObject m = a.optJSONObject(i);
            if (m != null && m.has("seq") && m.has("msg")) l.add(new Recibido(m.optLong("seq"), m.optString("msg")));
        }
        return l;
    }

    private JSONObject pedir(String metodo, String direccion, byte[] cuerpo) throws IOException {
        validarUrl(direccion.split("\\?")[0]);
        URL u = new URL(direccion);
        HttpsURLConnection con = (HttpsURLConnection) u.openConnection();
        int codigo = -1;
        int recibidos = 0;
        try {
            con.setInstanceFollowRedirects(false);
            con.setConnectTimeout(15_000);
            con.setReadTimeout(20_000);
            con.setUseCaches(false);
            con.setRequestMethod(metodo);
            con.setRequestProperty("Accept", "application/json");
            if (cuerpo != null) {
                con.setDoOutput(true);
                con.setRequestProperty("Content-Type", "application/json");
                con.setFixedLengthStreamingMode(cuerpo.length);
                try (OutputStream o = con.getOutputStream()) {
                    o.write(cuerpo);
                }
            }
            codigo = con.getResponseCode();
            InputStream in = codigo >= 400 ? con.getErrorStream() : con.getInputStream();
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            if (in != null) {
                try (InputStream s = in) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = s.read(buf)) > 0) {
                        b.write(buf, 0, n);
                        if (b.size() > MAX_RESPUESTA) throw new IOException("respuesta del buzón demasiado grande");
                    }
                }
            }
            recibidos = b.size();
            String texto = new String(b.toByteArray(), StandardCharsets.UTF_8);
            JSONObject r;
            try {
                r = new JSONObject(texto);
            } catch (Exception e) {
                throw new IOException("respuesta del buzón no válida (HTTP " + codigo + ")");
            }
            if (codigo == 404 && "no esta en el directorio".equals(r.optString("error"))) throw new NoEstaEnDirectorio();
            if (codigo == 409) throw new OtraEpoca(r.optString("error", "otra época"));
            if (codigo != 200) throw new IOException("buzón: " + r.optString("error", "HTTP " + codigo));
            return r;
        } finally {
            con.disconnect();
            registrar(u.getHost(), metodo, cuerpo == null ? 0 : cuerpo.length, recibidos, codigo);
        }
    }

    private static synchronized void registrar(String host, String metodo, int enviados, int recibidos, int codigo) {
        String hora = new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
        REGISTRO.addFirst(hora + "  " + metodo + " " + host + "  ↑" + enviados + " B ↓" + recibidos + " B  " + (codigo < 0 ? "sin respuesta" : codigo));
        while (REGISTRO.size() > MAX_REGISTRO) REGISTRO.removeLast();
    }

    static synchronized List<String> registro() {
        return new ArrayList<>(REGISTRO);
    }
}
