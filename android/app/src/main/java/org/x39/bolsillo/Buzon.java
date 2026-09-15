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
 * Sube cápsulas ya cifradas y firmadas y recoge las dirigidas a este móvil. Solo HTTPS, solo al
 * dominio configurado, sin redirecciones, respuestas de 256 kB como máximo. Cada conexión queda en
 * el registro que enseña Seguridad. El buzón ve direcciones, tamaños y horas; nunca el contenido.
 */
final class Buzon {
    static final String PREF_ACTIVO = "buzon_activo";
    static final String PREF_URL = "buzon_url";
    static final String PREF_DESDE = "buzon_desde";
    /** Canister buzon desplegado el 15/09/2026 (canister/buzon/canister_ids.json). Se puede cambiar en Seguridad. */
    static final String URL_POR_DEFECTO = "https://gx4ic-yqaaa-aaaah-qu43a-cai.raw.icp0.io";
    private static final int MAX_RESPUESTA = 256 * 1024;
    private static final int MAX_REGISTRO = 30;
    private static final ArrayDeque<String> REGISTRO = new ArrayDeque<>();

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
