package org.x39.bolsillo;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/**
 * El único cliente de red de la app (sección 6). Solo HTTPS, solo a calendarios de OpenTimestamps
 * (misma lista blanca que el cliente oficial), sin redirecciones y con respuestas de 10 kB como máximo.
 * Cada petición queda en el registro de red que enseña la pantalla Seguridad.
 */
final class RedX39 {
    /** Agregadores públicos por defecto del cliente oficial. */
    static final String[] CALENDARIOS = {
            "https://a.pool.opentimestamps.org",
            "https://b.pool.opentimestamps.org",
            "https://a.pool.eternitywall.com",
            "https://ots.btc.catallaxy.com",
    };
    private static final String[] HOSTS_EXACTOS = {
            "a.pool.opentimestamps.org", "b.pool.opentimestamps.org", "a.pool.eternitywall.com", "ots.btc.catallaxy.com",
    };
    /** Calendarios a los que apuntan las atestaciones pendientes (DEFAULT_CALENDAR_WHITELIST). */
    private static final String[] SUFIJOS = {
            ".calendar.opentimestamps.org", ".calendar.eternitywall.com", ".calendar.catallaxy.com",
    };
    static final int MAX_RESPUESTA = 10_000;
    private static final String REGISTRO = "registro_red.jsonl";
    private static final int MAX_LINEAS = 200;

    static final class Respuesta {
        final int codigo;
        final byte[] cuerpo;

        Respuesta(int codigo, byte[] cuerpo) {
            this.codigo = codigo;
            this.cuerpo = cuerpo;
        }
    }

    private RedX39() {}

    static boolean permitido(String url) {
        try {
            URL u = new URL(url);
            if (!"https".equals(u.getProtocol()) || u.getPort() != -1 || u.getQuery() != null || u.getUserInfo() != null || u.getRef() != null) {
                return false;
            }
            String h = u.getHost().toLowerCase(Locale.ROOT);
            for (String x : HOSTS_EXACTOS) if (h.equals(x)) return true;
            for (String s : SUFIJOS) if (h.endsWith(s)) return true;
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    static Respuesta post(Context c, String url, byte[] cuerpo) throws IOException {
        return pedir(c, "POST", url, cuerpo);
    }

    static Respuesta get(Context c, String url) throws IOException {
        return pedir(c, "GET", url, null);
    }

    private static Respuesta pedir(Context c, String metodo, String url, byte[] cuerpo) throws IOException {
        if (!permitido(url)) throw new IOException("destino no permitido: " + url);
        URL u = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) u.openConnection();
        int enviados = 0;
        int recibidos = 0;
        int codigo = -1;
        try {
            con.setInstanceFollowRedirects(false);
            con.setConnectTimeout(20_000);
            con.setReadTimeout(20_000);
            con.setUseCaches(false);
            con.setRequestMethod(metodo);
            con.setRequestProperty("Accept", "application/vnd.opentimestamps.v1");
            con.setRequestProperty("User-Agent", "x39/" + EvidenciaActivity.VERSION);
            if (cuerpo != null) {
                con.setDoOutput(true);
                con.setFixedLengthStreamingMode(cuerpo.length);
                try (OutputStream o = con.getOutputStream()) {
                    o.write(cuerpo);
                }
                enviados = cuerpo.length;
            }
            codigo = con.getResponseCode();
            InputStream in = codigo >= 400 ? con.getErrorStream() : con.getInputStream();
            byte[] datos = new byte[0];
            if (in != null) {
                try (InputStream s = in) {
                    ByteArrayOutputStream b = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = s.read(buf)) > 0) {
                        b.write(buf, 0, n);
                        if (b.size() > MAX_RESPUESTA) throw new IOException("respuesta de calendario demasiado grande");
                    }
                    datos = b.toByteArray();
                }
            }
            recibidos = datos.length;
            return new Respuesta(codigo, datos);
        } finally {
            con.disconnect();
            registrar(c, u.getHost(), metodo, enviados, recibidos, codigo);
        }
    }

    private static synchronized void registrar(Context c, String host, String metodo, int enviados, int recibidos, int codigo) {
        try {
            File f = new File(c.getApplicationContext().getFilesDir(), REGISTRO);
            String linea = new JSONObject().put("t", System.currentTimeMillis()).put("host", host).put("m", metodo)
                    .put("up", enviados).put("down", recibidos).put("code", codigo).toString() + "\n";
            try (FileOutputStream out = new FileOutputStream(f, true)) {
                out.write(linea.getBytes(StandardCharsets.UTF_8));
            }
            if (f.length() > 64_000) {
                List<String> l = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
                List<String> resto = l.subList(Math.max(0, l.size() - MAX_LINEAS), l.size());
                Evidencias.escribirAtomico(f, (String.join("\n", resto) + "\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignorado) {
            // El registro nunca debe tumbar el anclaje.
        }
    }

    /** Últimas peticiones, de la más reciente a la más antigua, ya formateadas para la pantalla. */
    static synchronized List<String> ultimas(Context c, int n) {
        List<String> salida = new ArrayList<>();
        File f = new File(c.getApplicationContext().getFilesDir(), REGISTRO);
        if (!f.exists()) return salida;
        try {
            List<String> l = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
            Collections.reverse(l);
            SimpleDateFormat hora = new SimpleDateFormat("dd/MM HH:mm:ss", Locale.ROOT);
            for (String s : l) {
                if (s.trim().isEmpty()) continue;
                JSONObject o = new JSONObject(s);
                salida.add(hora.format(new Date(o.getLong("t"))) + "  " + o.getString("m") + " " + o.getString("host")
                        + "  ↑" + o.getInt("up") + " B ↓" + o.getInt("down") + " B  " + (o.getInt("code") < 0 ? "sin respuesta" : o.getInt("code")));
                if (salida.size() >= n) break;
            }
        } catch (Exception ignorado) {
            // Si el registro está dañado se enseña vacío.
        }
        return salida;
    }
}
