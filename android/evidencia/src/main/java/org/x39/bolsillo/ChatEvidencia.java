package org.x39.bolsillo;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
import org.x39.chat.Protocolo;
import org.x39.chat.Sobres;
import org.x39.chat.TransporteWs;
import org.x39.chat.Troceo;
import org.x39matrix.evidencia.R;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * El chat de x39 Evidencia, sobre el módulo común x39-chat (el mismo de x39).
 *
 * Lo que es distinto de x39, y por qué:
 *   · NADA CADUCA. Ni se borra al leer ni con el tiempo: caducar una evidencia es
 *     destruirla. Lo único que el chat común aplica es la ventana de ENTREGA (cuánto se
 *     acepta un sobre que llega tarde), y aquí es larga.
 *   · No se limpian metadatos de nada. Lo que se adjunta es la cápsula entera.
 *   · Sin llamadas.
 *
 * El chat es TRANSPORTE. Que un mensaje esté aquí no prueba nada; lo que prueba es la
 * cápsula, que se verifica sola fuera de la app.
 *
 * Todo lo guardado (conversaciones) va cifrado con la clave del Keystore de esta app.
 */
final class ChatEvidencia implements TransporteWs.Escucha, Protocolo.Escucha {

    static final String URL_SENAL = "wss://livekit.x39matrix.org:8443";
    /** Lo que cabe en una cápsula por el chat (por el servidor). Igual que en x39. */
    static final int MAX_CAPSULA = 25 * 1024 * 1024;
    /** Ventana de entrega: un sobre sellado hace más de esto no se abre. Un año. */
    private static final long VENTANA_ENTREGA_S = 365L * 24 * 3600;

    /** Quién pinta la pantalla. Se llama en el hilo del chat: la pantalla pasa al suyo. */
    interface Oyente {
        void cambio(String bh);
        void estado(boolean enLinea);
    }

    static final class Msg {
        String id;
        boolean mio;
        String texto;
        long ts;
        /** pendiente → enviado → entregado. Cápsulas: también «esperando ancla» y «demasiado grande». */
        String estado;
        /** "txt" o "cap" (cápsula de una evidencia). */
        String tipo = "txt";
        /** Cápsula mía: id de la evidencia en este móvil. */
        String evId = "";
        /** Cápsula: nombre del original y tamaño de la cápsula. */
        String nombre = "";
        long bytes;
        /**
         * Cápsula recibida: lo que dio la comprobación, ya en palabras. Solo en mensajes guardados antes de
         * que la app tuviera idiomas; desde entonces se guarda el resultado (compDatos) y el texto se escribe
         * al enseñarlo, en el idioma de la app (textoComprobacion).
         */
        String comprobacion = "";
        /** Resultado de la comprobación, sin texto (ver Comprobacion.aJson). null si no hay o es antiguo. */
        JSONObject compDatos;
        boolean valida;

        boolean tieneComprobacion() { return compDatos != null || !comprobacion.isEmpty(); }

        boolean esCapsula() { return "cap".equals(tipo); }

        JSONObject aJson() throws Exception {
            return new JSONObject().put("id", id).put("mio", mio).put("t", texto).put("ts", ts).put("e", estado)
                    .put("tipo", tipo).put("ev", evId).put("nom", nombre).put("b", bytes)
                    .put("comp", comprobacion).put("cv", compDatos == null ? JSONObject.NULL : compDatos).put("ok", valida);
        }

        static Msg deJson(JSONObject o) {
            Msg m = new Msg();
            m.id = o.optString("id");
            m.mio = o.optBoolean("mio");
            m.texto = o.optString("t");
            m.ts = o.optLong("ts");
            m.estado = o.optString("e", "entregado");
            m.tipo = o.optString("tipo", "txt");
            m.evId = o.optString("ev", "");
            m.nombre = o.optString("nom", "");
            m.bytes = o.optLong("b", 0);
            m.comprobacion = o.optString("comp", "");
            m.compDatos = o.optJSONObject("cv");
            m.valida = o.optBoolean("ok", false);
            return m;
        }
    }

    private static ChatEvidencia unico;

    static synchronized ChatEvidencia de(Context c) {
        if (unico == null) unico = new ChatEvidencia(c.getApplicationContext());
        return unico;
    }

    private final Context app;
    private final Boveda boveda;
    private final Evidencias evidencias;
    private final Troceo.Juntador juntador = new Troceo.Juntador();
    /** Trozos entregados de cada cápsula mía en vuelo: id → cuántos. */
    private final java.util.Map<String, Integer> trozosEntregados = new java.util.HashMap<>();
    /** Cápsulas cuyo envío hay que cortar (el otro no está): no se gastan más trozos. */
    private final java.util.Set<String> cortar = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** Último intento de cada cápsula, para no reintentar 25 MB cada minuto. */
    private final java.util.Map<String, Long> ultimoIntento = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long REINTENTO_CAPSULA_MS = 10 * 60_000L;
    /** Progreso visible (enviando o recibiendo): id → «n/total». */
    private final java.util.Map<String, String> progreso = new java.util.concurrent.ConcurrentHashMap<>();
    private final Sobres sobres = new Sobres(MotorEvidencia.UNICO, VENTANA_ENTREGA_S);
    private final ExecutorService hilo = Executors.newSingleThreadExecutor(r -> new Thread(r, "x39-chat-evidencia"));
    private final SecureRandom azar = new SecureRandom();
    private TransporteWs transporte;
    private volatile boolean enLinea;
    private volatile Oyente oyente;

    private ChatEvidencia(Context app) {
        this.app = app;
        this.boveda = new Boveda(app);
        this.evidencias = new Evidencias(app);
        // Cada minuto se repasa la cola: una cápsula «esperando ancla» sale en cuanto los
        // calendarios devuelven la prueba .ots, sin que nadie tenga que tocar nada.
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "x39-chat-repaso"))
                .scheduleWithFixedDelay(() -> { if (enLinea) hilo.execute(() -> vaciarCola(false)); }, 60, 60,
                        java.util.concurrent.TimeUnit.SECONDS);
    }

    /** «3/12 trozos» mientras una cápsula va o viene; null si no hay nada en curso. */
    String progreso(String id) { return progreso.get(id); }

    void oyente(Oyente o) { this.oyente = o; }

    boolean enLinea() { return enLinea; }

    // ------------------------------------------------------------------ identidad

    /** ¿Tiene ya identidad de firma y clave de cifrar? La de cifrar se crea sola si falta. */
    boolean listo() {
        try {
            if (!boveda.tieneFirma()) return false;
            if (!boveda.tieneClaves()) boveda.crearClaves();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Mi identidad para mensajes, "X39ID1:…": clave de cifrar + clave de firmar. */
    String miIdentidadTexto() throws Exception {
        return X39Core.identityToText(boveda.clavePublica(), boveda.clavePublicaFirma());
    }

    String miBh() throws Exception { return hex(sha256(boveda.clavePublicaFirma())); }

    /** Lee una "X39ID1:…" ajena: {kemPk, sigPk, bh}. Lanza si no vale. */
    static Object[] leerIdentidad(String texto) {
        byte[] ambas = X39Core.identityFromText(texto.trim());
        byte[] kem = java.util.Arrays.copyOfRange(ambas, 0, X39Core.PK_LEN);
        byte[] sig = java.util.Arrays.copyOfRange(ambas, X39Core.PK_LEN, ambas.length);
        return new Object[]{kem, sig, hex(sha256(sig))};
    }

    // ------------------------------------------------------------------ línea

    /** Abre la línea con x39matrix.org (idempotente). Por Tor si el usuario lo tiene puesto. */
    synchronized void conectar() {
        if (!listo()) return;
        if (ColaAnclaje.aislado(app)) {
            // Modo aislado: NADA sale del móvil, tampoco el chat.
            if (transporte != null) { transporte.cerrar(); enLinea = false; }
            android.util.Log.i("X39_EV_CHAT", "modo aislado: el chat no se conecta");
            return;
        }
        if (transporte == null) {
            java.net.Proxy proxy = Orbot.soloTor(app)
                    ? new java.net.Proxy(java.net.Proxy.Type.HTTP, new java.net.InetSocketAddress("127.0.0.1", Orbot.PROXY_PUERTO))
                    : null;
            transporte = new TransporteWs(URL_SENAL, "", proxy, this);
            android.util.Log.i("X39_EV_CHAT", "línea con " + URL_SENAL + (proxy != null ? " por Tor (Orbot)" : ""));
        }
        transporte.conectar();
    }

    @Override public void alAbrir() {
        hilo.execute(() -> {
            try {
                transporte.enviar(Protocolo.registro(MotorEvidencia.UNICO, boveda.semillaFirma(),
                        boveda.clavePublicaFirma(), miBh()));
            } catch (Exception e) {
                android.util.Log.w("X39_EV_CHAT", "no se pudo registrar", e);
            }
        });
    }

    @Override public void alRecibir(String json) {
        hilo.execute(() -> {
            String tipo = Protocolo.tipoDe(json);
            if ("registered".equals(tipo)) {
                enLinea = true;
                android.util.Log.i("X39_EV_CHAT", "en línea (registrado)");
                Oyente o = oyente;
                if (o != null) o.estado(true);
                vaciarCola(true);
            } else if (Protocolo.esDelChat(tipo)) {
                Protocolo.repartir(tipo, json, this);
            } else if (!tipo.isEmpty() && !"pong".equals(tipo)) {
                android.util.Log.i("X39_EV_CHAT", "servidor manda tipo «" + tipo + "»" + ("error".equals(tipo) ? ": " + json : ""));
            }
            if ("error".equals(tipo)) {
                android.util.Log.w("X39_EV_CHAT", "el servidor dice: " + json);
            }
        });
    }

    @Override public void alCerrar(String motivo) {
        enLinea = false;
        Oyente o = oyente;
        if (o != null) o.estado(false);
    }

    // ------------------------------------------------------------------ enviar

    /** Escribe un mensaje: se guarda ya como pendiente y sale en cuanto haya línea. */
    void escribir(String bh, String texto) {
        hilo.execute(() -> {
            Msg m = new Msg();
            m.id = nuevoId();
            m.mio = true;
            m.texto = texto;
            m.ts = System.currentTimeMillis() / 1000L;
            m.estado = "pendiente";
            List<Msg> hilo = conversacion(bh);
            hilo.add(m);
            guardar(bh, hilo);
            avisar(bh);
            android.util.Log.i("X39_EV_CHAT", "escrito " + m.id + " para " + corto(bh) + (enLinea ? "" : " (sin línea: queda pendiente)"));
            if (enLinea) enviar(bh, m);
        });
    }

    private void enviar(String bh, Msg m) {
        if (m.esCapsula()) { enviarCapsula(bh, m); return; }
        JSONObject c = contacto(bh);
        if (c == null || c.optString("kem").isEmpty()) {
            android.util.Log.w("X39_EV_CHAT", "no sale " + m.id + ": " + corto(bh) + " no tiene clave de cifrar en contactos");
            return;
        }
        try {
            byte[] kem = Base64.decode(c.getString("kem"), Base64.NO_WRAP);
            byte[] carga = new JSONObject().put("v", 1).put("k", "txt").put("t", m.texto)
                    .toString().getBytes(StandardCharsets.UTF_8);
            String sobre = sobres.cerrar(kem, boveda.semillaFirma(), carga);
            transporte.enviar(Protocolo.mensaje(m.id, bh, sobre));
            android.util.Log.i("X39_EV_CHAT", "sale " + m.id + " → " + corto(bh) + " (" + sobre.length() + " car.)");
            if ("pendiente".equals(m.estado)) {
                m.estado = "enviado";
                cambiarEstado(bh, m.id, "enviado");
            }
        } catch (Exception e) {
            android.util.Log.w("X39_EV_CHAT", "no se pudo cerrar el sobre", e);
        }
    }

    /**
     * Adjunta una evidencia: lo que viaja es su CÁPSULA (original intacto + recibo + .ots),
     * no el fichero suelto. Queda en la conversación ya, y sale en cuanto se pueda.
     */
    void adjuntar(String bh, Evidencias.Ficha f, String nombreOriginal) {
        hilo.execute(() -> {
            Msg m = new Msg();
            m.id = nuevoId();
            m.mio = true;
            m.tipo = "cap";
            m.evId = f.id;
            m.nombre = nombreOriginal;
            m.texto = "Evidencia: " + nombreOriginal;
            m.ts = System.currentTimeMillis() / 1000L;
            m.estado = "pendiente";
            List<Msg> conv = conversacion(bh);
            conv.add(m);
            guardar(bh, conv);
            avisar(bh);
            if (enLinea) enviar(bh, m);
        });
    }

    /** Monta la cápsula, la parte en trozos, sella cada uno y los manda. */
    private void enviarCapsula(String bh, Msg m) {
        JSONObject c = contacto(bh);
        if (c == null || c.optString("kem").isEmpty()) return;
        try {
            Evidencias.Ficha f = evidencias.porId(m.evId);
            if (f == null) { cambiarEstado(bh, m.id, "la evidencia ya no está"); return; }
            if (evidencias.ots(f) == null) {
                // Sin la prueba .ots la cápsula no probaría la fecha: se espera a tenerla.
                cambiarEstado(bh, m.id, "esperando ancla");
                return;
            }
            java.io.ByteArrayOutputStream zip = new java.io.ByteArrayOutputStream();
            Capsula.escribir(evidencias, f, m.nombre, zip);
            byte[] datos = zip.toByteArray();
            if (datos.length > MAX_CAPSULA) { cambiarEstado(bh, m.id, "demasiado grande"); return; }
            actualizarTam(bh, m.id, datos.length);
            byte[] kem = Base64.decode(c.getString("kem"), Base64.NO_WRAP);
            byte[] semilla = boveda.semillaFirma();
            int total = Troceo.trozosDe(datos.length);
            synchronized (trozosEntregados) { trozosEntregados.put(m.id, 0); }
            cortar.remove(m.id);
            ultimoIntento.put(m.id, System.currentTimeMillis());
            for (int n = 0; n < total; n++) {
                if (!enLinea) { progreso.remove(m.id); return; }   // queda pendiente; sale en el próximo registro
                if (cortar.remove(m.id)) {
                    progreso.remove(m.id);
                    android.util.Log.i("X39_EV_CHAT", "cápsula " + m.id + ": el otro no está, se corta en el trozo " + n + " de " + total);
                    return;
                }
                String sobre = sobres.cerrar(kem, semilla,
                        Troceo.carga(m.id, datos, n, m.nombre, "application/zip", "capsula"));
                transporte.enviar(Protocolo.mensaje(Troceo.idTrozo(m.id, n), bh, sobre));
                progreso.put(m.id, (n + 1) + "/" + total);
                avisar(bh);
                Thread.sleep(25);   // respiro: que el socket no se sature
            }
            progreso.remove(m.id);
            cambiarEstado(bh, m.id, "enviado");
            android.util.Log.i("X39_EV_CHAT", "cápsula " + m.id + " enviada: " + total + " trozos, " + datos.length + " bytes");
        } catch (Exception e) {
            progreso.remove(m.id);
            android.util.Log.w("X39_EV_CHAT", "no se pudo enviar la cápsula", e);
        }
    }

    private void actualizarTam(String bh, String id, long bytes) {
        List<Msg> conv = conversacion(bh);
        for (Msg x : conv) if (x.id.equals(id)) { x.bytes = bytes; guardar(bh, conv); return; }
    }

    /**
     * Vuelve a sacar lo mío que no consta como entregado. Al registrarse (`todo`) sale todo
     * eso; en el repaso de cada minuto, solo lo que aún no ha salido nunca (pendiente o
     * esperando ancla), para no volver a mandar entera una cápsula que ya va de camino.
     */
    private void vaciarCola(boolean todo) {
        JSONArray cs = contactos();
        for (int i = 0; i < cs.length(); i++) {
            JSONObject c = cs.optJSONObject(i);
            if (c == null) continue;
            String bh = c.optString("huella");
            for (Msg m : conversacion(bh)) {
                if (!m.mio || "entregado".equals(m.estado) || "demasiado grande".equals(m.estado)) continue;
                if (!todo && m.esCapsula() && "pendiente".equals(m.estado)) {
                    Long u = ultimoIntento.get(m.id);
                    if (u != null && System.currentTimeMillis() - u < REINTENTO_CAPSULA_MS) continue;
                }
                if (todo || "pendiente".equals(m.estado) || "esperando ancla".equals(m.estado)) enviar(bh, m);
            }
        }
    }

    // ------------------------------------------------------------------ recibir

    @Override public void sobreRecibido(String deBh, String id, String sobre) {
        android.util.Log.i("X39_EV_CHAT", "llega " + id + " de " + corto(deBh) + " (" + sobre.length() + " car.)");
        JSONObject c = contacto(deBh);
        if (c == null || c.optString("sig").isEmpty()) {
            android.util.Log.i("X39_EV_CHAT", "sobre de alguien que no está en contactos (o sin su identidad): se tira");
            return;
        }
        try {
            byte[] sig = Base64.decode(c.getString("sig"), Base64.NO_WRAP);
            Sobres.Abierto a = sobres.abrir(boveda.claveSecreta(), boveda.clavePublica(), sig, sobre);
            JSONObject carga = new JSONObject(new String(a.carga, StandardCharsets.UTF_8));
            if (Troceo.esTrozo(carga)) { trozoRecibido(deBh, carga); return; }
            List<Msg> hilo = conversacion(deBh);
            for (Msg m : hilo) if (!m.mio && m.id.equals(id)) return;   // reintento ya recibido
            Msg m = new Msg();
            m.id = id;
            m.mio = false;
            m.texto = carga.optString("t");
            m.ts = System.currentTimeMillis() / 1000L;
            m.estado = "entregado";
            hilo.add(m);
            guardar(deBh, hilo);
            avisar(deBh);
            avisoFuera(deBh, c);
        } catch (Exception e) {
            android.util.Log.w("X39_EV_CHAT", "sobre que no abre o no firma quien dice: se tira", e);
        }
    }

    /** Llega un trozo de cápsula. Cuando están todos, se comprueba y se guarda cifrada. */
    private void trozoRecibido(String deBh, JSONObject carga) {
        String id = carga.optString("id");
        for (Msg m : conversacion(deBh)) if (!m.mio && m.id.equals(id)) return;   // ya la tengo
        byte[] zip = juntador.meter(carga);
        if (zip == null) {
            Troceo.Entrante e = juntador.enCurso(id);
            if (e != null) {
                boolean primero = progreso.get(id) == null;
                progreso.put(id, e.recibidos() + "/" + e.total);
                if (primero) {
                    // Burbuja «recibiendo…» desde el primer trozo.
                    Msg m = new Msg();
                    m.id = id; m.mio = false; m.tipo = "cap"; m.nombre = e.nombre;
                    m.texto = "Evidencia: " + e.nombre; m.ts = System.currentTimeMillis() / 1000L;
                    m.estado = "recibiendo"; m.bytes = e.tam;
                    List<Msg> conv = conversacion(deBh);
                    conv.add(m);
                    guardar(deBh, conv);
                }
                avisar(deBh);
            }
            return;
        }
        progreso.remove(id);
        Comprobacion r = comprobar(zip, deBh);
        try {
            Evidencias.escribirAtomico(ficheroCapsula(id), boveda.cifrarDatos(zip));
        } catch (Exception ex) {
            android.util.Log.w("X39_EV_CHAT", "no se pudo guardar la cápsula recibida", ex);
            return;
        }
        List<Msg> conv = conversacion(deBh);
        Msg m = null;
        for (Msg x : conv) if (!x.mio && x.id.equals(id)) m = x;
        if (m == null) { m = new Msg(); m.id = id; m.mio = false; m.tipo = "cap"; conv.add(m); }
        m.nombre = r.nombre.isEmpty() ? carga.optString("nom") : r.nombre;
        m.texto = "Evidencia: " + m.nombre;
        m.ts = System.currentTimeMillis() / 1000L;
        m.estado = "entregado";
        m.bytes = zip.length;
        m.valida = r.valida;
        m.comprobacion = "";
        m.compDatos = r.aJson();
        guardar(deBh, conv);
        android.util.Log.i("X39_EV_CHAT", "cápsula " + id + " recibida (" + zip.length + " bytes): " + m.compDatos);
        avisar(deBh);
        avisoFuera(deBh, contacto(deBh));
    }

    /** La cápsula recibida, descifrada, para compartirla o guardarla fuera. */
    byte[] capsulaRecibida(String id) throws Exception {
        return boveda.descifrarDatos(java.nio.file.Files.readAllBytes(ficheroCapsula(id).toPath()));
    }

    private File ficheroCapsula(String id) {
        File d = new File(app.getFilesDir(), "chat");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return new File(d, "cap_" + id.replaceAll("[^0-9a-f]", "") + ".enc");
    }

    /**
     * Lo que dio comprobar una cápsula, sin palabras: el texto lo pone textoComprobacion() al enseñarlo.
     * estado: "ok" (comprobada), "incompleta" (faltan piezas) o "error" (no se pudo leer; detalle = motivo).
     */
    static final class Comprobacion {
        boolean valida;
        String nombre = "";
        String estado = "error";
        String detalle = "";
        boolean okOriginal;
        /** Firma, texto firmado y clave del recibo, las tres bien. */
        boolean okFirma;
        boolean mismoRemitente;
        /** Primeros 16 hex de la clave que firmó (si no es la de quien la manda). */
        String fp16 = "";
        /** "no" (sin .ots), "pendiente" o "bitcoin" (bloques). */
        String ots = "no";
        String bloques = "";

        JSONObject aJson() {
            try {
                return new JSONObject().put("estado", estado).put("detalle", detalle).put("original", okOriginal)
                        .put("firma", okFirma).put("remitente", mismoRemitente).put("fp16", fp16)
                        .put("ots", ots).put("bloques", bloques);
            } catch (Exception e) {
                return new JSONObject();
            }
        }
    }

    /** El resultado de la comprobación de una cápsula recibida, en el idioma actual de la app. */
    static String textoComprobacion(Context c, Msg m) {
        JSONObject d = m.compDatos;
        if (d == null) return m.comprobacion;   // guardado antes de los idiomas: ya venía en palabras
        String estado = d.optString("estado");
        if ("incompleta".equals(estado)) return c.getString(R.string.x39_comp_incompleta);
        if (!"ok".equals(estado)) return c.getString(R.string.x39_comp_error_leer, d.optString("detalle"));
        StringBuilder t = new StringBuilder();
        t.append(c.getString(d.optBoolean("original") ? R.string.x39_comp_original_ok : R.string.x39_comp_original_mal)).append('\n');
        t.append(c.getString(d.optBoolean("firma") ? R.string.x39_comp_firma_ok : R.string.x39_comp_firma_mal)).append('\n');
        t.append(d.optBoolean("remitente") ? c.getString(R.string.x39_comp_remitente_ok)
                : c.getString(R.string.x39_comp_otra_clave, d.optString("fp16"))).append('\n');
        switch (d.optString("ots")) {
            case "bitcoin": t.append(c.getString(R.string.x39_comp_ots_bloque, d.optString("bloques"))); break;
            case "pendiente": t.append(c.getString(R.string.x39_comp_ots_pendiente)); break;
            default: t.append(c.getString(R.string.x39_comp_sin_ots)); break;
        }
        return t.toString();
    }

    /**
     * Comprueba una cápsula SOLO con lo que trae dentro, igual que lo haría alguien sin la
     * app: la huella del original, el texto firmado, la firma ML-DSA-87 y la prueba .ots.
     */
    static Comprobacion comprobar(byte[] zip, String deBh) {
        Comprobacion r = new Comprobacion();
        try {
            JSONObject recibo = null;
            byte[] firmado = null, original = null, ots = null;
            try (java.util.zip.ZipInputStream z = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zip))) {
                java.util.zip.ZipEntry e;
                while ((e = z.getNextEntry()) != null) {
                    java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[65536];
                    int k;
                    while ((k = z.read(buf)) > 0) b.write(buf, 0, k);
                    String n = e.getName();
                    if (n.equals("recibo.json")) recibo = new JSONObject(new String(b.toByteArray(), StandardCharsets.UTF_8));
                    else if (n.equals("firmado.txt")) firmado = b.toByteArray();
                    else if (n.startsWith("original/")) { original = b.toByteArray(); r.nombre = n.substring(9); }
                    else if (n.endsWith(".ots")) ots = b.toByteArray();
                }
            }
            if (recibo == null || firmado == null || original == null) {
                r.estado = "incompleta";
                return r;
            }
            String sha = recibo.optString("sha256");
            boolean okOriginal = hex(sha256(original)).equalsIgnoreCase(sha);
            String esperado = Evidencias.PREFIJO_CANONICO + sha + "|" + recibo.optString("captured_at_local");
            boolean okTexto = esperado.equals(new String(firmado, StandardCharsets.UTF_8));
            byte[] pk = Base64.decode(recibo.optString("signer_pk"), Base64.DEFAULT);
            String fp = hex(sha256(pk));
            boolean okClave = fp.equalsIgnoreCase(recibo.optString("signer_fp"));
            boolean okFirma;
            try {
                okFirma = X39Core.verifyMessage(pk, firmado, Base64.decode(recibo.optString("sig"), Base64.DEFAULT)) == 1;
            } catch (Exception ex) {
                okFirma = false;
            }
            r.okOriginal = okOriginal;
            r.okFirma = okFirma && okTexto && okClave;
            r.mismoRemitente = fp.equalsIgnoreCase(deBh);
            if (!r.mismoRemitente) r.fp16 = fp.substring(0, 16);
            if (ots == null) {
                r.ots = "no";
            } else {
                String bloques = "";
                try { bloques = X39Core.otsBlocks(ots); } catch (Exception ignorado) { }
                if (bloques == null || bloques.isEmpty()) {
                    r.ots = "pendiente";
                } else {
                    r.ots = "bitcoin";
                    r.bloques = bloques;
                }
            }
            r.valida = okOriginal && okFirma && okTexto && okClave;
            r.estado = "ok";
        } catch (Exception e) {
            r.estado = "error";
            r.detalle = String.valueOf(e.getMessage());
        }
        return r;
    }

    @Override public void acuseRecibo(String id, boolean entregado) {
        android.util.Log.i("X39_EV_CHAT", "servidor: " + id + (entregado ? " ENTREGADO" : " NO ENTREGADO (el otro no está)"));
        String deFichero = Troceo.ficheroDeIdTrozo(id);
        if (deFichero != null) { acuseTrozo(deFichero, entregado); return; }
        JSONArray cs = contactos();
        if (!entregado) {
            // No llegó (el otro no está en línea): vuelve a PENDIENTE y sale solo en el
            // repaso de cada minuto. Si se quedara en «enviado», no se reintentaría nunca.
            for (int i = 0; i < cs.length(); i++) {
                JSONObject c = cs.optJSONObject(i);
                if (c != null && cambiarEstado(c.optString("huella"), id, "pendiente")) return;
            }
            return;
        }
        for (int i = 0; i < cs.length(); i++) {
            JSONObject c = cs.optJSONObject(i);
            if (c != null && cambiarEstado(c.optString("huella"), id, "entregado")) return;
        }
    }

    /** Acuse de un trozo de cápsula: cuando han llegado todos, la cápsula está entregada. */
    private void acuseTrozo(String idCap, boolean entregado) {
        JSONArray cs = contactos();
        for (int i = 0; i < cs.length(); i++) {
            JSONObject c = cs.optJSONObject(i);
            if (c == null) continue;
            String bh = c.optString("huella");
            for (Msg m : conversacion(bh)) {
                if (!m.mio || !m.id.equals(idCap)) continue;
                if (!entregado) {
                    // Un trozo no llegó: se corta el envío y la cápsula entera vuelve a la cola.
                    cortar.add(idCap);
                    synchronized (trozosEntregados) { trozosEntregados.remove(idCap); }
                    cambiarEstado(bh, idCap, "pendiente");
                    return;
                }
                int total = Troceo.trozosDe(m.bytes);
                int n;
                synchronized (trozosEntregados) {
                    Integer v = trozosEntregados.get(idCap);
                    n = (v == null ? 0 : v) + 1;
                    trozosEntregados.put(idCap, n);
                }
                if (total > 0 && n >= total) {
                    synchronized (trozosEntregados) { trozosEntregados.remove(idCap); }
                    cambiarEstado(bh, idCap, "entregado");
                }
                return;
            }
        }
    }

    // ------------------------------------------------------------------ almacén

    List<Msg> conversacion(String bh) {
        List<Msg> r = new ArrayList<>();
        try {
            File f = fichero(bh);
            if (!f.exists()) return r;
            byte[] plano = boveda.descifrarDatos(java.nio.file.Files.readAllBytes(f.toPath()));
            JSONArray a = new JSONArray(new String(plano, StandardCharsets.UTF_8));
            for (int i = 0; i < a.length(); i++) r.add(Msg.deJson(a.getJSONObject(i)));
        } catch (Exception e) {
            android.util.Log.w("X39_EV_CHAT", "no se pudo leer la conversación", e);
        }
        return r;
    }

    private synchronized void guardar(String bh, List<Msg> hilo) {
        try {
            JSONArray a = new JSONArray();
            for (Msg m : hilo) a.put(m.aJson());
            Evidencias.escribirAtomico(fichero(bh), boveda.cifrarDatos(a.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            android.util.Log.w("X39_EV_CHAT", "no se pudo guardar la conversación", e);
        }
    }

    private boolean cambiarEstado(String bh, String id, String estado) {
        List<Msg> hilo = conversacion(bh);
        for (Msg m : hilo) {
            if (m.mio && m.id.equals(id)) {
                if (estado.equals(m.estado)) return true;
                m.estado = estado;
                guardar(bh, hilo);
                avisar(bh);
                return true;
            }
        }
        return false;
    }

    private File fichero(String bh) {
        File d = new File(app.getFilesDir(), "chat");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return new File(d, bh.replaceAll("[^0-9a-f]", "") + ".enc");
    }

    // ------------------------------------------------------------------ contactos

    JSONArray contactos() {
        try {
            File f = new File(app.getFilesDir(), "contactos.json");
            if (!f.exists()) return new JSONArray();
            return new JSONArray(new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    JSONObject contacto(String bh) {
        JSONArray cs = contactos();
        for (int i = 0; i < cs.length(); i++) {
            JSONObject c = cs.optJSONObject(i);
            if (c != null && bh.equals(c.optString("huella"))) return c;
        }
        return null;
    }

    /** Con la app fuera de la pantalla, aviso de QUIÉN escribe. Nunca el texto. */
    private void avisoFuera(String bh, JSONObject c) {
        if (oyente != null) return;   // la app está delante: ya lo ve
        String alguien = app.getString(R.string.x39_un_contacto);
        ServicioEvidencia.avisarMensaje(app, bh, c == null ? alguien : c.optString("nombre", alguien));
    }

    private void avisar(String bh) {
        Oyente o = oyente;
        if (o != null) o.cambio(bh);
    }

    private String nuevoId() {
        byte[] b = new byte[12];
        azar.nextBytes(b);
        return hex(b);
    }

    static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) { return Boveda.aHex(b); }

    private static String corto(String bh) { return bh.length() > 8 ? bh.substring(0, 8) + "…" : bh; }
}
