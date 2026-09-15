package org.x39.bolsillo;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Contactos y conversaciones. Todo se guarda en un único archivo cifrado con la clave
 * de Android Keystore (StrongBox si existe). Nada sale del móvil.
 */
final class Almacen {
    static final class Mensaje {
        final boolean saliente;
        final String texto;
        final long ts;
        /** Recibido: true = remitente solo declarado (sin firma comprobada); false = firma ML-DSA-87 verificada. */
        final boolean remitenteDeclarado;

        Mensaje(boolean saliente, String texto, long ts, boolean remitenteDeclarado) {
            this.saliente = saliente;
            this.texto = texto;
            this.ts = ts;
            this.remitenteDeclarado = remitenteDeclarado;
        }
    }

    static final class Contacto {
        String id;
        String nombre;
        String claveTexto;
        /** Clave ML-KEM-1024 para cifrarle. */
        byte[] clave;
        /** Clave ML-DSA-87 para comprobar sus mensajes. null = clave antigua X39PK1 de x39 0.2. */
        byte[] claveFirma;
        boolean verificado;
        long creado;
        /** Acreditación «X39ACR1:…» que venía con su clave, o null. */
        String acreditacionTexto;
        /** Nombre acreditado por el Ayuntamiento y último día de validez (AAAA-MM-DD), solo si la acreditación verificó. */
        String acreditadoNombre;
        String acreditadoHasta;
        final List<Mensaje> mensajes = new ArrayList<>();

        /** La invitación lleva «Nombre Apellidos · Cargo»; esto es solo el nombre (o todo, si no hay cargo). */
        String acreditadoSoloNombre() {
            if (acreditadoNombre == null) return null;
            int i = acreditadoNombre.indexOf(" · ");
            return i > 0 ? acreditadoNombre.substring(0, i).trim() : acreditadoNombre;
        }

        /** El cargo de la invitación, o null si no lo lleva. */
        String acreditadoCargo() {
            if (acreditadoNombre == null) return null;
            int i = acreditadoNombre.indexOf(" · ");
            return i > 0 ? acreditadoNombre.substring(i + 3).trim() : null;
        }

        String acreditadoHastaVisible() {
            if (acreditadoHasta == null || acreditadoHasta.length() != 10) return acreditadoHasta;
            String[] p = acreditadoHasta.split("-");
            return p.length == 3 ? p[2] + "/" + p[1] + "/" + p[0] : acreditadoHasta;
        }

        long ultimaActividad() {
            return mensajes.isEmpty() ? creado : mensajes.get(mensajes.size() - 1).ts;
        }

        String huella() {
            return claveFirma != null ? X39Core.identityFingerprint(clave, claveFirma) : X39Core.fingerprint(clave);
        }
    }

    /**
     * Lee un texto X39ID1 (cifrado + firma) o X39PK1 (solo cifrado), opcionalmente seguido de una
     * acreditación X39ACR1 (separada por espacio o salto de línea). Lanza RuntimeException si no es válido.
     */
    static Contacto leerTexto(String texto) {
        Contacto c = new Contacto();
        String t = texto.trim();
        String acr = null;
        int corte = t.indexOf("X39ACR1:");
        if (corte > 0) {
            acr = t.substring(corte).trim();
            t = t.substring(0, corte).trim();
        }
        if (t.startsWith("X39ID1:")) {
            byte[] ambas = X39Core.identityFromText(t);
            c.clave = Arrays.copyOfRange(ambas, 0, X39Core.PK_LEN);
            c.claveFirma = Arrays.copyOfRange(ambas, X39Core.PK_LEN, ambas.length);
        } else {
            c.clave = X39Core.publicKeyFromText(t);
        }
        c.claveTexto = t;
        c.acreditacionTexto = acr;
        return c;
    }

    private static final int MAX_MENSAJES = 500;

    private final Boveda boveda;
    private final File archivo;
    private final File temporal;
    final List<Contacto> contactos = new ArrayList<>();

    Almacen(Context context, Boveda boveda) {
        this.boveda = boveda;
        archivo = new File(context.getFilesDir(), "datos.enc");
        temporal = new File(context.getFilesDir(), "datos.enc.tmp");
    }

    static String idDeClave(byte[] clavePublica) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(clavePublica);
            return Boveda.aHex(Arrays.copyOf(h, 8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    void cargar() throws Exception {
        contactos.clear();
        if (!archivo.exists()) return;
        byte[] plano = boveda.descifrarDatos(Files.readAllBytes(archivo.toPath()));
        try {
            JSONObject raiz = new JSONObject(new String(plano, StandardCharsets.UTF_8));
            JSONArray cs = raiz.optJSONArray("contactos");
            if (cs == null) return;
            for (int i = 0; i < cs.length(); i++) {
                JSONObject o = cs.getJSONObject(i);
                Contacto c = new Contacto();
                c.id = o.getString("id");
                c.nombre = o.getString("nombre");
                Contacto leido = leerTexto(o.getString("clave"));
                c.claveTexto = leido.claveTexto;
                c.clave = leido.clave;
                c.claveFirma = leido.claveFirma;
                c.verificado = o.optBoolean("verificado", false);
                c.creado = o.optLong("creado", System.currentTimeMillis());
                c.acreditacionTexto = o.has("acr") ? o.optString("acr") : null;
                c.acreditadoNombre = o.has("acr_nombre") ? o.optString("acr_nombre") : null;
                c.acreditadoHasta = o.has("acr_hasta") ? o.optString("acr_hasta") : null;
                JSONArray ms = o.optJSONArray("mensajes");
                if (ms != null) {
                    for (int k = 0; k < ms.length(); k++) {
                        JSONObject m = ms.getJSONObject(k);
                        c.mensajes.add(new Mensaje(m.getBoolean("s"), m.getString("t"), m.getLong("ts"), m.optBoolean("d", false)));
                    }
                }
                contactos.add(c);
            }
        } finally {
            Arrays.fill(plano, (byte) 0);
        }
    }

    void guardar() throws Exception {
        JSONArray cs = new JSONArray();
        for (Contacto c : contactos) {
            JSONArray ms = new JSONArray();
            int desde = Math.max(0, c.mensajes.size() - MAX_MENSAJES);
            for (int k = desde; k < c.mensajes.size(); k++) {
                Mensaje m = c.mensajes.get(k);
                ms.put(new JSONObject().put("s", m.saliente).put("t", m.texto).put("ts", m.ts).put("d", m.remitenteDeclarado));
            }
            cs.put(new JSONObject()
                    .put("id", c.id)
                    .put("nombre", c.nombre)
                    .put("clave", c.claveTexto)
                    .put("verificado", c.verificado)
                    .put("creado", c.creado)
                    .put("acr", c.acreditacionTexto == null ? JSONObject.NULL : c.acreditacionTexto)
                    .put("acr_nombre", c.acreditadoNombre == null ? JSONObject.NULL : c.acreditadoNombre)
                    .put("acr_hasta", c.acreditadoHasta == null ? JSONObject.NULL : c.acreditadoHasta)
                    .put("mensajes", ms));
        }
        byte[] plano = new JSONObject().put("version", 1).put("contactos", cs).toString().getBytes(StandardCharsets.UTF_8);
        try {
            byte[] cifrado = boveda.cifrarDatos(plano);
            try (FileOutputStream out = new FileOutputStream(temporal)) {
                out.write(cifrado);
                out.getFD().sync();
            }
            if (!temporal.renameTo(archivo)) {
                throw new IllegalStateException("no se pudo guardar el almacén cifrado");
            }
        } finally {
            Arrays.fill(plano, (byte) 0);
        }
    }

    Contacto porId(String id) {
        for (Contacto c : contactos) {
            if (c.id.equals(id)) return c;
        }
        return null;
    }

    /**
     * Añade o actualiza un contacto por su clave de cifrado. Si cambia su clave de firma, la verificación
     * se pierde y hay que volver a comparar la huella. No se acepta sustituir una clave con firma por una antigua.
     */
    Contacto agregar(String nombre, String claveTexto) {
        Contacto leido = leerTexto(claveTexto);
        String id = idDeClave(leido.clave);
        Contacto c = porId(id);
        if (c == null) {
            c = leido;
            c.id = id;
            c.creado = System.currentTimeMillis();
            contactos.add(c);
        } else {
            if (c.claveFirma != null && leido.claveFirma == null) {
                throw new IllegalArgumentException("Ya tienes su clave con firma. Una clave antigua sin firma no la sustituye.");
            }
            if (!Arrays.equals(c.claveFirma, leido.claveFirma)) {
                c.verificado = false;
            }
            c.claveTexto = leido.claveTexto;
            c.clave = leido.clave;
            c.claveFirma = leido.claveFirma;
        }
        if (leido.acreditacionTexto != null) {
            // La acreditación se comprueba fuera (hace falta la clave de la autoridad): aquí solo se guarda.
            c.acreditacionTexto = leido.acreditacionTexto;
            c.acreditadoNombre = null;
            c.acreditadoHasta = null;
        }
        c.nombre = nombre;
        return c;
    }

    void eliminar(Contacto c) {
        contactos.remove(c);
    }

    List<Contacto> ordenados() {
        List<Contacto> l = new ArrayList<>(contactos);
        Collections.sort(l, (a, b) -> Long.compare(b.ultimaActividad(), a.ultimaActividad()));
        return l;
    }
}
