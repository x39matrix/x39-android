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
        /** Recibido: el remitente es declarado dentro del mensaje, todavía sin firma. */
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
        byte[] clave;
        boolean verificado;
        long creado;
        final List<Mensaje> mensajes = new ArrayList<>();

        long ultimaActividad() {
            return mensajes.isEmpty() ? creado : mensajes.get(mensajes.size() - 1).ts;
        }
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
                c.claveTexto = o.getString("clave");
                c.clave = X39Core.publicKeyFromText(c.claveTexto);
                c.verificado = o.optBoolean("verificado", false);
                c.creado = o.optLong("creado", System.currentTimeMillis());
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

    /** Añade o actualiza un contacto por su clave pública. */
    Contacto agregar(String nombre, String claveTexto, byte[] clave) {
        String id = idDeClave(clave);
        Contacto c = porId(id);
        if (c == null) {
            c = new Contacto();
            c.id = id;
            c.creado = System.currentTimeMillis();
            contactos.add(c);
        }
        c.nombre = nombre;
        c.claveTexto = claveTexto.trim();
        c.clave = clave;
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
