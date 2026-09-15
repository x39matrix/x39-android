package org.x39.bolsillo;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Registro público de documentos anclados en sevilla.x39matrix.org.
 * La copia viaja dentro de la app (assets/registro.json) y se regenera al compilar con
 * scripts/actualizar_registro.sh desde https://api.x39matrix.org/registro/registro.json.
 * Así se consulta sin internet; solo abrir un PDF necesita conexión (en el navegador).
 */
final class Registro {
    static final String PORTAL = "https://sevilla.x39matrix.org/";

    static final class Documento {
        String id, area, nombre, sesion, anclaje, sha256, bloque, verificadoBloque, qtst, qtstTsa, pdf;

        /** «10o Acta del Pleno» → «10.º Acta del Pleno». */
        String nombreVisible() {
            return nombre.replaceAll("(\\d+)o ", "$1.º ");
        }

        String sesionVisible() {
            return sesion.replace('-', '/');
        }

        String anclajeVisible() {
            return anclaje.replace('-', '/');
        }

        boolean bloqueVerificado() {
            return !verificadoBloque.isEmpty() && verificadoBloque.equals(bloque);
        }

        boolean selloCualificado() {
            return !qtst.isEmpty() && !"en proceso".equals(qtst);
        }

        String urlPdf() {
            return PORTAL + pdf;
        }

        String huellaCorta() {
            return sha256.substring(0, 8) + "…" + sha256.substring(56);
        }

        /** Orden cronológico: aaaammdd, o aaaamm00 si la sesión solo indica mes y año. */
        String orden() {
            String[] p = sesion.split("-");
            if (p.length == 3) return p[2] + p[1] + p[0];
            if (p.length == 2) return p[1] + p[0] + "00";
            return sesion;
        }
    }

    static final class Area {
        final String slug;
        final String nombre;
        final List<Documento> documentos = new ArrayList<>();

        Area(String slug, String nombre) {
            this.slug = slug;
            this.nombre = nombre;
        }
    }

    static final class Grupo {
        final String nombre;
        final List<Area> areas = new ArrayList<>();

        Grupo(String nombre) {
            this.nombre = nombre;
        }
    }

    /** Grupo municipal según el censo de sevilla.org: {grupo, identificador del portal, nombre}. */
    private static final String[][] CATALOGO = {
            {"Gobierno y contratación", "pleno", "Pleno Municipal"},
            {"Gobierno y contratación", "junta", "Junta de Gobierno"},
            {"Gobierno y contratación", "contratacion", "Contratación"},
            {"Gobierno y contratación", "juridica", "Relevancia jurídica"},
            {"Distritos", "d-bellavista", "Bellavista-La Palmera"},
            {"Distritos", "d-casco-antiguo", "Casco Antiguo"},
            {"Distritos", "d-cerro-amate", "Cerro-Amate"},
            {"Distritos", "d-este", "Este-Alcosa-Torreblanca"},
            {"Distritos", "d-los-remedios", "Los Remedios"},
            {"Distritos", "d-macarena", "Macarena"},
            {"Distritos", "d-nervion", "Nervión"},
            {"Distritos", "d-norte", "Norte"},
            {"Distritos", "d-san-pablo", "San Pablo-Santa Justa"},
            {"Distritos", "d-sur", "Sur"},
            {"Distritos", "d-triana", "Triana"},
            {"Organismos y servicios", "agencia-tributaria", "Agencia Tributaria de Sevilla"},
            {"Organismos y servicios", "gerencia-urbanismo", "Gerencia de Urbanismo"},
            {"Organismos y servicios", "icas", "Instituto de la Cultura y las Artes"},
            {"Organismos y servicios", "imd", "Instituto Municipal de Deportes"},
            {"Organismos y servicios", "alcazar", "Patronato del Real Alcázar"},
            {"Organismos y servicios", "omic", "OMIC · Consumo"},
            {"Organismos y servicios", "film-office", "Sevilla Film Office"},
            {"Organismos y servicios", "fundacion-ajb", "Fundación Alberto Jiménez Becerril"},
            {"Empresas municipales", "emasesa", "Emasesa"},
            {"Empresas municipales", "emvisesa", "Emvisesa"},
            {"Empresas municipales", "lipasam", "Lipasam"},
            {"Empresas municipales", "tussam", "Tussam"},
            {"Empresas municipales", "contursa", "Contursa · Fibes"},
    };

    final List<Grupo> grupos = new ArrayList<>();
    final Map<String, Area> areas = new LinkedHashMap<>();
    private final Map<String, Documento> porHuella = new HashMap<>();
    final String actualizado;
    final int total;

    private Registro(JSONObject raiz) throws Exception {
        Map<String, Grupo> porNombre = new LinkedHashMap<>();
        for (String[] fila : CATALOGO) {
            Grupo g = porNombre.get(fila[0]);
            if (g == null) {
                g = new Grupo(fila[0]);
                porNombre.put(fila[0], g);
                grupos.add(g);
            }
            Area a = new Area(fila[1], fila[2]);
            g.areas.add(a);
            areas.put(a.slug, a);
        }

        JSONArray docs = raiz.getJSONArray("documentos");
        for (int i = 0; i < docs.length(); i++) {
            JSONObject o = docs.getJSONObject(i);
            Documento d = new Documento();
            d.id = o.optString("id");
            d.area = o.optString("area");
            d.nombre = o.optString("nombre");
            d.sesion = o.optString("sesion");
            d.anclaje = o.optString("anclaje");
            d.sha256 = o.optString("sha256").toLowerCase(Locale.ROOT);
            d.bloque = o.optString("bloque");
            d.verificadoBloque = o.optString("verificado_bloque");
            d.qtst = o.optString("qtst");
            d.qtstTsa = o.optString("qtst_tsa");
            d.pdf = o.optString("pdf");
            // Mismas reglas que el script de actualización: huella completa y PDF dentro de actas/.
            if (!d.sha256.matches("[0-9a-f]{64}") || !d.pdf.matches("actas/[A-Za-z0-9._-]+\\.pdf")) continue;
            Area a = areas.get(d.area);
            if (a == null) {
                // Área nueva en el portal que esta versión de la app todavía no conoce.
                Grupo otros = porNombre.get("Otros");
                if (otros == null) {
                    otros = new Grupo("Otros");
                    porNombre.put("Otros", otros);
                    grupos.add(otros);
                }
                a = new Area(d.area, d.area);
                otros.areas.add(a);
                areas.put(a.slug, a);
            }
            a.documentos.add(d);
            porHuella.put(d.sha256, d);
        }
        for (Area a : areas.values()) {
            a.documentos.sort((x, y) -> y.orden().compareTo(x.orden()));
        }
        total = porHuella.size();
        actualizado = raiz.optString("actualizado", "");
    }

    static Registro cargar(Context contexto) throws Exception {
        try (InputStream in = contexto.getAssets().open("registro.json")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return new Registro(new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8)));
        }
    }

    /** Documento cuya huella SHA-256 (hex) coincide, o null. */
    Documento buscar(String sha256Hex) {
        return porHuella.get(sha256Hex.toLowerCase(Locale.ROOT));
    }

    /** «2026-09-14T22:00:47Z» → «14/09/2026». */
    String actualizadoVisible() {
        if (actualizado.length() < 10) return actualizado;
        String[] p = actualizado.substring(0, 10).split("-");
        return p.length == 3 ? p[2] + "/" + p[1] + "/" + p[0] : actualizado;
    }
}
