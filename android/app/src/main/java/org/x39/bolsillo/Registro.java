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
    /** Rutas de ficheros del portal que se aceptan del registro: solo dentro de actas/. */
    private static final String RUTA_ACTAS = "actas/[A-Za-z0-9._-]+";

    static final class Documento {
        String id, area, nombre, sesion, anclaje, sha256, bloque, verificadoBloque, verificadoEn, qtst, qtstTsa, pdf, ots, fuente, tsr;

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

        boolean bloqueEnCurso() {
            return "en curso".equals(bloque);
        }

        boolean bloqueVerificado() {
            return !verificadoBloque.isEmpty() && verificadoBloque.equals(bloque);
        }

        boolean selloCualificado() {
            return !qtst.isEmpty() && !"en proceso".equals(qtst);
        }

        /** «2026-09-12T16:12:48Z» → «12/09/2026». */
        String verificadoEnVisible() {
            if (verificadoEn.length() < 10) return verificadoEn;
            String[] p = verificadoEn.substring(0, 10).split("-");
            return p.length == 3 ? p[2] + "/" + p[1] + "/" + p[0] : verificadoEn;
        }

        String urlPdf() {
            return PORTAL + pdf;
        }

        String url(String ruta) {
            return PORTAL + ruta;
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

    /**
     * Grupo municipal según el censo de sevilla.org: {grupo, identificador del portal, nombre}.
     * Los nombres son exactamente los de sevilla.x39matrix.org (app.js, CATALOGO).
     */
    private static final String[][] CATALOGO = {
            {"Gobierno y contratación", "pleno", "Pleno Municipal"},
            {"Gobierno y contratación", "junta", "Junta de Gobierno"},
            {"Gobierno y contratación", "contratacion", "Contratación"},
            {"Gobierno y contratación", "juridica", "Relevancia Jurídica"},
            {"Distritos", "d-bellavista", "Distrito Bellavista-La Palmera"},
            {"Distritos", "d-casco-antiguo", "Distrito Casco Antiguo"},
            {"Distritos", "d-cerro-amate", "Distrito Cerro-Amate"},
            {"Distritos", "d-este", "Distrito Este-Alcosa-Torreblanca"},
            {"Distritos", "d-los-remedios", "Distrito Los Remedios"},
            {"Distritos", "d-macarena", "Distrito Macarena"},
            {"Distritos", "d-nervion", "Distrito Nervión"},
            {"Distritos", "d-norte", "Distrito Norte"},
            {"Distritos", "d-san-pablo", "Distrito San Pablo-Santa Justa"},
            {"Distritos", "d-sur", "Distrito Sur"},
            {"Distritos", "d-triana", "Distrito Triana"},
            {"Organismos y servicios", "agencia-tributaria", "Agencia Tributaria de Sevilla"},
            {"Organismos y servicios", "gerencia-urbanismo", "Gerencia de Urbanismo"},
            {"Organismos y servicios", "icas", "Instituto de la Cultura y las Artes"},
            {"Organismos y servicios", "imd", "Instituto Municipal de Deportes"},
            {"Organismos y servicios", "alcazar", "Patronato del Real Alcázar"},
            {"Organismos y servicios", "omic", "OMIC - Consumo"},
            {"Organismos y servicios", "film-office", "Sevilla Film Office"},
            {"Organismos y servicios", "fundacion-ajb", "Fundación Alberto Jiménez Becerril"},
            {"Empresas municipales", "emasesa", "Emasesa"},
            {"Empresas municipales", "emvisesa", "Emvisesa"},
            {"Empresas municipales", "lipasam", "Lipasam"},
            {"Empresas municipales", "tussam", "Tussam"},
            {"Empresas municipales", "contursa", "Contursa - Fibes"},
    };

    /** Orden de la cuadrícula «Áreas» y del selector del portal (alfabético, como app.js). */
    private static final String[] ORDEN_PORTAL = {
            "agencia-tributaria", "contratacion", "contursa", "d-bellavista", "d-casco-antiguo", "d-cerro-amate",
            "d-este", "d-los-remedios", "d-macarena", "d-nervion", "d-norte", "d-san-pablo", "d-sur", "d-triana",
            "emasesa", "emvisesa", "fundacion-ajb", "gerencia-urbanismo", "icas", "imd", "junta", "lipasam", "omic",
            "alcazar", "pleno", "juridica", "film-office", "tussam",
    };

    final List<Grupo> grupos = new ArrayList<>();
    final Map<String, Area> areas = new LinkedHashMap<>();
    /** Todos los documentos en el orden del registro (el de la tabla «Documentos anclados» del portal). */
    final List<Documento> documentos = new ArrayList<>();
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
            d.verificadoEn = o.optString("verificado_en");
            d.qtst = o.optString("qtst");
            d.qtstTsa = o.optString("qtst_tsa");
            d.pdf = o.optString("pdf");
            d.ots = rutaActas(o.optString("ots"));
            d.fuente = rutaActas(o.optString("fuente"));
            d.tsr = rutaActas(o.optString("tsr"));
            // Mismas reglas que el script de actualización: huella completa y PDF dentro de actas/.
            if (!d.sha256.matches("[0-9a-f]{64}") || !d.pdf.matches(RUTA_ACTAS + "\\.pdf")) continue;
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
            documentos.add(d);
            porHuella.put(d.sha256, d);
        }
        for (Area a : areas.values()) {
            a.documentos.sort((x, y) -> y.orden().compareTo(x.orden()));
        }
        total = porHuella.size();
        actualizado = raiz.optString("actualizado", "");
    }

    private static String rutaActas(String ruta) {
        return ruta.matches(RUTA_ACTAS) ? ruta : "";
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

    /** Áreas en el orden del portal; las que el portal aún no tenía van al final. */
    List<Area> areasPortal() {
        List<Area> l = new ArrayList<>();
        for (String slug : ORDEN_PORTAL) {
            Area a = areas.get(slug);
            if (a != null) l.add(a);
        }
        for (Area a : areas.values()) {
            if (!l.contains(a)) l.add(a);
        }
        return l;
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
