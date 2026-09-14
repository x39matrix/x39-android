package org.x39.bolsillo;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Contenido de un mensaje dentro de la cápsula cifrada.
 * v1: {"v":1, "de": id del remitente (declarado), "t": texto, "ts": hora de envío}.
 * Desde la v0.3 la carga va firmada con ML-DSA-87 (0x02 || firma || carga) y el campo «de» solo se
 * acepta si la firma corresponde a ese contacto; ver MainActivity.procesarTexto.
 */
final class Carga {
    private Carga() {}

    static byte[] crear(String deId, String texto, long tsMillis) throws Exception {
        return new JSONObject().put("v", 1).put("de", deId).put("t", texto).put("ts", tsMillis)
                .toString().getBytes(StandardCharsets.UTF_8);
    }

    static JSONObject leer(byte[] datos) {
        String s = new String(datos, StandardCharsets.UTF_8);
        try {
            JSONObject j = new JSONObject(s);
            if (j.optInt("v", 0) == 1 && j.has("t")) return j;
        } catch (Exception ignorado) {
            // Mensajes de x39 Bolsillo v0.1: texto plano sin remitente.
        }
        try {
            return new JSONObject().put("t", s);
        } catch (Exception e) {
            return new JSONObject();
        }
    }
}
