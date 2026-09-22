package org.x39.bolsillo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

/**
 * Identidad completa («X39ID1:…», 5.559 caracteres) repartida en varios QR pequeños que se alternan en pantalla.
 * Mismo formato que x39 Llamadas (QrPartes.kt): no necesita servidor, es el texto que se pega a mano, troceado.
 *
 *   parte:  "X39QP2:" + etiqueta + ":" + i + "/" + n + ":" + trozo      (i de 1 a n)
 *   etiqueta = SHA-256(texto completo), los 32 bytes, en base64url sin relleno (43 caracteres).
 *
 * La etiqueta ata cada parte a UNA identidad: si a mitad del escaneo aparece otra etiqueta, se para y se avisa.
 * Al completar, se recalcula SHA-256 del conjunto y se compara con la etiqueta (256 bits, tiempo constante).
 * Eso garantiza una identidad íntegra, no que sea de quien dice ser: eso lo da la comparación de huellas.
 */
final class QrPartes {
    static final String PREFIJO = "X39QP2:";
    static final int PARTES = 12;
    private static final int ETIQUETA_LEN = 43;

    private QrPartes() {}

    private static byte[] sha256(String texto) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(texto.getBytes(StandardCharsets.ISO_8859_1));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String etiqueta(String texto) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(texto));
    }

    static List<String> trocear(String texto, int n) {
        int tam = (texto.length() + n - 1) / n;
        String et = etiqueta(texto);
        List<String> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            int a = Math.min(i * tam, texto.length()), b = Math.min((i + 1) * tam, texto.length());
            out.add(PREFIJO + et + ":" + (i + 1) + "/" + n + ":" + texto.substring(a, b));
        }
        return out;
    }

    /** Partes de dos identidades distintas en el mismo escaneo, o un conjunto que no da su etiqueta. */
    static final class Mezcla extends Exception {
        Mezcla() { super("partes de dos identidades distintas"); }
    }

    /** Junta partes leídas en cualquier orden. Solo lo usa el hilo del análisis. */
    static final class Recolector {
        private String etiqueta;
        private int total;
        private final HashMap<Integer, String> trozos = new HashMap<>();

        int leidas() { return trozos.size(); }
        int totales() { return total; }

        /**
         * Añade una parte. Devuelve null si falta alguna; el texto completo, ya comprobado, cuando están todas.
         * Lanza {@link Mezcla} si es de otra identidad, si una posición ya leída llega con otro contenido o si el
         * conjunto no da la etiqueta. Lanza IllegalArgumentException si está mal formada (se ignora y se sigue).
         */
        String anadir(String parte) throws Mezcla {
            if (!parte.startsWith(PREFIJO)) throw new IllegalArgumentException("no es una parte " + PREFIJO);
            String[] campos = parte.substring(PREFIJO.length()).split(":", 3);
            if (campos.length != 3) throw new IllegalArgumentException("parte mal formada");
            String et = campos[0], pos = campos[1], trozo = campos[2];
            if (et.length() != ETIQUETA_LEN) throw new IllegalArgumentException("etiqueta de longitud incorrecta");
            String[] nums = pos.split("/");
            if (nums.length != 2) throw new IllegalArgumentException("posición mal formada: " + pos);
            int i, n;
            try { i = Integer.parseInt(nums[0]); n = Integer.parseInt(nums[1]); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("posición mal formada: " + pos); }
            if (n < 1 || n > 64 || i < 1 || i > n) throw new IllegalArgumentException("posición fuera de rango: " + pos);
            if (etiqueta == null) { etiqueta = et; total = n; }
            if (!et.equals(etiqueta) || n != total) throw new Mezcla();
            String previo = trozos.get(i);
            if (previo != null && !previo.equals(trozo)) throw new Mezcla();
            trozos.put(i, trozo);
            if (trozos.size() < total) return null;
            StringBuilder sb = new StringBuilder();
            for (int k = 1; k <= total; k++) sb.append(trozos.get(k));
            String texto = sb.toString();
            // Todas las posiciones con la misma etiqueta pero el conjunto no la da: partes manipuladas.
            if (!MessageDigest.isEqual(sha256(texto), Base64.getUrlDecoder().decode(et))) throw new Mezcla();
            return texto;
        }
    }
}
