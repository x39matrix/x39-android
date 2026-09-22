package org.x39.bolsillo;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.json.JSONObject;

/**
 * La cápsula de una evidencia: lo que se comparte, y lo que viajará por el chat.
 *
 * Un solo fichero .zip con:
 *   original/…        el contenido EXACTO, byte a byte, con todos sus metadatos (son parte
 *                     de la prueba; aquí no se limpia nada)
 *   recibo.json       huella SHA-256, firma ML-DSA-87, clave pública que firmó y hora declarada
 *   firmado.txt       la frase exacta que se firmó, para no tener que reconstruirla
 *   verificar_firma.py  comprueba la firma sin la app (pqcrypto, como la Notaría)
 *   ID.ots            la prueba de OpenTimestamps (ancla en Bitcoin), si ya la hay
 *   VERIFICAR.txt     cómo comprobarlo todo sin esta app, sin el chat y sin el móvil (español y,
 *                     detrás, inglés; siempre los dos, sea cual sea el idioma de la app)
 *
 * La cápsula se verifica sola. Si para verificarla hiciera falta el chat, estaría mal
 * diseñada: el chat es solo transporte.
 */
final class Capsula {

    private Capsula() { }

    /**
     * Escribe la cápsula de `f` en `destino`. Descifra el original mientras lo mete en el
     * zip y comprueba que su SHA-256 es la del recibo: si no cuadra, lanza y no sale nada
     * que parezca una prueba.
     */
    static void escribir(Evidencias evidencias, Evidencias.Ficha f, String nombreOriginal,
                         OutputStream destino) throws Exception {
        byte[] clavePk = f.firmante.equals(evidencias.huellaClave()) ? evidencias.clavePublica() : null;
        JSONObject recibo = Evidencias.recibo(f, clavePk);
        byte[] ots = evidencias.ots(f);

        ZipOutputStream zip = new ZipOutputStream(destino);
        zip.setComment("x39 Evidencia · cápsula " + f.id);

        zip.putNextEntry(new ZipEntry("VERIFICAR.txt"));
        zip.write(instrucciones(f, nombreOriginal, ots != null).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();

        zip.putNextEntry(new ZipEntry("recibo.json"));
        zip.write(recibo.toString(2).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();

        zip.putNextEntry(new ZipEntry("verificar_firma.py"));
        zip.write(scriptFirma(nombreOriginal).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();

        zip.putNextEntry(new ZipEntry("firmado.txt"));
        zip.write(f.canonica().getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();

        if (ots != null) {
            zip.putNextEntry(new ZipEntry(f.id + ".ots"));
            zip.write(ots);
            zip.closeEntry();
        }

        // El original, byte a byte, calculando su huella a la vez.
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        zip.putNextEntry(new ZipEntry("original/" + nombreOriginal));
        evidencias.descifrarA(f, new OutputStream() {
            @Override public void write(int b) throws java.io.IOException {
                sha.update((byte) b);
                zip.write(b);
            }
            @Override public void write(byte[] b, int off, int len) throws java.io.IOException {
                sha.update(b, off, len);
                zip.write(b, off, len);
            }
            @Override public void close() { /* el zip lo cierra quien lo abrió */ }
        });
        zip.closeEntry();
        String huella = Boveda.aHex(sha.digest());
        if (!huella.equalsIgnoreCase(f.sha256)) {
            throw new FalloVisible(org.x39matrix.evidencia.R.string.x39_motivo_original_no_cuadra);
        }
        zip.finish();
    }

    /** Script para verificar la firma sin la app, con la misma librería que usa la Notaría. */
    private static String scriptFirma(String nombre) {
        return "# x39 Evidencia: verificación de la firma ML-DSA-87 sin la app.\n"
                + "# pip install pqcrypto  &&  python3 verificar_firma.py\n"
                + "import json, base64, hashlib\n"
                + "from pqcrypto.sign import ml_dsa_87\n\n"
                + "def firma_ok(pk, msg, sig):\n"
                + "    # pqcrypto >= 1.0 devuelve None si vale y lanza si no; las anteriores, True/False.\n"
                + "    try:\n"
                + "        return ml_dsa_87.verify(pk, msg, sig) is not False\n"
                + "    except Exception:\n"
                + "        return False\n\n"
                + "r = json.load(open('recibo.json'))\n"
                + "firmado = open('firmado.txt', 'rb').read()\n"
                + "original = open('original/" + nombre.replace("'", "") + "', 'rb').read()\n"
                + "pk = base64.b64decode(r['signer_pk'])\n"
                + "sig = base64.b64decode(r['sig'])\n"
                + "huella = hashlib.sha256(original).hexdigest()\n"
                + "esperado = ('X39-EVIDENCIA-v1|' + r['sha256'] + '|' + r['captured_at_local']).encode()\n"
                + "ok_orig = huella == r['sha256']\n"
                + "ok_texto = firmado == esperado\n"
                + "ok_firma = firma_ok(pk, firmado, sig)\n"
                + "mala = bytearray(sig); mala[0] ^= 1\n"
                + "if ok_firma and firma_ok(pk, firmado, bytes(mala)):\n"
                + "    print('AVISO: esta instalación acepta una firma ALTERADA; el veredicto no vale')\n"
                + "    ok_firma = False\n"
                + "fp = hashlib.sha256(pk).hexdigest()\n"
                + "print('original = recibo      :', 'SÍ' if ok_orig else 'NO')\n"
                + "print('firmado.txt correcto   :', 'SÍ' if ok_texto else 'NO')\n"
                + "print('firma ML-DSA-87        :', 'VÁLIDA' if ok_firma else 'NO VÁLIDA')\n"
                + "print('huella de la clave     :', fp, '(recibo:', 'coincide' if fp == r['signer_fp'] else 'NO coincide', ')')\n"
                + "print('Contrasta esa huella fuera de esta cápsula.')\n";
    }

    /**
     * VERIFICAR.txt lo lee un tercero, no la app: va SIEMPRE en español y, detrás, en inglés completo.
     * No depende del idioma de la app. El español es el de siempre, sin cambiar una letra.
     */
    private static String instrucciones(Evidencias.Ficha f, String nombre, boolean hayOts) {
        return instruccionesEs(f, nombre, hayOts) + "\n" + instruccionesEn(f, nombre, hayOts);
    }

    private static String instruccionesEs(Evidencias.Ficha f, String nombre, boolean hayOts) {
        String ruta = "original/" + nombre;
        return "x39 Evidencia · cápsula " + f.id + "\n"
                + "==========================================\n\n"
                + "Esto se comprueba SIN la app, sin el chat y sin el móvil que la creó.\n\n"
                + "1) El contenido es el que se selló\n"
                + "   sha256sum \"" + ruta + "\"\n"
                + "   Tiene que dar: " + f.sha256 + "\n"
                + "   (es el campo \"sha256\" de recibo.json)\n\n"
                + "2) Existía antes de un bloque concreto de Bitcoin\n"
                + (hayOts
                    ? "   ots verify -f \"" + ruta + "\" " + f.id + ".ots\n"
                    + "   (cliente oficial de OpenTimestamps; o arrastra los dos ficheros a\n"
                    + "   https://opentimestamps.org). Si aún dice \"pending\", los calendarios\n"
                    + "   todavía no lo han metido en un bloque: se vuelve a mirar más tarde.\n\n"
                    : "   Esta cápsula se hizo antes de tener la prueba .ots: todavía no hay ancla.\n"
                    + "   Vuelve a pedir la cápsula cuando la app diga que está anclada.\n\n")
                + "3) Lo firmó quien dice (ML-DSA-87, FIPS 204)\n"
                + "   pip install pqcrypto\n"
                + "   python3 verificar_firma.py\n"
                + "   Comprueba la firma de firmado.txt con la clave pública del recibo, que\n"
                + "   firmado.txt es exactamente \"X39-EVIDENCIA-v1|<sha256>|<hora>\" y que el\n"
                + "   original da esa sha256. Te enseña la HUELLA de la clave que firmó.\n\n"
                + "   CONTRASTA esa huella por un canal que no sea esta cápsula (en persona, o\n"
                + "   con quien firmó por otro medio). Una cápsula falsa puede traer su propia\n"
                + "   clave y su propia huella, coherentes entre sí.\n\n"
                + "Si el .ots dice \"pending\":  ots upgrade " + f.id + ".ots  y vuelve a verificar.\n\n"
                + "Lo que esto NO prueba: la hora de \"captured_at_local\" la declara el móvil y no\n"
                + "es verificable. Lo verificable es el bloque de Bitcoin del punto 2: el contenido\n"
                + "existía, como muy tarde, cuando se minó ese bloque.\n";
    }

    /** La misma guía en inglés, para quien no lea español. */
    private static String instruccionesEn(Evidencias.Ficha f, String nombre, boolean hayOts) {
        String ruta = "original/" + nombre;
        return "x39 Evidencia · capsule " + f.id + " (English)\n"
                + "==========================================\n\n"
                + "This can be checked WITHOUT the app, without the chat and without the phone that created it.\n\n"
                + "1) The content is the one that was sealed\n"
                + "   sha256sum \"" + ruta + "\"\n"
                + "   It must give: " + f.sha256 + "\n"
                + "   (it is the \"sha256\" field in recibo.json)\n\n"
                + "2) It existed before a specific Bitcoin block\n"
                + (hayOts
                    ? "   ots verify -f \"" + ruta + "\" " + f.id + ".ots\n"
                    + "   (official OpenTimestamps client; or drag both files to\n"
                    + "   https://opentimestamps.org). If it still says \"pending\", the calendars\n"
                    + "   have not put it in a block yet: check again later.\n\n"
                    : "   This capsule was made before the .ots proof existed: there is no anchor yet.\n"
                    + "   Ask for the capsule again when the app says it is anchored.\n\n")
                + "3) It was signed by who it claims (ML-DSA-87, FIPS 204)\n"
                + "   pip install pqcrypto\n"
                + "   python3 verificar_firma.py\n"
                + "   It checks the signature of firmado.txt with the public key in the receipt,\n"
                + "   that firmado.txt is exactly \"X39-EVIDENCIA-v1|<sha256>|<time>\" and that\n"
                + "   the original gives that sha256. It shows you the FINGERPRINT of the signing key.\n"
                + "   The script prints its results in Spanish: SÍ = yes, NO = no,\n"
                + "   VÁLIDA = valid, coincide = matches.\n\n"
                + "   CHECK that fingerprint through a channel other than this capsule (in person,\n"
                + "   or with the signer by other means). A fake capsule can bring its own key\n"
                + "   and its own fingerprint, consistent with each other.\n\n"
                + "If the .ots says \"pending\":  ots upgrade " + f.id + ".ots  and verify again.\n\n"
                + "What this does NOT prove: the \"captured_at_local\" time is declared by the phone\n"
                + "and cannot be verified. What can be verified is the Bitcoin block in point 2: the\n"
                + "content existed, at the latest, when that block was mined.\n";
    }
}
