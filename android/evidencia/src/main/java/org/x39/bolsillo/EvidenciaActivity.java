package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Insets;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.Base64;
import android.view.Gravity;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * x39 · Evidencia v0.1 (etapa A).
 * Identidad ML-DSA-87 creada a mano en el primer arranque → foto de la cámara propia o cualquier archivo →
 * almacén cifrado → huella SHA-256 → firma → cola de anclaje OpenTimestamps. Lo guardado no sale del móvil;
 * por la red solo viajan compromisos de 32 bytes.
 * Textos según la sección 9 de la especificación: nada de «auténtica», «sin rastro» ni «subir».
 */
public class EvidenciaActivity extends Activity {
    static final String VERSION = "0.2.1";
    private static final int REQ_CAMARA = 1;
    private static final int REQ_EXPORTAR = 2;
    private static final int REQ_ARCHIVO = 3;
    private static final int REQ_MICROFONO = 4;
    private static final int REQ_MICROFONO_AUDIO = 5;
    /** Un vídeo de evidencia como máximo dura esto; a 8 Mbit/s son unos 600 MB. */
    private static final long MAX_VIDEO_MS = 10 * 60_000L;
    /** Una grabación de audio como máximo: a 128 kbit/s son unos 55 MB. */
    private static final long MAX_AUDIO_MS = 60 * 60_000L;
    private android.media.MediaRecorder grabadoraAudio;
    private File audioTmp;
    private long inicioAudio;
    /** Ya se pidió el micrófono una vez y se negó: se graba sin sonido en vez de insistir. */
    private boolean microfonoNegado;
    /** Hasta este tamaño una imagen se descifra en memoria para verla; por encima se muestra un icono. */
    private static final long MAX_VISTA = 25L << 20;
    private static final Locale ES = new Locale("es", "ES");
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("d MMM yyyy · HH:mm", ES);
    private static final String AVISO_IDENTIDAD = "Esta clave vive solo en este móvil. Si se pierde o se borra, se pierde la identidad: "
            + "los recibos ya emitidos siguen valiendo si exportaste la clave pública, pero las evidencias nuevas irán con otra identidad. "
            + "No hay copia en la nube, a propósito.";

    private enum Pestana { EVIDENCIAS, SEGURIDAD, AJUSTES }

    private FrameLayout raiz;
    private Pestana pestana = Pestana.EVIDENCIAS;
    private Runnable secundaria;
    private Evidencias evidencias;
    private Camara camara;
    private String exportandoId;

    // ------------------------------------------------------------------ ciclo de vida

    @Override
    protected void onCreate(Bundle estado) {
        super.onCreate(estado);
        // Sin capturas, sin grabación de pantalla y sin miniatura en «recientes».
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        raiz = new FrameLayout(this);
        raiz.setBackgroundColor(Ui.FONDO);
        raiz.setOnApplyWindowInsetsListener((v, ins) -> {
            aplicarInsets(v, ins);
            return ins;
        });
        setContentView(raiz);
        evidencias = new Evidencias(this);
        ColaAnclaje.programar(this);
    }

    @Override
    protected void onStart() {
        super.onStart();
        limpiarCompartidos();
        if (camara == null) render();
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (camara != null) {
            cerrarCamara();
            render();
        }
        // Grabando audio y la app se va al fondo (llamada, bloqueo): el tramo en curso se sella, no se pierde.
        if (grabadoraAudio != null) {
            descartarAudio();
            render();
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (camara != null) {
            cerrarCamara();
            mostrarPestana(Pestana.EVIDENCIAS);
        } else if (secundaria != null) {
            mostrarPestana(pestana);
        } else {
            super.onBackPressed();
        }
    }

    private static void aplicarInsets(View v, WindowInsets ins) {
        if (Build.VERSION.SDK_INT >= 30) {
            Insets s = ins.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
            v.setPadding(s.left, s.top, s.right, s.bottom);
        } else {
            @SuppressWarnings("deprecation")
            int izq = ins.getSystemWindowInsetLeft(), arr = ins.getSystemWindowInsetTop(),
                    der = ins.getSystemWindowInsetRight(), abj = ins.getSystemWindowInsetBottom();
            v.setPadding(izq, arr, der, abj);
        }
    }

    private int dp(float v) {
        return Ui.dp(this, v);
    }

    // ------------------------------------------------------------------ navegación

    private void render() {
        if (!evidencias.tieneIdentidad()) {
            // Pantalla 0: nada de cámara ni archivos hasta que exista la identidad.
            secundaria = null;
            mostrar(pantallaIdentidad(true), false);
        } else if (secundaria != null) {
            secundaria.run();
        } else {
            mostrarPestana(pestana);
        }
    }

    private void mostrar(View contenido, boolean conNavegacion) {
        raiz.removeAllViews();
        LinearLayout col = Ui.columna(this);
        col.addView(contenido, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        if (conNavegacion) {
            col.addView(barraNavegacion(), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, dp(64), 16, 6, 16, 12));
        }
        raiz.addView(col, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        raiz.requestApplyInsets();
    }

    private void mostrarPestana(Pestana p) {
        pestana = p;
        secundaria = null;
        View v;
        switch (p) {
            case SEGURIDAD: v = pantallaSeguridad(); break;
            case AJUSTES: v = pantallaAjustes(); break;
            default: v = pantallaEvidencias(); break;
        }
        mostrar(v, true);
    }

    private void abrirSecundaria(Runnable pantalla) {
        secundaria = pantalla;
        pantalla.run();
    }

    /** Cabecera de todas las pantallas: título a la izquierda; candado rojo y «x39» arriba a la derecha. */
    private View barraSuperior(String titulo, Runnable volver, int colorFondo) {
        LinearLayout f = Ui.fila(this);
        f.setPadding(dp(volver != null ? 4 : 20), dp(10), dp(18), dp(6));
        if (colorFondo != 0) f.setBackgroundColor(colorFondo);
        if (volver != null) f.addView(Ui.botonIcono(this, Icono.Tipo.ATRAS, Ui.TEXTO, "Volver", v -> volver.run()));
        f.addView(Ui.texto(this, titulo, volver != null ? 18 : 24, Ui.TEXTO, true), Ui.peso(1));
        ImageView candado = Ui.icono(this, Icono.Tipo.CANDADO, Ui.ROJO, 20);
        ((LinearLayout.LayoutParams) candado.getLayoutParams()).setMargins(0, 0, dp(6), 0);
        f.addView(candado);
        f.addView(Ui.marca(this));
        return f;
    }

    private View barraNavegacion() {
        LinearLayout barra = Ui.fila(this);
        barra.setBackground(Ui.redondeado(this, Ui.SUPERFICIE_2, 32));
        barra.setElevation(dp(8));
        barra.setPadding(dp(6), 0, dp(6), 0);
        barra.addView(itemNavegacion(Icono.Tipo.ACTAS, "Evidencias", pestana == Pestana.EVIDENCIAS && secundaria == null, () -> mostrarPestana(Pestana.EVIDENCIAS)), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.CAMARA, "Hacer una foto", false, this::abrirCamara), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.AUDIO, "Grabar audio", false, this::abrirGrabadora), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.ARCHIVO, "Elegir un archivo", false, this::elegirArchivo), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.ESCUDO, "Seguridad", pestana == Pestana.SEGURIDAD && secundaria == null, () -> mostrarPestana(Pestana.SEGURIDAD)), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.AJUSTES, "Ajustes", pestana == Pestana.AJUSTES && secundaria == null, () -> mostrarPestana(Pestana.AJUSTES)), Ui.peso(1));
        return barra;
    }

    private View itemNavegacion(Icono.Tipo tipo, String etiqueta, boolean activa, Runnable accion) {
        FrameLayout item = new FrameLayout(this);
        item.setMinimumHeight(dp(58));
        FrameLayout cuadro = new FrameLayout(this);
        if (activa) cuadro.setBackground(Ui.redondeado(this, Ui.FONDO, 15));
        cuadro.addView(Ui.icono(this, tipo, activa ? Ui.BLANCO : Ui.SUAVE, 22), new FrameLayout.LayoutParams(dp(22), dp(22), Gravity.CENTER));
        item.addView(cuadro, new FrameLayout.LayoutParams(dp(46), dp(46), Gravity.CENTER));
        item.setContentDescription(etiqueta);
        item.setOnClickListener(v -> accion.run());
        Ui.clicable(item);
        return item;
    }

    // ------------------------------------------------------------------ identidad (pantalla 0)

    /**
     * @param inicial sin flecha de volver: primer arranque (con «Continuar» una vez creada la clave).
     */
    private View pantallaIdentidad(boolean inicial) {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Tu identidad", inicial ? null : () -> mostrarPestana(pestana), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));

        if (!evidencias.tieneIdentidad()) {
            LinearLayout intro = Ui.columna(this);
            intro.setGravity(Gravity.CENTER_HORIZONTAL);
            intro.setPadding(dp(20), dp(28), dp(20), dp(22));
            intro.setBackground(Ui.degradado(this, 28));
            intro.addView(aro(Icono.Tipo.LLAVE), new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView t = Ui.texto(this, "Sin cuenta y sin registro", 20, Ui.TEXTO, true);
            t.setGravity(Gravity.CENTER);
            t.setPadding(0, dp(14), 0, dp(6));
            intro.addView(t);
            TextView d = Ui.texto(this, "Tu identidad es una clave de firma ML-DSA-87 que se crea ahora, en este móvil, y firma cada evidencia. No hay servidor ni alta: la clave es la identidad y nada más.", 14, Ui.TEXTO_2, false);
            d.setGravity(Gravity.CENTER);
            d.setPadding(0, 0, 0, dp(18));
            intro.addView(d);
            TextView crear = Ui.boton(this, "Crear identidad", true, null);
            crear.setOnClickListener(v -> crearIdentidad(crear));
            intro.addView(crear, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            col.addView(intro, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        } else {
            try {
                byte[] pk = evidencias.clavePublica();
                String fp = Evidencias.sha256Hex(pk);

                LinearLayout h = tarjeta(col, "Huella de tu clave");
                TextView hv = Ui.mono(this, bloquesHuella(fp), 17, Ui.TEXTO);
                hv.setLineSpacing(dp(4), 1f);
                h.addView(hv);
                TextView hn = Ui.texto(this, "SHA-256 de la clave pública. Quien reciba un recibo compara la huella que trae con esta.", 13, Ui.SUAVE, false);
                hn.setPadding(0, dp(8), 0, 0);
                h.addView(hn);
                h.addView(Ui.boton(this, "Copiar huella", false, v -> copiarHuella(fp)),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout k = tarjeta(col, "Clave pública");
                ImageView qr = new ImageView(this);
                qr.setAdjustViewBounds(true);
                qr.setScaleType(ImageView.ScaleType.FIT_CENTER);
                qr.setBackground(Ui.redondeado(this, 0xFFFFFFFF, 14));
                qr.setPadding(dp(8), dp(8), dp(8), dp(8));
                qr.setContentDescription("Código QR con la clave pública");
                k.addView(qr, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                dibujarQr(qr, pk);
                TextView ki = Ui.texto(this, "ML-DSA-87 · " + miles(pk.length) + " bytes. El QR lleva la clave entera (versión 40, 177 × 177 módulos): acerca bien la cámara al escanearlo.", 13, Ui.TEXTO_2, false);
                ki.setPadding(0, dp(10), 0, 0);
                k.addView(ki);
                k.addView(Ui.boton(this, "Exportar clave pública (.bin)", false, v -> compartirClave()),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout z = tarjeta(col, "Comprobar tamaños");
                TextView res = Ui.texto(this, "ML-DSA-87 son " + miles(Evidencias.PK_ESPERADA) + " bytes de clave pública y " + miles(Evidencias.FIRMA_ESPERADA)
                        + " de firma. Se miden aquí, en este móvil, con una firma de prueba.", 13, Ui.TEXTO_2, false);
                z.addView(res);
                z.addView(Ui.boton(this, "Comprobar en este móvil", false, v -> comprobarTamanos(res)),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout donde = tarjeta(col, "Dónde vive");
                donde.addView(Ui.texto(this, "La semilla de la clave está cifrada con una clave del Keystore de Android ("
                        + evidencias.nivelHardware() + "). Android aún no firma con ML-DSA dentro del Keystore, así que la firma "
                        + "se calcula en la app con la semilla descifrada solo en memoria y borrada al terminar.", 13, Ui.TEXTO_2, false));
            } catch (Exception e) {
                tarjeta(col, null).addView(Ui.texto(this, "No se pudo leer la clave: " + Ui.mensaje(e), 14, Ui.AVISO, false));
            }
        }

        LinearLayout aviso = Ui.fila(this);
        aviso.setGravity(Gravity.TOP);
        aviso.setPadding(dp(18), dp(16), dp(18), dp(16));
        aviso.setBackground(Ui.redondeado(this, Ui.CAJA, 24));
        aviso.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.AVISO, 20));
        TextView at = Ui.texto(this, AVISO_IDENTIDAD, 14, Ui.AVISO, false);
        at.setPadding(dp(12), 0, 0, 0);
        aviso.addView(at, Ui.peso(1));
        col.addView(aviso, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));

        if (inicial && evidencias.tieneIdentidad()) {
            col.addView(Ui.boton(this, "Continuar", true, v -> mostrarPestana(Pestana.EVIDENCIAS)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 18, 0, 0));
        }
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void crearIdentidad(TextView boton) {
        boton.setEnabled(false);
        boton.setText("Creando la clave…");
        new Thread(() -> {
            String fallo = null;
            try {
                evidencias.crearIdentidad();
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (error != null) {
                    boton.setEnabled(true);
                    boton.setText("Crear identidad");
                    aviso("No se pudo crear la identidad: " + error);
                    return;
                }
                abrirSecundaria(() -> mostrar(pantallaIdentidad(true), false));
            });
        }, "x39-identidad").start();
    }

    /** 64 hex en cuatro líneas de 16, en grupos de 4. */
    private static String bloquesHuella(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 4) {
            if (i > 0) sb.append(i % 16 == 0 ? '\n' : ' ');
            sb.append(hex, i, Math.min(i + 4, hex.length()));
        }
        return sb.toString();
    }

    private void copiarHuella(String fp) {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        if (cm == null) return;
        cm.setPrimaryClip(ClipData.newPlainText("Huella de la clave x39", fp));
        Toast.makeText(this, "Huella copiada", Toast.LENGTH_SHORT).show();
    }

    private void dibujarQr(ImageView destino, byte[] datos) {
        new Thread(() -> {
            try {
                byte[] m = X39Core.qrMatrix(datos);
                int ancho = ((m[0] & 0xff) << 8) | (m[1] & 0xff);
                int margen = 4;
                int lado = ancho + 2 * margen;
                int[] px = new int[lado * lado];
                Arrays.fill(px, 0xFFFFFFFF);
                for (int y = 0; y < ancho; y++) {
                    for (int x = 0; x < ancho; x++) {
                        if (m[2 + y * ancho + x] != 0) px[(y + margen) * lado + x + margen] = 0xFF000000;
                    }
                }
                Bitmap base = Bitmap.createBitmap(px, lado, lado, Bitmap.Config.ARGB_8888);
                int escala = Math.max(1, 1080 / lado);
                // Sin suavizado: cada módulo queda como un cuadrado nítido.
                Bitmap grande = Bitmap.createScaledBitmap(base, lado * escala, lado * escala, false);
                runOnUiThread(() -> {
                    if (!isDestroyed()) destino.setImageBitmap(grande);
                });
            } catch (Exception e) {
                runOnUiThread(() -> destino.setVisibility(View.GONE));
            }
        }, "x39-qr").start();
    }

    private void comprobarTamanos(TextView resultado) {
        resultado.setText("Firmando y midiendo…");
        new Thread(() -> {
            String texto;
            try {
                int[] t = evidencias.comprobarTamanos();
                boolean clave = t[0] == Evidencias.PK_ESPERADA;
                boolean firma = t[1] == Evidencias.FIRMA_ESPERADA;
                texto = "Clave pública: " + miles(t[0]) + " bytes " + (clave ? "✓" : "✗ (esperados " + miles(Evidencias.PK_ESPERADA) + ")")
                        + "\nFirma de prueba: " + miles(t[1]) + " bytes " + (firma ? "✓" : "✗ (esperados " + miles(Evidencias.FIRMA_ESPERADA) + ")")
                        + "\nLa firma de prueba verifica con la clave ✓"
                        + (clave && firma ? "\n\nMedido en este móvil: es ML-DSA-87." : "\n\nEstos tamaños no son de ML-DSA-87.");
            } catch (Exception e) {
                texto = "✗ La firma de prueba no se pudo hacer o no verifica: " + Ui.mensaje(e);
            }
            final String fin = texto;
            runOnUiThread(() -> resultado.setText(fin));
        }, "x39-tamanos").start();
    }

    private static String miles(long n) {
        return String.format(ES, "%,d", n);
    }

    // ------------------------------------------------------------------ evidencias

    private View pantallaEvidencias() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Evidencias", null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        col.addView(Ui.texto(this, "Lo que guardas no sale de este móvil. Solo viaja su huella.", 13, Ui.SUAVE, false));

        List<Evidencias.Ficha> fichas;
        try {
            fichas = evidencias.todas();
        } catch (Exception e) {
            fichas = new ArrayList<>();
            col.addView(Ui.texto(this, "No se pudo leer el almacén: " + Ui.mensaje(e), 14, Ui.AVISO, false));
        }
        if (fichas.isEmpty()) {
            LinearLayout vacio = Ui.columna(this);
            vacio.setGravity(Gravity.CENTER_HORIZONTAL);
            vacio.setPadding(dp(20), dp(28), dp(20), dp(22));
            vacio.setBackground(Ui.degradado(this, 28));
            vacio.addView(aro(Icono.Tipo.CAMARA), new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView t = Ui.texto(this, "Aún no hay evidencias", 20, Ui.TEXTO, true);
            t.setPadding(0, dp(14), 0, dp(6));
            vacio.addView(t);
            TextView d = Ui.texto(this, "Haz una foto desde aquí o elige cualquier archivo del móvil (PDF, vídeo, audio, lo que sea). Se guarda cifrado en este móvil, se firma con tu clave y su huella se ancla en Bitcoin sin que hagas nada más.", 14, Ui.TEXTO_2, false);
            d.setGravity(Gravity.CENTER);
            d.setPadding(0, 0, 0, dp(18));
            vacio.addView(d);
            vacio.addView(Ui.boton(this, "Hacer una foto", true, v -> abrirCamara()), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            vacio.addView(Ui.boton(this, "Elegir un archivo", false, v -> elegirArchivo()),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 0));
            col.addView(vacio, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        }
        for (Evidencias.Ficha f : fichas) col.addView(filaFicha(f));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private FrameLayout aro(Icono.Tipo tipo) {
        FrameLayout aro = new FrameLayout(this);
        GradientDrawable circulo = new GradientDrawable();
        circulo.setShape(GradientDrawable.OVAL);
        circulo.setColor(Ui.CAJA);
        circulo.setStroke(dp(2), Ui.BLANCO);
        aro.setBackground(circulo);
        aro.addView(Ui.icono(this, tipo, Ui.BLANCO, 34), new FrameLayout.LayoutParams(dp(34), dp(34), Gravity.CENTER));
        return aro;
    }

    private static Icono.Tipo iconoDe(Evidencias.Ficha f) {
        if (f.esFoto()) return Icono.Tipo.CAMARA;
        if (f.mime.startsWith("video/")) return Icono.Tipo.VIDEO;
        if (f.mime.startsWith("audio/")) return Icono.Tipo.AUDIO;
        return Icono.Tipo.ARCHIVO;
    }

    private String tamano(Evidencias.Ficha f) {
        return f.bytes >= 0 ? Formatter.formatShortFileSize(this, f.bytes) : "";
    }

    private View filaFicha(Evidencias.Ficha f) {
        LinearLayout card = Ui.fila(this);
        card.setPadding(dp(12), dp(12), dp(12), dp(12));
        card.setBackground(Ui.degradado(this, 22));
        FrameLayout mini = new FrameLayout(this);
        mini.setBackground(Ui.redondeado(this, Ui.CAJA, 14));
        mini.setClipToOutline(true);
        if (f.esImagen() && f.bytes <= MAX_VISTA) {
            ImageView img = new ImageView(this);
            img.setScaleType(ImageView.ScaleType.CENTER_CROP);
            mini.addView(img, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
            cargarImagen(f, img, 160);
        } else {
            mini.addView(Ui.icono(this, iconoDe(f), Ui.BLANCO, 28), new FrameLayout.LayoutParams(dp(28), dp(28), Gravity.CENTER));
        }
        card.addView(mini, new LinearLayout.LayoutParams(dp(64), dp(64)));

        LinearLayout t = Ui.columna(this);
        t.setPadding(dp(14), 0, dp(6), 0);
        TextView titulo = Ui.texto(this, f.esFoto() ? "Foto" : (f.nombre.isEmpty() ? "Archivo" : f.nombre), 15, Ui.TEXTO, true);
        titulo.setSingleLine(true);
        titulo.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        t.addView(titulo);
        t.addView(Ui.texto(this, fechaCorta(f.capturada) + (f.esFoto() ? "" : " · " + tamano(f)), 13, Ui.SUAVE, false));
        t.addView(Ui.mono(this, "huella " + f.sha256.substring(0, 12) + "…", 12, Ui.SUAVE));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(6), 0, 0);
        t.addView(pildora(f), lp);
        card.addView(t, Ui.peso(1));
        card.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.TENUE, 18));
        card.setContentDescription((f.esFoto() ? "Foto" : "Archivo") + " del " + fechaCorta(f.capturada));
        card.setOnClickListener(v -> abrirFicha(f.id));
        Ui.clicable(card);
        LinearLayout envoltura = Ui.columna(this);
        envoltura.addView(card, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        return envoltura;
    }

    /** Tres estados en escala de grafito (el rojo es solo de marca): ○ firmada, ◐ en calendarios, ● anclada. */
    private TextView pildora(Evidencias.Ficha f) {
        String texto;
        int fondo;
        int color;
        switch (f.otsEstado) {
            case "bitcoin":
                texto = "●  Anclada · bloque " + f.bloque;
                fondo = Ui.BLANCO;
                color = Ui.FONDO;
                break;
            case "calendar":
                texto = "◐  Enviada a los calendarios";
                fondo = Ui.SUPERFICIE_2;
                color = Ui.TEXTO;
                break;
            default:
                texto = "○  Firmada · en espera de ancla";
                fondo = Ui.CAJA;
                color = Ui.TEXTO_2;
                break;
        }
        TextView p = Ui.texto(this, texto, 12, color, true);
        p.setPadding(dp(10), dp(4), dp(10), dp(4));
        p.setBackground(Ui.redondeado(this, fondo, 12));
        return p;
    }

    private static String fechaCorta(String iso) {
        try {
            return FECHA.format(OffsetDateTime.parse(iso));
        } catch (Exception e) {
            return iso;
        }
    }

    /** Descifra y decodifica la imagen en memoria, reducida; nunca se guarda en claro. */
    private void cargarImagen(Evidencias.Ficha f, ImageView destino, int ladoMaximo) {
        new Thread(() -> {
            byte[] datos = null;
            try {
                datos = evidencias.leerEntero(f, MAX_VISTA);
                BitmapFactory.Options o = new BitmapFactory.Options();
                o.inJustDecodeBounds = true;
                BitmapFactory.decodeByteArray(datos, 0, datos.length, o);
                int muestra = 1;
                while (Math.max(o.outWidth, o.outHeight) / (muestra * 2) >= ladoMaximo) muestra *= 2;
                o.inJustDecodeBounds = false;
                o.inSampleSize = muestra;
                Bitmap bmp = BitmapFactory.decodeByteArray(datos, 0, datos.length, o);
                runOnUiThread(() -> {
                    if (!isDestroyed() && bmp != null) destino.setImageBitmap(bmp);
                });
            } catch (Exception ignorado) {
                // Sin miniatura: la ficha sigue siendo válida.
            } finally {
                if (datos != null) Arrays.fill(datos, (byte) 0);
            }
        }, "x39-imagen").start();
    }

    // ------------------------------------------------------------------ archivo

    private void elegirArchivo() {
        if (!evidencias.tieneIdentidad()) {
            render();
            return;
        }
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
        startActivityForResult(i, REQ_ARCHIVO);
    }

    private void sellarArchivo(Uri uri) {
        String nombre = null;
        long tam = -1;
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (i >= 0 && !c.isNull(i)) nombre = c.getString(i);
                int j = c.getColumnIndex(OpenableColumns.SIZE);
                if (j >= 0 && !c.isNull(j)) tam = c.getLong(j);
            }
        } catch (Exception ignorado) {
            // Sin nombre ni tamaño: se sella igual.
        }
        String tipoMime = getContentResolver().getType(uri);
        final String mime = tipoMime != null ? tipoMime : "application/octet-stream";
        final String nombreFinal = nombre != null ? nombre : "archivo";
        final long total = tam;
        if (total > 0 && total + (64L << 20) > evidencias.espacioLibre()) {
            aviso("No hay espacio en el móvil para guardar una copia cifrada de este archivo (" + Formatter.formatShortFileSize(this, total) + ").");
            return;
        }

        TextView estado = Ui.texto(this, "Calculando la huella y cifrando…", 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(nombreFinal).setView(estado).setCancelable(false).show();
        final long inicio = System.currentTimeMillis();
        new Thread(() -> {
            Evidencias.Sellado sellado = null;
            String fallo = null;
            long[] ultimoAviso = {0};
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IllegalStateException("el sistema no dio acceso al archivo");
                sellado = evidencias.sellar(in, Evidencias.ARCHIVO, nombreFinal, mime, hechos -> {
                    long ahora = System.currentTimeMillis();
                    if (ahora - ultimoAviso[0] < 250) return;
                    ultimoAviso[0] = ahora;
                    String t = Formatter.formatShortFileSize(this, hechos)
                            + (total > 0 ? " de " + Formatter.formatShortFileSize(this, total) + " (" + (hechos * 100 / total) + " %)" : "");
                    runOnUiThread(() -> estado.setText("Calculando la huella y cifrando…\n" + t));
                });
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            }
            final Evidencias.Sellado resultado = sellado;
            final String error = fallo;
            final long ms = System.currentTimeMillis() - inicio;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso("No se pudo sellar el archivo: " + error);
                } else if (resultado.yaExistia) {
                    aviso("Este archivo ya estaba sellado: tiene la misma huella que una evidencia de la lista.");
                } else {
                    Toast.makeText(this, "Guardado y firmado en " + duracion(ms), Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-archivo").start();
    }

    private static String duracion(long ms) {
        return ms < 1000 ? ms + " ms" : String.format(ES, "%.1f s", ms / 1000.0);
    }

    // ------------------------------------------------------------------ cámara

    private void abrirCamara() {
        if (!evidencias.tieneIdentidad()) {
            render();
            return;
        }
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMARA);
            return;
        }
        secundaria = null;
        FrameLayout marco = new FrameLayout(this);
        marco.setBackgroundColor(0xFF000000);
        TextureView tv = new TextureView(this);
        marco.addView(tv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER));
        marco.addView(new MarcoEnfoque(this), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        View cabecera = barraSuperior("Cámara", () -> {
            cerrarCamara();
            mostrarPestana(Pestana.EVIDENCIAS);
        }, 0x66000000);
        marco.addView(cabecera, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP));

        LinearLayout abajo = Ui.columna(this);
        abajo.setGravity(Gravity.CENTER_HORIZONTAL);
        abajo.setPadding(0, dp(12), 0, dp(24));
        abajo.setBackgroundColor(0x66000000);
        TextView ayuda = Ui.texto(this, "Se guarda cifrada y se firma al instante", 13, Ui.TEXTO_2, false);
        ayuda.setPadding(0, 0, 0, dp(14));
        abajo.addView(ayuda);
        TextView cronometro = Ui.mono(this, "", 22, Ui.BLANCO);
        cronometro.setPadding(0, 0, 0, dp(10));
        cronometro.setVisibility(View.GONE);
        abajo.addView(cronometro);
        LinearLayout mandos = Ui.fila(this);
        mandos.setGravity(Gravity.CENTER_VERTICAL);
        TextView botonVideo = Ui.boton(this, "Vídeo", false, null);
        FrameLayout disparador = new FrameLayout(this);
        GradientDrawable anillo = new GradientDrawable();
        anillo.setShape(GradientDrawable.OVAL);
        anillo.setColor(0x00000000);
        anillo.setStroke(dp(4), Ui.BLANCO);
        disparador.setBackground(anillo);
        View centro = new View(this);
        GradientDrawable punto = new GradientDrawable();
        punto.setShape(GradientDrawable.OVAL);
        punto.setColor(Ui.BLANCO);
        centro.setBackground(punto);
        disparador.addView(centro, new FrameLayout.LayoutParams(dp(60), dp(60), Gravity.CENTER));
        disparador.setContentDescription("Hacer la foto");
        disparador.setOnClickListener(v -> {
            if (camara == null || camara.grabando()) return;
            v.setEnabled(false);
            v.setAlpha(0.5f);
            camara.disparar();
        });
        // Vídeo: el mismo botón empieza y para. El cronómetro corre mientras graba y corta a los 10 minutos.
        final android.os.Handler reloj = new android.os.Handler(android.os.Looper.getMainLooper());
        final Runnable tic = new Runnable() {
            @Override
            public void run() {
                if (camara == null || !camara.grabando()) return;
                long ms = camara.duracionGrabacionMs();
                cronometro.setText(String.format(ES, "%02d:%02d", ms / 60_000, (ms / 1000) % 60));
                if (ms >= MAX_VIDEO_MS) {
                    camara.parar();
                    return;
                }
                reloj.postDelayed(this, 500);
            }
        };
        botonVideo.setOnClickListener(v -> {
            if (camara == null) return;
            if (camara.grabando()) {
                botonVideo.setEnabled(false);
                camara.parar();
                return;
            }
            boolean mic = checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED;
            if (!mic && !microfonoNegado) {
                requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, REQ_MICROFONO);
                return;
            }
            File tmp = new File(getCacheDir(), "v-" + System.currentTimeMillis() + ".mp4");
            botonVideo.setEnabled(false);
            camara.grabar(tmp, mic);
        });
        mandos.addView(botonVideo, new LinearLayout.LayoutParams(dp(110), dp(50)));
        mandos.addView(disparador, Ui.margen(this, dp(78), dp(78), 24, 0, 0, 0));
        View relleno = new View(this);
        mandos.addView(relleno, new LinearLayout.LayoutParams(dp(110), 1));
        abajo.addView(mandos);
        marco.addView(abajo, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));

        mostrar(marco, false);
        camara = new Camara(this, tv, new Camara.Resultado() {
            @Override
            public void foto(byte[] jpeg) {
                procesarFoto(jpeg);
            }

            @Override
            public void grabando() {
                botonVideo.setEnabled(true);
                botonVideo.setText("Parar");
                disparador.setVisibility(View.INVISIBLE);
                ayuda.setText("Grabando · se cifra y se firma al parar");
                cronometro.setText("00:00");
                cronometro.setVisibility(View.VISIBLE);
                reloj.post(tic);
            }

            @Override
            public void video(File archivo, long duracionMs) {
                reloj.removeCallbacks(tic);
                cerrarCamara();
                procesarGrabacion(archivo, duracionMs, Evidencias.VIDEO, "video", "mp4", "video/mp4", "Vídeo");
            }

            @Override
            public void error(String motivo) {
                reloj.removeCallbacks(tic);
                if (camara != null && !motivo.startsWith("la grabación es demasiado corta")) {
                    cerrarCamara();
                    mostrarPestana(Pestana.EVIDENCIAS);
                    aviso("No se pudo usar la cámara: " + motivo);
                    return;
                }
                // Grabación demasiado corta: la cámara sigue abierta en modo foto.
                botonVideo.setEnabled(true);
                botonVideo.setText("Vídeo");
                disparador.setVisibility(View.VISIBLE);
                cronometro.setVisibility(View.GONE);
                ayuda.setText("Se guarda cifrada y se firma al instante");
                Toast.makeText(EvidenciaActivity.this, "Vídeo demasiado corto: mantén la grabación al menos un segundo", Toast.LENGTH_SHORT).show();
            }
        });
        camara.abrir();
    }

    // ------------------------------------------------------------------ audio

    /** Cada tramo de audio se cierra y se sella por su cuenta: lo grabado hasta el minuto 40 existe aunque el 41 no llegue. */
    private static final long TRAMO_AUDIO_MS = 5 * 60_000L;
    /** Espacio mínimo antes de empezar a grabar (una hora a 64 kbit/s son ~29 MB; se pide margen). */
    private static final long ESPACIO_MIN_AUDIO = 100L << 20;
    private long inicioTramo;
    private int numTramo;
    private String sesionAudio;
    private android.media.AudioFocusRequest focoAudio;

    /**
     * Grabadora de audio: micrófono → AAC (64 kbit/s) en tramos de 5 minutos; cada tramo se cifra, se firma y
     * se ancla al cerrarse. Una llamada entrante (pérdida del foco de audio) o salir de la pantalla cierran y
     * sellan el tramo en curso: nada grabado se pierde.
     */
    private void abrirGrabadora() {
        if (!evidencias.tieneIdentidad()) {
            render();
            return;
        }
        secundaria = null;
        LinearLayout raizCol = Ui.columna(this);
        final android.os.Handler reloj = new android.os.Handler(android.os.Looper.getMainLooper());
        final Runnable[] ticRef = new Runnable[1];
        raizCol.addView(barraSuperior("Audio", () -> {
            if (grabadoraAudio != null) pararAudio(reloj, ticRef[0]);
            else mostrarPestana(Pestana.EVIDENCIAS);
        }, 0));
        LinearLayout col = Ui.columna(this);
        col.setGravity(Gravity.CENTER_HORIZONTAL);
        col.setPadding(dp(24), dp(40), dp(24), dp(24));
        col.addView(aro(Icono.Tipo.AUDIO), new LinearLayout.LayoutParams(dp(84), dp(84)));
        TextView ayuda = Ui.texto(this, "Se graba en tramos de 5 minutos; cada tramo se cifra, se firma y se ancla al cerrarse. El micrófono se pide al pulsar «Grabar».", 14, Ui.TEXTO_2, false);
        ayuda.setGravity(Gravity.CENTER);
        ayuda.setPadding(0, dp(18), 0, dp(24));
        col.addView(ayuda);
        TextView cronometro = Ui.mono(this, "00:00", 40, Ui.TEXTO);
        cronometro.setGravity(Gravity.CENTER);
        col.addView(cronometro);
        TextView tramoTxt = Ui.texto(this, "", 13, Ui.SUAVE, false);
        tramoTxt.setGravity(Gravity.CENTER);
        col.addView(tramoTxt);
        TextView boton = Ui.boton(this, "Grabar", true, null);
        ticRef[0] = new Runnable() {
            @Override
            public void run() {
                if (grabadoraAudio == null) return;
                long ahora = System.currentTimeMillis();
                long ms = ahora - inicioAudio;
                cronometro.setText(String.format(ES, "%02d:%02d", ms / 60_000, (ms / 1000) % 60));
                tramoTxt.setText("Tramo " + numTramo + " · " + (numTramo - 1) + (numTramo == 2 ? " sellado" : " sellados"));
                if (ms >= MAX_AUDIO_MS) {
                    pararAudio(reloj, this);
                    return;
                }
                if (ahora - inicioTramo >= TRAMO_AUDIO_MS) {
                    // Cierra el tramo (se sella en segundo plano) y abre el siguiente sin parar la escucha más de un instante.
                    File cerrado = cerrarTramo();
                    if (cerrado != null) sellarTramo(cerrado, numTramo, ahora - inicioTramo);
                    try {
                        iniciarTramo();
                    } catch (Exception e) {
                        grabadoraAudio = null;
                        soltarFoco();
                        aviso("La grabación se cortó al abrir el tramo siguiente: " + Ui.mensaje(e) + ". Lo anterior está sellado.");
                        abrirGrabadora();
                        return;
                    }
                }
                reloj.postDelayed(this, 500);
            }
        };
        boton.setOnClickListener(v -> {
            if (grabadoraAudio != null) {
                boton.setEnabled(false);
                pararAudio(reloj, ticRef[0]);
                return;
            }
            if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, REQ_MICROFONO_AUDIO);
                return;
            }
            long libre = evidencias.espacioLibre();
            if (libre < ESPACIO_MIN_AUDIO) {
                aviso("Quedan " + Formatter.formatShortFileSize(this, libre) + " libres. Hacen falta al menos 100 MB para grabar con margen.");
                return;
            }
            try {
                pedirFoco(reloj, ticRef[0]);
                sesionAudio = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss", ES).format(new java.util.Date());
                numTramo = 0;
                inicioAudio = System.currentTimeMillis();
                iniciarTramo();
                boton.setText("Parar");
                ayuda.setText("Grabando · cada 5 minutos se sella un tramo · al parar se sella el último");
                reloj.post(ticRef[0]);
            } catch (Exception e) {
                grabadoraAudio = null;
                soltarFoco();
                aviso("No se pudo grabar: " + Ui.mensaje(e));
            }
        });
        col.addView(boton, Ui.margen(this, dp(180), dp(56), 0, 28, 0, 0));
        raizCol.addView(col, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        mostrar(raizCol, false);
    }

    private void iniciarTramo() throws Exception {
        @SuppressWarnings("deprecation")
        android.media.MediaRecorder r = new android.media.MediaRecorder();
        r.setAudioSource(android.media.MediaRecorder.AudioSource.MIC);
        r.setOutputFormat(android.media.MediaRecorder.OutputFormat.MPEG_4);
        numTramo++;
        audioTmp = new File(getCacheDir(), "a-" + sesionAudio + "-t" + numTramo + ".m4a");
        r.setOutputFile(audioTmp.getAbsolutePath());
        r.setAudioEncoder(android.media.MediaRecorder.AudioEncoder.AAC);
        r.setAudioEncodingBitRate(64_000);
        r.setAudioSamplingRate(44_100);
        r.prepare();
        r.start();
        grabadoraAudio = r;
        inicioTramo = System.currentTimeMillis();
    }

    /** Para y libera la grabadora del tramo en curso. Devuelve el archivo si tiene contenido válido. */
    private File cerrarTramo() {
        android.media.MediaRecorder r = grabadoraAudio;
        File f = audioTmp;
        grabadoraAudio = null;
        audioTmp = null;
        if (r == null) return null;
        boolean valido;
        try {
            r.stop();
            valido = true;
        } catch (RuntimeException e) {
            valido = false;
        }
        r.release();
        if (!valido && f != null) {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
            return null;
        }
        return f;
    }

    private String nombreTramo(int tramo, String extension) {
        return "audio-" + sesionAudio + "-t" + String.format(ES, "%02d", tramo) + "." + extension;
    }

    /** Sella un tramo intermedio sin diálogo (la grabación sigue). */
    private void sellarTramo(File f, int tramo, long duracionMs) {
        final String nombre = nombreTramo(tramo, "m4a");
        new Thread(() -> {
            String fallo = null;
            try (InputStream in = new java.io.FileInputStream(f)) {
                evidencias.sellar(in, Evidencias.AUDIO, nombre, "audio/mp4", null);
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (error != null) aviso("No se pudo sellar el tramo " + tramo + ": " + error);
                else {
                    Toast.makeText(this, "Tramo " + tramo + " (" + duracion(duracionMs) + ") sellado", Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-tramo").start();
    }

    private void pararAudio(android.os.Handler reloj, Runnable tic) {
        if (tic != null) reloj.removeCallbacks(tic);
        soltarFoco();
        long duracion = System.currentTimeMillis() - inicioTramo;
        int tramo = numTramo;
        File f = cerrarTramo();
        if (f == null) {
            if (tramo <= 1) {
                aviso("La grabación es demasiado corta.");
                abrirGrabadora();
            } else {
                mostrarPestana(Pestana.EVIDENCIAS);
            }
            return;
        }
        procesarGrabacion(f, duracion, Evidencias.AUDIO, "audio", "m4a", "audio/mp4", tramo > 1 ? "Audio · tramo " + tramo : "Audio", nombreTramo(tramo, "m4a"));
    }

    /** Una llamada entrante u otra app con el micrófono quitan el foco de audio: se para y se sella lo grabado. */
    private void pedirFoco(android.os.Handler reloj, Runnable tic) {
        android.media.AudioManager am = getSystemService(android.media.AudioManager.class);
        if (am == null) return;
        focoAudio = new android.media.AudioFocusRequest.Builder(android.media.AudioManager.AUDIOFOCUS_GAIN)
                .setOnAudioFocusChangeListener(cambio -> {
                    if (cambio == android.media.AudioManager.AUDIOFOCUS_LOSS || cambio == android.media.AudioManager.AUDIOFOCUS_LOSS_TRANSIENT) {
                        if (grabadoraAudio != null) {
                            pararAudio(reloj, tic);
                            Toast.makeText(this, "Grabación cortada por una llamada u otra app: el tramo queda sellado", Toast.LENGTH_LONG).show();
                        }
                    }
                }, new android.os.Handler(android.os.Looper.getMainLooper()))
                .build();
        am.requestAudioFocus(focoAudio);
    }

    private void soltarFoco() {
        android.media.AudioManager am = getSystemService(android.media.AudioManager.class);
        if (am != null && focoAudio != null) am.abandonAudioFocusRequest(focoAudio);
        focoAudio = null;
    }

    /** Al salir de la pantalla de audio grabando (onStop): el tramo en curso se sella, no se pierde. */
    private void descartarAudio() {
        if (grabadoraAudio == null) return;
        soltarFoco();
        long duracion = System.currentTimeMillis() - inicioTramo;
        int tramo = numTramo;
        File f = cerrarTramo();
        if (f != null) sellarTramo(f, tramo, duracion);
    }

    private void procesarGrabacion(File archivo, long duracionMs, String tipo, String prefijo, String extension, String mime, String titulo) {
        procesarGrabacion(archivo, duracionMs, tipo, prefijo, extension, mime, titulo, null);
    }

    /** Sella una grabación temporal (vídeo o audio) como evidencia (huella, cifrado por trozos, firma) y la borra. */
    private void procesarGrabacion(File archivo, long duracionMs, String tipo, String prefijo, String extension, String mime, String titulo, String nombreFijo) {
        final long total = archivo.length();
        final String nombre = nombreFijo != null ? nombreFijo
                : prefijo + "-" + new java.text.SimpleDateFormat("yyyyMMdd-HHmmss", ES).format(new java.util.Date()) + "." + extension;
        TextView estado = Ui.texto(this, "Calculando la huella y cifrando…", 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(titulo + " · " + duracion(duracionMs)).setView(estado).setCancelable(false).show();
        final long inicio = System.currentTimeMillis();
        new Thread(() -> {
            Evidencias.Sellado sellado = null;
            String fallo = null;
            long[] ultimoAviso = {0};
            try (InputStream in = new java.io.FileInputStream(archivo)) {
                sellado = evidencias.sellar(in, tipo, nombre, mime, hechos -> {
                    long ahora = System.currentTimeMillis();
                    if (ahora - ultimoAviso[0] < 250) return;
                    ultimoAviso[0] = ahora;
                    String t = Formatter.formatShortFileSize(this, hechos) + (total > 0 ? " de " + Formatter.formatShortFileSize(this, total) : "");
                    runOnUiThread(() -> estado.setText("Calculando la huella y cifrando…\n" + t));
                });
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            } finally {
                // El MP4 en claro solo existe hasta aquí: la copia cifrada es la evidencia.
                //noinspection ResultOfMethodCallIgnored
                archivo.delete();
            }
            final Evidencias.Sellado resultado = sellado;
            final String error = fallo;
            final long ms = System.currentTimeMillis() - inicio;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso("No se pudo guardar: " + error);
                } else if (resultado.yaExistia) {
                    aviso("Esta grabación ya estaba sellada.");
                } else {
                    Toast.makeText(this, titulo + " guardado y firmado en " + duracion(ms), Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-grabacion").start();
    }

    private void cerrarCamara() {
        if (camara != null) camara.cerrar();
        camara = null;
    }

    private void procesarFoto(byte[] jpeg) {
        final long inicio = System.currentTimeMillis();
        cerrarCamara();
        new Thread(() -> {
            String fallo = null;
            try {
                evidencias.crearFoto(jpeg);
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            } finally {
                Arrays.fill(jpeg, (byte) 0);
            }
            final String error = fallo;
            final long ms = System.currentTimeMillis() - inicio;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso("No se pudo guardar la evidencia: " + error);
                } else {
                    Toast.makeText(this, "Firmada en " + duracion(ms), Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-evidencia").start();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_MICROFONO_AUDIO) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Ya puedes grabar: pulsa «Grabar»", Toast.LENGTH_SHORT).show();
            } else {
                aviso("Sin permiso de micrófono no se puede grabar audio. Puedes darlo en los ajustes de Android.");
            }
            return;
        }
        if (requestCode == REQ_MICROFONO) {
            // La cámara sigue abierta; el usuario vuelve a pulsar «Vídeo». Sin micrófono se graba sin sonido.
            if (grantResults.length == 0 || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                microfonoNegado = true;
                Toast.makeText(this, "Sin micrófono: el vídeo se grabará sin sonido", Toast.LENGTH_LONG).show();
            }
            return;
        }
        if (requestCode != REQ_CAMARA) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            abrirCamara();
        } else {
            aviso("Sin permiso de cámara no se pueden hacer fotos ni vídeos. Puedes darlo en los ajustes de Android. Los archivos se pueden sellar igual.");
        }
    }

    /** Esquinas del encuadre, como un visor. */
    private static final class MarcoEnfoque extends View {
        private final Paint pincel = new Paint(Paint.ANTI_ALIAS_FLAG);

        MarcoEnfoque(Context c) {
            super(c);
            pincel.setColor(Ui.BLANCO);
            pincel.setStyle(Paint.Style.STROKE);
            pincel.setStrokeCap(Paint.Cap.ROUND);
            pincel.setStrokeWidth(Ui.dp(c, 3));
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float w = getWidth(), h = getHeight();
            float lado = Math.min(w, h) * 0.62f;
            float x0 = (w - lado) / 2, y0 = (h - lado) / 2, x1 = x0 + lado, y1 = y0 + lado;
            float t = lado * 0.18f, r = lado * 0.07f;
            Path p = new Path();
            p.moveTo(x0, y0 + t); p.lineTo(x0, y0 + r); p.quadTo(x0, y0, x0 + r, y0); p.lineTo(x0 + t, y0);
            p.moveTo(x1 - t, y0); p.lineTo(x1 - r, y0); p.quadTo(x1, y0, x1, y0 + r); p.lineTo(x1, y0 + t);
            p.moveTo(x0, y1 - t); p.lineTo(x0, y1 - r); p.quadTo(x0, y1, x0 + r, y1); p.lineTo(x0 + t, y1);
            p.moveTo(x1 - t, y1); p.lineTo(x1 - r, y1); p.quadTo(x1, y1, x1, y1 - r); p.lineTo(x1, y1 - t);
            canvas.drawPath(p, pincel);
        }
    }

    // ------------------------------------------------------------------ ficha

    private void abrirFicha(String id) {
        abrirSecundaria(() -> {
            Evidencias.Ficha f = null;
            try {
                f = evidencias.porId(id);
            } catch (Exception ignorado) {
                // Se trata como borrada.
            }
            if (f == null) {
                mostrarPestana(Pestana.EVIDENCIAS);
                return;
            }
            mostrar(pantallaFicha(f), false);
        });
    }

    private View pantallaFicha(Evidencias.Ficha f) {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Evidencia", () -> mostrarPestana(Pestana.EVIDENCIAS), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), dp(4), dp(16), dp(24));

        if (f.esImagen() && f.bytes <= MAX_VISTA) {
            ImageView foto = new ImageView(this);
            foto.setAdjustViewBounds(true);
            foto.setScaleType(ImageView.ScaleType.FIT_CENTER);
            foto.setBackground(Ui.degradado(this, 24));
            foto.setClipToOutline(true);
            foto.setMinimumHeight(dp(200));
            col.addView(foto, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            cargarImagen(f, foto, getResources().getDisplayMetrics().widthPixels);
        }
        if (!f.esFoto()) {
            LinearLayout arch = Ui.fila(this);
            arch.setPadding(dp(16), dp(16), dp(16), dp(16));
            arch.setBackground(Ui.degradado(this, 24));
            arch.addView(aro(iconoDe(f)), new LinearLayout.LayoutParams(dp(64), dp(64)));
            LinearLayout tx = Ui.columna(this);
            tx.setPadding(dp(14), 0, 0, 0);
            tx.addView(Ui.texto(this, f.nombre.isEmpty() ? (f.esVideo() ? "Vídeo" : f.esAudio() ? "Audio" : "Archivo") : f.nombre, 16, Ui.TEXTO, true));
            tx.addView(Ui.texto(this, f.mime + " · " + tamano(f), 13, Ui.SUAVE, false));
            arch.addView(tx, Ui.peso(1));
            col.addView(arch, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, f.esImagen() && f.bytes <= MAX_VISTA ? 12 : 0, 0, 0));
        }

        LinearLayout datos = Ui.columna(this);
        datos.setPadding(dp(18), dp(16), dp(18), dp(16));
        datos.setBackground(Ui.degradado(this, 24));
        LinearLayout.LayoutParams lpp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        datos.addView(pildora(f), lpp);
        dato(datos, "Huella SHA-256", f.sha256, true);
        dato(datos, "Hora del dispositivo al sellar (declarada, no verificable)", f.capturada, false);
        String bytesClave;
        try {
            bytesClave = f.firmante.equals(evidencias.huellaClave()) ? " · clave pública " + miles(evidencias.clavePublica().length) + " bytes" : "";
        } catch (Exception e) {
            bytesClave = "";
        }
        dato(datos, "Firmada con la clave" + bytesClave, agrupar(f.firmante), true);
        int bytesFirma = Base64.decode(f.firma, Base64.NO_WRAP).length;
        dato(datos, "Firma", "ML-DSA-87 · " + miles(bytesFirma) + " bytes", false);
        String sujeto = f.esFoto() ? "Esta foto" : f.esVideo() ? "Este vídeo" : f.esAudio() ? "Este audio" : "Este archivo";
        String ancla;
        switch (f.otsEstado) {
            case "bitcoin":
                ancla = sujeto + " existía con este contenido exacto al menos desde el bloque " + f.bloque + " de Bitcoin, y no ha cambiado desde entonces.";
                break;
            case "calendar":
                ancla = "La huella está en los calendarios de OpenTimestamps. Bitcoin la confirma en una o dos horas.";
                break;
            default:
                ancla = "En espera de red para enviar la huella (32 bytes) a los calendarios.";
                break;
        }
        dato(datos, "Ancla en Bitcoin", ancla, false);
        col.addView(datos, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 14));

        col.addView(Ui.boton(this, "Verificar ahora", true, v -> verificar(f)));
        espacio(col);
        col.addView(Ui.boton(this, "Compartir recibo", false, v -> compartirRecibo(f)));
        espacio(col);
        col.addView(Ui.boton(this, f.esFoto() ? "Exportar foto" : "Exportar archivo", false, v -> confirmarExportar(f)));
        espacio(col);
        col.addView(Ui.boton(this, "Borrar", false, v -> confirmarBorrar(f)));
        TextView nota = Ui.texto(this, "El recibo lleva la huella, la firma y la prueba .ots. No lleva " + (f.esFoto() ? "la foto" : "el archivo")
                + ". Se verifica con herramientas públicas: OpenTimestamps.", 12, Ui.TENUE, false);
        nota.setPadding(dp(4), dp(14), dp(4), 0);
        col.addView(nota);
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void espacio(LinearLayout col) {
        col.addView(new View(this), new LinearLayout.LayoutParams(1, dp(10)));
    }

    private void dato(LinearLayout padre, String etiqueta, String valor, boolean mono) {
        TextView e = Ui.texto(this, etiqueta, 12, Ui.SUAVE, true);
        e.setPadding(0, dp(12), 0, dp(2));
        padre.addView(e);
        padre.addView(mono ? Ui.mono(this, valor, 13, Ui.TEXTO) : Ui.texto(this, valor, 14, Ui.TEXTO, false));
    }

    private static String agrupar(String hex) {
        return hex.substring(0, 8) + " " + hex.substring(8, 16) + " … " + hex.substring(hex.length() - 8);
    }

    private void verificar(Evidencias.Ficha f) {
        AlertDialog espera = new AlertDialog.Builder(this).setMessage("Recalculando la huella de lo guardado…").setCancelable(false).show();
        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            String guardado = f.esFoto() ? "la foto guardada" : "el archivo guardado";
            try {
                boolean huellaOk = evidencias.huellaGuardada(f).equals(f.sha256);
                sb.append(huellaOk ? "✓ La huella coincide: " + guardado + " no ha cambiado desde que se firmó.\n\n"
                        : "✗ La huella no coincide: " + guardado + " ha cambiado desde que se firmó.\n\n");
            } catch (GeneralSecurityException e) {
                // El cifrado autenticado detecta cualquier byte cambiado antes de llegar a la huella.
                sb.append("✗ La huella no coincide: ").append(guardado).append(" ha cambiado o está dañado desde que se firmó.\n\n");
            } catch (Exception e) {
                sb.append("✗ No se pudo leer ").append(guardado).append(": ").append(Ui.mensaje(e)).append("\n\n");
            }
            try {
                X39Core.verifyMessage(evidencias.clavePublica(), f.canonica().getBytes(StandardCharsets.UTF_8), Base64.decode(f.firma, Base64.NO_WRAP));
                boolean mismaClave = evidencias.huellaClave().equals(f.firmante);
                sb.append(mismaClave ? "✓ Firma ML-DSA-87 válida, hecha con la clave de este móvil.\n\n"
                        : "✗ La firma no es de la clave actual de este móvil.\n\n");
            } catch (Exception e) {
                sb.append("✗ La firma no es válida.\n\n");
            }
            try {
                byte[] ots = evidencias.ots(f);
                if (ots == null) {
                    sb.append("Ancla: todavía no hay prueba .ots (la huella no se ha enviado).");
                } else {
                    String bloques = X39Core.otsBlocks(ots);
                    String pendientes = X39Core.otsPending(ots);
                    int n = pendientes.isEmpty() ? 0 : pendientes.split("\n").length;
                    sb.append(bloques.isEmpty()
                            ? "Ancla: prueba .ots válida, pendiente en " + n + " calendarios."
                            : "✓ Ancla: prueba .ots con el bloque " + bloques + " de Bitcoin. Compruébalo fuera de la app con «ots verify».");
                }
            } catch (Exception e) {
                sb.append("✗ La prueba .ots no es válida: ").append(Ui.mensaje(e));
            }
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                new AlertDialog.Builder(this).setTitle("Verificación").setMessage(sb.toString()).setPositiveButton("Entendido", null).show();
            });
        }, "x39-verificar").start();
    }

    private void compartirRecibo(Evidencias.Ficha f) {
        try {
            File dir = ProveedorRecibos.carpeta(this);
            ArrayList<Uri> uris = new ArrayList<>();
            String json = f.id + ".json";
            // La clave pública que firmó va dentro del recibo (signer_pk): el recibo se verifica por sí solo.
            byte[] clavePk = f.firmante.equals(evidencias.huellaClave()) ? evidencias.clavePublica() : null;
            Evidencias.escribirAtomico(new File(dir, json), Evidencias.recibo(f, clavePk).toString(2).getBytes(StandardCharsets.UTF_8));
            uris.add(ProveedorRecibos.uri(this, json));
            byte[] ots = evidencias.ots(f);
            if (ots != null) {
                String nombre = f.id + ".ots";
                Evidencias.escribirAtomico(new File(dir, nombre), ots);
                uris.add(ProveedorRecibos.uri(this, nombre));
            }
            compartirFicheros(uris, f.esFoto() ? "Compartir recibo (sin la foto)" : "Compartir recibo (sin el archivo)");
        } catch (Exception e) {
            aviso("No se pudo preparar el recibo: " + Ui.mensaje(e));
        }
    }

    private void compartirFicheros(ArrayList<Uri> uris, String titulo) {
        Intent i = new Intent(uris.size() == 1 ? Intent.ACTION_SEND : Intent.ACTION_SEND_MULTIPLE);
        i.setType("application/octet-stream");
        if (uris.size() == 1) i.putExtra(Intent.EXTRA_STREAM, uris.get(0));
        else i.putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris);
        ClipData clip = ClipData.newRawUri(null, uris.get(0));
        for (int k = 1; k < uris.size(); k++) clip.addItem(new ClipData.Item(uris.get(k)));
        i.setClipData(clip);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivity(Intent.createChooser(i, titulo));
    }

    /**
     * Exportar = la hoja de compartir de Android con el archivo descifrado servido por el proveedor de la app
     * (lectura temporal), igual que el recibo: el periodista elige el destino (Signal, correo, USB…). La app
     * nunca escribe en DCIM, Pictures ni Movies, ni toca el MediaStore.
     */
    private void confirmarExportar(Evidencias.Ficha f) {
        String lo = f.esFoto() ? "La foto" : f.esVideo() ? "El vídeo" : f.esAudio() ? "El audio" : "El archivo";
        new AlertDialog.Builder(this)
                .setTitle(f.esFoto() ? "Exportar la foto" : f.esVideo() ? "Exportar el vídeo" : f.esAudio() ? "Exportar el audio" : "Exportar el archivo")
                .setMessage(lo + " se descifra y se entrega a la app que elijas. Fuera de la bóveda, este archivo puede sincronizarse con la nube de tu móvil. El recibo sigue valiendo: la huella es la misma.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Elegir destino", (d, w) -> exportar(f))
                .show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        if (requestCode == REQ_ARCHIVO) {
            sellarArchivo(data.getData());
        }
    }

    /** Nombre de fichero seguro para el proveedor (solo letras, dígitos, punto, guion). */
    private static String nombreExportado(Evidencias.Ficha f) {
        String base = f.esFoto() ? "x39-" + f.id + ".jpg" : (f.nombre.isEmpty() ? "x39-" + f.id : f.nombre);
        String limpio = base.replaceAll("[^A-Za-z0-9._-]", "-");
        if (limpio.length() > 80) limpio = limpio.substring(limpio.length() - 80);
        return limpio;
    }

    private void exportar(Evidencias.Ficha f) {
        final String nombre = nombreExportado(f);
        final File destino = new File(ProveedorRecibos.carpeta(this), nombre);
        TextView estado = Ui.texto(this, "Descifrando…", 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(nombre).setView(estado).setCancelable(false).show();
        new Thread(() -> {
            String fallo = null;
            try (OutputStream out = new java.io.FileOutputStream(destino)) {
                evidencias.descifrarA(f, out);
            } catch (GeneralSecurityException e) {
                fallo = "lo guardado ha cambiado o está dañado; no se exporta";
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                if (error != null) {
                    //noinspection ResultOfMethodCallIgnored
                    destino.delete();
                    aviso("No se pudo exportar: " + error);
                    return;
                }
                Uri uri = ProveedorRecibos.uri(this, nombre);
                Intent i = new Intent(Intent.ACTION_SEND).setType(f.mime).putExtra(Intent.EXTRA_STREAM, uri);
                i.setClipData(ClipData.newRawUri(null, uri));
                i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivity(Intent.createChooser(i, "Exportar " + nombre));
            });
        }, "x39-exportar").start();
    }

    /** Copias descifradas que quedaron en cache/compartir tras exportar: se borran pasados 15 minutos. */
    private void limpiarCompartidos() {
        File[] fs = ProveedorRecibos.carpeta(this).listFiles();
        if (fs == null) return;
        long limite = System.currentTimeMillis() - 15 * 60_000L;
        for (File x : fs) {
            String n = x.getName();
            if (!n.endsWith(".json") && !n.endsWith(".ots") && !n.endsWith(".txt") && x.lastModified() < limite) {
                //noinspection ResultOfMethodCallIgnored
                x.delete();
            }
        }
    }

    private void confirmarBorrar(Evidencias.Ficha f) {
        new AlertDialog.Builder(this)
                .setTitle("Borrar evidencia")
                .setMessage("Se borran " + (f.esFoto() ? "la foto" : "el archivo") + " y su ficha de este móvil. Un recibo que ya hayas compartido sigue valiendo.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Borrar", (d, w) -> {
                    try {
                        evidencias.borrar(f);
                    } catch (Exception e) {
                        aviso(Ui.mensaje(e));
                    }
                    mostrarPestana(Pestana.EVIDENCIAS);
                })
                .show();
    }

    // ------------------------------------------------------------------ seguridad

    private View pantallaSeguridad() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Seguridad", null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        col.addView(Ui.texto(this, "Lo que la app afirma de sí misma, comprobado en este móvil.", 13, Ui.SUAVE, false));

        LinearLayout permisos = tarjeta(col, "Permisos del manifiesto, tal cual");
        try {
            @SuppressWarnings("deprecation")
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_PERMISSIONS);
            if (pi.requestedPermissions != null) {
                for (String p : pi.requestedPermissions) permisos.addView(Ui.mono(this, p.replace("android.permission.", ""), 13, Ui.TEXTO));
            }
        } catch (Exception e) {
            permisos.addView(Ui.texto(this, "No se pudieron leer: " + Ui.mensaje(e), 13, Ui.AVISO, false));
        }
        TextView internet = Ui.texto(this, "Internet: sí, solo para enviar huellas (32 bytes) a los calendarios de OpenTimestamps y recibir pruebas. Nunca fotos, vídeos ni archivos. "
                + "Micrófono: solo mientras grabas un vídeo o un audio; si lo niegas, el vídeo se graba sin sonido y el audio no se puede grabar.", 13, Ui.TEXTO_2, false);
        internet.setPadding(0, dp(8), 0, 0);
        permisos.addView(internet);

        LinearLayout estado = tarjeta(col, null);
        boolean copias = (getApplicationInfo().flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
        filaEstado(estado, "Capturas de pantalla", "Bloqueadas", true);
        filaEstado(estado, "Evidencias en la galería", "Nunca", true);
        filaEstado(estado, "Copias en la nube", copias ? "Activadas" : "Desactivadas", !copias);
        filaEstado(estado, "Ubicación en las fotos", "No", true);
        boolean aislado = ColaAnclaje.aislado(this);
        filaEstado(estado, "Modo aislado", aislado ? "Activo: nada sale del móvil" : "Apagado", true);

        LinearLayout clave = tarjeta(col, "Tu identidad");
        try {
            clave.addView(Ui.mono(this, agrupar(evidencias.huellaClave()), 13, Ui.TEXTO));
            TextView medida = Ui.texto(this, "Clave pública ML-DSA-87: " + miles(evidencias.clavePublica().length) + " bytes (medido ahora)", 13, Ui.TEXTO_2, false);
            medida.setPadding(0, dp(6), 0, 0);
            clave.addView(medida);
        } catch (Exception e) {
            clave.addView(Ui.texto(this, "No se pudo leer la clave: " + Ui.mensaje(e), 13, Ui.AVISO, false));
        }
        clave.addView(Ui.boton(this, "Ver identidad, QR y tamaños", false, v -> abrirSecundaria(() -> mostrar(pantallaIdentidad(false), false))),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

        LinearLayout red = tarjeta(col, "Registro de red");
        List<String> lineas = RedX39.ultimas(this, 40);
        if (lineas.isEmpty()) red.addView(Ui.texto(this, "Todavía no ha habido ninguna conexión.", 13, Ui.SUAVE, false));
        for (String l : lineas) {
            TextView t = Ui.mono(this, l, 11, Ui.TEXTO_2);
            t.setPadding(0, dp(3), 0, dp(3));
            red.addView(t);
        }

        TextView ver = Ui.texto(this, "x39 " + VERSION, 12, Ui.TENUE, false);
        ver.setGravity(Gravity.CENTER);
        ver.setPadding(0, dp(18), 0, 0);
        col.addView(ver, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    /**
     * Prueba de aceptación 8: los bytes reales que salen del móvil, no los tests del motor.
     * Clave pública (2.592 B) y, si ya hay evidencias, la última firma real (4.627 B) con su mensaje firmado.
     */
    private void compartirClave() {
        try {
            File dir = ProveedorRecibos.carpeta(this);
            ArrayList<Uri> uris = new ArrayList<>();
            Evidencias.escribirAtomico(new File(dir, "clave_publica_mldsa87.bin"), evidencias.clavePublica());
            uris.add(ProveedorRecibos.uri(this, "clave_publica_mldsa87.bin"));
            List<Evidencias.Ficha> fichas = evidencias.todas();
            if (!fichas.isEmpty()) {
                Evidencias.Ficha f = fichas.get(0);
                Evidencias.escribirAtomico(new File(dir, "firma_" + f.id + ".bin"), Base64.decode(f.firma, Base64.NO_WRAP));
                Evidencias.escribirAtomico(new File(dir, "mensaje_" + f.id + ".txt"), f.canonica().getBytes(StandardCharsets.UTF_8));
                uris.add(ProveedorRecibos.uri(this, "firma_" + f.id + ".bin"));
                uris.add(ProveedorRecibos.uri(this, "mensaje_" + f.id + ".txt"));
            }
            compartirFicheros(uris, "Exportar clave pública");
        } catch (Exception e) {
            aviso(Ui.mensaje(e));
        }
    }

    // ------------------------------------------------------------------ ajustes

    private View pantallaAjustes() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Ajustes", null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        LinearLayout t = tarjeta(col, null);
        SharedPreferences p = ColaAnclaje.prefs(this);
        interruptor(t, "Anclar automáticamente", "Envía la huella a los calendarios en cuanto hay red.", ColaAnclaje.PREF_AUTO, true, p);
        interruptor(t, "Solo por Wi-Fi", "No usa datos móviles para anclar.", ColaAnclaje.PREF_SOLO_WIFI, false, p);
        interruptor(t, "Modo aislado", "Congela la cola: nada sale del móvil hasta que lo apagues.", ColaAnclaje.PREF_AISLADO, false, p);
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void interruptor(LinearLayout padre, String titulo, String descripcion, String clave, boolean porDefecto, SharedPreferences p) {
        LinearLayout f = Ui.fila(this);
        f.setPadding(0, dp(10), 0, dp(10));
        LinearLayout textos = Ui.columna(this);
        textos.addView(Ui.texto(this, titulo, 15, Ui.TEXTO, true));
        textos.addView(Ui.texto(this, descripcion, 13, Ui.SUAVE, false));
        f.addView(textos, Ui.peso(1));
        Switch s = new Switch(this);
        s.setChecked(p.getBoolean(clave, porDefecto));
        s.setContentDescription(titulo);
        s.setOnCheckedChangeListener((b, activo) -> {
            p.edit().putBoolean(clave, activo).apply();
            ColaAnclaje.programar(this);
        });
        f.addView(s);
        padre.addView(f);
    }

    // ------------------------------------------------------------------ piezas

    private LinearLayout tarjeta(LinearLayout padre, String titulo) {
        LinearLayout card = Ui.columna(this);
        card.setPadding(dp(18), dp(16), dp(18), dp(16));
        card.setBackground(Ui.degradado(this, 24));
        if (titulo != null) {
            TextView t = Ui.texto(this, titulo, 16, Ui.TEXTO, true);
            t.setPadding(0, 0, 0, dp(8));
            card.addView(t);
        }
        padre.addView(card, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        return card;
    }

    private void filaEstado(LinearLayout lista, String etiqueta, String valor, boolean bien) {
        LinearLayout f = Ui.fila(this);
        f.setMinimumHeight(dp(42));
        f.addView(Ui.texto(this, etiqueta, 14, Ui.TEXTO_2, false), Ui.peso(1));
        f.addView(Ui.icono(this, bien ? Icono.Tipo.CHECK : Icono.Tipo.AVISO, Ui.TEXTO, 15));
        TextView v = Ui.texto(this, valor, 14, Ui.TEXTO, false);
        v.setPadding(dp(6), 0, 0, 0);
        f.addView(v);
        lista.addView(f);
    }

    private void aviso(String texto) {
        new AlertDialog.Builder(this).setMessage(texto).setPositiveButton("Entendido", null).show();
    }
}
