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

import org.x39matrix.evidencia.R;

/**
 * x39 · Evidencia v0.1 (etapa A).
 * Identidad ML-DSA-87 creada a mano en el primer arranque → foto de la cámara propia o cualquier archivo →
 * almacén cifrado → huella SHA-256 → firma → cola de anclaje OpenTimestamps. Lo guardado no sale del móvil;
 * por la red solo viajan compromisos de 32 bytes.
 * Textos según la sección 9 de la especificación: nada de «auténtica», «sin rastro» ni «subir».
 */
public class EvidenciaActivity extends Activity {
    static final String VERSION = "0.3.0";
    private static final int REQ_CAMARA = 1;
    private static final int REQ_EXPORTAR = 2;
    private static final int REQ_ARCHIVO = 3;
    private static final int REQ_MICROFONO = 4;
    private static final int REQ_MICROFONO_AUDIO = 5;
    private static final int REQ_ESCANER = 6;
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
    /** Solo para lo que no se enseña (nombres de fichero, hex en minúsculas). Lo visible usa idioma(). */
    private static final Locale ES = new Locale("es", "ES");
    /** Fecha corta de las fichas; el Locale es el actual de la app (idioma()). */
    private static final String PATRON_FECHA = "d MMM yyyy · HH:mm";

    private enum Pestana { EVIDENCIAS, MENSAJES, CONTACTOS, SEGURIDAD, AJUSTES }

    private FrameLayout raiz;
    private Pestana pestana = Pestana.EVIDENCIAS;
    private Runnable secundaria;
    private Evidencias evidencias;
    private Camara camara;
    private String exportandoId;

    // ------------------------------------------------------------------ ciclo de vida

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(Idioma.envolver(base));
    }

    @Override
    protected void onSaveInstanceState(Bundle salida) {
        super.onSaveInstanceState(salida);
        // Al cambiar de idioma la pantalla se recrea: se vuelve a la misma pestaña.
        salida.putString("pestana", pestana.name());
    }

    @Override
    protected void onCreate(Bundle estado) {
        super.onCreate(estado);
        if (estado != null && estado.getString("pestana") != null) {
            try { pestana = Pestana.valueOf(estado.getString("pestana")); } catch (IllegalArgumentException ignorada) { }
        }
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
        if (receptorOrbot == null) {
            receptorOrbot = Orbot.receptor(this::refrescarTor);
            Orbot.registrar(this, receptorOrbot);
        }
        refrescarTor();
        if (camara == null) render();
    }

    // ------------------------------------------------------------------ Tor (Orbot)

    private android.content.BroadcastReceiver receptorOrbot;
    /** Último resultado de Orbot.listo(), medido en segundo plano (abre un socket; no se hace en pantalla). */
    private boolean torListo;

    private boolean esperandoTor() {
        return Orbot.soloTor(this) && !torListo;
    }

    /** Vuelve a medir si Orbot está listo y repinta si cambió. */
    private void refrescarTor() {
        if (!Orbot.soloTor(this)) {
            torListo = false;
            return;
        }
        new Thread(() -> {
            boolean listo = Orbot.listo(this);
            runOnUiThread(() -> {
                if (isDestroyed() || listo == torListo) return;
                torListo = listo;
                if (camara == null && grabadoraAudio == null) render();
                if (listo) ColaAnclaje.programar(this);
            });
        }, "x39-tor").start();
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (receptorOrbot != null) {
            try {
                unregisterReceiver(receptorOrbot);
            } catch (IllegalArgumentException ignorado) {
                // Ya quitado.
            }
            receptorOrbot = null;
        }
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
            case MENSAJES: v = pantallaMensajes(); break;
            case CONTACTOS: v = pantallaContactos(); break;
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
        f.setPaddingRelative(dp(volver != null ? 4 : 20), dp(10), dp(18), dp(6));
        if (colorFondo != 0) f.setBackgroundColor(colorFondo);
        if (volver != null) f.addView(Ui.botonIcono(this, Icono.Tipo.ATRAS, Ui.TEXTO, getString(R.string.x39_volver), v -> volver.run()));
        f.addView(Ui.texto(this, titulo, volver != null ? 18 : 24, Ui.TEXTO, true), Ui.peso(1));
        ImageView candado = Ui.icono(this, Icono.Tipo.CANDADO, Ui.ROJO, 20);
        ((LinearLayout.LayoutParams) candado.getLayoutParams()).setMarginEnd(dp(6));
        f.addView(candado);
        f.addView(Ui.marca(this));
        return f;
    }

    private View barraNavegacion() {
        LinearLayout barra = Ui.fila(this);
        barra.setBackground(Ui.redondeado(this, Ui.SUPERFICIE_2, 32));
        barra.setElevation(dp(8));
        barra.setPadding(dp(6), 0, dp(6), 0);
        barra.addView(itemNavegacion(Icono.Tipo.ACTAS, getString(R.string.x39_evidencias), pestana == Pestana.EVIDENCIAS && secundaria == null, () -> mostrarPestana(Pestana.EVIDENCIAS)), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.CAMARA, getString(R.string.x39_hacer_una_foto), false, this::abrirCamara), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.AUDIO, getString(R.string.x39_grabar_audio), false, this::abrirGrabadora), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.CHAT, getString(R.string.x39_mensajes), pestana == Pestana.MENSAJES && secundaria == null, () -> mostrarPestana(Pestana.MENSAJES)), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.CONTACTOS, getString(R.string.x39_contactos), pestana == Pestana.CONTACTOS && secundaria == null, () -> mostrarPestana(Pestana.CONTACTOS)), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.ARCHIVO, getString(R.string.x39_elegir_un_archivo), false, this::elegirArchivo), Ui.peso(1));
        barra.addView(itemNavegacion(Icono.Tipo.ESCUDO, getString(R.string.x39_seguridad), pestana == Pestana.SEGURIDAD && secundaria == null, () -> mostrarPestana(Pestana.SEGURIDAD)), Ui.peso(1));
        return barra;
    }

    private View itemNavegacion(Icono.Tipo tipo, String etiqueta, boolean activa, Runnable accion) {
        return itemNavegacion(tipo, etiqueta, activa, accion, activa ? Ui.BLANCO : Ui.SUAVE);
    }

    private View itemNavegacion(Icono.Tipo tipo, String etiqueta, boolean activa, Runnable accion, int color) {
        FrameLayout item = new FrameLayout(this);
        item.setMinimumHeight(dp(58));
        FrameLayout cuadro = new FrameLayout(this);
        if (activa) cuadro.setBackground(Ui.redondeado(this, Ui.FONDO, 15));
        cuadro.addView(Ui.icono(this, tipo, color, 22), new FrameLayout.LayoutParams(dp(22), dp(22), Gravity.CENTER));
        item.addView(cuadro, new FrameLayout.LayoutParams(dp(46), dp(46), Gravity.CENTER));
        item.setContentDescription(etiqueta);
        // Navegar a mano cancela un «adjuntar al chat» que se quedara a medias.
        item.setOnClickListener(v -> { adjuntarA = null; accion.run(); });
        Ui.clicable(item);
        return item;
    }

    // ------------------------------------------------------------------ identidad (pantalla 0)

    /**
     * @param inicial sin flecha de volver: primer arranque (con «Continuar» una vez creada la clave).
     */
    private View pantallaIdentidad(boolean inicial) {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_tu_identidad), inicial ? null : () -> mostrarPestana(pestana), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));

        if (!evidencias.tieneIdentidad()) {
            LinearLayout intro = Ui.columna(this);
            intro.setGravity(Gravity.CENTER_HORIZONTAL);
            intro.setPadding(dp(20), dp(28), dp(20), dp(22));
            intro.setBackground(Ui.degradado(this, 28));
            intro.addView(aro(Icono.Tipo.LLAVE), new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView t = Ui.texto(this, getString(R.string.x39_identidad_sin_cuenta), 20, Ui.TEXTO, true);
            t.setGravity(Gravity.CENTER);
            t.setPadding(0, dp(14), 0, dp(6));
            intro.addView(t);
            TextView d = Ui.texto(this, getString(R.string.x39_identidad_intro), 14, Ui.TEXTO_2, false);
            d.setGravity(Gravity.CENTER);
            d.setPadding(0, 0, 0, dp(18));
            intro.addView(d);
            TextView crear = Ui.boton(this, getString(R.string.x39_crear_identidad), true, null);
            crear.setOnClickListener(v -> crearIdentidad(crear));
            intro.addView(crear, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            col.addView(intro, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        } else {
            try {
                byte[] pk = evidencias.clavePublica();
                String fp = Evidencias.sha256Hex(pk);

                LinearLayout h = tarjeta(col, getString(R.string.x39_identidad_huella_titulo));
                TextView hv = Ui.mono(this, bloquesHuella(fp), 17, Ui.TEXTO);
                hv.setLineSpacing(dp(4), 1f);
                h.addView(hv);
                TextView hn = Ui.texto(this, getString(R.string.x39_identidad_huella_nota), 13, Ui.SUAVE, false);
                hn.setPadding(0, dp(8), 0, 0);
                h.addView(hn);
                h.addView(Ui.boton(this, getString(R.string.x39_copiar_huella), false, v -> copiarHuella(fp)),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout k = tarjeta(col, getString(R.string.x39_identidad_clave_publica));
                ImageView qr = new ImageView(this);
                qr.setAdjustViewBounds(true);
                qr.setScaleType(ImageView.ScaleType.FIT_CENTER);
                qr.setBackground(Ui.redondeado(this, 0xFFFFFFFF, 14));
                qr.setPadding(dp(8), dp(8), dp(8), dp(8));
                qr.setContentDescription(getString(R.string.x39_identidad_qr_desc));
                k.addView(qr, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                dibujarQr(qr, pk);
                TextView ki = Ui.texto(this, getString(R.string.x39_identidad_clave_info, miles(pk.length)), 13, Ui.TEXTO_2, false);
                ki.setPadding(0, dp(10), 0, 0);
                k.addView(ki);
                k.addView(Ui.boton(this, getString(R.string.x39_exportar_clave_bin), false, v -> compartirClave()),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout z = tarjeta(col, getString(R.string.x39_comprobar_tamanos_titulo));
                TextView res = Ui.texto(this, getString(R.string.x39_comprobar_tamanos_texto, miles(Evidencias.PK_ESPERADA), miles(Evidencias.FIRMA_ESPERADA)), 13, Ui.TEXTO_2, false);
                z.addView(res);
                z.addView(Ui.boton(this, getString(R.string.x39_comprobar_en_este_movil), false, v -> comprobarTamanos(res)),
                        Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

                LinearLayout donde = tarjeta(col, getString(R.string.x39_donde_vive));
                donde.addView(Ui.texto(this, getString(R.string.x39_donde_vive_texto, textoNivel(evidencias.nivel())), 13, Ui.TEXTO_2, false));
            } catch (Exception e) {
                tarjeta(col, null).addView(Ui.texto(this, getString(R.string.x39_error_leer_clave, motivo(e)), 14, Ui.AVISO, false));
            }
        }

        LinearLayout aviso = Ui.fila(this);
        aviso.setGravity(Gravity.TOP);
        aviso.setPadding(dp(18), dp(16), dp(18), dp(16));
        aviso.setBackground(Ui.redondeado(this, Ui.CAJA, 24));
        aviso.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.AVISO, 20));
        TextView at = Ui.texto(this, getString(R.string.x39_identidad_aviso), 14, Ui.AVISO, false);
        at.setPaddingRelative(dp(12), 0, 0, 0);
        aviso.addView(at, Ui.peso(1));
        col.addView(aviso, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));

        if (inicial && evidencias.tieneIdentidad()) {
            col.addView(Ui.boton(this, getString(R.string.x39_continuar), true, v -> mostrarPestana(Pestana.EVIDENCIAS)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 18, 0, 0));
        }
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void crearIdentidad(TextView boton) {
        boton.setEnabled(false);
        boton.setText(R.string.x39_creando_clave);
        new Thread(() -> {
            String fallo = null;
            try {
                evidencias.crearIdentidad();
            } catch (Exception e) {
                fallo = motivo(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (error != null) {
                    boton.setEnabled(true);
                    boton.setText(R.string.x39_crear_identidad);
                    aviso(getString(R.string.x39_error_crear_identidad, error));
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
        cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.x39_clip_huella), fp));
        Toast.makeText(this, R.string.x39_huella_copiada, Toast.LENGTH_SHORT).show();
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
        resultado.setText(R.string.x39_firmando_midiendo);
        new Thread(() -> {
            String texto;
            try {
                int[] t = evidencias.comprobarTamanos();
                boolean clave = t[0] == Evidencias.PK_ESPERADA;
                boolean firma = t[1] == Evidencias.FIRMA_ESPERADA;
                texto = (clave ? getString(R.string.x39_tamanos_clave_ok, miles(t[0]))
                                : getString(R.string.x39_tamanos_clave_mal, miles(t[0]), miles(Evidencias.PK_ESPERADA)))
                        + "\n" + (firma ? getString(R.string.x39_tamanos_firma_ok, miles(t[1]))
                                : getString(R.string.x39_tamanos_firma_mal, miles(t[1]), miles(Evidencias.FIRMA_ESPERADA)))
                        + "\n" + getString(R.string.x39_tamanos_verifica)
                        + "\n\n" + getString(clave && firma ? R.string.x39_tamanos_es_mldsa : R.string.x39_tamanos_no_mldsa);
            } catch (Exception e) {
                texto = getString(R.string.x39_tamanos_error, motivo(e));
            }
            final String fin = texto;
            runOnUiThread(() -> resultado.setText(fin));
        }, "x39-tamanos").start();
    }

    private String miles(long n) {
        return String.format(idioma(), "%,d", n);
    }

    /** El idioma con el que la app está pintando ahora (el del sistema o el elegido para la app). */
    private Locale idioma() {
        return getResources().getConfiguration().getLocales().get(0);
    }

    /** El motivo de un fallo tal como se enseña, en el idioma actual. */
    private String motivo(Exception e) {
        return FalloVisible.motivo(this, e);
    }

    /** Dónde vive la clave del Keystore, en palabras (Boveda solo da el nivel). */
    private String textoNivel(Boveda.Nivel n) {
        switch (n) {
            case STRONGBOX: return getString(R.string.x39_nivel_strongbox);
            case TEE: return getString(R.string.x39_nivel_tee);
            case HARDWARE_SEGURO: return getString(R.string.x39_nivel_hardware_seguro);
            case SOFTWARE: return getString(R.string.x39_nivel_software);
            default: return getString(R.string.x39_nivel_desconocido);
        }
    }

    // ------------------------------------------------------------------ evidencias

    private View pantallaEvidencias() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_evidencias), null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        col.addView(Ui.texto(this, getString(R.string.x39_evidencias_subtitulo), 13, Ui.SUAVE, false));

        List<Evidencias.Ficha> fichas;
        try {
            fichas = evidencias.todas();
        } catch (Exception e) {
            fichas = new ArrayList<>();
            col.addView(Ui.texto(this, getString(R.string.x39_error_leer_almacen, motivo(e)), 14, Ui.AVISO, false));
        }
        if (fichas.isEmpty()) {
            LinearLayout vacio = Ui.columna(this);
            vacio.setGravity(Gravity.CENTER_HORIZONTAL);
            vacio.setPadding(dp(20), dp(28), dp(20), dp(22));
            vacio.setBackground(Ui.degradado(this, 28));
            vacio.addView(aro(Icono.Tipo.CAMARA), new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView t = Ui.texto(this, getString(R.string.x39_evidencias_vacio_titulo), 20, Ui.TEXTO, true);
            t.setPadding(0, dp(14), 0, dp(6));
            vacio.addView(t);
            TextView d = Ui.texto(this, getString(R.string.x39_evidencias_vacio_texto), 14, Ui.TEXTO_2, false);
            d.setGravity(Gravity.CENTER);
            d.setPadding(0, 0, 0, dp(18));
            vacio.addView(d);
            vacio.addView(Ui.boton(this, getString(R.string.x39_hacer_una_foto), true, v -> abrirCamara()), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            vacio.addView(Ui.boton(this, getString(R.string.x39_elegir_un_archivo), false, v -> elegirArchivo()),
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
        t.setPaddingRelative(dp(14), 0, dp(6), 0);
        TextView titulo = Ui.texto(this, f.esFoto() ? getString(R.string.x39_foto) : (f.nombre.isEmpty() ? getString(R.string.x39_archivo) : f.nombre), 15, Ui.TEXTO, true);
        titulo.setSingleLine(true);
        titulo.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        t.addView(titulo);
        t.addView(Ui.texto(this, fechaCorta(f.capturada) + (f.esFoto() ? "" : " · " + tamano(f)), 13, Ui.SUAVE, false));
        t.addView(Ui.mono(this, getString(R.string.x39_huella_corta, f.sha256.substring(0, 12)), 12, Ui.SUAVE));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(6), 0, 0);
        t.addView(pildora(f), lp);
        card.addView(t, Ui.peso(1));
        card.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.TENUE, 18));
        card.setContentDescription(getString(f.esFoto() ? R.string.x39_ficha_desc_foto : R.string.x39_ficha_desc_archivo, fechaCorta(f.capturada)));
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
                texto = getString(R.string.x39_pildora_anclada, f.bloque);
                fondo = Ui.BLANCO;
                color = Ui.FONDO;
                break;
            case "calendar":
                texto = getString(R.string.x39_pildora_calendarios);
                fondo = Ui.SUPERFICIE_2;
                color = Ui.TEXTO;
                break;
            default:
                // El texto sigue al interruptor: con «Anclar solo por Tor» encendido la huella espera a Tor, apagado espera red.
                texto = getString(Orbot.soloTor(this) ? R.string.x39_pildora_espera_tor : R.string.x39_pildora_espera_red);
                fondo = Ui.CAJA;
                color = Ui.TEXTO_2;
                break;
        }
        TextView p = Ui.texto(this, texto, 12, color, true);
        p.setPadding(dp(10), dp(4), dp(10), dp(4));
        p.setBackground(Ui.redondeado(this, fondo, 12));
        return p;
    }

    private String fechaCorta(String iso) {
        try {
            return DateTimeFormatter.ofPattern(PATRON_FECHA, idioma()).format(OffsetDateTime.parse(iso));
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
            aviso(getString(R.string.x39_sin_espacio_archivo, Formatter.formatShortFileSize(this, total)));
            return;
        }

        TextView estado = Ui.texto(this, getString(R.string.x39_calculando_huella), 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(nombreFinal).setView(estado).setCancelable(false).show();
        final long inicio = System.currentTimeMillis();
        new Thread(() -> {
            Evidencias.Sellado sellado = null;
            String fallo = null;
            long[] ultimoAviso = {0};
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new FalloVisible(R.string.x39_motivo_sin_acceso_archivo);
                sellado = evidencias.sellar(in, Evidencias.ARCHIVO, nombreFinal, mime, hechos -> {
                    long ahora = System.currentTimeMillis();
                    if (ahora - ultimoAviso[0] < 250) return;
                    ultimoAviso[0] = ahora;
                    String t = total > 0
                            ? getString(R.string.x39_progreso_de_total_pct, Formatter.formatShortFileSize(this, hechos),
                                    Formatter.formatShortFileSize(this, total), hechos * 100 / total)
                            : Formatter.formatShortFileSize(this, hechos);
                    runOnUiThread(() -> estado.setText(getString(R.string.x39_calculando_huella_progreso, t)));
                });
            } catch (Exception e) {
                fallo = motivo(e);
            }
            final Evidencias.Sellado resultado = sellado;
            final String error = fallo;
            final long ms = System.currentTimeMillis() - inicio;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                if (!alChatSiToca(resultado, error)) mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso(getString(R.string.x39_error_sellar_archivo, error));
                } else if (resultado.yaExistia) {
                    aviso(getString(R.string.x39_archivo_ya_sellado));
                } else {
                    Toast.makeText(this, getString(R.string.x39_guardado_firmado_en, duracion(ms)), Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-archivo").start();
    }

    /** Duración con unidades del SI (ms, s): no se traducen; los decimales siguen al idioma actual. */
    private String duracion(long ms) {
        return ms < 1000 ? ms + " ms" : String.format(idioma(), "%.1f s", ms / 1000.0);
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

        View cabecera = barraSuperior(getString(R.string.x39_camara), () -> {
            cerrarCamara();
            mostrarPestana(Pestana.EVIDENCIAS);
        }, 0x66000000);
        marco.addView(cabecera, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP));

        LinearLayout abajo = Ui.columna(this);
        abajo.setGravity(Gravity.CENTER_HORIZONTAL);
        abajo.setPadding(0, dp(12), 0, dp(24));
        abajo.setBackgroundColor(0x66000000);
        TextView ayuda = Ui.texto(this, getString(R.string.x39_camara_ayuda), 13, Ui.TEXTO_2, false);
        ayuda.setPadding(0, 0, 0, dp(14));
        abajo.addView(ayuda);
        TextView cronometro = Ui.mono(this, "", 22, Ui.BLANCO);
        cronometro.setPadding(0, 0, 0, dp(10));
        cronometro.setVisibility(View.GONE);
        abajo.addView(cronometro);
        LinearLayout mandos = Ui.fila(this);
        mandos.setGravity(Gravity.CENTER_VERTICAL);
        TextView botonVideo = Ui.boton(this, getString(R.string.x39_video), false, null);
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
        disparador.setContentDescription(getString(R.string.x39_hacer_la_foto));
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
                cronometro.setText(String.format(idioma(), "%02d:%02d", ms / 60_000, (ms / 1000) % 60));
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
                botonVideo.setText(R.string.x39_parar);
                disparador.setVisibility(View.INVISIBLE);
                ayuda.setText(R.string.x39_camara_grabando);
                cronometro.setText("00:00");
                cronometro.setVisibility(View.VISIBLE);
                reloj.post(tic);
            }

            @Override
            public void video(File archivo, long duracionMs) {
                reloj.removeCallbacks(tic);
                cerrarCamara();
                procesarGrabacion(archivo, duracionMs, Evidencias.VIDEO, "video", "mp4", "video/mp4", getString(R.string.x39_video),
                        d -> getString(R.string.x39_video_guardado_firmado, d));
            }

            @Override
            public void error(String motivo) {
                reloj.removeCallbacks(tic);
                if (camara != null && !motivo.startsWith("la grabación es demasiado corta")) {
                    cerrarCamara();
                    mostrarPestana(Pestana.EVIDENCIAS);
                    aviso(getString(R.string.x39_error_camara, motivo));
                    return;
                }
                // Grabación demasiado corta: la cámara sigue abierta en modo foto.
                botonVideo.setEnabled(true);
                botonVideo.setText(R.string.x39_video);
                disparador.setVisibility(View.VISIBLE);
                cronometro.setVisibility(View.GONE);
                ayuda.setText(R.string.x39_camara_ayuda);
                Toast.makeText(EvidenciaActivity.this, R.string.x39_video_corto, Toast.LENGTH_SHORT).show();
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
        raizCol.addView(barraSuperior(getString(R.string.x39_audio), () -> {
            if (grabadoraAudio != null) pararAudio(reloj, ticRef[0]);
            else mostrarPestana(Pestana.EVIDENCIAS);
        }, 0));
        LinearLayout col = Ui.columna(this);
        col.setGravity(Gravity.CENTER_HORIZONTAL);
        col.setPadding(dp(24), dp(40), dp(24), dp(24));
        col.addView(aro(Icono.Tipo.AUDIO), new LinearLayout.LayoutParams(dp(84), dp(84)));
        TextView ayuda = Ui.texto(this, getString(R.string.x39_audio_ayuda), 14, Ui.TEXTO_2, false);
        ayuda.setGravity(Gravity.CENTER);
        ayuda.setPadding(0, dp(18), 0, dp(24));
        col.addView(ayuda);
        TextView cronometro = Ui.mono(this, "00:00", 40, Ui.TEXTO);
        cronometro.setGravity(Gravity.CENTER);
        col.addView(cronometro);
        TextView tramoTxt = Ui.texto(this, "", 13, Ui.SUAVE, false);
        tramoTxt.setGravity(Gravity.CENTER);
        col.addView(tramoTxt);
        TextView boton = Ui.boton(this, getString(R.string.x39_grabar), true, null);
        ticRef[0] = new Runnable() {
            @Override
            public void run() {
                if (grabadoraAudio == null) return;
                long ahora = System.currentTimeMillis();
                long ms = ahora - inicioAudio;
                cronometro.setText(String.format(idioma(), "%02d:%02d", ms / 60_000, (ms / 1000) % 60));
                tramoTxt.setText(getResources().getQuantityString(R.plurals.x39_audio_tramo_sellados, numTramo - 1, numTramo, numTramo - 1));
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
                        aviso(getString(R.string.x39_audio_error_tramo_siguiente, motivo(e)));
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
                aviso(getString(R.string.x39_audio_sin_espacio, Formatter.formatShortFileSize(this, libre)));
                return;
            }
            try {
                pedirFoco(reloj, ticRef[0]);
                sesionAudio = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss", ES).format(new java.util.Date());
                numTramo = 0;
                inicioAudio = System.currentTimeMillis();
                iniciarTramo();
                boton.setText(R.string.x39_parar);
                ayuda.setText(R.string.x39_audio_grabando);
                reloj.post(ticRef[0]);
            } catch (Exception e) {
                grabadoraAudio = null;
                soltarFoco();
                aviso(getString(R.string.x39_error_grabar, motivo(e)));
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
                fallo = motivo(e);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (error != null) aviso(getString(R.string.x39_error_sellar_tramo, tramo, error));
                else {
                    Toast.makeText(this, getString(R.string.x39_tramo_sellado, tramo, duracion(duracionMs)), Toast.LENGTH_SHORT).show();
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
                aviso(getString(R.string.x39_grabacion_corta));
                abrirGrabadora();
            } else {
                mostrarPestana(Pestana.EVIDENCIAS);
            }
            return;
        }
        procesarGrabacion(f, duracion, Evidencias.AUDIO, "audio", "m4a", "audio/mp4",
                tramo > 1 ? getString(R.string.x39_audio_tramo_titulo, tramo) : getString(R.string.x39_audio),
                tramo > 1 ? d -> getString(R.string.x39_audio_tramo_guardado_firmado, tramo, d)
                        : d -> getString(R.string.x39_audio_guardado_firmado, d),
                nombreTramo(tramo, "m4a"));
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
                            Toast.makeText(this, R.string.x39_grabacion_cortada_llamada, Toast.LENGTH_LONG).show();
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

    private void procesarGrabacion(File archivo, long duracionMs, String tipo, String prefijo, String extension, String mime, String titulo,
                                   java.util.function.Function<String, String> hecho) {
        procesarGrabacion(archivo, duracionMs, tipo, prefijo, extension, mime, titulo, hecho, null);
    }

    /**
     * Sella una grabación temporal (vídeo o audio) como evidencia (huella, cifrado por trozos, firma) y la borra.
     * @param hecho el aviso final entero («Vídeo guardado y firmado en …») a partir de la duración ya formateada.
     */
    private void procesarGrabacion(File archivo, long duracionMs, String tipo, String prefijo, String extension, String mime, String titulo,
                                   java.util.function.Function<String, String> hecho, String nombreFijo) {
        final long total = archivo.length();
        final String nombre = nombreFijo != null ? nombreFijo
                : prefijo + "-" + new java.text.SimpleDateFormat("yyyyMMdd-HHmmss", ES).format(new java.util.Date()) + "." + extension;
        TextView estado = Ui.texto(this, getString(R.string.x39_calculando_huella), 14, Ui.TEXTO, false);
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
                    String t = total > 0
                            ? getString(R.string.x39_progreso_de_total, Formatter.formatShortFileSize(this, hechos), Formatter.formatShortFileSize(this, total))
                            : Formatter.formatShortFileSize(this, hechos);
                    runOnUiThread(() -> estado.setText(getString(R.string.x39_calculando_huella_progreso, t)));
                });
            } catch (Exception e) {
                fallo = motivo(e);
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
                if (!alChatSiToca(resultado, error)) mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso(getString(R.string.x39_error_guardar, error));
                } else if (resultado.yaExistia) {
                    aviso(getString(R.string.x39_grabacion_ya_sellada));
                } else {
                    Toast.makeText(this, hecho.apply(duracion(ms)), Toast.LENGTH_SHORT).show();
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
                fallo = motivo(e);
            } finally {
                Arrays.fill(jpeg, (byte) 0);
            }
            final String error = fallo;
            final long ms = System.currentTimeMillis() - inicio;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                mostrarPestana(Pestana.EVIDENCIAS);
                if (error != null) {
                    aviso(getString(R.string.x39_error_guardar_evidencia, error));
                } else {
                    Toast.makeText(this, getString(R.string.x39_firmada_en, duracion(ms)), Toast.LENGTH_SHORT).show();
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
                Toast.makeText(this, R.string.x39_ya_puedes_grabar, Toast.LENGTH_SHORT).show();
            } else {
                aviso(getString(R.string.x39_sin_permiso_microfono_audio));
            }
            return;
        }
        if (requestCode == REQ_MICROFONO) {
            // La cámara sigue abierta; el usuario vuelve a pulsar «Vídeo». Sin micrófono se graba sin sonido.
            if (grantResults.length == 0 || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                microfonoNegado = true;
                Toast.makeText(this, R.string.x39_sin_microfono_video, Toast.LENGTH_LONG).show();
            }
            return;
        }
        if (requestCode != REQ_CAMARA) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            abrirCamara();
        } else {
            aviso(getString(R.string.x39_sin_permiso_camara));
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
        raizCol.addView(barraSuperior(getString(R.string.x39_evidencia_titulo), () -> mostrarPestana(Pestana.EVIDENCIAS), 0));
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
            tx.setPaddingRelative(dp(14), 0, 0, 0);
            tx.addView(Ui.texto(this, f.nombre.isEmpty() ? getString(f.esVideo() ? R.string.x39_video : f.esAudio() ? R.string.x39_audio : R.string.x39_archivo) : f.nombre, 16, Ui.TEXTO, true));
            tx.addView(Ui.texto(this, f.mime + " · " + tamano(f), 13, Ui.SUAVE, false));
            arch.addView(tx, Ui.peso(1));
            col.addView(arch, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, f.esImagen() && f.bytes <= MAX_VISTA ? 12 : 0, 0, 0));
        }

        LinearLayout datos = Ui.columna(this);
        datos.setPadding(dp(18), dp(16), dp(18), dp(16));
        datos.setBackground(Ui.degradado(this, 24));
        LinearLayout.LayoutParams lpp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        datos.addView(pildora(f), lpp);
        dato(datos, getString(R.string.x39_ficha_huella), f.sha256, true);
        dato(datos, getString(R.string.x39_ficha_hora), f.capturada, false);
        String etiquetaClave;
        try {
            etiquetaClave = f.firmante.equals(evidencias.huellaClave())
                    ? getString(R.string.x39_ficha_firmada_con_clave_bytes, miles(evidencias.clavePublica().length))
                    : getString(R.string.x39_ficha_firmada_con_clave);
        } catch (Exception e) {
            etiquetaClave = getString(R.string.x39_ficha_firmada_con_clave);
        }
        dato(datos, etiquetaClave, agrupar(f.firmante), true);
        int bytesFirma = Base64.decode(f.firma, Base64.NO_WRAP).length;
        dato(datos, getString(R.string.x39_ficha_firma), getString(R.string.x39_ficha_firma_valor, miles(bytesFirma)), false);
        String ancla;
        switch (f.otsEstado) {
            case "bitcoin":
                ancla = getString(f.esFoto() ? R.string.x39_ancla_bitcoin_foto : f.esVideo() ? R.string.x39_ancla_bitcoin_video
                        : f.esAudio() ? R.string.x39_ancla_bitcoin_audio : R.string.x39_ancla_bitcoin_archivo, f.bloque);
                break;
            case "calendar":
                ancla = getString(R.string.x39_ancla_calendarios);
                break;
            default:
                ancla = getString(Orbot.soloTor(this) ? R.string.x39_ancla_espera_tor : R.string.x39_ancla_espera_red);
                break;
        }
        dato(datos, getString(R.string.x39_ficha_ancla), ancla, false);
        col.addView(datos, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 14));

        col.addView(Ui.boton(this, getString(R.string.x39_verificar_ahora), true, v -> verificar(f)));
        espacio(col);
        col.addView(Ui.boton(this, getString(R.string.x39_compartir_recibo), false, v -> compartirRecibo(f)));
        espacio(col);
        col.addView(Ui.boton(this, getString(R.string.x39_compartir_capsula), false, v -> confirmarCapsula(f)));
        espacio(col);
        col.addView(Ui.boton(this, getString(f.esFoto() ? R.string.x39_exportar_foto : R.string.x39_exportar_archivo), false, v -> confirmarExportar(f)));
        espacio(col);
        col.addView(Ui.boton(this, getString(R.string.x39_borrar), false, v -> confirmarBorrar(f)));
        TextView nota = Ui.texto(this, getString(f.esFoto() ? R.string.x39_ficha_nota_foto : R.string.x39_ficha_nota_archivo), 12, Ui.TENUE, false);
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
        AlertDialog espera = new AlertDialog.Builder(this).setMessage(R.string.x39_verificando).setCancelable(false).show();
        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            boolean foto = f.esFoto();
            try {
                boolean huellaOk = evidencias.huellaGuardada(f).equals(f.sha256);
                sb.append(getString(huellaOk
                        ? (foto ? R.string.x39_verif_huella_ok_foto : R.string.x39_verif_huella_ok_archivo)
                        : (foto ? R.string.x39_verif_huella_mal_foto : R.string.x39_verif_huella_mal_archivo))).append("\n\n");
            } catch (GeneralSecurityException e) {
                // El cifrado autenticado detecta cualquier byte cambiado antes de llegar a la huella.
                sb.append(getString(foto ? R.string.x39_verif_huella_danada_foto : R.string.x39_verif_huella_danada_archivo)).append("\n\n");
            } catch (Exception e) {
                sb.append(getString(foto ? R.string.x39_verif_no_leer_foto : R.string.x39_verif_no_leer_archivo, motivo(e))).append("\n\n");
            }
            try {
                X39Core.verifyMessage(evidencias.clavePublica(), f.canonica().getBytes(StandardCharsets.UTF_8), Base64.decode(f.firma, Base64.NO_WRAP));
                boolean mismaClave = evidencias.huellaClave().equals(f.firmante);
                sb.append(getString(mismaClave ? R.string.x39_verif_firma_ok : R.string.x39_verif_firma_otra_clave)).append("\n\n");
            } catch (Exception e) {
                sb.append(getString(R.string.x39_verif_firma_invalida)).append("\n\n");
            }
            try {
                byte[] ots = evidencias.ots(f);
                if (ots == null) {
                    sb.append(getString(R.string.x39_verif_sin_ots));
                } else {
                    String bloques = X39Core.otsBlocks(ots);
                    String pendientes = X39Core.otsPending(ots);
                    int n = pendientes.isEmpty() ? 0 : pendientes.split("\n").length;
                    sb.append(bloques.isEmpty()
                            ? getResources().getQuantityString(R.plurals.x39_verif_ots_pendiente, n, n)
                            : getString(R.string.x39_verif_ots_bloque, bloques));
                }
            } catch (Exception e) {
                sb.append(getString(R.string.x39_verif_ots_invalida, motivo(e)));
            }
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                new AlertDialog.Builder(this).setTitle(R.string.x39_verificacion).setMessage(sb.toString()).setPositiveButton(R.string.x39_entendido, null).show();
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
            compartirFicheros(uris, getString(f.esFoto() ? R.string.x39_compartir_recibo_sin_foto : R.string.x39_compartir_recibo_sin_archivo));
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_preparar_recibo, motivo(e)));
        }
    }

    /**
     * La cápsula lleva el ORIGINAL tal cual, con todos sus datos (ubicación, hora, cámara):
     * son parte de la prueba y aquí no se limpia nada. Por eso se avisa antes.
     */
    private void confirmarCapsula(Evidencias.Ficha f) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.x39_capsula_titulo)
                .setMessage(f.esFoto() ? R.string.x39_capsula_confirmar_foto : R.string.x39_capsula_confirmar_archivo)
                .setPositiveButton(R.string.x39_preparar_capsula, (d, w) -> compartirCapsula(f))
                .setNegativeButton(R.string.x39_cancelar, null)
                .show();
    }

    private void compartirCapsula(Evidencias.Ficha f) {
        final String nombre = "x39-capsula-" + f.id + ".zip";
        final File destino = new File(ProveedorRecibos.carpeta(this), nombre);
        TextView estado = Ui.texto(this, getString(R.string.x39_preparando_capsula), 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(nombre).setView(estado).setCancelable(false).show();
        new Thread(() -> {
            String fallo = null;
            try (OutputStream out = new java.io.FileOutputStream(destino)) {
                Capsula.escribir(evidencias, f, nombreExportado(f), out);
            } catch (GeneralSecurityException e) {
                fallo = getString(R.string.x39_motivo_danado_no_entrega);
            } catch (Exception e) {
                fallo = motivo(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                if (error != null) {
                    //noinspection ResultOfMethodCallIgnored
                    destino.delete();
                    aviso(getString(R.string.x39_error_preparar_capsula, error));
                    return;
                }
                ArrayList<Uri> uris = new ArrayList<>();
                uris.add(ProveedorRecibos.uri(this, nombre));
                compartirFicheros(uris, getString(R.string.x39_compartir_capsula_id, f.id));
            });
        }, "x39-capsula").start();
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
        new AlertDialog.Builder(this)
                .setTitle(f.esFoto() ? R.string.x39_exportar_titulo_foto : f.esVideo() ? R.string.x39_exportar_titulo_video
                        : f.esAudio() ? R.string.x39_exportar_titulo_audio : R.string.x39_exportar_titulo_archivo)
                .setMessage(f.esFoto() ? R.string.x39_exportar_mensaje_foto : f.esVideo() ? R.string.x39_exportar_mensaje_video
                        : f.esAudio() ? R.string.x39_exportar_mensaje_audio : R.string.x39_exportar_mensaje_archivo)
                .setNegativeButton(R.string.x39_cancelar, null)
                .setPositiveButton(R.string.x39_elegir_destino, (d, w) -> exportar(f))
                .show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_ESCANER) {
            if (resultCode == RESULT_OK && data != null) recibirEscaneo(data);
            return;
        }
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
        TextView estado = Ui.texto(this, getString(R.string.x39_descifrando), 14, Ui.TEXTO, false);
        estado.setPadding(dp(24), dp(20), dp(24), dp(8));
        AlertDialog espera = new AlertDialog.Builder(this).setTitle(nombre).setView(estado).setCancelable(false).show();
        new Thread(() -> {
            String fallo = null;
            try (OutputStream out = new java.io.FileOutputStream(destino)) {
                evidencias.descifrarA(f, out);
            } catch (GeneralSecurityException e) {
                fallo = getString(R.string.x39_motivo_danado_no_exporta);
            } catch (Exception e) {
                fallo = motivo(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                espera.dismiss();
                if (error != null) {
                    //noinspection ResultOfMethodCallIgnored
                    destino.delete();
                    aviso(getString(R.string.x39_error_exportar, error));
                    return;
                }
                Uri uri = ProveedorRecibos.uri(this, nombre);
                Intent i = new Intent(Intent.ACTION_SEND).setType(f.mime).putExtra(Intent.EXTRA_STREAM, uri);
                i.setClipData(ClipData.newRawUri(null, uri));
                i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivity(Intent.createChooser(i, getString(R.string.x39_exportar_nombre, nombre)));
            });
        }, "x39-exportar").start();
    }

    private void avisoOrbotNoInstalado() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.x39_orbot_no_instalado_titulo)
                .setMessage(R.string.x39_orbot_no_instalado_texto)
                .setNegativeButton(R.string.x39_ahora_no, null)
                .setNeutralButton(R.string.x39_guardian_project, (d, w) -> abrirWeb(Orbot.GUARDIAN))
                .setPositiveButton(R.string.x39_f_droid, (d, w) -> abrirWeb(Orbot.F_DROID))
                .show();
    }

    /** Abre una web en el navegador del sistema (la app no la descarga: solo lanza el intent). */
    private void abrirWeb(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (android.content.ActivityNotFoundException e) {
            aviso(getString(R.string.x39_sin_navegador, url));
        }
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
                .setTitle(R.string.x39_borrar_evidencia_titulo)
                .setMessage(f.esFoto() ? R.string.x39_borrar_evidencia_foto : R.string.x39_borrar_evidencia_archivo)
                .setNegativeButton(R.string.x39_cancelar, null)
                .setPositiveButton(R.string.x39_borrar, (d, w) -> {
                    try {
                        evidencias.borrar(f);
                    } catch (Exception e) {
                        aviso(motivo(e));
                    }
                    mostrarPestana(Pestana.EVIDENCIAS);
                })
                .show();
    }

    // ------------------------------------------------------------------ seguridad

    private View pantallaContactos() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_contactos), null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));

        LinearLayout mia = tarjeta(col, getString(R.string.x39_mi_identidad));
        if (evidencias.tieneIdentidad()) {
            try {
            byte[] pk = evidencias.clavePublica();
            String fp = Evidencias.sha256Hex(pk);
            TextView hv = Ui.mono(this, bloquesHuella(fp), 15, Ui.TEXTO);
            hv.setLineSpacing(dp(4), 1f);
            mia.addView(hv);
            mia.addView(Ui.texto(this, getString(R.string.x39_contactos_mi_huella_nota), 13, Ui.SUAVE, false),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
            ImageView qr = new ImageView(this);
            qr.setAdjustViewBounds(true);
            qr.setScaleType(ImageView.ScaleType.FIT_CENTER);
            qr.setBackground(Ui.redondeado(this, 0xFFFFFFFF, 14));
            qr.setPadding(dp(8), dp(8), dp(8), dp(8));
            qr.setContentDescription(getString(R.string.x39_contactos_qr_desc));
            mia.addView(qr, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
            dibujarQr(qr, pk);
            mia.addView(Ui.boton(this, getString(R.string.x39_qr_por_partes), true, v -> qrPorPartes()),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
            mia.addView(Ui.boton(this, getString(R.string.x39_copiar_mi_huella), false, v -> copiarHuella(fp)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
            mia.addView(Ui.boton(this, getString(R.string.x39_copiar_identidad_mensajes), false, v -> copiarIdentidadMensajes()),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
            mia.addView(Ui.texto(this, getString(R.string.x39_contactos_identidad_nota), 12, Ui.TENUE, false),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 0));
            } catch (Exception e) {
                mia.addView(Ui.texto(this, getString(R.string.x39_error_leer_identidad), 13, Ui.AVISO, false));
            }
        } else {
            mia.addView(Ui.texto(this, getString(R.string.x39_sin_identidad), 13, Ui.AVISO, false));
        }

        LinearLayout add = tarjeta(col, getString(R.string.x39_anadir_contacto));
        add.addView(Ui.boton(this, getString(R.string.x39_escanear_qr_otra), true, v -> escanear()),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 6));
        final android.widget.EditText nombre = Ui.campo(this, getString(R.string.x39_hint_nombre_contacto), 1, false);
        final android.widget.EditText clave = Ui.campo(this, getString(R.string.x39_hint_identidad_contacto), 3, true);
        add.addView(nombre, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 0));
        add.addView(clave, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
        add.addView(Ui.boton(this, getString(R.string.x39_guardar_contacto), true, v -> {
            String n = nombre.getText().toString().trim();
            String bruto = clave.getText().toString().trim();
            if (n.isEmpty()) { aviso(getString(R.string.x39_contacto_sin_nombre)); return; }
            if (bruto.startsWith("X39ID1:")) {
                try {
                    Object[] id = ChatEvidencia.leerIdentidad(bruto);
                    if (esPropia((byte[]) id[0], (byte[]) id[1])) { aviso(getString(R.string.x39_identidad_propia)); return; }
                    guardarContacto(n, (String) id[2], (byte[]) id[0], (byte[]) id[1]);
                    aviso(getString(R.string.x39_contacto_guardado_sin_verificar));
                    compararHuellas((String) id[2]);
                } catch (Exception e) {
                    aviso(getString(R.string.x39_identidad_no_valida, motivo(e)));
                }
                return;
            }
            String hh = bruto.toLowerCase(ES).replaceAll("[^0-9a-f]", "");
            if (hh.length() != 64) { aviso(getString(R.string.x39_huella_64)); return; }
            guardarContacto(n, hh);
            aviso(getString(R.string.x39_contacto_guardado));
            mostrarPestana(Pestana.CONTACTOS);
        }), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

        LinearLayout lista = tarjeta(col, getString(R.string.x39_tus_contactos));
        org.json.JSONArray cs = cargarContactos();
        if (cs.length() == 0) {
            lista.addView(Ui.texto(this, getString(R.string.x39_sin_contactos), 13, Ui.SUAVE, false));
        } else {
            for (int i = 0; i < cs.length(); i++) {
                org.json.JSONObject c = cs.optJSONObject(i);
                if (c == null) continue;
                String h = c.optString("huella", "");
                LinearLayout fila = Ui.fila(this);
                LinearLayout txt = Ui.columna(this);
                txt.addView(Ui.texto(this, c.optString("nombre", getString(R.string.x39_sin_nombre)), 15, Ui.TEXTO, true));
                txt.addView(Ui.mono(this, getString(R.string.x39_huella_corta, h.length() >= 12 ? h.substring(0, 12) : h), 12, Ui.SUAVE));
                if (!c.optString("kem").isEmpty()) txt.addView(estadoVerificacion(c.optBoolean("verificado", false)));
                final org.json.JSONObject cf = c;
                fila.addView(txt, Ui.peso(1));
                fila.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.SUAVE, 18));
                fila.setClickable(true);
                fila.setOnClickListener(vv -> menuContacto(cf));
                fila.setPadding(dp(4), dp(10), dp(4), dp(10));
                lista.addView(fila);
            }
        }

        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private File ficheroContactos() {
        return new File(getFilesDir(), "contactos.json");
    }

    private org.json.JSONArray cargarContactos() {
        try {
            File f = ficheroContactos();
            if (!f.exists()) return new org.json.JSONArray();
            byte[] b = new byte[(int) f.length()];
            try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
                int off = 0, r;
                while (off < b.length && (r = in.read(b, off, b.length - off)) > 0) off += r;
            }
            return new org.json.JSONArray(new String(b, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new org.json.JSONArray();
        }
    }

    private void guardarContactos(org.json.JSONArray cs) {
        try {
            Evidencias.escribirAtomico(ficheroContactos(), cs.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_guardar, motivo(e)));
        }
    }

    /** Contacto con identidad para mensajes: guarda también su clave de cifrar y la de firmar. */
    private void guardarContacto(String nombre, String huella, byte[] kem, byte[] sig) {
        try {
            org.json.JSONArray cs = cargarContactos();
            org.json.JSONObject c = null;
            for (int i = 0; i < cs.length(); i++) {
                org.json.JSONObject x = cs.optJSONObject(i);
                if (x != null && huella.equals(x.optString("huella"))) c = x;
            }
            if (c == null) { c = new org.json.JSONObject(); cs.put(c); }
            String kemB = Base64.encodeToString(kem, Base64.NO_WRAP), sigB = Base64.encodeToString(sig, Base64.NO_WRAP);
            // «Verificado» solo se conserva si las claves son las mismas que se compararon de viva voz.
            if (!kemB.equals(c.optString("kem")) || !sigB.equals(c.optString("sig"))) c.remove("verificado");
            c.put("nombre", nombre);
            c.put("huella", huella);
            c.put("kem", kemB);
            c.put("sig", sigB);
            guardarContactos(cs);
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_guardar, motivo(e)));
        }
    }

    private void copiarIdentidadMensajes() {
        try {
            ChatEvidencia chat = ChatEvidencia.de(this);
            if (!chat.listo()) { aviso(getString(R.string.x39_crea_identidad_primero)); return; }
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.x39_clip_identidad), chat.miIdentidadTexto()));
            aviso(getString(R.string.x39_identidad_copiada));
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_copiar, motivo(e)));
        }
    }

    private void guardarContacto(String nombre, String huella) {
        try {
            org.json.JSONArray cs = cargarContactos();
            for (int i = 0; i < cs.length(); i++) {
                org.json.JSONObject c = cs.optJSONObject(i);
                if (c != null && huella.equals(c.optString("huella"))) {
                    c.put("nombre", nombre);
                    guardarContactos(cs);
                    return;
                }
            }
            org.json.JSONObject c = new org.json.JSONObject();
            c.put("nombre", nombre);
            c.put("huella", huella);
            cs.put(c);
            guardarContactos(cs);
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_guardar, motivo(e)));
        }
    }

    private void borrarContacto(int idx) {
        org.json.JSONArray cs = cargarContactos();
        org.json.JSONArray n = new org.json.JSONArray();
        for (int i = 0; i < cs.length(); i++) if (i != idx) n.put(cs.opt(i));
        guardarContactos(n);
    }

    // ------------------------------------------------------------------ QR y verificación de huellas

    private void escanear() {
        startActivityForResult(new Intent(this, EscanerQrActivity.class), REQ_ESCANER);
    }

    /** true si las claves leídas son las de este mismo móvil: nadie se añade a sí mismo. */
    private boolean esPropia(byte[] kem, byte[] sig) {
        try {
            Object[] mia = ChatEvidencia.leerIdentidad(ChatEvidencia.de(this).miIdentidadTexto());
            return Arrays.equals((byte[]) mia[0], kem) || Arrays.equals((byte[]) mia[1], sig);
        } catch (Exception e) {
            return false;
        }
    }

    private void recibirEscaneo(Intent data) {
        if (data.getStringExtra(EscanerQrActivity.RESULTADO_ERROR) != null) {
            new AlertDialog.Builder(this).setTitle(R.string.x39_qr_mezcla_titulo).setMessage(R.string.x39_qr_mezcla_texto)
                    .setPositiveButton(R.string.x39_entendido, null).show();
            return;
        }
        String texto = data.getStringExtra(EscanerQrActivity.RESULTADO_TEXTO);
        if (texto == null) return;
        final Object[] id;
        try {
            id = ChatEvidencia.leerIdentidad(texto);
        } catch (Exception e) {
            aviso(getString(R.string.x39_identidad_no_valida, motivo(e)));
            return;
        }
        if (esPropia((byte[]) id[0], (byte[]) id[1])) { aviso(getString(R.string.x39_qr_propio)); return; }
        final android.widget.EditText campo = Ui.campo(this, getString(R.string.x39_hint_nombre_contacto), 1, false);
        FrameLayout marco = new FrameLayout(this);
        marco.setPadding(dp(20), dp(8), dp(20), 0);
        marco.addView(campo);
        final String h = (String) id[2];
        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.x39_identidad_leida, h.substring(0, 12)))
                .setView(marco)
                .setPositiveButton(R.string.x39_guardar_contacto, (d, w) -> {
                    String n = campo.getText().toString().trim();
                    if (n.isEmpty()) { aviso(getString(R.string.x39_contacto_sin_nombre)); return; }
                    // Se guarda NO verificado y se pasa siempre a comparar las huellas de viva voz.
                    guardarContacto(n, h, (byte[]) id[0], (byte[]) id[1]);
                    aviso(getString(R.string.x39_contacto_guardado_sin_verificar));
                    compararHuellas(h);
                })
                .setNegativeButton(R.string.x39_cancelar, null)
                .show();
    }

    private org.json.JSONObject contactoPorHuella(String huella) {
        org.json.JSONArray cs = cargarContactos();
        for (int i = 0; i < cs.length(); i++) {
            org.json.JSONObject c = cs.optJSONObject(i);
            if (c != null && huella.equals(c.optString("huella"))) return c;
        }
        return null;
    }

    private void marcarVerificado(String huella, boolean si) {
        try {
            org.json.JSONArray cs = cargarContactos();
            for (int i = 0; i < cs.length(); i++) {
                org.json.JSONObject c = cs.optJSONObject(i);
                if (c != null && huella.equals(c.optString("huella"))) {
                    if (si) c.put("verificado", true); else c.remove("verificado");
                }
            }
            guardarContactos(cs);
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_guardar, motivo(e)));
        }
    }

    /** «✓ verificado» discreto, o «⚠ SIN VERIFICAR» bien visible. */
    private View estadoVerificacion(boolean verificado) {
        TextView t = Ui.texto(this, getString(verificado ? R.string.x39_contacto_verificado : R.string.x39_contacto_sin_verificar),
                verificado ? 12 : 13, verificado ? Ui.SUAVE : 0xFF000000, !verificado);
        if (!verificado) {
            t.setBackground(Ui.redondeado(this, 0xFFE3A83A, 8));
            t.setPadding(dp(8), dp(2), dp(8), dp(2));
        }
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(4);
        t.setLayoutParams(lp);
        return t;
    }

    /**
     * Las DOS huellas (la mía y la suya, sobre las dos claves) para leerlas en voz alta. Solo al confirmar que
     * coinciden pasa a verificado. «No coinciden»: aviso serio y se borra el contacto. «Ahora no»: queda sin verificar.
     */
    private void compararHuellas(String huella) {
        abrirSecundaria(() -> mostrar(pantallaComparar(huella), true));
    }

    private View pantallaComparar(String huella) {
        org.json.JSONObject c = contactoPorHuella(huella);
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_huellas_titulo), () -> mostrarPestana(Pestana.CONTACTOS), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        if (c == null || c.optString("kem").isEmpty()) {
            col.addView(Ui.texto(this, getString(R.string.x39_contacto_sin_identidad_mensajes), 13, Ui.SUAVE, false));
        } else {
            final String nombre = c.optString("nombre", getString(R.string.x39_sin_nombre));
            String suya = null, mia = null;
            try {
                suya = X39Core.identityFingerprint(Base64.decode(c.optString("kem"), Base64.NO_WRAP), Base64.decode(c.optString("sig"), Base64.NO_WRAP));
                Object[] yo = ChatEvidencia.leerIdentidad(ChatEvidencia.de(this).miIdentidadTexto());
                mia = X39Core.identityFingerprint((byte[]) yo[0], (byte[]) yo[1]);
            } catch (Exception e) {
                col.addView(Ui.texto(this, getString(R.string.x39_error_leer_identidad), 13, Ui.AVISO, false));
            }
            if (suya != null && mia != null) {
                col.addView(Ui.texto(this, getString(R.string.x39_huellas_texto), 13, Ui.SUAVE, false));
                LinearLayout t1 = tarjeta(col, getString(R.string.x39_huellas_la_tuya));
                t1.addView(Ui.mono(this, cuatroPorLinea(mia), 17, Ui.TEXTO));
                LinearLayout t2 = tarjeta(col, getString(R.string.x39_huellas_la_de, nombre.toUpperCase(Locale.getDefault())));
                t2.addView(Ui.mono(this, cuatroPorLinea(suya), 17, Ui.TEXTO));
                col.addView(Ui.boton(this, getString(R.string.x39_huellas_coinciden), true, v -> {
                    marcarVerificado(huella, true);
                    aviso(getString(R.string.x39_huellas_verificado, nombre));
                    mostrarPestana(Pestana.CONTACTOS);
                }), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 16, 0, 0));
                col.addView(Ui.boton(this, getString(R.string.x39_huellas_no_coinciden), false, v ->
                        new AlertDialog.Builder(this)
                                .setTitle(R.string.x39_huellas_no_coinciden_titulo)
                                .setMessage(getString(R.string.x39_huellas_no_coinciden_texto, nombre))
                                .setCancelable(false)
                                .setPositiveButton(R.string.x39_borrar_contacto, (d, w) -> {
                                    borrarContactoPorHuella(huella);
                                    aviso(getString(R.string.x39_contacto_borrado));
                                    mostrarPestana(Pestana.CONTACTOS);
                                })
                                .setNegativeButton(R.string.x39_cancelar, null)
                                .show()), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
                col.addView(Ui.boton(this, getString(R.string.x39_ahora_no), false, v -> {
                    org.json.JSONObject ahora = contactoPorHuella(huella);
                    if (ahora != null && !ahora.optBoolean("verificado", false)) aviso(getString(R.string.x39_contacto_guardado_sin_verificar));
                    mostrarPestana(Pestana.CONTACTOS);
                }), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
            }
        }
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    /** "12345 67890 …" (12 grupos) en tres líneas de cuatro grupos, para leerla sin perderse. */
    private static String cuatroPorLinea(String h) {
        String[] g = h.trim().split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < g.length; i++) {
            sb.append(g[i]);
            if (i < g.length - 1) sb.append(i % 4 == 3 ? "\n" : "  ");
        }
        return sb.toString();
    }

    /**
     * Identidad COMPLETA (X39ID1, las dos claves) en 12 QR pequeños que se alternan cada 1,2 s a pantalla completa,
     * con el brillo al máximo y la pantalla encendida. Sin servidor. Tocar para cerrar.
     */
    private void qrPorPartes() {
        final java.util.List<String> partes;
        try {
            partes = QrPartes.trocear(ChatEvidencia.de(this).miIdentidadTexto(), QrPartes.PARTES);
        } catch (Exception e) {
            aviso(getString(R.string.x39_crea_identidad_primero));
            return;
        }
        final android.app.Dialog dialogo = new android.app.Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen);
        final ImageView img = new ImageView(this);
        img.setScaleType(ImageView.ScaleType.FIT_CENTER);
        img.setBackgroundColor(0xFFFFFFFF);
        img.setPadding(dp(12), dp(12), dp(12), dp(12));
        img.setContentDescription(getString(R.string.x39_qr_por_partes));
        final TextView cuenta = new TextView(this);
        cuenta.setTextColor(0xFF000000);
        cuenta.setTextSize(14);
        cuenta.setGravity(android.view.Gravity.CENTER);
        cuenta.setBackgroundColor(0xFFFFFFFF);
        cuenta.setPadding(0, dp(8), 0, dp(16));
        LinearLayout raiz = new LinearLayout(this);
        raiz.setOrientation(LinearLayout.VERTICAL);
        raiz.setBackgroundColor(0xFFFFFFFF);
        raiz.addView(img, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        raiz.addView(cuenta);
        raiz.setOnClickListener(v -> dialogo.dismiss());
        img.setOnClickListener(v -> dialogo.dismiss());
        dialogo.setContentView(raiz);
        if (dialogo.getWindow() != null) {
            dialogo.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            WindowManager.LayoutParams a = dialogo.getWindow().getAttributes();
            a.screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL;
            dialogo.getWindow().setAttributes(a);
        }
        final android.graphics.drawable.BitmapDrawable[] mapas = new android.graphics.drawable.BitmapDrawable[partes.size()];
        final android.os.Handler bucle = new android.os.Handler(getMainLooper());
        final int[] i = {0};
        final Runnable paso = new Runnable() {
            @Override public void run() {
                if (!dialogo.isShowing()) return;
                if (mapas[i[0]] == null) {
                    mapas[i[0]] = new android.graphics.drawable.BitmapDrawable(getResources(),
                            bitmapQr(partes.get(i[0]).getBytes(StandardCharsets.ISO_8859_1)));
                    mapas[i[0]].setFilterBitmap(false);
                }
                img.setImageDrawable(mapas[i[0]]);
                cuenta.setText(getString(R.string.x39_qr_parte_de, i[0] + 1, partes.size()));
                i[0] = (i[0] + 1) % partes.size();
                bucle.postDelayed(this, 1200);
            }
        };
        dialogo.setOnDismissListener(d -> bucle.removeCallbacks(paso));
        dialogo.show();
        paso.run();
    }

    /** Bitmap nítido de un QR: margen de 4 módulos, escala entera hasta ~1080 px, sin suavizado. */
    private static Bitmap bitmapQr(byte[] datos) {
        byte[] m = X39Core.qrMatrix(datos);
        int ancho = ((m[0] & 0xff) << 8) | (m[1] & 0xff);
        int margen = 4, lado = ancho + 2 * margen;
        int[] px = new int[lado * lado];
        Arrays.fill(px, 0xFFFFFFFF);
        for (int y = 0; y < ancho; y++) for (int x = 0; x < ancho; x++) {
            if (m[2 + y * ancho + x] != 0) px[(y + margen) * lado + x + margen] = 0xFF000000;
        }
        Bitmap base = Bitmap.createBitmap(px, lado, lado, Bitmap.Config.ARGB_8888);
        int escala = Math.max(1, 1080 / lado);
        return Bitmap.createScaledBitmap(base, lado * escala, lado * escala, false);
    }

    private View pantallaFichaContacto(final org.json.JSONObject c) {
        final String nombre = c.optString("nombre", getString(R.string.x39_sin_nombre));
        final String huella = c.optString("huella", "");
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(nombre, () -> mostrarPestana(Pestana.CONTACTOS), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));

        LinearLayout th = tarjeta(col, getString(R.string.x39_su_huella));
        TextView hv = Ui.mono(this, bloquesHuella(huella), 15, Ui.TEXTO);
        hv.setLineSpacing(dp(4), 1f);
        th.addView(hv);
        th.addView(Ui.texto(this, getString(R.string.x39_su_huella_nota), 13, Ui.SUAVE, false),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
        th.addView(Ui.boton(this, getString(R.string.x39_copiar_huella), false, v -> copiarHuella(huella)),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

        if (!c.optString("kem").isEmpty()) {
            LinearLayout tv = tarjeta(col, getString(R.string.x39_huellas_titulo));
            tv.addView(estadoVerificacion(c.optBoolean("verificado", false)));
            tv.addView(Ui.boton(this, getString(R.string.x39_comparar_huellas), !c.optBoolean("verificado", false), v -> compararHuellas(huella)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        }

        LinearLayout tm = tarjeta(col, getString(R.string.x39_mensajes));
        if (c.optString("kem").isEmpty()) {
            tm.addView(Ui.texto(this, getString(R.string.x39_contacto_sin_identidad_mensajes), 13, Ui.SUAVE, false));
        } else {
            tm.addView(Ui.boton(this, getString(R.string.x39_escribir_a, nombre), true, v -> abrirConversacion(huella, nombre)));
        }

        col.addView(Ui.boton(this, getString(R.string.x39_borrar_contacto), false, v -> { borrarContactoPorHuella(huella); mostrarPestana(Pestana.CONTACTOS); }),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 16, 0, 0));

        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void borrarContactoPorHuella(String huella) {
        org.json.JSONArray cs = cargarContactos();
        org.json.JSONArray n = new org.json.JSONArray();
        for (int i = 0; i < cs.length(); i++) {
            org.json.JSONObject c = cs.optJSONObject(i);
            if (c != null && huella.equals(c.optString("huella"))) continue;
            n.put(cs.opt(i));
        }
        guardarContactos(n);
    }

    private View pantallaSeguridad() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_seguridad), null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        col.addView(Ui.texto(this, getString(R.string.x39_seguridad_subtitulo), 13, Ui.SUAVE, false));

        col.addView(Ui.boton(this, getString(R.string.x39_ajustes), false, v -> mostrarPestana(Pestana.AJUSTES)), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 4, 0, 8));
        LinearLayout permisos = tarjeta(col, getString(R.string.x39_permisos_titulo));
        try {
            @SuppressWarnings("deprecation")
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_PERMISSIONS);
            if (pi.requestedPermissions != null) {
                for (String p : pi.requestedPermissions) permisos.addView(Ui.mono(this, p.replace("android.permission.", ""), 13, Ui.TEXTO));
            }
        } catch (Exception e) {
            permisos.addView(Ui.texto(this, getString(R.string.x39_error_leer_permisos, motivo(e)), 13, Ui.AVISO, false));
        }
        TextView internet = Ui.texto(this, getString(R.string.x39_permisos_internet), 13, Ui.TEXTO_2, false);
        internet.setPadding(0, dp(8), 0, 0);
        permisos.addView(internet);

        LinearLayout estado = tarjeta(col, null);
        boolean copias = (getApplicationInfo().flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
        filaEstado(estado, getString(R.string.x39_estado_capturas), getString(R.string.x39_estado_bloqueadas), true);
        filaEstado(estado, getString(R.string.x39_estado_galeria), getString(R.string.x39_estado_nunca), true);
        filaEstado(estado, getString(R.string.x39_estado_copias),
                getString(copias ? R.string.x39_estado_activadas : R.string.x39_estado_desactivadas), !copias);
        filaEstado(estado, getString(R.string.x39_estado_ubicacion), getString(R.string.x39_estado_no), true);
        boolean aislado = ColaAnclaje.aislado(this);
        filaEstado(estado, getString(R.string.x39_modo_aislado),
                getString(aislado ? R.string.x39_estado_aislado_activo : R.string.x39_estado_apagado), true);

        // Tor opcional (0.3): las huellas salen solo por el proxy HTTP de Orbot; sin Orbot, esperan.
        LinearLayout tor = tarjeta(col, getString(R.string.x39_anclar_solo_tor));
        LinearLayout filaTor = Ui.fila(this);
        filaTor.setPadding(0, dp(4), 0, dp(6));
        filaTor.addView(Ui.texto(this, getString(R.string.x39_anclar_solo_tor), 15, Ui.TEXTO, true), Ui.peso(1));
        Switch swTor = new Switch(this);
        swTor.setChecked(Orbot.soloTor(this));
        swTor.setContentDescription(getString(R.string.x39_anclar_solo_tor));
        swTor.setOnCheckedChangeListener((b, activo) -> {
            ColaAnclaje.prefs(this).edit().putBoolean(Orbot.PREF_SOLO_TOR, activo).apply();
            if (activo) {
                if (!Orbot.instalado(this)) {
                    avisoOrbotNoInstalado();
                } else {
                    Orbot.pedirArranque(this);
                }
            }
            refrescarTor();
            ColaAnclaje.programar(this);
            mostrarPestana(Pestana.SEGURIDAD);
        });
        filaTor.addView(swTor);
        tor.addView(filaTor);
        tor.addView(Ui.texto(this, getString(R.string.x39_tor_explicacion), 13, Ui.TEXTO_2, false));
        String estadoTor;
        if (!Orbot.instalado(this)) {
            estadoTor = getString(R.string.x39_orbot_no_instalado_estado);
        } else {
            String e = Orbot.ultimoEstado(this);
            long hace = Orbot.ultimoEstadoHace(this);
            // Un aviso de Orbot de hace más de 10 minutos ya no dice nada: «no conocido» no significa Tor caído,
            // significa que la app no tiene noticias recientes (ábrelo y avisará). El anclaje no depende de este texto.
            // Una frase entera por caso (estado de Orbot × proxy listo o no).
            int frase;
            if (hace < 0 || hace > 10 * 60_000L) {
                frase = torListo ? R.string.x39_tor_estado_desconocido_listo : R.string.x39_tor_estado_desconocido_no_disponible;
            } else if ("ON".equals(e)) {
                frase = torListo ? R.string.x39_tor_estado_conectado_listo : R.string.x39_tor_estado_conectado_no_disponible;
            } else if ("STARTING".equals(e)) {
                frase = torListo ? R.string.x39_tor_estado_arrancando_listo : R.string.x39_tor_estado_arrancando_no_disponible;
            } else if ("OFF".equals(e)) {
                frase = torListo ? R.string.x39_tor_estado_apagado_listo : R.string.x39_tor_estado_apagado_no_disponible;
            } else {
                frase = torListo ? R.string.x39_tor_estado_desconocido_listo : R.string.x39_tor_estado_desconocido_no_disponible;
            }
            estadoTor = getString(frase);
        }
        TextView et = Ui.texto(this, estadoTor, 13, Ui.SUAVE, false);
        et.setPadding(0, dp(8), 0, 0);
        tor.addView(et);
        if (!Orbot.instalado(this)) {
            tor.addView(Ui.boton(this, getString(R.string.x39_instalar_orbot_fdroid), false, v -> abrirWeb(Orbot.F_DROID)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 0));
            tor.addView(Ui.boton(this, getString(R.string.x39_orbot_guardian), false, v -> abrirWeb(Orbot.GUARDIAN)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
        } else if (Orbot.soloTor(this) && !torListo) {
            tor.addView(Ui.boton(this, getString(R.string.x39_pedir_arranque_orbot), false, v -> {
                Orbot.pedirArranque(this);
                Toast.makeText(this, R.string.x39_pedido_orbot, Toast.LENGTH_SHORT).show();
                refrescarTor();
            }), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 0));
        }

        LinearLayout clave = tarjeta(col, getString(R.string.x39_tu_identidad));
        try {
            clave.addView(Ui.mono(this, agrupar(evidencias.huellaClave()), 13, Ui.TEXTO));
            TextView medida = Ui.texto(this, getString(R.string.x39_seguridad_clave_medida, miles(evidencias.clavePublica().length)), 13, Ui.TEXTO_2, false);
            medida.setPadding(0, dp(6), 0, 0);
            clave.addView(medida);
        } catch (Exception e) {
            clave.addView(Ui.texto(this, getString(R.string.x39_error_leer_clave, motivo(e)), 13, Ui.AVISO, false));
        }
        clave.addView(Ui.boton(this, getString(R.string.x39_ver_identidad), false, v -> abrirSecundaria(() -> mostrar(pantallaIdentidad(false), false))),
                Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));

        LinearLayout red = tarjeta(col, getString(R.string.x39_registro_red));
        List<String> lineas = RedX39.ultimas(this, 40);
        if (lineas.isEmpty()) red.addView(Ui.texto(this, getString(R.string.x39_red_sin_conexiones), 13, Ui.SUAVE, false));
        for (String l : lineas) {
            TextView t = Ui.mono(this, l, 11, Ui.TEXTO_2);
            t.setPadding(0, dp(3), 0, dp(3));
            red.addView(t);
        }

        TextView ver = Ui.texto(this, getString(R.string.x39_version, VERSION), 12, Ui.TENUE, false);
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
            compartirFicheros(uris, getString(R.string.x39_exportar_clave_publica));
        } catch (Exception e) {
            aviso(motivo(e));
        }
    }

    // ------------------------------------------------------------------ ajustes

    private View pantallaAjustes() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_ajustes), () -> mostrarPestana(Pestana.SEGURIDAD), 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        LinearLayout t = tarjeta(col, null);
        SharedPreferences p = ColaAnclaje.prefs(this);
        interruptor(t, getString(R.string.x39_ajuste_auto), getString(R.string.x39_ajuste_auto_desc), ColaAnclaje.PREF_AUTO, true, p);
        interruptor(t, getString(R.string.x39_ajuste_wifi), getString(R.string.x39_ajuste_wifi_desc), ColaAnclaje.PREF_SOLO_WIFI, false, p);
        interruptor(t, getString(R.string.x39_modo_aislado), getString(R.string.x39_ajuste_aislado_desc), ColaAnclaje.PREF_AISLADO, false, p);
        interruptor(t, getString(R.string.x39_ajuste_fondo), getString(R.string.x39_ajuste_fondo_desc),
                ServicioEvidencia.PREF_FONDO, true, p);
        filaIdioma(t);
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    /** Fila «Idioma»: Sistema + cinco idiomas, cada uno escrito en su lengua. Cambia al instante y se recuerda. */
    private void filaIdioma(LinearLayout padre) {
        LinearLayout f = Ui.fila(this);
        f.setPadding(0, dp(10), 0, dp(10));
        LinearLayout textos = Ui.columna(this);
        textos.addView(Ui.texto(this, getString(R.string.x39_idioma), 15, Ui.TEXTO, true));
        textos.addView(Ui.texto(this, Idioma.nombreActual(this), 13, Ui.SUAVE, false));
        f.addView(textos, Ui.peso(1));
        f.setClickable(true);
        f.setContentDescription(getString(R.string.x39_idioma));
        f.setOnClickListener(v -> {
            String[] nombres = Idioma.NOMBRES.clone();
            nombres[0] = getString(R.string.x39_idioma_sistema);
            String actual = Idioma.actual(this);
            int marcado = 0;
            for (int i = 1; i < Idioma.ETIQUETAS.length; i++) if (Idioma.ETIQUETAS[i].equals(actual)) marcado = i;
            new AlertDialog.Builder(this)
                    .setTitle(R.string.x39_idioma)
                    .setSingleChoiceItems(nombres, marcado, (d, i) -> {
                        d.dismiss();
                        if (!Idioma.ETIQUETAS[i].equals(actual)) Idioma.poner(this, Idioma.ETIQUETAS[i]);
                    })
                    .setNegativeButton(R.string.x39_cancelar, null)
                    .show();
        });
        padre.addView(f);
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
            ServicioEvidencia.sincronizar(this);
            ChatEvidencia.de(this).conectar();
        });
        f.addView(s);
        padre.addView(f);
    }

    // ------------------------------------------------------------------ piezas

    // ------------------------------------------------------------------ mensajes

    /** Conversación abierta ahora (huella), para refrescarla cuando llega algo. */
    private String conversacionAbierta;

    @Override
    protected void onResume() {
        super.onResume();
        ChatEvidencia chat = ChatEvidencia.de(this);
        chat.oyente(new ChatEvidencia.Oyente() {
            @Override public void cambio(String bh) {
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    if (bh.equals(conversacionAbierta)) {
                        JSONObjectNombre n = nombreDe(bh);
                        mostrar(pantallaConversacion(bh, n.nombre), false);
                    } else if (pestana == Pestana.MENSAJES && secundaria == null) {
                        mostrarPestana(Pestana.MENSAJES);
                    }
                });
            }
            @Override public void estado(boolean enLinea) {
                runOnUiThread(() -> {
                    if (!isDestroyed() && pestana == Pestana.MENSAJES && secundaria == null) mostrarPestana(Pestana.MENSAJES);
                });
            }
        });
        chat.conectar();
        if (ServicioEvidencia.quiereFondo(this)) {
            // Android 13+: sin este permiso la línea funciona, pero los avisos no se ven.
            if (Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                    && !ColaAnclaje.prefs(this).getBoolean("pedido_avisos", false)) {
                ColaAnclaje.prefs(this).edit().putBoolean("pedido_avisos", true).apply();
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 39);
            }
        }
        ServicioEvidencia.sincronizar(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ChatEvidencia.de(this).oyente(null);
    }

    private static final class JSONObjectNombre { String nombre; }

    private JSONObjectNombre nombreDe(String bh) {
        JSONObjectNombre n = new JSONObjectNombre();
        org.json.JSONObject c = ChatEvidencia.de(this).contacto(bh);
        n.nombre = c == null ? bh.substring(0, 12) + "…" : c.optString("nombre", getString(R.string.x39_sin_nombre));
        return n;
    }

    /** Si se está adjuntando desde un chat, al terminar de sellar se manda su cápsula y se vuelve al chat. */
    private String adjuntarA;

    private boolean alChatSiToca(Evidencias.Sellado resultado, String error) {
        String bh = adjuntarA;
        adjuntarA = null;
        if (bh == null) return false;
        String nombre = nombreDe(bh).nombre;
        if (error == null && resultado != null) {
            ChatEvidencia.de(this).adjuntar(bh, resultado.ficha, nombreExportado(resultado.ficha));
            ColaAnclaje.programar(this);
        }
        abrirConversacion(bh, nombre);
        return true;
    }

    /** Tocar un contacto: escribirle, o ver su ficha. */
    private void menuContacto(org.json.JSONObject c) {
        final String h = c.optString("huella");
        final String n = c.optString("nombre", getString(R.string.x39_sin_nombre));
        if (c.optString("kem").isEmpty()) {
            abrirSecundaria(() -> mostrar(pantallaFichaContacto(c), true));
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle(n)
                .setItems(new String[]{getString(R.string.x39_mandar_mensaje), getString(R.string.x39_ver_ficha)}, (d, i) -> {
                    if (i == 0) abrirConversacion(h, n);
                    else abrirSecundaria(() -> mostrar(pantallaFichaContacto(c), true));
                })
                .show();
    }

    /**
     * Lo que se adjunta NO viaja suelto: primero se sella como evidencia (huella, firma,
     * ancla) y lo que sale es su cápsula.
     */
    private void menuAdjuntar(String bh, String nombre) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.x39_adjuntar_titulo)
                .setItems(new String[]{getString(R.string.x39_hacer_una_foto), getString(R.string.x39_grabar_audio),
                        getString(R.string.x39_elegir_un_archivo), getString(R.string.x39_evidencia_ya_guardada)}, (d, i) -> {
                    switch (i) {
                        case 0: adjuntarA = bh; abrirCamara(); break;
                        case 1: adjuntarA = bh; abrirGrabadora(); break;
                        case 2: adjuntarA = bh; elegirArchivo(); break;
                        default: elegirEvidenciaGuardada(bh, nombre); break;
                    }
                })
                .show();
    }

    private void elegirEvidenciaGuardada(String bh, String nombre) {
        final java.util.List<Evidencias.Ficha> todas;
        try {
            todas = evidencias.todas();
        } catch (Exception e) {
            aviso(getString(R.string.x39_error_leer_evidencias, motivo(e)));
            return;
        }
        if (todas.isEmpty()) { aviso(getString(R.string.x39_sin_evidencias_guardadas)); return; }
        String[] nombres = new String[todas.size()];
        for (int i = 0; i < todas.size(); i++) {
            Evidencias.Ficha f = todas.get(i);
            nombres[i] = nombreExportado(f) + " · " + f.capturada;
        }
        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.x39_que_evidencia_mandas, nombre))
                .setItems(nombres, (d, i) -> {
                    Evidencias.Ficha f = todas.get(i);
                    ChatEvidencia.de(this).adjuntar(bh, f, nombreExportado(f));
                })
                .show();
    }

    /** Una cápsula recibida sale entera, tal cual llegó: original intacto, recibo y .ots. */
    private void compartirCapsulaRecibida(String id, String nombre) {
        new Thread(() -> {
            String fallo = null;
            String fichero = "x39-capsula-recibida-" + id + ".zip";
            try {
                byte[] zip = ChatEvidencia.de(this).capsulaRecibida(id);
                Evidencias.escribirAtomico(new File(ProveedorRecibos.carpeta(this), fichero), zip);
            } catch (Exception e) {
                fallo = motivo(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (error != null) { aviso(getString(R.string.x39_error_preparar, error)); return; }
                ArrayList<Uri> uris = new ArrayList<>();
                uris.add(ProveedorRecibos.uri(this, fichero));
                compartirFicheros(uris, getString(R.string.x39_compartir_capsula_de, nombre));
            });
        }, "x39-capsula-recibida").start();
    }

    private View pantallaMensajes() {
        conversacionAbierta = null;
        ChatEvidencia chat = ChatEvidencia.de(this);
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(getString(R.string.x39_mensajes), null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));

        if (!evidencias.tieneIdentidad()) {
            col.addView(Ui.texto(this, getString(R.string.x39_crea_identidad_en_contactos), 14, Ui.AVISO, false));
        } else {
            col.addView(Ui.texto(this, getString(chat.enLinea() ? R.string.x39_chat_en_linea : R.string.x39_chat_conectando),
                    13, chat.enLinea() ? Ui.TEXTO : Ui.SUAVE, false), Ui.margen(this,
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 4, 0, 0, 12));
            org.json.JSONArray cs = chat.contactos();
            int conClave = 0;
            for (int i = 0; i < cs.length(); i++) {
                org.json.JSONObject c = cs.optJSONObject(i);
                if (c == null || c.optString("kem").isEmpty()) continue;
                final String h = c.optString("huella");
                final String n = c.optString("nombre", getString(R.string.x39_sin_nombre));
                java.util.List<ChatEvidencia.Msg> hilo = chat.conversacion(h);
                // Aquí solo las conversaciones empezadas: se empiezan desde Contactos.
                if (hilo.isEmpty()) continue;
                conClave++;
                String ultimo = hilo.isEmpty() ? getString(R.string.x39_sin_mensajes_todavia) : resumen(hilo.get(hilo.size() - 1));
                LinearLayout fila = Ui.fila(this);
                LinearLayout txt = Ui.columna(this);
                txt.addView(Ui.texto(this, n, 16, Ui.TEXTO, true));
                TextView u = Ui.texto(this, ultimo, 13, Ui.SUAVE, false);
                u.setSingleLine(true);
                u.setEllipsize(TextUtils.TruncateAt.END);
                txt.addView(u);
                fila.addView(txt, Ui.peso(1));
                fila.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.SUAVE, 18));
                fila.setPadding(dp(12), dp(14), dp(12), dp(14));
                fila.setBackground(Ui.redondeado(this, Ui.SUPERFICIE, 16));
                fila.setClickable(true);
                fila.setOnClickListener(v -> abrirConversacion(h, n));
                col.addView(fila, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 8));
            }
            if (conClave == 0) {
                col.addView(Ui.texto(this, getString(R.string.x39_sin_conversaciones), 13, Ui.SUAVE, false));
            }
            col.addView(Ui.texto(this, getString(R.string.x39_chat_transporte_nota), 12, Ui.TENUE, false),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 4, 16, 4, 0));
        }
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    /**
     * La línea de la lista de conversaciones con el último mensaje. Una cápsula guarda en su texto
     * «Evidencia: nombre» (dato antiguo, en español): aquí se escribe de nuevo en el idioma de la app.
     */
    private String resumen(ChatEvidencia.Msg m) {
        if (m.esCapsula()) {
            return getString(m.mio ? R.string.x39_chat_ultimo_mio_evidencia : R.string.x39_chat_evidencia_nombre, m.nombre);
        }
        return m.mio ? getString(R.string.x39_chat_ultimo_mio, m.texto) : m.texto;
    }

    /** Pie de una burbuja: hora y, si es mía, en qué punto está. Una frase entera por estado. */
    private String pie(ChatEvidencia.Msg m, String hora) {
        if (m.mio) {
            switch (String.valueOf(m.estado)) {
                case "pendiente": return getString(R.string.x39_pie_pendiente, hora);
                case "esperando ancla": return getString(R.string.x39_pie_esperando_ancla, hora);
                case "demasiado grande": return getString(R.string.x39_pie_demasiado_grande, hora);
                case "enviado": return getString(R.string.x39_pie_enviado, hora);
                case "entregado": return getString(R.string.x39_pie_entregado, hora);
                case "la evidencia ya no está": return getString(R.string.x39_pie_evidencia_no_esta, hora);
                default: return hora + " · " + m.estado;   // estado desconocido: se enseña tal cual se guardó
            }
        }
        return "recibiendo".equals(m.estado) ? getString(R.string.x39_pie_recibiendo, hora) : hora;
    }

    private void abrirConversacion(String bh, String nombre) {
        abrirSecundaria(() -> mostrar(pantallaConversacion(bh, nombre), false));
    }

    private View pantallaConversacion(String bh, String nombre) {
        conversacionAbierta = bh;
        ChatEvidencia chat = ChatEvidencia.de(this);
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior(nombre, () -> mostrarPestana(Pestana.MENSAJES), 0));

        ScrollView sv = new ScrollView(this);
        LinearLayout lista = Ui.columna(this);
        lista.setPadding(dp(12), dp(4), dp(12), dp(12));
        java.util.List<ChatEvidencia.Msg> hilo = chat.conversacion(bh);
        if (hilo.isEmpty()) {
            lista.addView(Ui.texto(this, getString(R.string.x39_chat_vacio, nombre), 13, Ui.SUAVE, false));
        }
        java.text.DateFormat hora = java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT, idioma());
        for (ChatEvidencia.Msg m : hilo) {
            LinearLayout burbuja = Ui.columna(this);
            burbuja.setPadding(dp(12), dp(8), dp(12), dp(8));
            burbuja.setBackground(Ui.redondeado(this, m.mio ? Ui.BURBUJA_SALIENTE : Ui.BURBUJA_ENTRANTE, 18));
            if (m.esCapsula()) {
                burbuja.addView(Ui.texto(this, "📎 " + m.nombre, 15, Ui.TEXTO, true));
                String pr = chat.progreso(m.id);
                String tam = m.bytes > 0 ? Formatter.formatShortFileSize(this, m.bytes) : "";
                if (pr != null) {
                    burbuja.addView(Ui.texto(this, tam.isEmpty() ? getString(R.string.x39_chat_trozos, pr)
                            : getString(R.string.x39_chat_trozos_tam, tam, pr), 12, Ui.SUAVE, false));
                } else if (!m.mio && m.tieneComprobacion()) {
                    burbuja.addView(Ui.texto(this, ChatEvidencia.textoComprobacion(this, m), 12, m.valida ? Ui.TEXTO_2 : Ui.AVISO, false));
                    final String idCap = m.id;
                    final String nomCap = m.nombre;
                    TextView comp = Ui.boton(this, getString(R.string.x39_compartir_capsula), false, v -> compartirCapsulaRecibida(idCap, nomCap));
                    burbuja.addView(comp, Ui.margen(this, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 0));
                } else if (m.mio) {
                    burbuja.addView(Ui.texto(this, tam.isEmpty() ? getString(R.string.x39_chat_capsula_mia)
                            : getString(R.string.x39_chat_capsula_mia_tam, tam), 12, Ui.SUAVE, false));
                }
            } else {
                burbuja.addView(Ui.texto(this, m.texto, 16, Ui.TEXTO, false));
            }
            burbuja.addView(Ui.texto(this, pie(m, hora.format(new java.util.Date(m.ts * 1000L))), 11, Ui.TENUE, false));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.gravity = m.mio ? Gravity.END : Gravity.START;
            lp.setMargins(0, dp(4), 0, dp(4));
            // start/end y no izquierda/derecha: en árabe las burbujas propias van a la izquierda.
            lp.setMarginStart(m.mio ? dp(48) : 0);
            lp.setMarginEnd(m.mio ? 0 : dp(48));
            lista.addView(burbuja, lp);
        }
        sv.addView(lista);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        sv.post(() -> sv.fullScroll(View.FOCUS_DOWN));

        LinearLayout barra = Ui.fila(this);
        barra.setPadding(dp(12), dp(6), dp(12), dp(10));
        barra.setGravity(Gravity.CENTER_VERTICAL);
        View clip = Ui.botonIcono(this, Icono.Tipo.MAS, Ui.TEXTO, getString(R.string.x39_adjuntar), v -> menuAdjuntar(bh, nombre));
        barra.addView(clip);
        View micro = Ui.botonIcono(this, Icono.Tipo.AUDIO, Ui.TEXTO, getString(R.string.x39_grabar_audio), v -> { adjuntarA = bh; abrirGrabadora(); });
        barra.addView(micro);
        final android.widget.EditText campo = Ui.campo(this, getString(R.string.x39_hint_mensaje), 1, true);
        barra.addView(campo, Ui.peso(1));
        TextView enviar = Ui.boton(this, getString(R.string.x39_enviar), true, v -> {
            String t = campo.getText().toString().trim();
            if (t.isEmpty()) return;
            campo.setText("");
            chat.escribir(bh, t);
        });
        barra.addView(enviar, Ui.margen(this, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, 8, 0, 0, 0));
        raizCol.addView(barra);
        return raizCol;
    }

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
        v.setPaddingRelative(dp(6), 0, 0, 0);
        f.addView(v);
        lista.addView(f);
    }

    private void aviso(String texto) {
        new AlertDialog.Builder(this).setMessage(texto).setPositiveButton(R.string.x39_entendido, null).show();
    }
}
