package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Insets;
import android.graphics.Paint;
import android.graphics.Path;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * x39 · Evidencia v0.1 (etapa A).
 * Foto desde la cámara propia → almacén cifrado → huella SHA-256 → firma ML-DSA-87 → cola de anclaje
 * OpenTimestamps. La foto no sale del móvil; por la red solo viajan compromisos de 32 bytes.
 * Textos según la sección 9 de la especificación: nada de «auténtica», «sin rastro» ni «subir».
 */
public class EvidenciaActivity extends Activity {
    static final String VERSION = "0.1.0";
    private static final int REQ_CAMARA = 1;
    private static final int REQ_EXPORTAR_FOTO = 2;
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("d MMM yyyy · HH:mm", new Locale("es", "ES"));

    private enum Pestana { EVIDENCIAS, SEGURIDAD, AJUSTES }

    private FrameLayout raiz;
    private Pestana pestana = Pestana.EVIDENCIAS;
    private Runnable secundaria;
    private Evidencias evidencias;
    private Camara camara;
    private String exportandoId;
    private String errorInicio;

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
        try {
            evidencias.asegurarIdentidad();
        } catch (Exception e) {
            errorInicio = Ui.mensaje(e);
        }
        ColaAnclaje.programar(this);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (camara == null) render();
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (camara != null) {
            cerrarCamara();
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
        if (errorInicio != null) {
            mostrarError();
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
        barra.addView(itemNavegacion(Icono.Tipo.CAMARA, "Cámara", false, this::abrirCamara), Ui.peso(1));
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

    // ------------------------------------------------------------------ evidencias

    private View pantallaEvidencias() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(barraSuperior("Evidencias", null, 0));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(16), 0, dp(16), dp(24));
        col.addView(Ui.texto(this, "La foto no sale de este móvil. Solo viaja su huella.", 13, Ui.SUAVE, false));

        List<Evidencias.Ficha> fichas;
        try {
            fichas = evidencias.todas();
        } catch (Exception e) {
            fichas = new ArrayList<>();
            col.addView(Ui.texto(this, "⚠ No se pudo leer el almacén: " + Ui.mensaje(e), 14, Ui.AVISO, false));
        }
        if (fichas.isEmpty()) {
            LinearLayout vacio = Ui.columna(this);
            vacio.setGravity(Gravity.CENTER_HORIZONTAL);
            vacio.setPadding(dp(20), dp(28), dp(20), dp(22));
            vacio.setBackground(Ui.degradado(this, 28));
            FrameLayout aro = aro(Icono.Tipo.CAMARA);
            vacio.addView(aro, new LinearLayout.LayoutParams(dp(84), dp(84)));
            TextView t = Ui.texto(this, "Aún no hay evidencias", 20, Ui.TEXTO, true);
            t.setPadding(0, dp(14), 0, dp(6));
            vacio.addView(t);
            TextView d = Ui.texto(this, "Haz una foto desde aquí: se guarda cifrada en este móvil, se firma con tu clave y su huella se ancla en Bitcoin sin que tengas que hacer nada más.", 14, Ui.TEXTO_2, false);
            d.setGravity(Gravity.CENTER);
            d.setPadding(0, 0, 0, dp(18));
            vacio.addView(d);
            vacio.addView(Ui.boton(this, "Hacer una foto", true, v -> abrirCamara()), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            col.addView(vacio, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        }
        for (Evidencias.Ficha f : fichas) col.addView(filaFicha(f));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private FrameLayout aro(Icono.Tipo tipo) {
        FrameLayout aro = new FrameLayout(this);
        android.graphics.drawable.GradientDrawable circulo = new android.graphics.drawable.GradientDrawable();
        circulo.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        circulo.setColor(Ui.CAJA);
        circulo.setStroke(dp(2), Ui.BLANCO);
        aro.setBackground(circulo);
        aro.addView(Ui.icono(this, tipo, Ui.BLANCO, 34), new FrameLayout.LayoutParams(dp(34), dp(34), Gravity.CENTER));
        return aro;
    }

    private View filaFicha(Evidencias.Ficha f) {
        LinearLayout card = Ui.fila(this);
        card.setPadding(dp(12), dp(12), dp(12), dp(12));
        card.setBackground(Ui.degradado(this, 22));
        ImageView mini = new ImageView(this);
        mini.setScaleType(ImageView.ScaleType.CENTER_CROP);
        mini.setBackground(Ui.redondeado(this, Ui.CAJA, 14));
        mini.setClipToOutline(true);
        card.addView(mini, new LinearLayout.LayoutParams(dp(64), dp(64)));
        cargarImagen(f, mini, 160);

        LinearLayout t = Ui.columna(this);
        t.setPadding(dp(14), 0, dp(6), 0);
        t.addView(Ui.texto(this, fechaCorta(f.capturada), 15, Ui.TEXTO, true));
        t.addView(Ui.mono(this, "huella " + f.sha256.substring(0, 12) + "…", 12, Ui.SUAVE));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(6), 0, 0);
        t.addView(pildora(f), lp);
        card.addView(t, Ui.peso(1));
        card.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.TENUE, 18));
        card.setContentDescription("Evidencia del " + fechaCorta(f.capturada));
        card.setOnClickListener(v -> abrirFicha(f.id));
        Ui.clicable(card);
        LinearLayout envoltura = Ui.columna(this);
        envoltura.addView(card, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        return envoltura;
    }

    private TextView pildora(Evidencias.Ficha f) {
        String texto;
        int fondo;
        int color;
        switch (f.otsEstado) {
            case "bitcoin":
                texto = "Anclada · bloque " + f.bloque;
                fondo = Ui.BLANCO;
                color = Ui.FONDO;
                break;
            case "calendar":
                texto = "Enviada a los calendarios";
                fondo = Ui.SUPERFICIE_2;
                color = Ui.TEXTO;
                break;
            default:
                texto = "Firmada · en espera de ancla";
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

    /** Descifra y decodifica la foto en memoria, reducida; nunca se guarda en claro. */
    private void cargarImagen(Evidencias.Ficha f, ImageView destino, int ladoMaximo) {
        new Thread(() -> {
            byte[] datos = null;
            try {
                datos = evidencias.foto(f);
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

    // ------------------------------------------------------------------ cámara

    private void abrirCamara() {
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
        FrameLayout disparador = new FrameLayout(this);
        android.graphics.drawable.GradientDrawable anillo = new android.graphics.drawable.GradientDrawable();
        anillo.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        anillo.setColor(0x00000000);
        anillo.setStroke(dp(4), Ui.BLANCO);
        disparador.setBackground(anillo);
        View centro = new View(this);
        android.graphics.drawable.GradientDrawable punto = new android.graphics.drawable.GradientDrawable();
        punto.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        punto.setColor(Ui.BLANCO);
        centro.setBackground(punto);
        disparador.addView(centro, new FrameLayout.LayoutParams(dp(60), dp(60), Gravity.CENTER));
        disparador.setContentDescription("Hacer la foto");
        disparador.setOnClickListener(v -> {
            if (camara == null) return;
            v.setEnabled(false);
            v.setAlpha(0.5f);
            camara.disparar();
        });
        abajo.addView(disparador, new LinearLayout.LayoutParams(dp(78), dp(78)));
        marco.addView(abajo, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));

        mostrar(marco, false);
        camara = new Camara(this, tv, new Camara.Resultado() {
            @Override
            public void foto(byte[] jpeg) {
                procesarFoto(jpeg);
            }

            @Override
            public void error(String motivo) {
                cerrarCamara();
                mostrarPestana(Pestana.EVIDENCIAS);
                aviso("No se pudo usar la cámara: " + motivo);
            }
        });
        camara.abrir();
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
                evidencias.crear(jpeg);
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
                    Toast.makeText(this, "Firmada en " + ms + " ms", Toast.LENGTH_SHORT).show();
                    ColaAnclaje.programar(this);
                }
            });
        }, "x39-evidencia").start();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQ_CAMARA) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            abrirCamara();
        } else {
            aviso("Sin permiso de cámara no se pueden hacer fotos. Puedes darlo en los ajustes de Android.");
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

        ImageView foto = new ImageView(this);
        foto.setAdjustViewBounds(true);
        foto.setScaleType(ImageView.ScaleType.FIT_CENTER);
        foto.setBackground(Ui.degradado(this, 24));
        foto.setClipToOutline(true);
        foto.setMinimumHeight(dp(200));
        col.addView(foto, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        cargarImagen(f, foto, getResources().getDisplayMetrics().widthPixels);

        LinearLayout datos = Ui.columna(this);
        datos.setPadding(dp(18), dp(16), dp(18), dp(16));
        datos.setBackground(Ui.degradado(this, 24));
        LinearLayout.LayoutParams lpp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        datos.addView(pildora(f), lpp);
        dato(datos, "Huella SHA-256", f.sha256, true);
        dato(datos, "Hora del dispositivo (no verificable)", f.capturada, false);
        dato(datos, "Firmada con la clave", agrupar(f.firmante), true);
        int bytesFirma = Base64.decode(f.firma, Base64.NO_WRAP).length;
        dato(datos, "Firma", "ML-DSA-87 · " + bytesFirma + " bytes", false);
        String ancla;
        switch (f.otsEstado) {
            case "bitcoin":
                ancla = "Esta foto existía con este contenido exacto al menos desde el bloque " + f.bloque + " de Bitcoin, y no ha cambiado desde entonces.";
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
        col.addView(Ui.boton(this, "Exportar foto", false, v -> confirmarExportar(f)));
        espacio(col);
        col.addView(Ui.boton(this, "Borrar", false, v -> confirmarBorrar(f)));
        TextView nota = Ui.texto(this, "El recibo lleva la huella, la firma y la prueba .ots. No lleva la foto. Se verifica con herramientas públicas: OpenTimestamps.", 12, Ui.TENUE, false);
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
        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            byte[] datos = null;
            try {
                datos = evidencias.foto(f);
                boolean huellaOk = Evidencias.sha256Hex(datos).equals(f.sha256);
                sb.append(huellaOk ? "✓ La huella coincide: la foto guardada no ha cambiado.\n\n"
                        : "✗ La huella no coincide: la foto guardada ha cambiado desde que se firmó.\n\n");
            } catch (Exception e) {
                sb.append("✗ No se pudo leer la foto guardada: ").append(Ui.mensaje(e)).append("\n\n");
            } finally {
                if (datos != null) Arrays.fill(datos, (byte) 0);
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
                    int pendientes = X39Core.otsPending(ots).isEmpty() ? 0 : X39Core.otsPending(ots).split("\n").length;
                    sb.append(bloques.isEmpty()
                            ? "Ancla: prueba .ots válida, pendiente en " + pendientes + " calendarios."
                            : "✓ Ancla: prueba .ots con el bloque " + bloques + " de Bitcoin. Compruébalo fuera de la app con «ots verify».");
                }
            } catch (Exception e) {
                sb.append("✗ La prueba .ots no es válida: ").append(Ui.mensaje(e));
            }
            runOnUiThread(() -> {
                if (!isDestroyed()) new AlertDialog.Builder(this).setTitle("Verificación").setMessage(sb.toString()).setPositiveButton("Entendido", null).show();
            });
        }, "x39-verificar").start();
    }

    private void compartirRecibo(Evidencias.Ficha f) {
        try {
            File dir = ProveedorRecibos.carpeta(this);
            ArrayList<Uri> uris = new ArrayList<>();
            String json = f.id + ".json";
            Evidencias.escribirAtomico(new File(dir, json), Evidencias.recibo(f).toString(2).getBytes(StandardCharsets.UTF_8));
            uris.add(ProveedorRecibos.uri(this, json));
            byte[] ots = evidencias.ots(f);
            if (ots != null) {
                String nombre = f.id + ".ots";
                Evidencias.escribirAtomico(new File(dir, nombre), ots);
                uris.add(ProveedorRecibos.uri(this, nombre));
            }
            compartirFicheros(uris, "Compartir recibo (sin la foto)");
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

    private void confirmarExportar(Evidencias.Ficha f) {
        new AlertDialog.Builder(this)
                .setTitle("Exportar la foto")
                .setMessage("La foto saldrá del almacén cifrado de la app y quedará como un archivo normal donde elijas. Quien tenga ese archivo podrá verla. El recibo sigue valiendo: la huella del archivo exportado es la misma.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Exportar", (d, w) -> {
                    exportandoId = f.id;
                    Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                            .setType("image/jpeg").putExtra(Intent.EXTRA_TITLE, "x39-" + f.id + ".jpg");
                    startActivityForResult(i, REQ_EXPORTAR_FOTO);
                })
                .show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_EXPORTAR_FOTO || resultCode != RESULT_OK || data == null || data.getData() == null || exportandoId == null) return;
        final String id = exportandoId;
        exportandoId = null;
        final Uri destino = data.getData();
        new Thread(() -> {
            String fallo = null;
            byte[] datos = null;
            try {
                Evidencias.Ficha f = evidencias.porId(id);
                if (f == null) throw new IllegalStateException("la evidencia ya no existe");
                datos = evidencias.foto(f);
                try (OutputStream out = getContentResolver().openOutputStream(destino)) {
                    if (out == null) throw new IllegalStateException("el sistema no dio el destino");
                    out.write(datos);
                }
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            } finally {
                if (datos != null) Arrays.fill(datos, (byte) 0);
            }
            final String error = fallo;
            runOnUiThread(() -> Toast.makeText(this, error == null ? "Foto exportada" : "No se pudo exportar: " + error, Toast.LENGTH_LONG).show());
        }, "x39-exportar").start();
    }

    private void confirmarBorrar(Evidencias.Ficha f) {
        new AlertDialog.Builder(this)
                .setTitle("Borrar evidencia")
                .setMessage("Se borran la foto y su ficha de este móvil. Un recibo que ya hayas compartido sigue valiendo.")
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
        TextView internet = Ui.texto(this, "Internet: sí, solo para enviar huellas (32 bytes) a los calendarios de OpenTimestamps y recibir pruebas. Nunca fotos.", 13, Ui.TEXTO_2, false);
        internet.setPadding(0, dp(8), 0, 0);
        permisos.addView(internet);

        LinearLayout estado = tarjeta(col, null);
        boolean copias = (getApplicationInfo().flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
        filaEstado(estado, "Capturas de pantalla", "Bloqueadas", true);
        filaEstado(estado, "Fotos en la galería", "Nunca", true);
        filaEstado(estado, "Copias en la nube", copias ? "Activadas" : "Desactivadas", !copias);
        filaEstado(estado, "Ubicación en las fotos", "No", true);
        boolean aislado = ColaAnclaje.aislado(this);
        filaEstado(estado, "Modo aislado", aislado ? "Activo: nada sale del móvil" : "Apagado", true);

        LinearLayout clave = tarjeta(col, "Tu clave de firma");
        try {
            byte[] pk = evidencias.clavePublica();
            clave.addView(Ui.mono(this, agrupar(Evidencias.sha256Hex(pk)), 13, Ui.TEXTO));
            TextView medida = Ui.texto(this, "Clave pública ML-DSA-87: " + pk.length + " bytes (medido ahora)", 13, Ui.TEXTO_2, false);
            medida.setPadding(0, dp(6), 0, 0);
            clave.addView(medida);
            List<Evidencias.Ficha> fichas = evidencias.todas();
            if (!fichas.isEmpty()) {
                int n = Base64.decode(fichas.get(0).firma, Base64.NO_WRAP).length;
                clave.addView(Ui.texto(this, "Última firma: " + n + " bytes (medido ahora)", 13, Ui.TEXTO_2, false));
            }
            TextView boton = Ui.boton(this, "Compartir clave pública y última firma", false, v -> compartirClave());
            clave.addView(boton, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        } catch (Exception e) {
            clave.addView(Ui.texto(this, "No se pudo leer la clave: " + Ui.mensaje(e), 13, Ui.AVISO, false));
        }

        LinearLayout red = tarjeta(col, "Registro de red");
        List<String> lineas = RedX39.ultimas(this, 40);
        if (lineas.isEmpty()) red.addView(Ui.texto(this, "Todavía no ha habido ninguna conexión.", 13, Ui.SUAVE, false));
        for (String l : lineas) {
            TextView t = Ui.mono(this, l, 11, Ui.TEXTO_2);
            t.setPadding(0, dp(3), 0, dp(3));
            red.addView(t);
        }

        TextView ver = Ui.texto(this, "x39 · Evidencia " + VERSION, 12, Ui.TENUE, false);
        ver.setGravity(Gravity.CENTER);
        ver.setPadding(0, dp(18), 0, 0);
        col.addView(ver, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    /** Prueba de aceptación 8: los bytes reales que salen del móvil, no los tests del motor. */
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
            compartirFicheros(uris, "Compartir clave pública y firma");
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

    private void mostrarError() {
        LinearLayout col = Ui.columna(this);
        col.setPadding(dp(24), dp(48), dp(24), 0);
        col.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.TEXTO, 32));
        TextView t = Ui.texto(this, "No se pudo abrir la clave de firma", 18, Ui.TEXTO, true);
        t.setPadding(0, dp(12), 0, dp(8));
        col.addView(t);
        col.addView(Ui.texto(this, errorInicio, 14, Ui.TEXTO_2, false));
        mostrar(col, false);
    }

    private void aviso(String texto) {
        new AlertDialog.Builder(this).setMessage(texto).setPositiveButton("Entendido", null).show();
    }
}
