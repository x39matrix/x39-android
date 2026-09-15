package org.x39.bolsillo;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/**
 * Paleta y piezas de interfaz de x39. Solo widgets de Android, sin librerías.
 * Grafito con tarjetas en degradado. El rojo es SOLO la marca «x39»; los avisos van en blanco
 * con icono ⚠, nunca solo por color. Regla: ningún verde.
 */
final class Ui {
    static final int FONDO = 0xFF1B1B1D;
    static final int SUPERFICIE = 0xFF2B2B2F;
    static final int SUPERFICIE_2 = 0xFF3A3A40;
    /** Fondo de las cajas de icono y de las baldosas del menú. */
    static final int CAJA = 0xFF3C3C42;
    static final int BURBUJA_ENTRANTE = 0xFF2E2E33;
    static final int BURBUJA_SALIENTE = 0xFF4A4A52;
    /** Solo para la marca «x39». */
    static final int ROJO = 0xFFE53935;
    /** Avisos: blanco, siempre acompañado de icono o del signo ⚠. */
    static final int AVISO = 0xFFFFFFFF;
    static final int BLANCO = 0xFFF2F2F2;
    static final int TEXTO = 0xFFF2F2F2;
    static final int TEXTO_2 = 0xFFB8B8BE;
    static final int SUAVE = 0xFF9A9AA1;
    static final int TENUE = 0xFF6E6E75;
    static final int LINEA = 0x14FFFFFF;
    private static final int DEGRADADO_CLARO = 0xFF46464D;
    private static final int DEGRADADO_OSCURO = 0xFF2A2A2F;
    private static final int[] AVATARES = {0xFF3C3C42, 0xFF45454C, 0xFF34343A, 0xFF4A4A52, 0xFF3F3F46, 0xFF2F2F35};

    private Ui() {}

    static int dp(Context c, float v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    static TextView texto(Context c, CharSequence s, float sp, int color, boolean negrita) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setTypeface(negrita ? Typeface.create("sans-serif-medium", Typeface.NORMAL) : Typeface.SANS_SERIF);
        t.setLineSpacing(0, 1.15f);
        return t;
    }

    static TextView mono(Context c, String s, float sp, int color) {
        TextView t = texto(c, s, sp, color, false);
        t.setTypeface(Typeface.MONOSPACE);
        return t;
    }

    static GradientDrawable redondeado(Context c, int color, float radioDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(c, radioDp));
        return g;
    }

    /** Tarjeta en degradado grafito, de la esquina superior izquierda (clara) a la inferior derecha. */
    static GradientDrawable degradado(Context c, float radioDp) {
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR, new int[]{DEGRADADO_CLARO, DEGRADADO_OSCURO});
        g.setCornerRadius(dp(c, radioDp));
        return g;
    }

    /** La marca «x39» en rojo, arriba a la derecha de las pantallas principales. */
    static TextView marca(Context c) {
        TextView t = texto(c, "x39", 22, ROJO, true);
        t.setLetterSpacing(0.02f);
        t.setContentDescription("x39");
        return t;
    }

    static LinearLayout columna(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    static LinearLayout fila(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    static LinearLayout.LayoutParams lp(int ancho, int alto) {
        return new LinearLayout.LayoutParams(ancho, alto);
    }

    static LinearLayout.LayoutParams peso(float peso) {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, peso);
    }

    static LinearLayout.LayoutParams margen(Context c, int ancho, int alto, int izq, int arriba, int der, int abajo) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ancho, alto);
        p.setMargins(dp(c, izq), dp(c, arriba), dp(c, der), dp(c, abajo));
        return p;
    }

    static void clicable(View v) {
        TypedValue tv = new TypedValue();
        v.getContext().getTheme().resolveAttribute(android.R.attr.selectableItemBackground, tv, true);
        v.setForeground(v.getContext().getDrawable(tv.resourceId));
        v.setClickable(true);
        v.setFocusable(true);
    }

    static ImageView icono(Context c, Icono.Tipo tipo, int color, int tamDp) {
        ImageView i = new ImageView(c);
        i.setImageDrawable(new Icono(tipo, color));
        i.setLayoutParams(new LinearLayout.LayoutParams(dp(c, tamDp), dp(c, tamDp)));
        return i;
    }

    static View botonIcono(Context c, Icono.Tipo tipo, int color, String descripcion, View.OnClickListener accion) {
        FrameLayout f = new FrameLayout(c);
        f.setLayoutParams(new LinearLayout.LayoutParams(dp(c, 48), dp(c, 48)));
        ImageView i = new ImageView(c);
        i.setImageDrawable(new Icono(tipo, color));
        FrameLayout.LayoutParams p = new FrameLayout.LayoutParams(dp(c, 23), dp(c, 23), Gravity.CENTER);
        f.addView(i, p);
        f.setContentDescription(descripcion);
        f.setOnClickListener(accion);
        clicable(f);
        return f;
    }

    static TextView boton(Context c, String s, boolean primario, View.OnClickListener accion) {
        // Principal: píldora blanca con texto oscuro. Secundario: píldora grafito.
        TextView b = texto(c, s, 15, primario ? FONDO : TEXTO, true);
        b.setGravity(Gravity.CENTER);
        b.setMinHeight(dp(c, 50));
        b.setPadding(dp(c, 18), 0, dp(c, 18), 0);
        b.setBackground(redondeado(c, primario ? BLANCO : SUPERFICIE_2, 26));
        b.setOnClickListener(accion);
        clicable(b);
        return b;
    }

    static EditText campo(Context c, String pista, int lineas, boolean multilinea) {
        EditText e = new EditText(c);
        e.setHint(pista);
        e.setHintTextColor(TENUE);
        e.setTextColor(TEXTO);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setBackground(redondeado(c, SUPERFICIE, 14));
        e.setPadding(dp(c, 14), dp(c, 12), dp(c, 14), dp(c, 12));
        e.setMinLines(lineas);
        e.setGravity(Gravity.TOP | Gravity.START);
        int tipo = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
        if (multilinea) tipo |= InputType.TYPE_TEXT_FLAG_MULTI_LINE;
        else tipo |= InputType.TYPE_TEXT_FLAG_CAP_WORDS;
        e.setInputType(tipo);
        // Teclado en modo incógnito: que no aprenda lo que escribes.
        e.setImeOptions(e.getImeOptions() | 0x1000000);
        return e;
    }

    static TextView avatar(Context c, String nombre, int tamDp) {
        String inicial = TextUtils.isEmpty(nombre) ? "?" : nombre.trim().substring(0, 1).toUpperCase(Locale.ROOT);
        TextView t = texto(c, inicial, tamDp * 0.36f, TEXTO, true);
        t.setGravity(Gravity.CENTER);
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        g.setColor(AVATARES[Math.abs(nombre == null ? 0 : nombre.hashCode()) % AVATARES.length]);
        t.setBackground(g);
        t.setLayoutParams(new LinearLayout.LayoutParams(dp(c, tamDp), dp(c, tamDp)));
        return t;
    }

    /** Huella de 12 grupos de 5 dígitos en rejilla de 3 columnas. */
    static View huella(Context c, String huella, float sp) {
        LinearLayout col = columna(c);
        String[] g = huella.trim().split("\\s+");
        for (int fila = 0; fila * 3 < g.length; fila++) {
            LinearLayout f = fila(c);
            for (int i = 0; i < 3; i++) {
                int k = fila * 3 + i;
                TextView t = mono(c, k < g.length ? g[k] : "", sp, TEXTO);
                t.setGravity(Gravity.CENTER);
                f.addView(t, peso(1));
            }
            f.setPadding(0, dp(c, 4), 0, dp(c, 4));
            col.addView(f);
        }
        return col;
    }

    static View separador(Context c) {
        View v = new View(c);
        v.setBackgroundColor(LINEA);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1));
        return v;
    }

    static String hora(long millis) {
        Calendar ahora = Calendar.getInstance();
        Calendar m = Calendar.getInstance();
        m.setTimeInMillis(millis);
        boolean hoy = ahora.get(Calendar.YEAR) == m.get(Calendar.YEAR) && ahora.get(Calendar.DAY_OF_YEAR) == m.get(Calendar.DAY_OF_YEAR);
        String patron = hoy ? "HH:mm" : "d MMM";
        return new SimpleDateFormat(patron, new Locale("es", "ES")).format(new Date(millis));
    }

    static String mensaje(Exception e) {
        String m = e.getMessage();
        if (m == null || m.isEmpty()) return e.getClass().getSimpleName();
        // El puente JNI antepone «Rust error: »; al usuario solo le importa el motivo.
        return m.startsWith("Rust error: ") ? m.substring("Rust error: ".length()) : m;
    }
}
