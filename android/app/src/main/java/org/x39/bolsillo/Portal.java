package org.x39.bolsillo;

import android.content.Context;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.TextView;

/**
 * Estética de sevilla.x39matrix.org para la pestaña Plenos: granate y dorado con los mismos valores que el
 * portal (index.html: --bg, --bg2, --card, --line, --ink, --ink2, --gold, --amb).
 * Única diferencia: el portal marca «coincide» en verde; en la app va en dorado (regla: ningún verde).
 */
final class Portal {
    static final int FONDO = 0xFF22050A;
    static final int FONDO_2 = 0xFF470A12;
    static final int TARJETA = 0xFF2E070C;
    /** rgba(255,217,192,.16) */
    static final int LINEA = 0x29FFD9C0;
    static final int TINTA = 0xFFFFD9C0;
    static final int TINTA_2 = 0xFFD9A98F;
    static final int ORO = 0xFFF2C48D;
    static final int AMBAR = 0xFFFFB36B;
    /** Fondo del selector de área. */
    static final int SELECTOR = 0xFF160305;
    private static final int BOTON = 0xFF1A0407;
    /** rgba(242,196,141,.45): borde punteado de la zona de comprobar. */
    private static final int ORO_45 = 0x73F2C48D;
    /** rgba(255,179,107,.4): borde de la píldora «en proceso». */
    private static final int AMBAR_40 = 0x66FFB36B;
    /** rgba(0,0,0,.22): relleno de la zona de comprobar. */
    private static final int SOMBRA_22 = 0x38000000;

    private Portal() {}

    /** Fondo de la pestaña: granate oscuro con el granate claro en el centro, como el portal. */
    static GradientDrawable fondo() {
        return new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{FONDO, FONDO_2, FONDO});
    }

    static GradientDrawable caja(Context c, int relleno, int borde, float grosorDp, float radioDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(relleno);
        g.setStroke(Ui.dp(c, grosorDp), borde);
        g.setCornerRadius(Ui.dp(c, radioDp));
        return g;
    }

    static GradientDrawable tarjeta(Context c) {
        return caja(c, TARJETA, LINEA, 1, 14);
    }

    /** Zona punteada de «Compruebe un documento». */
    static GradientDrawable punteada(Context c) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(SOMBRA_22);
        g.setStroke(Ui.dp(c, 2), ORO_45, Ui.dp(c, 8), Ui.dp(c, 6));
        g.setCornerRadius(Ui.dp(c, 16));
        return g;
    }

    /** Titulares en serif dorado, como los h2 del portal. */
    static TextView titulo(Context c, String s, float sp) {
        TextView t = Ui.texto(c, s, sp, ORO, false);
        t.setTypeface(Typeface.create(Typeface.SERIF, Typeface.BOLD));
        return t;
    }

    static TextView texto(Context c, CharSequence s, float sp, int color) {
        return Ui.texto(c, s, sp, color, false);
    }

    static TextView mono(Context c, String s, float sp, int color) {
        return Ui.mono(c, s, sp, color);
    }

    static TextView enlace(Context c, String s, View.OnClickListener accion) {
        TextView t = Ui.texto(c, s, 14, ORO, false);
        t.setPaintFlags(t.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        t.setPadding(0, Ui.dp(c, 7), Ui.dp(c, 16), Ui.dp(c, 7));
        t.setOnClickListener(accion);
        return t;
    }

    /** Píldora del portal: hecho en dorado; «en proceso» o «en curso» en ámbar. */
    static TextView pildora(Context c, String s, boolean hecho) {
        TextView p = Ui.texto(c, s, 12, hecho ? ORO : AMBAR, false);
        p.setPadding(Ui.dp(c, 10), Ui.dp(c, 3), Ui.dp(c, 10), Ui.dp(c, 3));
        p.setBackground(caja(c, 0x00000000, hecho ? ORO : AMBAR_40, 1, 12));
        return p;
    }

    static TextView boton(Context c, String s, View.OnClickListener accion) {
        TextView b = Ui.texto(c, s, 15, TINTA, true);
        b.setGravity(Gravity.CENTER);
        b.setMinHeight(Ui.dp(c, 46));
        b.setPadding(Ui.dp(c, 22), 0, Ui.dp(c, 22), 0);
        b.setBackground(caja(c, BOTON, LINEA, 1, 10));
        b.setOnClickListener(accion);
        Ui.clicable(b);
        return b;
    }
}
