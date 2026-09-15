package org.x39.bolsillo;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/** Iconos de trazo dibujados sobre una rejilla de 24 unidades, coherentes con el diseño. */
final class Icono extends Drawable {
    enum Tipo { INICIO, CHAT, CONTACTOS, ACTAS, ESCUDO, ESCUDO_OK, CANDADO, ATRAS, MAS, ENVIAR, PEGAR, COMPARTIR, COPIAR, AVISO, CHECK, LLAVE, CHEVRON, ENLACE }

    private final Tipo tipo;
    private final Paint pincel = new Paint(Paint.ANTI_ALIAS_FLAG);

    Icono(Tipo tipo, int color) {
        this.tipo = tipo;
        pincel.setColor(color);
        pincel.setStyle(Paint.Style.STROKE);
        pincel.setStrokeWidth(1.9f);
        pincel.setStrokeCap(Paint.Cap.ROUND);
        pincel.setStrokeJoin(Paint.Join.ROUND);
    }

    @Override
    public void draw(Canvas c) {
        Rect b = getBounds();
        c.save();
        c.translate(b.left, b.top);
        c.scale(b.width() / 24f, b.height() / 24f);
        Path p = new Path();
        switch (tipo) {
            case INICIO:
                p.moveTo(3.5f, 11); p.lineTo(12, 4); p.lineTo(20.5f, 11);
                p.addRoundRect(new RectF(6, 10, 18, 20.5f), 2, 2, Path.Direction.CW);
                p.moveTo(10, 20.5f); p.lineTo(10, 15.5f); p.lineTo(14, 15.5f); p.lineTo(14, 20.5f);
                break;
            case CHAT:
                p.moveTo(4, 5); p.lineTo(20, 5); p.lineTo(20, 16); p.lineTo(9, 16); p.lineTo(4, 20); p.close();
                break;
            case CONTACTOS:
                p.addCircle(9, 8, 3.5f, Path.Direction.CW);
                p.moveTo(3, 20); p.arcTo(new RectF(3, 14, 15, 26), 180, 180, false);
                p.moveTo(16, 4.5f); p.arcTo(new RectF(12.5f, 4.5f, 19.5f, 11.5f), -90, 180, false);
                p.moveTo(18, 14); p.quadTo(21, 15.5f, 21, 20);
                break;
            case ACTAS:
                // Documento con esquina doblada y un sello (check) abajo.
                p.moveTo(6, 3); p.lineTo(14, 3); p.lineTo(19, 8); p.lineTo(19, 21); p.lineTo(6, 21); p.close();
                p.moveTo(14, 3); p.lineTo(14, 8); p.lineTo(19, 8);
                p.moveTo(9, 15); p.lineTo(11.5f, 17.5f); p.lineTo(16, 12);
                break;
            case ENLACE:
                p.moveTo(14, 4); p.lineTo(20, 4); p.lineTo(20, 10);
                p.moveTo(20, 4); p.lineTo(11, 13);
                p.moveTo(17, 13); p.lineTo(17, 20); p.lineTo(4, 20); p.lineTo(4, 7); p.lineTo(11, 7);
                break;
            case ESCUDO:
            case ESCUDO_OK:
                p.moveTo(12, 3); p.lineTo(19, 6); p.lineTo(19, 11);
                p.quadTo(19, 18, 12, 21); p.quadTo(5, 18, 5, 11); p.lineTo(5, 6); p.close();
                if (tipo == Tipo.ESCUDO_OK) { p.moveTo(9, 12); p.lineTo(11, 14); p.lineTo(15, 10); }
                break;
            case CANDADO:
                p.addRoundRect(new RectF(5, 11, 19, 21), 2, 2, Path.Direction.CW);
                p.moveTo(8, 11); p.lineTo(8, 8); p.arcTo(new RectF(8, 4, 16, 12), 180, 180, false); p.lineTo(16, 11);
                break;
            case ATRAS:
                p.moveTo(15, 6); p.lineTo(9, 12); p.lineTo(15, 18);
                break;
            case CHEVRON:
                p.moveTo(9, 6); p.lineTo(15, 12); p.lineTo(9, 18);
                break;
            case MAS:
                p.moveTo(12, 5); p.lineTo(12, 19); p.moveTo(5, 12); p.lineTo(19, 12);
                break;
            case ENVIAR:
                p.moveTo(4, 12); p.lineTo(20, 4); p.lineTo(14, 20); p.lineTo(11, 13); p.close();
                break;
            case PEGAR:
                p.addRoundRect(new RectF(6, 5, 18, 21), 2, 2, Path.Direction.CW);
                p.addRoundRect(new RectF(9, 3, 15, 7), 1, 1, Path.Direction.CW);
                p.moveTo(9, 12); p.lineTo(15, 12); p.moveTo(9, 16); p.lineTo(13, 16);
                break;
            case COMPARTIR:
                p.addCircle(6, 12, 2.5f, Path.Direction.CW);
                p.addCircle(18, 6, 2.5f, Path.Direction.CW);
                p.addCircle(18, 18, 2.5f, Path.Direction.CW);
                p.moveTo(8.2f, 10.9f); p.lineTo(15.8f, 7.1f);
                p.moveTo(8.2f, 13.1f); p.lineTo(15.8f, 16.9f);
                break;
            case COPIAR:
                p.addRoundRect(new RectF(9, 9, 20, 20), 2, 2, Path.Direction.CW);
                p.moveTo(15, 9); p.lineTo(15, 5); p.lineTo(4, 5); p.lineTo(4, 15); p.lineTo(9, 15);
                break;
            case AVISO:
                p.moveTo(12, 3); p.lineTo(22, 21); p.lineTo(2, 21); p.close();
                p.moveTo(12, 10); p.lineTo(12, 15); p.moveTo(12, 18); p.lineTo(12, 18.01f);
                break;
            case CHECK:
                p.moveTo(5, 12); p.lineTo(10, 17); p.lineTo(19, 7);
                break;
            case LLAVE:
                p.addCircle(8, 15, 4, Path.Direction.CW);
                p.moveTo(11, 12); p.lineTo(20, 3); p.moveTo(17, 6); p.lineTo(20, 9);
                break;
        }
        c.drawPath(p, pincel);
        c.restore();
    }

    @Override
    public void setAlpha(int alpha) {
        pincel.setAlpha(alpha);
    }

    @Override
    public void setColorFilter(ColorFilter cf) {
        pincel.setColorFilter(cf);
    }

    @Override
    @SuppressWarnings("deprecation")
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }
}
