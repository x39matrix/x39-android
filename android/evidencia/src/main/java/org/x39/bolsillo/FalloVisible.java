package org.x39.bolsillo;

import android.content.Context;

import java.io.IOException;

/**
 * Un fallo cuyo motivo acaba delante del usuario (en un aviso). Guarda el @StringRes y sus datos, no el texto:
 * el motivo se escribe al mostrarlo, en el idioma que tenga la app en ese momento.
 */
final class FalloVisible extends IOException {
    private final int texto;
    private final Object[] datos;

    FalloVisible(int texto, Object... datos) {
        super("FalloVisible 0x" + Integer.toHexString(texto));
        this.texto = texto;
        this.datos = datos;
    }

    String motivo(Context c) {
        return c.getString(texto, datos);
    }

    /** El motivo de cualquier excepción tal como se enseña: el de la app si es nuestro, el de Ui.mensaje si no. */
    static String motivo(Context c, Exception e) {
        return e instanceof FalloVisible ? ((FalloVisible) e).motivo(c) : Ui.mensaje(e);
    }
}
