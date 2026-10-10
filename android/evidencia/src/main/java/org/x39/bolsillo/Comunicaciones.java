package org.x39.bolsillo;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

/**
 * X39 Comunicaciones (llamadas, videollamadas y mensajes privados) es OTRA app, con su paquete y sus permisos.
 * Evidencia no la incluye ni depende de ella: solo la abre si está instalada (visibilidad declarada en el manifest).
 */
final class Comunicaciones {
    static final String PAQUETE = "org.x39matrix.llamadas";
    static final String WEB = "https://x39matrix.org/";

    private Comunicaciones() {}

    static boolean instalada(Context c) {
        try {
            c.getPackageManager().getPackageInfo(PAQUETE, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    /** Abre X39 Comunicaciones. Devuelve false si no hay nada que lanzar (no instalada). */
    static boolean abrir(Context c) {
        Intent i = c.getPackageManager().getLaunchIntentForPackage(PAQUETE);
        if (i == null) return false;
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        c.startActivity(i);
        return true;
    }
}
