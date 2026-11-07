package org.x39.bolsillo;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

final class Comunicaciones {
    static final String[] PAQUETES = {
        "org.x39matrix.llamadas.escritorio",
        "org.x39matrix.llamadas"
    };
    static final String WEB = "https://mining.x39matrix.org/app/fdroid/repo/index.html";

    private Comunicaciones() {}

    static boolean instalada(Context c) {
        PackageManager pm = c.getPackageManager();
        for (String pkg : PAQUETES) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return false;
    }

    static boolean abrir(Context c) {
        PackageManager pm = c.getPackageManager();
        for (String pkg : PAQUETES) {
            Intent i = pm.getLaunchIntentForPackage(pkg);
            if (i != null) {
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                c.startActivity(i);
                return true;
            }
        }
        return false;
    }
}
