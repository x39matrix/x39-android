package org.x39.bolsillo;

import android.app.Activity;
import android.app.LocaleManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Build;
import android.os.LocaleList;

import java.util.Locale;

import org.x39matrix.evidencia.R;

/**
 * Idioma de la app elegido en Ajustes, sin AndroidX ("Google 0").
 * Android 13+: LocaleManager del sistema (se integra con Ajustes › Idioma de la app y recrea las pantallas solo).
 * Android 9-12: la etiqueta se guarda aquí y cada pantalla/servicio envuelve su contexto con ella; al elegir, recreate().
 */
final class Idioma {

    /** "" = el del sistema. El resto, etiquetas BCP 47. Mismo orden que NOMBRES. */
    static final String[] ETIQUETAS = {"", "es", "en", "zh-CN", "ja", "ar"};
    /** Cada idioma escrito en su propia lengua; el primero ("Sistema") se pone traducido desde strings.xml. */
    static final String[] NOMBRES = {null, "Español", "English", "中文", "日本語", "العربية"};

    private static final String PREFS = "x39_idioma";
    private static final String CLAVE = "idioma";

    private Idioma() {}

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** Etiqueta elegida ahora ("" = sistema). */
    static String actual(Context c) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            LocaleList l = c.getSystemService(LocaleManager.class).getApplicationLocales();
            if (l.isEmpty()) return "";
            // zh-CN se guarda como tal pero se reconoce por el idioma ("zh").
            String idioma = l.get(0).getLanguage();
            for (int i = 1; i < ETIQUETAS.length; i++) if (ETIQUETAS[i].split("-")[0].equals(idioma)) return ETIQUETAS[i];
            return "";
        }
        return prefs(c).getString(CLAVE, "");
    }

    /** Nombre visible de la opción elegida ahora. */
    static String nombreActual(Context c) {
        String etq = actual(c);
        for (int i = 1; i < ETIQUETAS.length; i++) if (ETIQUETAS[i].equals(etq)) return NOMBRES[i];
        return c.getString(R.string.x39_idioma_sistema);
    }

    /** Cambia el idioma al instante, sin reiniciar la app. */
    static void poner(Activity a, String etiqueta) {
        prefs(a).edit().putString(CLAVE, etiqueta).apply();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // El sistema lo recuerda y recrea las actividades abiertas.
            a.getSystemService(LocaleManager.class).setApplicationLocales(
                    etiqueta.isEmpty() ? LocaleList.getEmptyLocaleList() : LocaleList.forLanguageTags(etiqueta));
        } else {
            a.recreate();
        }
        // El aviso fijo del servicio y los nombres de los canales se vuelven a escribir en el idioma nuevo.
        ServicioEvidencia.sincronizar(a.getApplicationContext());
    }

    /** Para attachBaseContext de actividades y servicios en Android 9-12. En 13+ lo hace el sistema. */
    static Context envolver(Context base) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return base;
        String etq = prefs(base).getString(CLAVE, "");
        if (etq.isEmpty()) return base;
        Locale loc = Locale.forLanguageTag(etq);
        Locale.setDefault(loc);
        Configuration conf = new Configuration(base.getResources().getConfiguration());
        conf.setLocale(loc);
        conf.setLayoutDirection(loc);
        return base.createConfigurationContext(conf);
    }
}
