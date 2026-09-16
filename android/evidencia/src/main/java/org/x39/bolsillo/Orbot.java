package org.x39.bolsillo;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Orbot (Tor en el móvil) sin bibliotecas: los mismos intents públicos que usa NetCipher, escritos aquí.
 * x39 no lleva Tor: cuando el interruptor «Anclar solo por Tor» está encendido, las huellas salen por el
 * proxy HTTP local de Orbot (127.0.0.1:8118). Con el proxy HTTP el nombre del calendario viaja dentro del
 * túnel (CONNECT); con SOCKS el móvil resolvería el DNS y delataría el destino, por eso no se usa 9050.
 */
final class Orbot {
    static final String PAQUETE = "org.torproject.android";
    static final String PROXY_HOST = "127.0.0.1";
    static final int PROXY_PUERTO = 8118;
    static final String ACCION_START = "org.torproject.android.intent.action.START";
    static final String ACCION_STATUS = "org.torproject.android.intent.action.STATUS";
    static final String EXTRA_STATUS = "org.torproject.android.intent.extra.STATUS";
    static final String EXTRA_PAQUETE = "org.torproject.android.intent.extra.PACKAGE_NAME";
    static final String PREF_SOLO_TOR = "anclar_solo_tor";
    private static final String PREF_ESTADO = "tor_estado";
    private static final String PREF_ESTADO_HORA = "tor_estado_hora";
    static final String F_DROID = "https://f-droid.org/packages/org.torproject.android/";
    static final String GUARDIAN = "https://guardianproject.info/apps/org.torproject.android/";

    private Orbot() {}

    static boolean soloTor(Context c) {
        return ColaAnclaje.prefs(c).getBoolean(PREF_SOLO_TOR, false);
    }

    static boolean instalado(Context c) {
        try {
            c.getPackageManager().getPackageInfo(PAQUETE, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    /** Pide a Orbot que arranque (si está instalado). Orbot contesta con un broadcast STATUS a este paquete. */
    static void pedirArranque(Context c) {
        if (!instalado(c)) return;
        Intent i = new Intent(ACCION_START).setPackage(PAQUETE).putExtra(EXTRA_PAQUETE, c.getPackageName());
        c.sendBroadcast(i);
    }

    /** Último estado que Orbot comunicó (ON, STARTING, OFF) y hace cuánto. */
    static String ultimoEstado(Context c) {
        return ColaAnclaje.prefs(c).getString(PREF_ESTADO, "desconocido");
    }

    static long ultimoEstadoHace(Context c) {
        long t = ColaAnclaje.prefs(c).getLong(PREF_ESTADO_HORA, 0);
        return t == 0 ? -1 : System.currentTimeMillis() - t;
    }

    /** Receptor de los broadcasts STATUS de Orbot; registrarlo mientras la pantalla o el trabajo lo necesiten. */
    static BroadcastReceiver receptor(Runnable alCambiar) {
        return new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!ACCION_STATUS.equals(intent.getAction())) return;
                String s = intent.getStringExtra(EXTRA_STATUS);
                if (s == null) s = "desconocido";
                ColaAnclaje.prefs(context).edit().putString(PREF_ESTADO, s).putLong(PREF_ESTADO_HORA, System.currentTimeMillis()).apply();
                if (alCambiar != null) alCambiar.run();
            }
        };
    }

    static void registrar(Context c, BroadcastReceiver r) {
        IntentFilter f = new IntentFilter(ACCION_STATUS);
        if (Build.VERSION.SDK_INT >= 33) c.registerReceiver(r, f, Context.RECEIVER_EXPORTED);
        else c.registerReceiver(r, f);
    }

    /** ¿Está abierto el proxy HTTP de Orbot? (no garantiza que Tor haya terminado de conectar). */
    static boolean proxyAbierto() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(PROXY_HOST, PROXY_PUERTO), 1500);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Listo para anclar por Tor: instalado, proxy abierto y (si Orbot lo ha dicho hace poco) estado ON. */
    static boolean listo(Context c) {
        if (!instalado(c) || !proxyAbierto()) return false;
        String e = ultimoEstado(c);
        long hace = ultimoEstadoHace(c);
        // Sin noticias recientes de Orbot se confía en el proxy abierto; con noticias, manda lo que dijo.
        return hace < 0 || hace > 10 * 60_000L || "ON".equals(e);
    }
}
