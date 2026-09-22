package org.x39.bolsillo;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import org.x39matrix.evidencia.R;

/**
 * Mantiene la línea del chat con la app cerrada. Sin esto, en cuanto la pantalla se va,
 * Android congela la app y los mensajes no llegan: el servidor no guarda nada.
 *
 * Cuesta una notificación fija, y esa notificación deja ver que en este móvil hay x39
 * Evidencia. Por eso es un interruptor de Ajustes («Recibir con la app cerrada»): quien
 * corra riesgo lo apaga y solo recibe con la app abierta.
 *
 * Los avisos de mensaje dicen QUIÉN escribe, nunca QUÉ.
 */
public final class ServicioEvidencia extends Service {

    static final String PREF_FONDO = "chat_fondo";
    private static final String CANAL_LINEA = "linea";
    /**
     * «_v2» porque la importancia de un canal no se puede subir después de crearlo: el
     * primero («mensajes») nació con importancia normal y por eso el aviso no se asomaba
     * arriba (solo el «1» en el icono). Se borra y se crea este, con importancia alta.
     */
    private static final String CANAL_MENSAJES = "mensajes_v2";
    private static final int ID_LINEA = 39;

    /** Arranca o para el servicio según Ajustes (y el modo aislado). */
    static void sincronizar(Context c) {
        Intent i = new Intent(c, ServicioEvidencia.class);
        if (quiereFondo(c)) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) c.startForegroundService(i);
                else c.startService(i);
            } catch (Exception e) {
                android.util.Log.w("X39_EV_CHAT", "no se pudo arrancar el servicio", e);
            }
        } else {
            c.stopService(i);
        }
    }

    static boolean quiereFondo(Context c) {
        return ColaAnclaje.prefs(c).getBoolean(PREF_FONDO, true) && !ColaAnclaje.aislado(c);
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public void onCreate() {
        super.onCreate();
        avisoFijo();
        ChatEvidencia.de(this).conectar();
        android.util.Log.i("X39_EV_CHAT", "servicio en marcha: la línea sigue con la app cerrada");
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (!quiereFondo(this)) { stopSelf(); return START_NOT_STICKY; }
        avisoFijo(); // tras cambiar de idioma, el aviso y los canales se reescriben en el nuevo
        ChatEvidencia.de(this).conectar();
        return START_STICKY;
    }

    /** El aviso permanente, en el idioma elegido ahora mismo en Ajustes. */
    private void avisoFijo() {
        Context c = Idioma.envolver(getApplicationContext());
        canales(c);
        Notification n = base(c, CANAL_LINEA)
                .setContentTitle(c.getString(R.string.x39_notif_titulo))
                .setContentText(c.getString(R.string.x39_notif_en_linea))
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(ID_LINEA, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(ID_LINEA, n);
        }
    }

    /** Aviso de mensaje nuevo: el nombre del contacto y nada más. */
    static void avisarMensaje(Context c0, String bh, String nombre) {
        Context c = Idioma.envolver(c0.getApplicationContext());
        canales(c);
        Notification n = base(c, CANAL_MENSAJES)
                .setContentTitle(c.getString(R.string.x39_notif_titulo))
                .setContentText(c.getString(R.string.x39_notif_mensaje_nuevo, nombre))
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setPriority(Notification.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build();
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        try {
            nm.notify(bh.hashCode(), n);
        } catch (SecurityException sinPermiso) {
            // Sin permiso de notificaciones: el mensaje queda en la app igualmente.
        }
    }

    private static Notification.Builder base(Context c, String canal) {
        Intent abrir = new Intent(c, EvidenciaActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(c, 0, abrir, PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(c, canal) : new Notification.Builder(c);
        return b.setSmallIcon(android.R.drawable.stat_notify_chat)
                .setContentIntent(pi)
                .setVisibility(Notification.VISIBILITY_PRIVATE);
    }

    private static void canales(Context c) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CANAL_LINEA, c.getString(R.string.x39_canal_linea), NotificationManager.IMPORTANCE_MIN));
        nm.deleteNotificationChannel("mensajes");
        nm.createNotificationChannel(new NotificationChannel(CANAL_MENSAJES, c.getString(R.string.x39_mensajes), NotificationManager.IMPORTANCE_HIGH));
    }
}
