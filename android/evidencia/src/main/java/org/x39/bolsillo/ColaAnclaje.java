package org.x39.bolsillo;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;

/**
 * Cola de anclaje (sección 6), con JobScheduler del sistema.
 * pending  → envía el compromiso (32 bytes) a los calendarios; con 2 o más respuestas guarda el .ots.
 * calendar → pide a cada calendario la actualización; cuando aparece un bloque de Bitcoin, la ficha queda anclada.
 * El estado vive en la ficha, no en memoria: si la app muere a mitad, se retoma.
 * Con «Anclar solo por Tor» (0.3): cada envío pasa por el proxy de Orbot; si Orbot no está, la cola espera.
 */
public class ColaAnclaje extends JobService {
    static final String PREFS = "evidencia";
    static final String PREF_AUTO = "anclar_auto";
    static final String PREF_SOLO_WIFI = "solo_wifi";
    static final String PREF_AISLADO = "modo_aislado";
    private static final int JOB_AHORA = 3901;
    private static final int JOB_PERIODICO = 3902;
    private static final int MIN_CALENDARIOS = 2;

    static SharedPreferences prefs(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static boolean aislado(Context c) {
        return prefs(c).getBoolean(PREF_AISLADO, false);
    }

    /** Programa (o cancela) los trabajos según los ajustes. */
    static void programar(Context c) {
        JobScheduler js = c.getSystemService(JobScheduler.class);
        if (js == null) return;
        SharedPreferences p = prefs(c);
        if (p.getBoolean(PREF_AISLADO, false) || !p.getBoolean(PREF_AUTO, true)) {
            js.cancel(JOB_AHORA);
            js.cancel(JOB_PERIODICO);
            return;
        }
        int red = p.getBoolean(PREF_SOLO_WIFI, false) ? JobInfo.NETWORK_TYPE_UNMETERED : JobInfo.NETWORK_TYPE_ANY;
        ComponentName servicio = new ComponentName(c, ColaAnclaje.class);
        js.schedule(new JobInfo.Builder(JOB_AHORA, servicio)
                .setRequiredNetworkType(red)
                .setBackoffCriteria(30_000, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                .build());
        js.schedule(new JobInfo.Builder(JOB_PERIODICO, servicio)
                .setRequiredNetworkType(red)
                .setPeriodic(60 * 60 * 1000L)
                .setPersisted(false)
                .build());
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        if (aislado(this)) return false;
        if (Orbot.soloTor(this) && !Orbot.listo(this)) {
            // Regla sin excepciones: sin Orbot activo, la cola espera. Se le pide que arranque y se reintenta.
            Orbot.pedirArranque(this);
            jobFinished(params, params.getJobId() == JOB_AHORA);
            return true;
        }
        new Thread(() -> {
            boolean reintentar = false;
            try {
                reintentar = trabajar(this);
            } catch (Exception e) {
                reintentar = true;
            } finally {
                jobFinished(params, reintentar && params.getJobId() == JOB_AHORA);
            }
        }, "x39-anclaje").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true;
    }

    /** Devuelve true si quedan compromisos sin enviar (hay que reintentar pronto). */
    static boolean trabajar(Context c) throws Exception {
        Evidencias ev = new Evidencias(c);
        boolean faltanEnvios = false;
        for (Evidencias.Ficha f : ev.todas()) {
            if (aislado(c)) return false;
            // Orbot se cerró a mitad de la tanda: lo que queda espera; nada sale por la red directa.
            if (Orbot.soloTor(c) && !Orbot.listo(c)) return true;
            if ("pending".equals(f.otsEstado)) {
                if (!enviar(c, ev, f)) faltanEnvios = true;
            } else if ("calendar".equals(f.otsEstado)) {
                actualizar(c, ev, f);
            }
        }
        return faltanEnvios;
    }

    private static boolean enviar(Context c, Evidencias ev, Evidencias.Ficha f) throws Exception {
        byte[] huella = Evidencias.deHex(f.sha256);
        byte[] nonce = Evidencias.deHex(f.nonce);
        byte[] compromiso = Evidencias.deHex(f.compromiso);
        byte[] ots = null;
        int aceptados = 0;
        for (String cal : RedX39.CALENDARIOS) {
            try {
                RedX39.Respuesta r = RedX39.post(c, cal + "/digest", compromiso);
                if (r.codigo != 200) continue;
                ots = X39Core.otsIncorporate(ots, huella, nonce, compromiso, r.cuerpo);
                aceptados++;
            } catch (Exception ignorado) {
                // Un calendario caído no impide usar los demás.
            }
        }
        if (aceptados < MIN_CALENDARIOS) return false;
        ev.guardarOts(f, ots);
        f.otsEstado = "calendar";
        ev.actualizar(f);
        return true;
    }

    private static void actualizar(Context c, Evidencias ev, Evidencias.Ficha f) throws Exception {
        byte[] ots = ev.ots(f);
        if (ots == null) {
            f.otsEstado = "pending";
            ev.actualizar(f);
            return;
        }
        List<String[]> pendientes = new ArrayList<>();
        for (String linea : X39Core.otsPending(ots).split("\n")) {
            String[] p = linea.trim().split(" ");
            if (p.length == 2) pendientes.add(p);
        }
        boolean cambio = false;
        for (String[] p : pendientes) {
            try {
                RedX39.Respuesta r = RedX39.get(c, p[0] + "/timestamp/" + p[1]);
                if (r.codigo != 200) continue;
                ots = X39Core.otsIncorporate(ots, null, null, Evidencias.deHex(p[1]), r.cuerpo);
                cambio = true;
            } catch (Exception ignorado) {
                // 404 = aún pendiente; errores de red se reintentan en la siguiente vuelta.
            }
        }
        if (!cambio) return;
        ev.guardarOts(f, ots);
        String bloques = X39Core.otsBlocks(ots);
        if (!bloques.isEmpty()) {
            f.otsEstado = "bitcoin";
            f.bloque = Long.parseLong(bloques.split(",")[0]);
            ev.actualizar(f);
        }
    }
}
