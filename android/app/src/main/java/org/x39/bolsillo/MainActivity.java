package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.InputStream;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * x39 v0.6 · transparencia verificable y canal seguro para el Ayuntamiento.
 * Ciudadanos: consultan plenos, distritos y organismos y comprueban documentos, sin clave ni cuenta.
 * Plenos tiene la misma estructura y los mismos colores que sevilla.x39matrix.org.
 * Personal: además, mensajes cifrados con ML-KEM-1024 y firmados con ML-DSA-87.
 * Internet solo para el buzón del Ayuntamiento (canister/buzon), por el que viajan las cápsulas ya cifradas;
 * sin buzón configurado, los mensajes se comparten a mano. Los PDF se abren en el navegador.
 */
public class MainActivity extends Activity {
    private static final long TTL_SEGUNDOS = 7L * 24 * 3600;
    private static final int REQ_DESBLOQUEO = 39;
    private static final int REQ_COMPROBAR = 40;
    private static final long GRACIA_BLOQUEO_MS = 60_000;
    private static final String VERSION = "0.9.1";
    /** Tiempo mínimo de la pantalla «Creando tus claves» para que no parpadee. */
    private static final long CREACION_MIN_MS = 900;
    private static final String PREFS = "x39";
    /** El usuario eligió entrar como ciudadano: sin claves, solo plenos y comprobación. */
    private static final String PREF_CIUDADANO = "modo_ciudadano";

    private enum Pestana { INICIO, CHATS, CONTACTOS, PLENOS, SEGURIDAD }

    private Boveda boveda;
    private Almacen almacen;
    private byte[] clavePublica;
    private byte[] claveFirma;
    private String miId;
    private String errorInicio;
    /** Primer arranque: todavía no hay claves y se muestra la portada. */
    private boolean enBienvenida;
    /** Entró como ciudadano: sin claves; solo Plenos y comprobar documentos. */
    private boolean modoCiudadano;
    private Registro registro;
    private String errorRegistro;

    private FrameLayout raiz;
    /** La primera página, también para el personal, es Plenos: la misma que sevilla.x39matrix.org. */
    private Pestana pestana = Pestana.PLENOS;
    private Runnable pantallaSecundaria;
    private boolean desbloqueado;
    private boolean esperandoDesbloqueo;
    private long ultimaSalida;
    private String pendienteCompartido;

    private Buzon buzon;
    /** Sondeo del buzón cada pocos segundos mientras la app está delante y desbloqueada. */
    private final android.os.Handler sondeador = new android.os.Handler(android.os.Looper.getMainLooper());
    private boolean sondeando;
    private boolean sincronizando;
    private String estadoBuzon = "Todavía no se ha consultado.";
    private final Runnable sondeo = new Runnable() {
        @Override
        public void run() {
            if (!sondeando) return;
            sincronizarBuzon();
            // Con una conversación o Chats delante se pregunta más a menudo; el resto del tiempo, menos.
            boolean atento = pantallaSecundaria != null || pestana == Pestana.CHATS;
            sondeador.postDelayed(this, atento ? 3_000 : 10_000);
        }
    };

    // ------------------------------------------------------------------ ciclo de vida

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Bloquea capturas, grabación de pantalla y la miniatura en «recientes».
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);

        raiz = new FrameLayout(this);
        raiz.setBackgroundColor(Ui.FONDO);
        raiz.setOnApplyWindowInsetsListener((v, ins) -> {
            aplicarInsets(v, ins);
            return ins;
        });
        setContentView(raiz);

        boveda = new Boveda(this);
        almacen = new Almacen(this, boveda);
        buzon = new Buzon(this);
        try {
            if (boveda.tieneClaves()) {
                cargarIdentidad();
            } else if (prefs().getBoolean(PREF_CIUDADANO, false)) {
                modoCiudadano = true;
                pestana = Pestana.PLENOS;
            } else {
                enBienvenida = true;
            }
        } catch (Exception e) {
            errorInicio = Ui.mensaje(e);
        }
        guardarCompartido(getIntent());
    }

    /** Lee las claves existentes. Quien viene de x39 0.2 recibe aquí su clave de firma. */
    private void cargarIdentidad() throws Exception {
        clavePublica = boveda.clavePublica();
        if (!boveda.tieneFirma()) {
            boveda.crearFirma();
        }
        claveFirma = boveda.clavePublicaFirma();
        miId = Almacen.idDeClave(clavePublica);
        almacen.cargar();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    /** Copia del registro de actas incluida en la app; se lee una sola vez. */
    private Registro registro() {
        if (registro == null && errorRegistro == null) {
            try {
                registro = Registro.cargar(this);
            } catch (Exception e) {
                errorRegistro = Ui.mensaje(e);
            }
        }
        return registro;
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (esperandoDesbloqueo) return;
        if (enBienvenida || clavePublica == null) {
            // Sin claves no hay nada que proteger: la portada y el modo ciudadano no piden desbloqueo.
            desbloqueado = true;
            render();
            return;
        }
        if (desbloqueado && System.currentTimeMillis() - ultimaSalida < GRACIA_BLOQUEO_MS) {
            procesarPendiente();
            return;
        }
        desbloqueado = false;
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km != null && km.isDeviceSecure()) {
            @SuppressWarnings("deprecation")
            Intent i = km.createConfirmDeviceCredentialIntent("x39", "Desbloquea para ver tus mensajes");
            if (i != null) {
                raiz.removeAllViews();
                esperandoDesbloqueo = true;
                startActivityForResult(i, REQ_DESBLOQUEO);
                return;
            }
        }
        desbloqueado = true;
        render();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_COMPROBAR) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) comprobarDocumento(data.getData());
            return;
        }
        if (requestCode != REQ_DESBLOQUEO) return;
        esperandoDesbloqueo = false;
        if (resultCode == RESULT_OK) {
            desbloqueado = true;
            ultimaSalida = System.currentTimeMillis();
            render();
        } else {
            finish();
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (!esperandoDesbloqueo) ultimaSalida = System.currentTimeMillis();
        sondeando = false;
        sondeador.removeCallbacks(sondeo);
    }

    private void iniciarSondeo() {
        if (sondeando || clavePublica == null || enBienvenida) return;
        sondeando = true;
        sondeador.post(sondeo);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        guardarCompartido(intent);
        if (desbloqueado && !esperandoDesbloqueo) procesarPendiente();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (pantallaSecundaria != null) {
            if (enBienvenida) volverDeInvitacion();
            else mostrarPestana(pestana);
        } else {
            super.onBackPressed();
        }
    }

    private static void aplicarInsets(View v, WindowInsets ins) {
        if (Build.VERSION.SDK_INT >= 30) {
            Insets s = ins.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
            v.setPadding(s.left, s.top, s.right, s.bottom);
        } else {
            @SuppressWarnings("deprecation")
            int izq = ins.getSystemWindowInsetLeft(), arr = ins.getSystemWindowInsetTop(),
                    der = ins.getSystemWindowInsetRight(), abj = ins.getSystemWindowInsetBottom();
            v.setPadding(izq, arr, der, abj);
        }
    }

    // ------------------------------------------------------------------ navegación

    private void render() {
        if (errorInicio != null) {
            mostrarError();
            return;
        }
        if (enBienvenida) {
            mostrar(clavePublica == null ? pantallaBienvenida() : pantallaClaveLista(), false);
            return;
        }
        if (pantallaSecundaria != null) pantallaSecundaria.run();
        else mostrarPestana(pestana);
        procesarPendiente();
        iniciarSondeo();
    }

    private void mostrar(View contenido, boolean conNavegacion) {
        mostrar(contenido, conNavegacion, false);
    }

    /** @param granate fondo del portal de Sevilla (pestaña Plenos); si no, el grafito del resto de la app. */
    private void mostrar(View contenido, boolean conNavegacion, boolean granate) {
        if (granate) {
            raiz.setBackground(Portal.fondo());
        } else {
            raiz.setBackgroundColor(Ui.FONDO);
        }
        raiz.removeAllViews();
        LinearLayout col = Ui.columna(this);
        col.addView(contenido, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        if (conNavegacion) {
            // Barra flotante en forma de píldora, separada de los bordes.
            col.addView(barraNavegacion(), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 64), 16, 6, 16, 12));
        }
        raiz.addView(col, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        raiz.requestApplyInsets();
    }

    private void mostrarPestana(Pestana p) {
        // Sin claves (ciudadano) solo existe Plenos, y sin barra de navegación.
        if (clavePublica == null) p = Pestana.PLENOS;
        pestana = p;
        pantallaSecundaria = null;
        View v;
        switch (p) {
            case CHATS: v = pantallaChats(); break;
            case CONTACTOS: v = pantallaContactos(); break;
            case PLENOS: v = pantallaPlenos(); break;
            case SEGURIDAD: v = pantallaSeguridad(); break;
            default: v = pantallaInicio(); break;
        }
        mostrar(conBarraSuperior(v), clavePublica != null, p == Pestana.PLENOS);
    }

    /** Barra superior de las pantallas principales: la marca «x39» en rojo, a la derecha. */
    private View conBarraSuperior(View contenido) {
        LinearLayout col = Ui.columna(this);
        LinearLayout barra = Ui.fila(this);
        barra.setPadding(Ui.dp(this, 20), Ui.dp(this, 10), Ui.dp(this, 20), 0);
        // «x39» a la derecha por gravedad. Antes se empujaba con un View vacío de peso 1: un View sin
        // contenido mide TODA la altura disponible, la barra se estiraba a pantalla completa y el contenido
        // de la pestaña se quedaba sin sitio (pantallas vacías con «x39» en el centro, 0.5.0 y 0.6.x).
        barra.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        barra.addView(Ui.marca(this));
        col.addView(barra);
        col.addView(contenido, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return col;
    }

    /** Pantalla encima de una pestaña. Si se está pidiendo el desbloqueo, se muestra al volver. */
    private void abrirSecundaria(Runnable pantalla) {
        pantallaSecundaria = pantalla;
        if (!esperandoDesbloqueo) pantalla.run();
    }

    private void abrirConversacion(Almacen.Contacto c) {
        final String id = c.id;
        abrirSecundaria(() -> {
            Almacen.Contacto actual = almacen.porId(id);
            if (actual == null) { mostrarPestana(Pestana.CHATS); return; }
            mostrar(pantallaConversacion(actual), false);
        });
    }

    private void abrirVerificar(Almacen.Contacto c) {
        final String id = c.id;
        abrirSecundaria(() -> {
            Almacen.Contacto actual = almacen.porId(id);
            if (actual == null) { mostrarPestana(Pestana.CONTACTOS); return; }
            mostrar(pantallaVerificar(actual), false);
        });
    }

    private void abrirAgregar(String claveInicial) {
        abrirSecundaria(() -> mostrar(pantallaAgregar(claveInicial), false));
    }

    private View barraNavegacion() {
        LinearLayout barra = Ui.fila(this);
        barra.setBackground(Ui.redondeado(this, Ui.SUPERFICIE_2, 32));
        barra.setElevation(Ui.dp(this, 8));
        barra.setPadding(Ui.dp(this, 6), 0, Ui.dp(this, 6), 0);
        barra.addView(itemNavegacion(Pestana.INICIO, Icono.Tipo.INICIO, "Inicio"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.CHATS, Icono.Tipo.CHAT, "Chats"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.CONTACTOS, Icono.Tipo.CONTACTOS, "Contactos"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.PLENOS, Icono.Tipo.ACTAS, "Plenos"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.SEGURIDAD, Icono.Tipo.ESCUDO, "Seguridad"), Ui.peso(1));
        return barra;
    }

    private View itemNavegacion(Pestana p, Icono.Tipo tipo, String etiqueta) {
        boolean activa = p == pestana && pantallaSecundaria == null;
        // Activa: icono blanco dentro de un cuadrado oscuro. Resto: icono gris sobre la píldora.
        FrameLayout item = new FrameLayout(this);
        item.setMinimumHeight(Ui.dp(this, 58));
        FrameLayout cuadro = new FrameLayout(this);
        if (activa) cuadro.setBackground(Ui.redondeado(this, Ui.FONDO, 15));
        cuadro.addView(Ui.icono(this, tipo, activa ? Ui.BLANCO : Ui.SUAVE, 22),
                new FrameLayout.LayoutParams(Ui.dp(this, 22), Ui.dp(this, 22), Gravity.CENTER));
        item.addView(cuadro, new FrameLayout.LayoutParams(Ui.dp(this, 46), Ui.dp(this, 46), Gravity.CENTER));
        item.setContentDescription(etiqueta);
        item.setOnClickListener(v -> mostrarPestana(p));
        Ui.clicable(item);
        return item;
    }

    // ------------------------------------------------------------------ primer arranque

    /** Portada: foto de fondo, qué es x39 y dos entradas: ciudadano (sin clave) o personal (crea la clave). */
    private View pantallaBienvenida() {
        FrameLayout marco = new FrameLayout(this);
        marco.setBackgroundColor(Ui.FONDO);
        int foto = getResources().getIdentifier("portada_sevilla", "drawable", getPackageName());
        if (foto != 0) {
            ImageView fondo = new ImageView(this);
            fondo.setImageResource(foto);
            fondo.setScaleType(ImageView.ScaleType.CENTER_CROP);
            fondo.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            marco.addView(fondo, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }
        // Velo: deja ver la foto arriba y oscurece abajo para que el texto se lea.
        android.graphics.drawable.GradientDrawable velo = new android.graphics.drawable.GradientDrawable(
                android.graphics.drawable.GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{foto != 0 ? 0x33000000 : 0xFF2A0B0A, 0xB30D0D0D, 0xF20D0D0D, 0xFF0D0D0D});
        View capa = new View(this);
        capa.setBackground(velo);
        marco.addView(capa, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout col = Ui.columna(this);
        col.setGravity(Gravity.BOTTOM);
        col.setPadding(Ui.dp(this, 24), Ui.dp(this, 24), Ui.dp(this, 24), Ui.dp(this, 20));

        LinearLayout marca = Ui.fila(this);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_launcher_frente);
        marca.addView(logo, new LinearLayout.LayoutParams(Ui.dp(this, 64), Ui.dp(this, 64)));
        marca.addView(Ui.texto(this, "x39", 40, Ui.ROJO, true));
        col.addView(marca);
        TextView lema = Ui.texto(this, "Transparencia verificable y canal seguro del Ayuntamiento.", 17, Ui.TEXTO_2, false);
        lema.setPadding(Ui.dp(this, 4), Ui.dp(this, 2), 0, Ui.dp(this, 14));
        col.addView(lema);

        col.addView(puntoBienvenida(Icono.Tipo.ACTAS, "Plenos y distritos", "Consulta las actas publicadas y comprueba que no se han alterado."));
        col.addView(puntoBienvenida(Icono.Tipo.CANDADO, "Canal seguro del personal", "Mensajes cifrados y firmados con estándares poscuánticos del NIST."));
        col.addView(puntoBienvenida(Icono.Tipo.ESCUDO_OK, "Sin cuentas ni Google", "Internet solo para el buzón del Ayuntamiento; sin capturas de pantalla."));

        if (!movilConBloqueo()) {
            LinearLayout av = Ui.columna(this);
            av.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 12));
            android.graphics.drawable.GradientDrawable borde = new android.graphics.drawable.GradientDrawable();
            borde.setColor(0x14FFFFFF);
            borde.setCornerRadius(Ui.dp(this, 14));
            borde.setStroke(Ui.dp(this, 1), 0x66FFFFFF);
            av.setBackground(borde);
            LinearLayout avTit = Ui.fila(this);
            avTit.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.AVISO, 18));
            TextView avT = Ui.texto(this, "Tu móvil no tiene bloqueo de pantalla", 14, Ui.TEXTO, true);
            avT.setPadding(Ui.dp(this, 10), 0, 0, 0);
            avTit.addView(avT, Ui.peso(1));
            av.addView(avTit);
            TextView avD = Ui.texto(this, "Si eres personal del Ayuntamiento, actívalo antes de crear tu clave: sin él, cualquiera que coja el móvil entra en tus mensajes.", 13, Ui.TEXTO_2, false);
            avD.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 8));
            av.addView(avD);
            TextView ajustes = Ui.texto(this, "Activar bloqueo de pantalla", 14, Ui.AVISO, true);
            ajustes.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 2));
            ajustes.setOnClickListener(v -> abrirAjustesSeguridad());
            Ui.clicable(ajustes);
            av.addView(ajustes);
            col.addView(av, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 4));
        }

        TextView ciudadano = Ui.boton(this, "Ver plenos y comprobar documentos", true, v -> entrarComoCiudadano());
        col.addView(ciudadano, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 16, 0, 10));
        TextView personal = Ui.boton(this, "Soy personal del Ayuntamiento", false, v -> pedirInvitacion());
        col.addView(personal, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 10));
        TextView pie = Ui.texto(this, "Versión de prueba · protocolo pendiente de auditoría externa", 12, Ui.TENUE, false);
        pie.setGravity(Gravity.CENTER);
        col.addView(pie, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        sv.addView(col, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        marco.addView(sv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        return marco;
    }

    private View puntoBienvenida(Icono.Tipo tipo, String titulo, String texto) {
        LinearLayout f = Ui.fila(this);
        f.setGravity(Gravity.TOP);
        f.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
        FrameLayout caja = new FrameLayout(this);
        caja.setBackground(Ui.redondeado(this, Ui.CAJA, 12));
        caja.addView(Ui.icono(this, tipo, Ui.TEXTO, 20), new FrameLayout.LayoutParams(Ui.dp(this, 20), Ui.dp(this, 20), Gravity.CENTER));
        f.addView(caja, new LinearLayout.LayoutParams(Ui.dp(this, 40), Ui.dp(this, 40)));
        LinearLayout t = Ui.columna(this);
        t.setPadding(Ui.dp(this, 14), 0, 0, 0);
        t.addView(Ui.texto(this, titulo, 15, Ui.TEXTO, true));
        t.addView(Ui.texto(this, texto, 13, Ui.TEXTO_2, false));
        f.addView(t, Ui.peso(1));
        return f;
    }

    private View pantallaCreando() {
        LinearLayout col = Ui.columna(this);
        col.setGravity(Gravity.CENTER);
        col.setPadding(Ui.dp(this, 32), 0, Ui.dp(this, 32), 0);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_launcher_frente);
        col.addView(logo, new LinearLayout.LayoutParams(Ui.dp(this, 96), Ui.dp(this, 96)));
        ProgressBar pb = new ProgressBar(this);
        pb.setIndeterminate(true);
        pb.setIndeterminateTintList(ColorStateList.valueOf(Ui.BLANCO));
        col.addView(pb, Ui.margen(this, Ui.dp(this, 40), Ui.dp(this, 40), 0, 16, 0, 16));
        TextView t = Ui.texto(this, "Creando tus claves…", 20, Ui.TEXTO, true);
        t.setGravity(Gravity.CENTER);
        col.addView(t);
        TextView d = Ui.texto(this, "ML-KEM-1024 para cifrar · ML-DSA-87 para firmar", 13, Ui.SUAVE, false);
        d.setGravity(Gravity.CENTER);
        d.setPadding(0, Ui.dp(this, 6), 0, 0);
        col.addView(d);
        return col;
    }

    /** Tras crear la clave: la huella explicada y el botón para entrar. */
    private View pantallaClaveLista() {
        LinearLayout raizCol = Ui.columna(this);
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 24), Ui.dp(this, 40), Ui.dp(this, 24), Ui.dp(this, 16));
        FrameLayout caja = new FrameLayout(this);
        caja.setBackground(Ui.redondeado(this, Ui.CAJA, 18));
        caja.addView(Ui.icono(this, Icono.Tipo.ESCUDO_OK, Ui.TEXTO, 30), new FrameLayout.LayoutParams(Ui.dp(this, 30), Ui.dp(this, 30), Gravity.CENTER));
        col.addView(caja, new LinearLayout.LayoutParams(Ui.dp(this, 60), Ui.dp(this, 60)));
        TextView t = Ui.texto(this, "Tu clave está lista", 26, Ui.TEXTO, true);
        t.setPadding(0, Ui.dp(this, 18), 0, Ui.dp(this, 8));
        col.addView(t);
        col.addView(Ui.texto(this, "Esta es tu huella de seguridad. Cuando añadas a alguien, comparad estos 60 dígitos en persona: si coinciden, nadie se ha puesto en medio.", 15, Ui.TEXTO_2, false));
        LinearLayout marcoHuella = Ui.columna(this);
        marcoHuella.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        marcoHuella.setBackground(Ui.degradado(this, 24));
        marcoHuella.addView(Ui.huella(this, miHuella(), 18));
        col.addView(marcoHuella, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 20, 0, 14));
        col.addView(Ui.texto(this, "Puedes volver a verla en Contactos › Mi clave.", 13, Ui.SUAVE, false));
        if (!movilConBloqueo()) {
            TextView b = Ui.texto(this, "⚠ Recuerda activar el bloqueo de pantalla del móvil.", 13, Ui.AVISO, false);
            b.setPadding(0, Ui.dp(this, 10), 0, 0);
            col.addView(b);
        }
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        TextView entrar = Ui.boton(this, "Entrar", true, v -> {
            enBienvenida = false;
            mostrarPestana(Pestana.PLENOS);
            procesarPendiente();
        });
        raizCol.addView(entrar, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 24, 8, 24, 20));
        return raizCol;
    }

    /** Genera ML-KEM-1024 y ML-DSA-87 fuera del hilo de la interfaz. */
    private void crearIdentidad() {
        mostrar(pantallaCreando(), false);
        new Thread(() -> {
            long inicio = System.currentTimeMillis();
            String error = null;
            try {
                boveda.crearClaves();
                if (!boveda.tieneFirma()) boveda.crearFirma();
            } catch (Exception e) {
                error = Ui.mensaje(e);
            }
            long resto = CREACION_MIN_MS - (System.currentTimeMillis() - inicio);
            if (resto > 0) {
                try { Thread.sleep(resto); } catch (InterruptedException ignorado) { Thread.currentThread().interrupt(); }
            }
            final String fallo = error;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                if (fallo != null) {
                    if (modoCiudadano) mostrarPestana(Pestana.PLENOS);
                    else mostrar(pantallaBienvenida(), false);
                    aviso("No se pudo crear la clave: " + fallo);
                    return;
                }
                try {
                    cargarIdentidad();
                } catch (Exception e) {
                    errorInicio = Ui.mensaje(e);
                    render();
                    return;
                }
                crearAcreditacion();
                modoCiudadano = false;
                prefs().edit().remove(PREF_CIUDADANO).apply();
                enBienvenida = true;
                mostrar(pantallaClaveLista(), false);
            });
        }, "x39-claves").start();
    }

    private boolean movilConBloqueo() {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        return km != null && km.isDeviceSecure();
    }

    private void abrirAjustesSeguridad() {
        try {
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
        } catch (android.content.ActivityNotFoundException e) {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    private void entrarComoCiudadano() {
        prefs().edit().putBoolean(PREF_CIUDADANO, true).apply();
        modoCiudadano = true;
        enBienvenida = false;
        mostrarPestana(Pestana.PLENOS);
    }

    /** Desde el modo ciudadano: el acceso del personal pasa siempre por la invitación. */
    private void activarAccesoPersonal() {
        pedirInvitacion();
    }

    // ------------------------------------------------------------------ invitación del Ayuntamiento

    private static final String ASSET_AUTORIDAD = "autoridad.pk";
    private static final String PREF_INV_NOMBRE = "invitacion_nombre";
    private static final String PREF_INV_CADUCA = "invitacion_caduca";
    private static final String PREF_INV_TEXTO = "invitacion_texto";
    private static final String PREF_ACREDITACION = "acreditacion";
    /** true: la invitación pegada acredita la clave que ya existe en este móvil, no crea una nueva. */
    private boolean invitacionParaAcreditar;
    /** Invitación que llegó compartida desde otra app; se rellena en la pantalla y se olvida. */
    private String invitacionInicial;

    /** Clave pública ML-DSA-87 de la autoridad (el Ayuntamiento), incluida en la app; null si esta compilación no la lleva. */
    private byte[] autoridad() {
        try (InputStream in = getAssets().open(ASSET_AUTORIDAD)) {
            byte[] pk = new byte[X39Core.DSA_PK_LEN];
            int total = 0;
            while (total < pk.length) {
                int n = in.read(pk, total, pk.length - total);
                if (n < 0) break;
                total += n;
            }
            return total == pk.length && in.read() < 0 ? pk : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * «Soy personal del Ayuntamiento» no crea la clave sin más: hace falta una invitación firmada por la
     * autoridad del Ayuntamiento (texto «X39INV1:…» que llega por cualquier canal). Sin servidor.
     */
    private void pedirInvitacion() {
        pedirInvitacion(false);
    }

    private void pedirInvitacion(boolean paraAcreditar) {
        invitacionParaAcreditar = paraAcreditar;
        if (autoridad() == null) {
            aviso("Esta versión de la app no lleva la clave de la autoridad del Ayuntamiento, así que no puede "
                    + "comprobar invitaciones. Pide una compilación que la incluya.");
            return;
        }
        pantallaSecundaria = () -> mostrar(pantallaInvitacion(), false);
        pantallaSecundaria.run();
    }

    private void volverDeInvitacion() {
        pantallaSecundaria = null;
        if (enBienvenida) mostrar(pantallaBienvenida(), false);
        else mostrarPestana(Pestana.PLENOS);
    }

    private View pantallaInvitacion() {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(cabeceraSecundaria("Invitación del Ayuntamiento", this::volverDeInvitacion));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 20), Ui.dp(this, 4), Ui.dp(this, 20), Ui.dp(this, 24));

        col.addView(Ui.texto(this, "El acceso del personal lo da el Ayuntamiento", 22, Ui.TEXTO, true));
        TextView d = Ui.texto(this, "Pega aquí la invitación que te ha enviado el Ayuntamiento (empieza por X39INV1). "
                + "La app comprueba su firma sin conexión; si es válida y no ha caducado, crea tu clave en este móvil.", 15, Ui.TEXTO_2, false);
        d.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 16));
        col.addView(d);

        EditText campo = Ui.campo(this, "X39INV1:…", 5, true);
        if (invitacionInicial != null) {
            campo.setText(invitacionInicial);
            invitacionInicial = null;
        }
        col.addView(campo, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView pegar = Ui.boton(this, "Pegar del portapapeles", false, v -> {
            String t = portapapeles();
            if (t == null || t.trim().isEmpty()) aviso("No hay nada copiado.");
            else campo.setText(t.trim());
        });
        col.addView(pegar, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        TextView comprobar = Ui.boton(this, "Comprobar la invitación", true, v -> comprobarInvitacion(campo.getText().toString()));
        col.addView(comprobar, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 0));

        TextView nota = Ui.texto(this, "La invitación lleva la firma ML-DSA-87 de la autoridad del Ayuntamiento, una fecha de caducidad "
                + "y el nombre o cargo para quien se emitió. No se envía a ningún sitio: se comprueba en este móvil.", 12, Ui.TENUE, false);
        nota.setPadding(0, Ui.dp(this, 16), 0, 0);
        col.addView(nota);
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private void comprobarInvitacion(String texto) {
        byte[] pk = autoridad();
        String s = texto.trim();
        if (pk == null || s.isEmpty()) {
            aviso("Pega primero la invitación.");
            return;
        }
        if (s.startsWith("X39ID1:") || s.startsWith("X39PK1:")) {
            aviso("Esto es la clave de un contacto, no una invitación. Va en Contactos › Añadir.");
            return;
        }
        if (s.startsWith("X39MSG1:")) {
            aviso("Esto es un mensaje cifrado, no una invitación. Va en Chats › Abrir mensaje copiado.");
            return;
        }
        if (!s.startsWith("X39INV1:")) {
            aviso("La invitación tiene que empezar por X39INV1. Copia el texto entero que te envió el Ayuntamiento.");
            return;
        }
        String hoy = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(new Date());
        String resultado;
        try {
            resultado = X39Core.invitationVerify(pk, texto, hoy);
        } catch (Exception e) {
            aviso("Invitación no válida: " + Ui.mensaje(e));
            return;
        }
        int sep = resultado.indexOf('|');
        final String caduca = sep > 0 ? resultado.substring(0, sep) : resultado;
        final String nombre = sep > 0 ? resultado.substring(sep + 1) : "";
        String[] p = caduca.split("-");
        String caducaVisible = p.length == 3 ? p[2] + "/" + p[1] + "/" + p[0] : caduca;
        final String invitacion = s;
        if (invitacionParaAcreditar) {
            new AlertDialog.Builder(this)
                    .setTitle("Invitación válida")
                    .setMessage("Emitida para: " + nombre + "\nVálida hasta el " + caducaVisible + ".\n\n"
                            + "Ese nombre se unirá a la clave que ya tienes en este móvil, firmándolo con ella. "
                            + "Quien te añada verá el nombre acreditado por el Ayuntamiento.")
                    .setNegativeButton("Cancelar", null)
                    .setPositiveButton("Acreditar mi clave", (dlg, w) -> {
                        prefs().edit().putString(PREF_INV_NOMBRE, nombre).putString(PREF_INV_CADUCA, caduca).putString(PREF_INV_TEXTO, invitacion).apply();
                        crearAcreditacion();
                        pantallaSecundaria = null;
                        mostrarPestana(Pestana.CONTACTOS);
                    })
                    .show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Invitación válida")
                .setMessage("Emitida para: " + nombre + "\nVálida hasta el " + caducaVisible + ".\n\n"
                        + "Se creará tu clave en este móvil (ML-KEM-1024 y ML-DSA-87) y ese nombre quedará unido a ella. "
                        + "Los chats solo funcionan entre personas que hayan comparado su huella en persona.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Crear mi clave", (dlg, w) -> {
                    prefs().edit().putString(PREF_INV_NOMBRE, nombre).putString(PREF_INV_CADUCA, caduca).putString(PREF_INV_TEXTO, invitacion).apply();
                    pantallaSecundaria = null;
                    crearIdentidad();
                })
                .show();
    }

    /** Si hay una invitación pendiente, la firma con la clave de este móvil y guarda la acreditación. */
    private void crearAcreditacion() {
        String inv = prefs().getString(PREF_INV_TEXTO, null);
        if (inv == null || clavePublica == null) return;
        byte[] semilla = null;
        try {
            semilla = boveda.semillaFirma();
            String acr = X39Core.accreditationCreate(semilla, inv);
            prefs().edit().putString(PREF_ACREDITACION, acr).remove(PREF_INV_TEXTO).apply();
        } catch (Exception e) {
            aviso("No se pudo crear la acreditación: " + Ui.mensaje(e));
        } finally {
            if (semilla != null) Arrays.fill(semilla, (byte) 0);
        }
    }

    private String miAcreditacion() {
        return prefs().getString(PREF_ACREDITACION, null);
    }

    /** Comprueba la acreditación que vino con la clave del contacto: firma del Ayuntamiento y firma del propio contacto. */
    private void acreditarContacto(Almacen.Contacto c) {
        c.acreditadoNombre = null;
        c.acreditadoHasta = null;
        if (c.acreditacionTexto == null || c.claveFirma == null) return;
        byte[] pk = autoridad();
        if (pk == null) return;
        try {
            String hoy = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(new Date());
            String r = X39Core.accreditationVerify(pk, c.claveFirma, c.acreditacionTexto, hoy);
            int sep = r.indexOf('|');
            if (sep > 0) {
                c.acreditadoHasta = r.substring(0, sep);
                c.acreditadoNombre = r.substring(sep + 1);
            }
        } catch (Exception ignorado) {
            // Se conserva el texto: no verifica hoy (firma, fecha o esta compilación sin clave de la autoridad).
        }
    }

    private static String etiquetaAcreditado(Almacen.Contacto c) {
        return c.acreditadoNombre + " · acreditación del Ayuntamiento hasta el " + c.acreditadoHastaVisible();
    }

    private static String fechaVisible(String iso) {
        if (iso == null || iso.length() != 10) return iso == null ? "" : iso;
        String[] p = iso.split("-");
        return p.length == 3 ? p[2] + "/" + p[1] + "/" + p[0] : iso;
    }

    // ------------------------------------------------------------------ inicio

    /** Inicio: tarjeta de identidad (sin correo ni contraseña: la identidad es la clave) y menú en cuadrícula. */
    private View pantallaInicio() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 16), Ui.dp(this, 4), Ui.dp(this, 16), Ui.dp(this, 24));

        LinearLayout perfil = Ui.columna(this);
        perfil.setGravity(Gravity.CENTER_HORIZONTAL);
        perfil.setPadding(Ui.dp(this, 20), Ui.dp(this, 22), Ui.dp(this, 20), Ui.dp(this, 18));
        perfil.setBackground(Ui.degradado(this, 28));

        FrameLayout aro = new FrameLayout(this);
        android.graphics.drawable.GradientDrawable circulo = new android.graphics.drawable.GradientDrawable();
        circulo.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        circulo.setColor(Ui.CAJA);
        circulo.setStroke(Ui.dp(this, 2), Ui.BLANCO);
        aro.setBackground(circulo);
        aro.addView(Ui.icono(this, Icono.Tipo.LLAVE, Ui.BLANCO, 34), new FrameLayout.LayoutParams(Ui.dp(this, 34), Ui.dp(this, 34), Gravity.CENTER));
        perfil.addView(aro, new LinearLayout.LayoutParams(Ui.dp(this, 84), Ui.dp(this, 84)));

        TextView nombre = Ui.texto(this, "Mi identidad", 20, Ui.TEXTO, true);
        nombre.setPadding(0, Ui.dp(this, 12), 0, Ui.dp(this, 2));
        perfil.addView(nombre);
        String[] grupos = miHuella().split(" ");
        String resumen = grupos.length >= 3 ? grupos[0] + " " + grupos[1] + " " + grupos[2] + " …" : "";
        perfil.addView(Ui.mono(this, "huella " + resumen, 13, Ui.SUAVE));

        int mensajes = 0;
        for (Almacen.Contacto c : almacen.contactos) mensajes += c.mensajes.size();
        Registro r = registro();
        LinearLayout cifras = Ui.fila(this);
        cifras.setPadding(0, Ui.dp(this, 18), 0, 0);
        cifras.addView(cifra(String.valueOf(almacen.contactos.size()), "Contactos"), Ui.peso(1));
        cifras.addView(cifra(String.valueOf(mensajes), "Mensajes"), Ui.peso(1));
        cifras.addView(cifra(r == null ? "—" : String.valueOf(r.total), "Actas"), Ui.peso(1));
        perfil.addView(cifras, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        perfil.setContentDescription("Mi identidad. Abrir mi clave");
        perfil.setOnClickListener(v -> mostrarPestana(Pestana.CONTACTOS));
        Ui.clicable(perfil);
        col.addView(perfil);

        LinearLayout menu = Ui.columna(this);
        menu.setPadding(Ui.dp(this, 10), Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 10));
        menu.setBackground(Ui.degradado(this, 28));
        TextView tm = Ui.texto(this, "Menú", 15, Ui.TEXTO_2, false);
        tm.setGravity(Gravity.CENTER);
        tm.setPadding(0, 0, 0, Ui.dp(this, 8));
        menu.addView(tm, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        menu.addView(filaBaldosas(
                baldosa(Icono.Tipo.CHAT, "Chats", () -> mostrarPestana(Pestana.CHATS)),
                baldosa(Icono.Tipo.CONTACTOS, "Contactos", () -> mostrarPestana(Pestana.CONTACTOS)),
                baldosa(Icono.Tipo.ACTAS, "Plenos", () -> mostrarPestana(Pestana.PLENOS))));
        menu.addView(filaBaldosas(
                baldosa(Icono.Tipo.ESCUDO_OK, "Comprobar", this::elegirDocumento),
                baldosa(Icono.Tipo.ESCUDO, "Seguridad", () -> mostrarPestana(Pestana.SEGURIDAD)),
                baldosa(Icono.Tipo.ENLACE, "Portal", () -> abrirEnlace(Registro.PORTAL))));
        col.addView(menu, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));

        LinearLayout cripto = Ui.columna(this);
        cripto.setPadding(Ui.dp(this, 18), Ui.dp(this, 16), Ui.dp(this, 18), Ui.dp(this, 12));
        cripto.setBackground(Ui.degradado(this, 28));
        cripto.addView(Ui.texto(this, "Criptografía", 16, Ui.TEXTO, true));
        TextView subCripto = Ui.texto(this, "Lo que usa esta app, en tu móvil y sin servidores", 12, Ui.SUAVE, false);
        subCripto.setPadding(0, Ui.dp(this, 2), 0, Ui.dp(this, 8));
        cripto.addView(subCripto);
        cripto.addView(filaAlgoritmo("ML-KEM-1024", "cifra los mensajes · NIST FIPS 203"));
        cripto.addView(filaAlgoritmo("ML-DSA-87", "firma al remitente · NIST FIPS 204"));
        cripto.addView(filaAlgoritmo("AES-256-GCM", "protege el contenido y el almacén"));
        cripto.addView(filaAlgoritmo("SHA-256", "huella de las actas que compruebas"));
        cripto.setOnClickListener(v -> mostrarPestana(Pestana.SEGURIDAD));
        Ui.clicable(cripto);
        col.addView(cripto, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));

        col.addView(franjaProteccion(), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        sv.addView(col);
        return sv;
    }

    private View filaAlgoritmo(String algoritmo, String uso) {
        LinearLayout f = Ui.fila(this);
        f.setPadding(0, Ui.dp(this, 5), 0, Ui.dp(this, 5));
        TextView chip = Ui.mono(this, algoritmo, 12, Ui.BLANCO);
        chip.setGravity(Gravity.CENTER);
        chip.setMinWidth(Ui.dp(this, 112));
        chip.setPadding(Ui.dp(this, 10), Ui.dp(this, 5), Ui.dp(this, 10), Ui.dp(this, 5));
        chip.setBackground(Ui.redondeado(this, Ui.CAJA, 10));
        f.addView(chip);
        TextView t = Ui.texto(this, uso, 13, Ui.TEXTO_2, false);
        t.setPadding(Ui.dp(this, 12), 0, 0, 0);
        f.addView(t, Ui.peso(1));
        return f;
    }

    private View cifra(String valor, String etiqueta) {
        LinearLayout c = Ui.columna(this);
        c.setGravity(Gravity.CENTER_HORIZONTAL);
        TextView v = Ui.texto(this, valor, 22, Ui.TEXTO, true);
        v.setGravity(Gravity.CENTER);
        c.addView(v);
        TextView e = Ui.texto(this, etiqueta, 12, Ui.SUAVE, false);
        e.setGravity(Gravity.CENTER);
        c.addView(e);
        return c;
    }

    private View filaBaldosas(View... baldosas) {
        LinearLayout f = Ui.fila(this);
        for (View b : baldosas) {
            LinearLayout.LayoutParams lp = Ui.peso(1);
            lp.setMargins(Ui.dp(this, 5), Ui.dp(this, 5), Ui.dp(this, 5), Ui.dp(this, 5));
            f.addView(b, lp);
        }
        return f;
    }

    private View baldosa(Icono.Tipo tipo, String etiqueta, Runnable accion) {
        LinearLayout t = Ui.columna(this);
        t.setGravity(Gravity.CENTER);
        t.setMinimumHeight(Ui.dp(this, 96));
        t.setPadding(Ui.dp(this, 6), Ui.dp(this, 14), Ui.dp(this, 6), Ui.dp(this, 12));
        t.setBackground(Ui.redondeado(this, Ui.CAJA, 22));
        t.addView(Ui.icono(this, tipo, Ui.BLANCO, 28));
        TextView e = Ui.texto(this, etiqueta, 12, Ui.TEXTO_2, false);
        e.setGravity(Gravity.CENTER);
        e.setPadding(0, Ui.dp(this, 8), 0, 0);
        t.addView(e);
        t.setContentDescription(etiqueta);
        t.setOnClickListener(v -> accion.run());
        Ui.clicable(t);
        return t;
    }

    // ------------------------------------------------------------------ pantallas

    private View pantallaChats() {
        FrameLayout marco = new FrameLayout(this);
        LinearLayout col = Ui.columna(this);

        LinearLayout cab = Ui.fila(this);
        cab.setPadding(Ui.dp(this, 20), Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 6));
        cab.addView(Ui.texto(this, "Chats", 24, Ui.TEXTO, true), Ui.peso(1));
        cab.addView(Ui.botonIcono(this, Icono.Tipo.PEGAR, Ui.TEXTO, "Abrir mensaje copiado", v -> procesarTexto(portapapeles())));
        col.addView(cab);

        col.addView(franjaProteccion(), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 16, 0, 16, 0));

        LinearLayout tit = Ui.fila(this);
        tit.setPadding(Ui.dp(this, 20), Ui.dp(this, 22), Ui.dp(this, 20), Ui.dp(this, 6));
        tit.addView(Ui.texto(this, "Conversaciones", 17, Ui.TEXTO, true), Ui.peso(1));
        tit.addView(Ui.texto(this, almacen.contactos.size() + (almacen.contactos.size() == 1 ? " contacto" : " contactos"), 12, Ui.SUAVE, false));
        col.addView(tit);

        ScrollView sv = new ScrollView(this);
        LinearLayout lista = Ui.columna(this);
        lista.setPadding(0, 0, 0, Ui.dp(this, 96));
        List<Almacen.Contacto> cs = almacen.ordenados();
        if (cs.isEmpty()) {
            lista.addView(estadoVacio());
        } else {
            for (Almacen.Contacto c : cs) lista.addView(filaChat(c));
        }
        sv.addView(lista);
        col.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        marco.addView(col);

        FrameLayout fab = new FrameLayout(this);
        fab.setBackground(Ui.redondeado(this, Ui.BLANCO, 20));
        fab.setElevation(Ui.dp(this, 6));
        ImageView mas = new ImageView(this);
        mas.setImageDrawable(new Icono(Icono.Tipo.MAS, Ui.FONDO));
        fab.addView(mas, new FrameLayout.LayoutParams(Ui.dp(this, 24), Ui.dp(this, 24), Gravity.CENTER));
        fab.setContentDescription("Añadir contacto");
        fab.setOnClickListener(v -> abrirAgregar(""));
        Ui.clicable(fab);
        FrameLayout.LayoutParams lpFab = new FrameLayout.LayoutParams(Ui.dp(this, 56), Ui.dp(this, 56), Gravity.BOTTOM | Gravity.END);
        lpFab.setMargins(0, 0, Ui.dp(this, 20), Ui.dp(this, 20));
        marco.addView(fab, lpFab);
        return marco;
    }

    private View franjaProteccion() {
        LinearLayout f = Ui.fila(this);
        f.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 12));
        f.setBackground(Ui.degradado(this, 22));
        FrameLayout caja = new FrameLayout(this);
        caja.setBackground(Ui.redondeado(this, Ui.CAJA, 12));
        caja.addView(Ui.icono(this, Icono.Tipo.ESCUDO_OK, Ui.TEXTO, 20), new FrameLayout.LayoutParams(Ui.dp(this, 20), Ui.dp(this, 20), Gravity.CENTER));
        f.addView(caja, new LinearLayout.LayoutParams(Ui.dp(this, 38), Ui.dp(this, 38)));
        LinearLayout textos = Ui.columna(this);
        textos.setPadding(Ui.dp(this, 12), 0, 0, 0);
        textos.addView(Ui.texto(this, "Protección activa", 14, Ui.TEXTO, true));
        textos.addView(Ui.texto(this, "Cifrado y firmado poscuántico · por el buzón del Ayuntamiento", 12, Ui.SUAVE, false));
        f.addView(textos, Ui.peso(1));
        f.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.TENUE, 18));
        f.setOnClickListener(v -> mostrarPestana(Pestana.SEGURIDAD));
        Ui.clicable(f);
        return f;
    }

    private View estadoVacio() {
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 20), Ui.dp(this, 28), Ui.dp(this, 20), 0);
        TextView t = Ui.texto(this, "Aún no tienes contactos", 16, Ui.TEXTO, true);
        col.addView(t);
        TextView d = Ui.texto(this, "Comparte tu clave con alguien de confianza y añade la suya. Después comparad la huella de seguridad en persona.", 14, Ui.SUAVE, false);
        d.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 16));
        col.addView(d);
        col.addView(Ui.boton(this, "Compartir mi clave", true, v -> compartir(miIdentidad(), "Compartir mi clave x39")));
        View esp = new View(this);
        col.addView(esp, new LinearLayout.LayoutParams(1, Ui.dp(this, 10)));
        col.addView(Ui.boton(this, "Añadir un contacto", false, v -> abrirAgregar("")));
        return col;
    }

    private View filaChat(Almacen.Contacto c) {
        LinearLayout f = Ui.fila(this);
        f.setPadding(Ui.dp(this, 20), Ui.dp(this, 10), Ui.dp(this, 20), Ui.dp(this, 10));
        f.setMinimumHeight(Ui.dp(this, 72));
        f.addView(Ui.avatar(this, c.nombre, 48));

        LinearLayout textos = Ui.columna(this);
        textos.setPadding(Ui.dp(this, 14), 0, Ui.dp(this, 8), 0);
        LinearLayout nombre = Ui.fila(this);
        nombre.addView(Ui.texto(this, c.nombre, 16, Ui.TEXTO, true));
        if (c.verificado) {
            ImageView ok = Ui.icono(this, Icono.Tipo.ESCUDO_OK, Ui.SUAVE, 14);
            ((LinearLayout.LayoutParams) ok.getLayoutParams()).setMargins(Ui.dp(this, 6), 0, 0, 0);
            nombre.addView(ok);
        } else {
            TextView chip = Ui.texto(this, "Sin verificar", 11, Ui.AVISO, false);
            chip.setPadding(Ui.dp(this, 6), Ui.dp(this, 1), Ui.dp(this, 6), Ui.dp(this, 1));
            android.graphics.drawable.GradientDrawable borde = new android.graphics.drawable.GradientDrawable();
            borde.setCornerRadius(Ui.dp(this, 6));
            borde.setStroke(Ui.dp(this, 1), 0x66FFFFFF);
            chip.setBackground(borde);
            nombre.addView(chip, Ui.margen(this, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, 8, 0, 0, 0));
        }
        textos.addView(nombre);
        if (c.acreditadoNombre != null) textos.addView(Ui.texto(this, c.acreditadoNombre + " · acreditación del Ayuntamiento", 12, Ui.SUAVE, false));
        String vista;
        if (c.mensajes.isEmpty()) {
            vista = "Sin mensajes todavía";
        } else {
            Almacen.Mensaje m = c.mensajes.get(c.mensajes.size() - 1);
            vista = (m.saliente ? "Tú: " : "") + m.texto;
        }
        TextView prev = Ui.texto(this, vista, 14, Ui.TEXTO_2, false);
        prev.setSingleLine(true);
        prev.setEllipsize(TextUtils.TruncateAt.END);
        textos.addView(prev);
        f.addView(textos, Ui.peso(1));

        if (!c.mensajes.isEmpty()) {
            f.addView(Ui.texto(this, Ui.hora(c.ultimaActividad()), 12, Ui.TENUE, false));
        }
        f.setOnClickListener(v -> abrirConversacion(c));
        f.setOnLongClickListener(v -> {
            confirmarEliminar(c);
            return true;
        });
        Ui.clicable(f);
        return f;
    }

    private View pantallaConversacion(Almacen.Contacto c) {
        LinearLayout col = Ui.columna(this);

        LinearLayout cab = Ui.fila(this);
        cab.setPadding(Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 4), Ui.dp(this, 8));
        cab.addView(Ui.botonIcono(this, Icono.Tipo.ATRAS, Ui.TEXTO, "Volver", v -> mostrarPestana(Pestana.CHATS)));
        cab.addView(Ui.avatar(this, c.nombre, 40));
        LinearLayout textos = Ui.columna(this);
        textos.setPadding(Ui.dp(this, 10), 0, 0, 0);
        textos.addView(Ui.texto(this, c.nombre, 16, Ui.TEXTO, true));
        String subTexto;
        if (c.claveFirma == null) subTexto = "Clave antigua sin firma · toca para ver";
        else subTexto = c.verificado ? "Verificado · cifrado y firmado" : "Sin verificar · toca para comparar la huella";
        if (c.acreditadoNombre != null) subTexto = c.acreditadoNombre + " · " + subTexto;
        boolean subBien = c.claveFirma != null && c.verificado;
        TextView sub = Ui.texto(this, subTexto, 12, subBien ? Ui.SUAVE : Ui.AVISO, false);
        textos.addView(sub);
        textos.setOnClickListener(v -> abrirVerificar(c));
        Ui.clicable(textos);
        cab.addView(textos, Ui.peso(1));
        cab.addView(Ui.botonIcono(this, Icono.Tipo.PEGAR, Ui.TEXTO, "Abrir mensaje copiado", v -> procesarTexto(portapapeles())));
        col.addView(cab);
        col.addView(Ui.separador(this));

        ScrollView sv = new ScrollView(this);
        LinearLayout hilo = Ui.columna(this);
        hilo.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 12));

        TextView aviso = Ui.texto(this, buzon.activo()
                ? "Cifrado ML-KEM-1024 y firmado ML-DSA-87 en este móvil. Viaja por el buzón del Ayuntamiento, que no puede leerlo."
                : "Cifrado ML-KEM-1024 y firmado ML-DSA-87 en este móvil. Sin buzón configurado: envías compartiendo el texto cifrado y recibes abriéndolo aquí.", 12, Ui.SUAVE, false);
        aviso.setGravity(Gravity.CENTER);
        aviso.setPadding(Ui.dp(this, 14), Ui.dp(this, 8), Ui.dp(this, 14), Ui.dp(this, 8));
        aviso.setBackground(Ui.redondeado(this, Ui.SUPERFICIE, 14));
        hilo.addView(aviso, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 10));

        int anchoMax = (int) (getResources().getDisplayMetrics().widthPixels * 0.76f);
        for (Almacen.Mensaje m : c.mensajes) {
            hilo.addView(burbuja(m, anchoMax));
        }
        sv.addView(hilo);
        col.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        sv.post(() -> sv.fullScroll(View.FOCUS_DOWN));

        LinearLayout compositor = Ui.fila(this);
        compositor.setPadding(Ui.dp(this, 12), Ui.dp(this, 8), Ui.dp(this, 12), Ui.dp(this, 12));
        EditText et = Ui.campo(this, "Mensaje para " + c.nombre, 1, true);
        et.setMaxLines(5);
        compositor.addView(et, Ui.peso(1));
        FrameLayout enviar = new FrameLayout(this);
        android.graphics.drawable.GradientDrawable circulo = new android.graphics.drawable.GradientDrawable();
        circulo.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        circulo.setColor(Ui.BLANCO);
        enviar.setBackground(circulo);
        ImageView flecha = new ImageView(this);
        flecha.setImageDrawable(new Icono(Icono.Tipo.ENVIAR, Ui.FONDO));
        enviar.addView(flecha, new FrameLayout.LayoutParams(Ui.dp(this, 20), Ui.dp(this, 20), Gravity.CENTER));
        enviar.setContentDescription("Enviar");
        enviar.setOnClickListener(v -> enviar(c, et));
        Ui.clicable(enviar);
        compositor.addView(enviar, Ui.margen(this, Ui.dp(this, 48), Ui.dp(this, 48), 8, 0, 0, 0));
        col.addView(compositor);
        return col;
    }

    private View burbuja(Almacen.Mensaje m, int anchoMax) {
        LinearLayout b = Ui.columna(this);
        b.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 14), Ui.dp(this, 8));
        android.graphics.drawable.GradientDrawable fondo = new android.graphics.drawable.GradientDrawable();
        fondo.setColor(m.saliente ? Ui.BURBUJA_SALIENTE : Ui.BURBUJA_ENTRANTE);
        float r = Ui.dp(this, 18), p = Ui.dp(this, 6);
        fondo.setCornerRadii(m.saliente
                ? new float[]{r, r, r, r, p, p, r, r}
                : new float[]{r, r, r, r, r, r, p, p});
        b.setBackground(fondo);
        TextView t = Ui.texto(this, m.texto, 15, Ui.TEXTO, false);
        t.setMaxWidth(anchoMax - Ui.dp(this, 28));
        // Sin selección ni copia del texto descifrado: no hay forma de reenviarlo desde la app.
        t.setTextIsSelectable(false);
        t.setLongClickable(false);
        b.addView(t);
        String pie = Ui.hora(m.ts) + (m.saliente ? " · firmado y cifrado" : (m.remitenteDeclarado ? "" : " · firma verificada"));
        TextView h = Ui.texto(this, pie, 11, m.saliente ? 0xA6FFFFFF : 0xFF7A7A80, false);
        h.setGravity(Gravity.END);
        b.addView(h, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        if (!m.saliente && m.remitenteDeclarado) {
            TextView d = Ui.texto(this, "Remitente declarado, sin firma comprobada", 11, 0xFF7A7A80, false);
            d.setGravity(Gravity.END);
            b.addView(d, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = m.saliente ? Gravity.END : Gravity.START;
        lp.setMargins(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        b.setLayoutParams(lp);
        return b;
    }

    private View pantallaContactos() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 24));
        col.addView(Ui.texto(this, "Contactos", 24, Ui.TEXTO, true));

        LinearLayout mia = tarjeta(col, "Mi clave");
        mia.addView(Ui.texto(this, "Tu huella de seguridad. Tus contactos deben ver estos mismos 60 dígitos.", 13, Ui.SUAVE, false));
        View huella = Ui.huella(this, miHuella(), 17);
        huella.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
        mia.addView(huella);
        LinearLayout botones = Ui.fila(this);
        TextView compartir = Ui.boton(this, "Compartir", true, v -> compartir(miIdentidad(), "Compartir mi clave x39"));
        botones.addView(compartir, Ui.peso(1));
        TextView copiar = Ui.boton(this, "Copiar", false, v -> copiar("Clave x39", miIdentidad(), false));
        LinearLayout.LayoutParams lpc = Ui.peso(1);
        lpc.setMargins(Ui.dp(this, 10), 0, 0, 0);
        botones.addView(copiar, lpc);
        mia.addView(botones);
        String acrNombre = prefs().getString(PREF_INV_NOMBRE, null);
        if (miAcreditacion() != null && acrNombre != null) {
            TextView acr = Ui.texto(this, "Acreditado por el Ayuntamiento como " + acrNombre + " · hasta el "
                    + fechaVisible(prefs().getString(PREF_INV_CADUCA, "")) + ". La acreditación viaja con tu clave al compartirla.", 13, Ui.SUAVE, false);
            acr.setPadding(0, Ui.dp(this, 12), 0, 0);
            mia.addView(acr);
        } else {
            mia.addView(Ui.boton(this, "Acreditar mi clave con una invitación", false, v -> pedirInvitacion(true)),
                    Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 12, 0, 0));
        }

        LinearLayout tit = Ui.fila(this);
        tit.setPadding(0, Ui.dp(this, 22), 0, Ui.dp(this, 8));
        tit.addView(Ui.texto(this, "Tus contactos", 17, Ui.TEXTO, true), Ui.peso(1));
        TextView anadir = Ui.texto(this, "Añadir", 15, Ui.TEXTO, true);
        anadir.setPadding(Ui.dp(this, 12), Ui.dp(this, 12), 0, Ui.dp(this, 12));
        anadir.setOnClickListener(v -> abrirAgregar(""));
        Ui.clicable(anadir);
        tit.addView(anadir);
        col.addView(tit);

        if (almacen.contactos.isEmpty()) {
            col.addView(Ui.texto(this, "Todavía no has añadido a nadie.", 14, Ui.SUAVE, false));
        }
        for (Almacen.Contacto c : almacen.ordenados()) {
            LinearLayout f = Ui.fila(this);
            f.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
            f.addView(Ui.avatar(this, c.nombre, 44));
            LinearLayout t = Ui.columna(this);
            t.setPadding(Ui.dp(this, 12), 0, 0, 0);
            t.addView(Ui.texto(this, c.nombre, 16, Ui.TEXTO, true));
            if (c.acreditadoNombre != null) t.addView(Ui.texto(this, etiquetaAcreditado(c), 13, Ui.TEXTO_2, false));
            String estadoContacto = c.claveFirma == null ? "Clave antigua sin firma" : (c.verificado ? "Verificado" : "Sin verificar");
            t.addView(Ui.texto(this, estadoContacto, 13, c.claveFirma != null && c.verificado ? Ui.SUAVE : Ui.AVISO, false));
            f.addView(t, Ui.peso(1));
            f.addView(Ui.icono(this, Icono.Tipo.CHEVRON, Ui.TENUE, 18));
            f.setOnClickListener(v -> abrirVerificar(c));
            f.setOnLongClickListener(v -> {
                confirmarEliminar(c);
                return true;
            });
            Ui.clicable(f);
            col.addView(f);
        }
        sv.addView(col);
        return sv;
    }

    private View pantallaAgregar(String claveInicial) {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(cabeceraSecundaria("Añadir contacto", () -> mostrarPestana(pestana)));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 16), Ui.dp(this, 8), Ui.dp(this, 16), Ui.dp(this, 24));

        col.addView(Ui.texto(this, "Nombre", 13, Ui.SUAVE, true));
        EditText nombre = Ui.campo(this, "Cómo quieres llamarle", 1, false);
        col.addView(nombre, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 16));

        col.addView(Ui.texto(this, "Su clave (X39ID1)", 13, Ui.SUAVE, true));
        EditText clave = Ui.campo(this, "Pega aquí la clave que te ha compartido", 4, true);
        clave.setTextSize(13);
        if (!TextUtils.isEmpty(claveInicial)) clave.setText(claveInicial);
        col.addView(clave, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 8));

        TextView estado = Ui.texto(this, "", 13, Ui.SUAVE, false);
        col.addView(estado);
        View[] huellaVista = new View[1];
        LinearLayout huellaCaja = Ui.columna(this);
        col.addView(huellaCaja, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 8, 0, 16));

        Runnable validar = () -> {
            huellaCaja.removeAllViews();
            String t = clave.getText().toString().trim();
            if (t.isEmpty()) { estado.setText(""); return; }
            // Lo más habitual al equivocarse de sitio: pegar aquí un mensaje o una invitación.
            if (t.startsWith("X39MSG1:")) {
                estado.setTextColor(Ui.AVISO);
                estado.setText("⚠ Esto es un mensaje cifrado, no la clave de un contacto. Va en Chats.");
                huellaCaja.addView(Ui.boton(this, "Abrir el mensaje en Chats", true, v -> procesarTexto(t)));
                return;
            }
            if (t.startsWith("X39INV1:")) {
                estado.setTextColor(Ui.AVISO);
                estado.setText("⚠ Esto es una invitación del Ayuntamiento, no la clave de un contacto. Va en «Soy personal del Ayuntamiento».");
                return;
            }
            try {
                Almacen.Contacto leido = Almacen.leerTexto(t);
                if (Arrays.equals(leido.clave, clavePublica)) {
                    estado.setTextColor(Ui.AVISO);
                    estado.setText("⚠ Esa es tu propia clave.");
                    return;
                }
                if (leido.claveFirma == null) {
                    estado.setTextColor(Ui.AVISO);
                    estado.setText("⚠ Clave antigua de x39 0.2, sin firma: podrás escribirle, pero no comprobar que sus mensajes son suyos. Pídele que actualice y te comparta su clave nueva. Su huella:");
                } else {
                    estado.setTextColor(Ui.SUAVE);
                    estado.setText("Clave válida con firma ML-DSA-87. Su huella de seguridad:");
                }
                huellaVista[0] = Ui.huella(this, leido.huella(), 16);
                huellaCaja.addView(huellaVista[0]);
                if (leido.acreditacionTexto != null) {
                    acreditarContacto(leido);
                    boolean ok = leido.acreditadoNombre != null;
                    huellaCaja.addView(Ui.texto(this, ok
                            ? "Acreditado por el Ayuntamiento como " + leido.acreditadoNombre + " · hasta el " + leido.acreditadoHastaVisible()
                            : "⚠ Trae una acreditación que no verifica (firma o fecha).", 13, ok ? Ui.SUAVE : Ui.AVISO, false));
                }
            } catch (RuntimeException e) {
                estado.setTextColor(Ui.AVISO);
                estado.setText("⚠ " + e.getMessage());
            }
        };
        clave.addTextChangedListener(new Observador(validar));
        validar.run();

        col.addView(Ui.boton(this, "Pegar del portapapeles", false, v -> {
            String p = portapapeles();
            if (p != null) clave.setText(p.trim());
        }));
        View esp = new View(this);
        col.addView(esp, new LinearLayout.LayoutParams(1, Ui.dp(this, 10)));
        col.addView(Ui.boton(this, "Guardar contacto", true, v -> {
            String n = nombre.getText().toString().trim();
            String t = clave.getText().toString().trim();
            if (n.isEmpty()) { aviso("Escribe un nombre para el contacto."); return; }
            try {
                if (Arrays.equals(Almacen.leerTexto(t).clave, clavePublica)) { aviso("No puedes añadir tu propia clave como contacto."); return; }
                Almacen.Contacto c = almacen.agregar(n, t);
                acreditarContacto(c);
                almacen.guardar();
                abrirVerificar(c);
            } catch (Exception e) {
                aviso(Ui.mensaje(e));
            }
        }));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    private View pantallaVerificar(Almacen.Contacto c) {
        LinearLayout raizCol = Ui.columna(this);
        raizCol.addView(cabeceraSecundaria("Verificar a " + c.nombre, () -> mostrarPestana(pestana)));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 20), Ui.dp(this, 8), Ui.dp(this, 20), Ui.dp(this, 24));

        col.addView(Ui.texto(this, "Pide a " + c.nombre + " que abra x39 › Contactos › Mi clave. Si sus 60 dígitos son idénticos a estos, nadie se ha puesto en medio.", 15, Ui.TEXTO_2, false));
        LinearLayout caja = Ui.columna(this);
        caja.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        caja.setBackground(Ui.degradado(this, 24));
        caja.addView(Ui.huella(this, c.huella(), 20));
        col.addView(caja, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 18, 0, 18));

        if (c.acreditadoNombre != null) {
            TextView acr = Ui.texto(this, "Acreditado por el Ayuntamiento como " + c.acreditadoNombre + " · hasta el " + c.acreditadoHastaVisible()
                    + ". El Ayuntamiento firmó su invitación y esta misma clave la firmó a su vez.", 14, Ui.TEXTO_2, false);
            col.addView(acr, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 14));
        } else if (c.acreditacionTexto != null) {
            TextView acr = Ui.texto(this, "⚠ Su clave traía una acreditación que no verifica (firma o fecha). No se muestra ningún nombre acreditado.", 14, Ui.AVISO, false);
            col.addView(acr, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 14));
        }

        if (c.claveFirma == null) {
            TextView antigua = Ui.texto(this, "⚠ Tienes su clave antigua de x39 0.2, sin firma. Puedes escribirle, pero sus mensajes llegarán como «remitente declarado». "
                    + "Pídele que actualice x39 y te comparta su clave nueva: al pegarla se conserva la conversación.", 14, Ui.AVISO, false);
            col.addView(antigua, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 14));
        }

        TextView estado = Ui.texto(this, c.verificado ? "Marcado como verificado." : "Todavía sin verificar.", 14, c.verificado ? Ui.SUAVE : Ui.AVISO, false);
        col.addView(estado, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 14));

        col.addView(Ui.boton(this, c.verificado ? "Quitar verificación" : "Los dígitos coinciden · marcar verificado", !c.verificado, v -> {
            c.verificado = !c.verificado;
            try {
                almacen.guardar();
            } catch (Exception e) {
                aviso(Ui.mensaje(e));
            }
            abrirVerificar(c);
        }));
        View esp = new View(this);
        col.addView(esp, new LinearLayout.LayoutParams(1, Ui.dp(this, 10)));
        col.addView(Ui.boton(this, "Abrir conversación", false, v -> abrirConversacion(c)));
        sv.addView(col);
        raizCol.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return raizCol;
    }

    // ------------------------------------------------------------------ plenos: transparencia verificable

    /** Plenos, distritos, organismos y empresas del registro incluido en la app, y la comprobación de documentos. */
    // ------------------------------------------------------------------ Plenos, como sevilla.x39matrix.org

    private static final int DESPLAZAR_NADA = 0;
    private static final int DESPLAZAR_RESULTADO = 1;
    private static final int DESPLAZAR_AREAS = 2;
    private static final int DESPLAZAR_DOCUMENTOS = 3;

    /** Filtro del registro, como en el portal: «todas» o el identificador de un área. */
    private String filtroArea = "todas";
    /** «Ver registro completo»: la lista con todos los documentos, sin filtro. */
    private boolean vistaCompleta;
    /** Área elegida en el selector de «Compruebe un documento». */
    private String areaElegida = "todas";
    /** Última comprobación: se muestra en la propia pantalla, como en el portal. */
    private boolean hayComprobacion;
    private String compArchivo;
    private String compHuella;
    private Registro.Documento compDocumento;
    private int desplazarPlenos = DESPLAZAR_NADA;

    /**
     * Misma estructura que el portal: «Compruebe un documento» (con selector de área) arriba, «Áreas» con su
     * contador debajo y, al pulsar un área, «Mostrando: …» y los documentos anclados de esa área.
     * Al comprobar un documento que está en el registro, la pantalla salta sola a su área.
     */
    private View pantallaPlenos() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 18), Ui.dp(this, 6), Ui.dp(this, 18), Ui.dp(this, 28));
        View destino = null;

        TextView etiqueta = Portal.texto(this, "TRANSPARENCIA VERIFICABLE · SEVILLA", 11, Portal.TINTA_2);
        etiqueta.setLetterSpacing(0.08f);
        col.addView(etiqueta);
        col.addView(Portal.titulo(this, "Plenos", 30));

        Registro r = registro();

        // ---- Compruebe un documento
        col.addView(Portal.titulo(this, "Compruebe un documento", 22), margenArriba(20));
        col.addView(Portal.texto(this, "Elija un archivo y su huella SHA-256 se calculará en su propio móvil: el documento no sale del teléfono. "
                + "Al instante se contrasta con el registro de esta maqueta. Funciona también sin conexión.", 14, Portal.TINTA_2), margenArriba(6));

        LinearLayout zona = Ui.columna(this);
        zona.setGravity(Gravity.CENTER_HORIZONTAL);
        zona.setPadding(Ui.dp(this, 20), Ui.dp(this, 28), Ui.dp(this, 20), Ui.dp(this, 28));
        zona.setBackground(Portal.punteada(this));
        TextView flecha = Portal.texto(this, "⬇", 18, Portal.TINTA_2);
        flecha.setGravity(Gravity.CENTER);
        zona.addView(flecha);
        TextView toque = Portal.texto(this, "Toque aquí para elegir el documento", 15, Portal.TINTA_2);
        toque.setGravity(Gravity.CENTER);
        toque.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 12));
        zona.addView(toque);
        zona.addView(Portal.boton(this, "Elegir archivo", v -> elegirDocumento()),
                Ui.margen(this, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, 0));
        zona.setContentDescription("Elegir el documento que se quiere comprobar");
        zona.setOnClickListener(v -> elegirDocumento());
        col.addView(zona, margenArriba(14));

        LinearLayout barraArea = Ui.fila(this);
        barraArea.addView(Portal.texto(this, "Área:", 14, Portal.TINTA_2));
        LinearLayout.LayoutParams lpSelector = new LinearLayout.LayoutParams(0, Ui.dp(this, 44), 1f);
        lpSelector.setMargins(Ui.dp(this, 10), 0, 0, 0);
        barraArea.addView(selectorArea(r), lpSelector);
        col.addView(barraArea, margenArriba(12));

        if (hayComprobacion) {
            View resultado = tarjetaComprobacion(r);
            col.addView(resultado, margenArriba(14));
            if (desplazarPlenos == DESPLAZAR_RESULTADO) destino = resultado;
        }

        TextView nota = Portal.texto(this, "Esta comprobación contrasta la huella con el registro de la maqueta: cómoda e inmediata. "
                + "La verificación independiente completa de los sellos, sin confiar en esta app, se hace con las herramientas públicas del portal.", 13, Portal.TINTA_2);
        nota.setPadding(Ui.dp(this, 12), 0, 0, 0);
        col.addView(nota, margenArriba(12));

        if (r == null) {
            col.addView(Portal.texto(this, "⚠ No se pudo leer el registro incluido en la app: " + errorRegistro, 14, Portal.TINTA), margenArriba(20));
        } else {
            // ---- Áreas
            View tituloAreas = Portal.titulo(this, "Áreas", 22);
            col.addView(tituloAreas, margenArriba(30));
            if (desplazarPlenos == DESPLAZAR_AREAS) destino = tituloAreas;
            col.addView(Portal.texto(this, "El grupo municipal completo: órganos, distritos, organismos autónomos y empresas, según el censo de sevilla.org. "
                    + "Pulse cualquier área para ver sus documentos; el contador indica los anclados en esta maqueta.", 14, Portal.TINTA_2), margenArriba(6));
            for (Registro.Area a : r.areasPortal()) col.addView(ente(a), margenArriba(8));
            col.addView(Portal.enlace(this, "Ver registro completo (" + r.total + " documentos)", v -> {
                filtroArea = "todas";
                vistaCompleta = true;
                refrescarPlenos(DESPLAZAR_DOCUMENTOS);
            }), margenArriba(10));

            if (!"todas".equals(filtroArea)) {
                Registro.Area fa = r.areas.get(filtroArea);
                String nombre = fa != null ? fa.nombre : filtroArea;
                TextView mostrando = Portal.texto(this, "Mostrando: " + nombre, 14, Portal.ORO);
                mostrando.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL));
                col.addView(mostrando, margenArriba(12));
                col.addView(Portal.enlace(this, "Ver todas las áreas", v -> {
                    filtroArea = "todas";
                    vistaCompleta = false;
                    refrescarPlenos(DESPLAZAR_AREAS);
                }));
                if (fa != null && fa.documentos.isEmpty()) {
                    col.addView(Portal.texto(this, "Esta área aún no tiene documentos anclados en la maqueta: el registro los incorpora progresivamente, "
                            + "y el piloto cubre el grupo municipal completo.", 13, Portal.TINTA_2), margenArriba(6));
                }
            }

            // ---- Documentos anclados
            if (!"todas".equals(filtroArea) || vistaCompleta) {
                View tituloDocs = Portal.titulo(this, "Documentos anclados", 22);
                col.addView(tituloDocs, margenArriba(30));
                if (desplazarPlenos == DESPLAZAR_DOCUMENTOS) destino = tituloDocs;
                col.addView(Portal.texto(this, "Registro público de esta maqueta. Solo se muestra lo emitido y comprobado: nada se anticipa.", 14, Portal.TINTA_2), margenArriba(6));
                for (Registro.Documento d : r.documentos) {
                    if (vistaCompleta || d.area.equals(filtroArea)) col.addView(filaDocumento(d), margenArriba(10));
                }
                col.addView(Portal.texto(this, "Toque un documento para abrir su PDF congelado en el navegador (necesita conexión).", 12, Portal.TINTA_2), margenArriba(10));
            }
        }

        LinearLayout portal = Ui.fila(this);
        portal.setPadding(0, Ui.dp(this, 26), 0, Ui.dp(this, 10));
        portal.addView(Ui.icono(this, Icono.Tipo.ENLACE, Portal.ORO, 18));
        TextView tp = Portal.texto(this, "Abrir sevilla.x39matrix.org", 15, Portal.ORO);
        tp.setPadding(Ui.dp(this, 10), 0, 0, 0);
        portal.addView(tp, Ui.peso(1));
        portal.setOnClickListener(v -> abrirEnlace(Registro.PORTAL));
        Ui.clicable(portal);
        col.addView(portal);

        if (clavePublica == null) {
            TextView acceso = Portal.texto(this, "¿Es usted personal del Ayuntamiento? Activar acceso", 15, Portal.TINTA);
            acceso.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
            acceso.setOnClickListener(v -> activarAccesoPersonal());
            Ui.clicable(acceso);
            col.addView(acceso);
        }

        TextView aviso = Portal.texto(this, "Maqueta con documentos públicos de sevilla.org. No es un portal oficial del Ayuntamiento de Sevilla.", 12, Portal.TINTA_2);
        aviso.setAlpha(0.75f);
        aviso.setGravity(Gravity.CENTER);
        aviso.setPadding(Ui.dp(this, 8), Ui.dp(this, 18), Ui.dp(this, 8), 0);
        col.addView(aviso, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        if (clavePublica == null) {
            TextView ver = Portal.texto(this, "x39 " + VERSION, 12, Portal.TINTA_2);
            ver.setAlpha(0.75f);
            ver.setGravity(Gravity.CENTER);
            ver.setPadding(0, Ui.dp(this, 6), 0, 0);
            col.addView(ver, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        sv.addView(col);

        desplazarPlenos = DESPLAZAR_NADA;
        if (destino != null) {
            final View objetivo = destino;
            sv.post(() -> sv.scrollTo(0, Math.max(0, objetivo.getTop() - Ui.dp(this, 12))));
        }
        return sv;
    }

    private void refrescarPlenos(int desplazar) {
        desplazarPlenos = desplazar;
        mostrarPestana(Pestana.PLENOS);
    }

    private LinearLayout.LayoutParams margenArriba(int dp) {
        return Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, dp, 0, 0);
    }

    /** Selector «Área» del portal: «Todas las áreas» y las 28 áreas en el mismo orden. */
    private Spinner selectorArea(Registro r) {
        final List<String> slugs = new ArrayList<>();
        final List<String> nombres = new ArrayList<>();
        slugs.add("todas");
        nombres.add("Todas las áreas");
        if (r != null) {
            for (Registro.Area a : r.areasPortal()) {
                slugs.add(a.slug);
                nombres.add(a.nombre);
            }
        }
        Spinner s = new Spinner(this, Spinner.MODE_DROPDOWN);
        s.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, nombres) {
            @Override
            public View getView(int posicion, View reciclada, ViewGroup padre) {
                return filaSelector(nombres.get(posicion), false);
            }

            @Override
            public View getDropDownView(int posicion, View reciclada, ViewGroup padre) {
                return filaSelector(nombres.get(posicion), slugs.get(posicion).equals(areaElegida));
            }
        });
        s.setBackground(Portal.caja(this, Portal.SELECTOR, Portal.LINEA, 1, 8));
        s.setPopupBackgroundDrawable(new android.graphics.drawable.ColorDrawable(Portal.SELECTOR));
        s.setSelection(Math.max(0, slugs.indexOf(areaElegida)), false);
        s.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> padre, View vista, int posicion, long id) {
                areaElegida = slugs.get(posicion);
            }

            @Override
            public void onNothingSelected(AdapterView<?> padre) {
                // Sin cambios.
            }
        });
        s.setContentDescription("Área");
        return s;
    }

    private TextView filaSelector(String texto, boolean elegido) {
        TextView t = Portal.texto(this, texto, 14, elegido ? Portal.ORO : Portal.TINTA);
        t.setSingleLine(true);
        t.setEllipsize(TextUtils.TruncateAt.END);
        t.setGravity(Gravity.CENTER_VERTICAL);
        t.setPadding(Ui.dp(this, 12), Ui.dp(this, 11), Ui.dp(this, 12), Ui.dp(this, 11));
        return t;
    }

    /** Casilla de la cuadrícula «Áreas»: nombre y contador; la elegida lleva borde dorado. */
    private View ente(Registro.Area a) {
        int n = a.documentos.size();
        boolean elegida = a.slug.equals(filtroArea);
        LinearLayout f = Ui.fila(this);
        f.setMinimumHeight(Ui.dp(this, 46));
        f.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 14), Ui.dp(this, 10));
        f.setBackground(Portal.caja(this, Portal.TARJETA, elegida ? Portal.ORO : Portal.LINEA, elegida ? 2 : 1, 10));
        f.addView(Portal.texto(this, a.nombre, 14, Portal.TINTA), Ui.peso(1));
        TextView cnt = Portal.texto(this, String.valueOf(n), 16, n > 0 ? Portal.ORO : Portal.TINTA_2);
        cnt.setTypeface(android.graphics.Typeface.SERIF);
        if (n == 0) cnt.setAlpha(0.5f);
        cnt.setGravity(Gravity.END);
        cnt.setMinWidth(Ui.dp(this, 24));
        cnt.setPadding(Ui.dp(this, 10), 0, 0, 0);
        f.addView(cnt);
        f.setContentDescription(a.nombre + ", " + n + (n == 1 ? " documento" : " documentos"));
        f.setOnClickListener(v -> {
            boolean quitar = a.slug.equals(filtroArea);
            filtroArea = quitar ? "todas" : a.slug;
            vistaCompleta = false;
            refrescarPlenos(quitar ? DESPLAZAR_AREAS : DESPLAZAR_DOCUMENTOS);
        });
        Ui.clicable(f);
        return f;
    }

    /** Fila de «Documentos anclados»: documento, publicado, huella y las píldoras de bloque y sello. */
    private View filaDocumento(Registro.Documento d) {
        LinearLayout card = Ui.columna(this);
        card.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        card.setBackground(Portal.tarjeta(this));
        card.addView(Portal.texto(this, d.nombreVisible() + " — sesión de " + d.sesion, 15, Portal.TINTA));
        LinearLayout datos = Ui.fila(this);
        datos.addView(Portal.texto(this, "Publicado ", 12, Portal.TINTA_2));
        datos.addView(Portal.mono(this, d.sesion, 12, Portal.TINTA_2));
        datos.addView(Portal.mono(this, "   " + d.huellaCorta(), 12, Portal.TINTA_2));
        LinearLayout.LayoutParams lpDatos = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpDatos.setMargins(0, Ui.dp(this, 6), 0, 0);
        card.addView(datos, lpDatos);
        LinearLayout pildoras = Ui.fila(this);
        pildoras.addView(Portal.pildora(this, textoBloque(d), !d.bloqueEnCurso()));
        LinearLayout.LayoutParams lpSello = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpSello.setMargins(Ui.dp(this, 8), 0, 0, 0);
        pildoras.addView(Portal.pildora(this, textoSello(d), d.selloCualificado()), lpSello);
        LinearLayout.LayoutParams lpPildoras = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpPildoras.setMargins(0, Ui.dp(this, 10), 0, 0);
        card.addView(pildoras, lpPildoras);
        card.setContentDescription(d.nombreVisible() + ". Abrir PDF");
        card.setOnClickListener(v -> abrirEnlace(d.urlPdf()));
        Ui.clicable(card);
        return card;
    }

    private static String textoBloque(Registro.Documento d) {
        if (d.bloqueEnCurso()) return "anclaje en curso";
        return "bloque " + d.bloque + (d.bloqueVerificado() ? " ✓" : "");
    }

    private static String textoSello(Registro.Documento d) {
        if (!d.selloCualificado()) return "en proceso";
        return "sello " + d.qtst + (d.qtstTsa.isEmpty() ? "" : " ✓");
    }

    private static String bloqueDetalle(Registro.Documento d) {
        if (d.bloqueEnCurso()) return "en curso";
        if (d.bloqueVerificado()) return d.bloque + " (verificado contra nodo propio el " + d.verificadoEnVisible() + ")";
        if (!d.verificadoBloque.isEmpty()) return d.bloque + " declarado, pero el nodo propio confirma el " + d.verificadoBloque + " — DISCREPANCIA";
        return d.bloque + " (pendiente de verificar contra nodo propio)";
    }

    /** Resultado de «Compruebe un documento», con los mismos textos que el portal. */
    private View tarjetaComprobacion(Registro r) {
        final Registro.Documento m = compDocumento;
        LinearLayout card = Ui.columna(this);
        card.setPadding(Ui.dp(this, 18), Ui.dp(this, 16), Ui.dp(this, 18), Ui.dp(this, 16));
        card.setBackground(Portal.caja(this, Portal.TARJETA, m != null ? Portal.ORO : Portal.AMBAR, 1, 14));
        if (m != null) {
            card.addView(Portal.titulo(this, "✓ Coincide con el registro", 18));
            card.addView(Portal.texto(this, m.nombreVisible() + " · sesión de " + m.sesion, 15, Portal.TINTA), margenArriba(8));
            Registro.Area area = r == null ? null : r.areas.get(m.area);
            String nombreArea = area != null ? area.nombre : m.area;
            String lineaArea = "Área: " + nombreArea;
            if (!"todas".equals(areaElegida) && !areaElegida.equals(m.area)) {
                Registro.Area elegida = r == null ? null : r.areas.get(areaElegida);
                lineaArea += " (usted seleccionó " + (elegida != null ? elegida.nombre : areaElegida)
                        + "; el documento pertenece a " + nombreArea + ")";
            }
            card.addView(Portal.texto(this, lineaArea, 14, Portal.TINTA_2), margenArriba(6));
            card.addView(Portal.mono(this, "huella: " + m.huellaCorta(), 12, Portal.TINTA_2), margenArriba(6));
            card.addView(Portal.texto(this, "Anclado el " + m.anclaje + " · bloque Bitcoin: " + bloqueDetalle(m)
                    + " · sello cualificado: " + m.qtst, 13, Portal.TINTA_2), margenArriba(6));
            LinearLayout enlaces = Ui.columna(this);
            enlaces.addView(Portal.enlace(this, "PDF congelado", v -> abrirEnlace(m.urlPdf())));
            if (!m.ots.isEmpty()) enlaces.addView(Portal.enlace(this, "Sello soberano (.ots)", v -> abrirEnlace(m.url(m.ots))));
            if (!m.fuente.isEmpty()) enlaces.addView(Portal.enlace(this, "Procedencia", v -> abrirEnlace(m.url(m.fuente))));
            if (!m.tsr.isEmpty()) enlaces.addView(Portal.enlace(this, "Sello cualificado (.tsr)", v -> abrirEnlace(m.url(m.tsr))));
            enlaces.addView(Portal.enlace(this, "Ver su área", v -> {
                filtroArea = m.area;
                vistaCompleta = false;
                refrescarPlenos(DESPLAZAR_DOCUMENTOS);
            }));
            card.addView(enlaces, margenArriba(8));
        } else {
            TextView t = Portal.titulo(this, "✗ No coincide con el registro", 18);
            t.setTextColor(Portal.AMBAR);
            card.addView(t);
            String ambito;
            if ("todas".equals(areaElegida)) {
                ambito = "ningún documento anclado en esta maqueta";
            } else {
                Registro.Area elegida = r == null ? null : r.areas.get(areaElegida);
                ambito = "ningún documento del área " + (elegida != null ? elegida.nombre : areaElegida) + " (ni del resto del registro)";
            }
            card.addView(Portal.texto(this, "El archivo " + compArchivo + " no es idéntico a " + ambito
                    + ": o es otro documento, o ha sido modificado. Un solo byte cambia la huella por completo.", 14, Portal.TINTA_2), margenArriba(8));
            if (compHuella != null && compHuella.length() == 64) {
                card.addView(Portal.mono(this, "huella calculada: " + compHuella.substring(0, 8) + "…" + compHuella.substring(56), 12, Portal.TINTA_2), margenArriba(6));
            }
            if (r != null) {
                card.addView(Portal.texto(this, "El registro de esta app es del " + r.actualizadoVisible()
                        + ". Si el documento es más reciente, puede no estar incluido todavía.", 12, Portal.TINTA_2), margenArriba(8));
            }
        }
        return card;
    }

    private void elegirDocumento() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/pdf");
        try {
            startActivityForResult(i, REQ_COMPROBAR);
        } catch (android.content.ActivityNotFoundException e) {
            aviso("Este móvil no tiene selector de archivos.");
        }
    }

    /** SHA-256 del archivo elegido, calculada en el móvil y comparada con el registro incluido. */
    private void comprobarDocumento(Uri uri) {
        final String archivo = nombreDeArchivo(uri);
        abrirSecundaria(() -> mostrar(pantallaCalculando(archivo), false));
        new Thread(() -> {
            String huella = null;
            String error = null;
            try {
                InputStream entrada = getContentResolver().openInputStream(uri);
                if (entrada == null) throw new IllegalStateException("el sistema no entregó el archivo");
                try (InputStream in = entrada) {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] buf = new byte[64 * 1024];
                    int n;
                    while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
                    huella = Boveda.aHex(md.digest());
                }
            } catch (Exception e) {
                error = Ui.mensaje(e);
            }
            final String h = huella;
            final String fallo = error;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                if (fallo != null) {
                    mostrarPestana(Pestana.PLENOS);
                    aviso("No se pudo leer el documento: " + fallo);
                    return;
                }
                Registro r = registro();
                Registro.Documento doc = r == null ? null : r.buscar(h);
                // Como en el portal: el resultado aparece en la propia pantalla y, si el documento está en el
                // registro, la lista salta sola a su área.
                hayComprobacion = true;
                compArchivo = archivo;
                compHuella = h;
                compDocumento = doc;
                if (doc != null) {
                    filtroArea = doc.area;
                    vistaCompleta = false;
                }
                refrescarPlenos(DESPLAZAR_RESULTADO);
            });
        }, "x39-huella").start();
    }

    private String nombreDeArchivo(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String n = c.getString(0);
                if (n != null && !n.isEmpty()) return n;
            }
        } catch (Exception ignorado) {
            // Sin nombre visible: se usa uno genérico.
        }
        return "documento";
    }

    private View pantallaCalculando(String archivo) {
        LinearLayout col = Ui.columna(this);
        col.setGravity(Gravity.CENTER);
        col.setPadding(Ui.dp(this, 32), 0, Ui.dp(this, 32), 0);
        ProgressBar pb = new ProgressBar(this);
        pb.setIndeterminate(true);
        pb.setIndeterminateTintList(ColorStateList.valueOf(Ui.BLANCO));
        col.addView(pb, Ui.margen(this, Ui.dp(this, 40), Ui.dp(this, 40), 0, 0, 0, 16));
        TextView t = Ui.texto(this, "Calculando la huella…", 20, Ui.TEXTO, true);
        t.setGravity(Gravity.CENTER);
        col.addView(t);
        TextView d = Ui.texto(this, archivo, 13, Ui.SUAVE, false);
        d.setGravity(Gravity.CENTER);
        d.setPadding(0, Ui.dp(this, 6), 0, 0);
        col.addView(d);
        return col;
    }

    private View pantallaSeguridad() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 24));
        col.addView(Ui.texto(this, "Seguridad", 24, Ui.TEXTO, true));
        TextView sub = Ui.texto(this, "Comprobado ahora en este móvil.", 13, Ui.SUAVE, false);
        sub.setPadding(0, Ui.dp(this, 2), 0, 0);
        col.addView(sub);

        boolean internet = getPackageManager().checkPermission(Manifest.permission.INTERNET, getPackageName()) == PackageManager.PERMISSION_GRANTED;
        boolean copias = (getApplicationInfo().flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
        KeyguardManager km = getSystemService(KeyguardManager.class);
        boolean bloqueo = km != null && km.isDeviceSecure();
        String hw = boveda.nivelHardware();

        LinearLayout lista = tarjeta(col, null);
        int conFirma = 0;
        for (Almacen.Contacto c : almacen.contactos) {
            if (c.claveFirma != null) conFirma++;
        }
        filaEstado(lista, "Cifrado", "ML-KEM-1024 + AES-256-GCM", true);
        filaEstado(lista, "Firma del remitente", "ML-DSA-87", true);
        filaEstado(lista, "Contactos con firma", conFirma + " de " + almacen.contactos.size(), conFirma == almacen.contactos.size());
        filaEstado(lista, "Claves en hardware", hw, !"Software".equals(hw) && !"Desconocido".equals(hw));
        filaEstado(lista, "Capturas de pantalla", "Bloqueadas", true);
        filaEstado(lista, "Copiar o reenviar mensajes", "No disponible", true);
        filaEstado(lista, "Acceso a internet", !internet ? "Sin permiso" : (buzon.activo() ? "Solo al buzón del Ayuntamiento" : "Permitido · buzón sin configurar"), true);
        filaEstado(lista, "Servicios de Google", "Ninguno", true);
        filaEstado(lista, "Copias en la nube", copias ? "Activadas" : "Desactivadas", !copias);
        filaEstado(lista, "Bloqueo al abrir", bloqueo ? "Bloqueo del móvil" : "Sin bloqueo de pantalla", bloqueo);
        filaEstado(lista, "Mensajes abiertos", boveda.aperturasRegistradas() + " (anti-replay)", true);

        LinearLayout huella = tarjeta(col, "Tu huella de seguridad");
        huella.addView(Ui.huella(this, miHuella(), 17));

        LinearLayout bz = tarjeta(col, "Buzón del Ayuntamiento");
        bz.addView(Ui.texto(this, "Los mensajes viajan cifrados y firmados por un buzón en un canister del Ayuntamiento. "
                + "El buzón no puede leerlos; sí ve a qué dirección van, su tamaño y cuándo.", 13, Ui.TEXTO_2, false));
        LinearLayout filaSw = Ui.fila(this);
        filaSw.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 4));
        filaSw.addView(Ui.texto(this, "Usar el buzón", 15, Ui.TEXTO, true), Ui.peso(1));
        Switch sw = new Switch(this);
        sw.setChecked(prefs().getBoolean(Buzon.PREF_ACTIVO, true));
        sw.setContentDescription("Usar el buzón");
        sw.setOnCheckedChangeListener((b, activo) -> {
            prefs().edit().putBoolean(Buzon.PREF_ACTIVO, activo).apply();
            if (activo) iniciarSondeo();
        });
        filaSw.addView(sw);
        bz.addView(filaSw);
        EditText urlCampo = Ui.campo(this, "https://xxxxx-xxxxx-xxxxx-xxxxx-cai.raw.icp0.io", 1, false);
        urlCampo.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        urlCampo.setText(buzon.url());
        bz.addView(urlCampo, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 6, 0, 0));
        bz.addView(Ui.boton(this, "Guardar dirección del buzón", false, v -> {
            try {
                String u = Buzon.validarUrl(urlCampo.getText().toString());
                if (!u.equals(buzon.url())) prefs().edit().putString(Buzon.PREF_URL, u).putLong(Buzon.PREF_DESDE, 0).apply();
                Toast.makeText(this, "Buzón guardado", Toast.LENGTH_SHORT).show();
                iniciarSondeo();
                mostrarPestana(Pestana.SEGURIDAD);
            } catch (IllegalArgumentException e) {
                aviso(e.getMessage());
            }
        }), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 10, 0, 0));
        TextView est = Ui.texto(this, estadoBuzon, 13, Ui.SUAVE, false);
        est.setPadding(0, Ui.dp(this, 10), 0, 0);
        bz.addView(est);
        if (clavePublica != null) {
            TextView dir = Ui.mono(this, "Tu dirección de buzón: " + Buzon.direccion(clavePublica).substring(0, 16) + "…", 12, Ui.TENUE);
            dir.setPadding(0, Ui.dp(this, 6), 0, 0);
            bz.addView(dir);
        }
        List<String> registro = Buzon.registro();
        if (!registro.isEmpty()) {
            TextView rt = Ui.texto(this, "Últimas conexiones", 13, Ui.SUAVE, true);
            rt.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 2));
            bz.addView(rt);
            for (String l : registro) bz.addView(Ui.mono(this, l, 11, Ui.TEXTO_2));
        }

        LinearLayout aviso = Ui.columna(this);
        aviso.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        android.graphics.drawable.GradientDrawable borde = new android.graphics.drawable.GradientDrawable();
        borde.setColor(0x0AFFFFFF);
        borde.setCornerRadius(Ui.dp(this, 18));
        borde.setStroke(Ui.dp(this, 1), 0x33FFFFFF);
        aviso.setBackground(borde);
        LinearLayout avTit = Ui.fila(this);
        avTit.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.AVISO, 18));
        TextView avT = Ui.texto(this, "Lo que aún no está cubierto", 14, Ui.TEXTO, true);
        avT.setPadding(Ui.dp(this, 10), 0, 0, 0);
        avTit.addView(avT);
        aviso.addView(avTit);
        TextView avD = Ui.texto(this,
                "Aún no hay forward secrecy: si alguien robara tu clave secreta, podría leer los mensajes cifrados antiguos que hubiera guardado. "
                        + "El buzón ve quién escribe a quién y cuándo (no el contenido) y aún no exige invitación para dejar mensajes. "
                        + "Tampoco hay auditoría externa del protocolo. "
                        + "Los contactos con clave antigua sin firma no pueden probar que sus mensajes son suyos.", 13, Ui.TEXTO_2, false);
        avD.setPadding(0, Ui.dp(this, 6), 0, 0);
        aviso.addView(avD);
        col.addView(aviso, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));

        TextView ver = Ui.texto(this, "x39 " + VERSION, 12, Ui.TENUE, false);
        ver.setGravity(Gravity.CENTER);
        ver.setPadding(0, Ui.dp(this, 18), 0, 0);
        col.addView(ver, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        sv.addView(col);
        return sv;
    }

    private void mostrarError() {
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 24), Ui.dp(this, 48), Ui.dp(this, 24), 0);
        col.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.AVISO, 32));
        TextView t = Ui.texto(this, "No se pudieron abrir tus claves", 18, Ui.TEXTO, true);
        t.setPadding(0, Ui.dp(this, 12), 0, Ui.dp(this, 8));
        col.addView(t);
        col.addView(Ui.texto(this, errorInicio, 14, Ui.TEXTO_2, false));
        mostrar(col, false);
    }

    // ------------------------------------------------------------------ piezas comunes

    private LinearLayout tarjeta(LinearLayout padre, String titulo) {
        LinearLayout card = Ui.columna(this);
        card.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 16));
        card.setBackground(Ui.degradado(this, 24));
        if (titulo != null) {
            TextView t = Ui.texto(this, titulo, 16, Ui.TEXTO, true);
            t.setPadding(0, 0, 0, Ui.dp(this, 8));
            card.addView(t);
        }
        padre.addView(card, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 14, 0, 0));
        return card;
    }

    private void filaEstado(LinearLayout lista, String etiqueta, String valor, boolean bien) {
        LinearLayout f = Ui.fila(this);
        f.setMinimumHeight(Ui.dp(this, 44));
        f.addView(Ui.texto(this, etiqueta, 14, Ui.TEXTO_2, false), Ui.peso(1));
        f.addView(Ui.icono(this, bien ? Icono.Tipo.CHECK : Icono.Tipo.AVISO, bien ? Ui.TEXTO : Ui.AVISO, 15));
        TextView v = Ui.texto(this, valor, 14, bien ? Ui.TEXTO : Ui.AVISO, false);
        v.setPadding(Ui.dp(this, 6), 0, 0, 0);
        f.addView(v);
        lista.addView(f);
    }

    private View cabeceraSecundaria(String titulo, Runnable volver) {
        LinearLayout cab = Ui.fila(this);
        cab.setPadding(Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 16), Ui.dp(this, 8));
        cab.addView(Ui.botonIcono(this, Icono.Tipo.ATRAS, Ui.TEXTO, "Volver", v -> volver.run()));
        TextView t = Ui.texto(this, titulo, 17, Ui.TEXTO, true);
        t.setSingleLine(true);
        t.setEllipsize(TextUtils.TruncateAt.END);
        cab.addView(t, Ui.peso(1));
        return cab;
    }

    // ------------------------------------------------------------------ acciones

    /** Mi identidad para compartir: X39ID1 = clave de cifrado + clave de firma. */
    private String miIdentidad() {
        String id = X39Core.identityToText(clavePublica, claveFirma);
        String acr = miAcreditacion();
        // La acreditación viaja con la clave: quien la pegue en Añadir contacto verá el nombre acreditado.
        return acr == null ? id : id + "\n" + acr;
    }

    private String miHuella() {
        return X39Core.identityFingerprint(clavePublica, claveFirma);
    }

    private void enviar(Almacen.Contacto c, EditText et) {
        String texto = et.getText().toString().trim();
        if (texto.isEmpty()) return;
        byte[] carga = null;
        byte[] semilla = null;
        String cifrada = null;
        try {
            long ahoraMs = System.currentTimeMillis();
            carga = Carga.crear(miId, texto, ahoraMs);
            semilla = boveda.semillaFirma();
            cifrada = X39Core.sealSigned(c.clave, semilla, carga, ahoraMs / 1000L);
            c.mensajes.add(new Almacen.Mensaje(true, texto, ahoraMs, false));
            almacen.guardar();
            et.setText("");
        } catch (Exception e) {
            aviso(Ui.mensaje(e));
            return;
        } finally {
            if (carga != null) Arrays.fill(carga, (byte) 0);
            if (semilla != null) Arrays.fill(semilla, (byte) 0);
        }
        final String capsula = cifrada;
        final String nombre = c.nombre;
        abrirConversacion(c);
        if (!buzon.activo()) {
            // Sin buzón configurado: como en las versiones anteriores, el texto cifrado se comparte a mano.
            compartir(capsula, "Enviar mensaje cifrado a " + nombre);
            return;
        }
        // Por el buzón: la cápsula ya va cifrada y firmada; el buzón solo ve la dirección de destino.
        final String para = Buzon.direccion(c.clave);
        new Thread(() -> {
            String fallo = null;
            try {
                buzon.poner(para, capsula);
            } catch (Exception e) {
                fallo = Ui.mensaje(e);
            }
            final String error = fallo;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                if (error == null) {
                    Toast.makeText(this, "Enviado por el buzón", Toast.LENGTH_SHORT).show();
                    return;
                }
                estadoBuzon = "Error al enviar: " + error;
                new AlertDialog.Builder(this)
                        .setTitle("El buzón no responde")
                        .setMessage(error + "\n\nPuedes enviar el mensaje cifrado por otra app.")
                        .setNegativeButton("Ahora no", null)
                        .setPositiveButton("Compartir", (d, w) -> compartir(capsula, "Enviar mensaje cifrado a " + nombre))
                        .show();
            });
        }, "x39-buzon-enviar").start();
    }

    /** Recoge del buzón lo dirigido a este móvil y lo abre en silencio. */
    private void sincronizarBuzon() {
        if (clavePublica == null || sincronizando || !buzon.activo()) return;
        sincronizando = true;
        final String miDireccion = Buzon.direccion(clavePublica);
        final long desde = buzon.desde();
        new Thread(() -> {
            List<Buzon.Recibido> lote;
            try {
                lote = buzon.recoger(miDireccion, desde);
            } catch (Exception e) {
                final String err = Ui.mensaje(e);
                runOnUiThread(() -> {
                    sincronizando = false;
                    estadoBuzon = "Sin conexión con el buzón: " + err;
                });
                return;
            }
            runOnUiThread(() -> {
                sincronizando = false;
                if (isFinishing() || isDestroyed()) return;
                boolean nuevos = false;
                for (Buzon.Recibido r : lote) {
                    if (abrirCapsula(r.msg, false) != null) nuevos = true;
                    buzon.guardarDesde(Math.max(buzon.desde(), r.seq));
                }
                estadoBuzon = "Buzón consultado a las " + Ui.hora(System.currentTimeMillis()) + (lote.isEmpty() ? "" : " · " + lote.size() + " recibidos");
                if (nuevos) refrescarTrasRecibir();
            });
        }, "x39-buzon-recoger").start();
    }

    private void refrescarTrasRecibir() {
        if (pantallaSecundaria != null) pantallaSecundaria.run();
        else if (pestana == Pestana.CHATS || pestana == Pestana.INICIO) mostrarPestana(pestana);
    }

    private void guardarCompartido(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return;
        String texto = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (texto != null) pendienteCompartido = texto;
    }

    private void procesarPendiente() {
        if (pendienteCompartido == null || errorInicio != null || enBienvenida) return;
        if (clavePublica == null) {
            // Modo ciudadano: sin clave no hay mensajes ni contactos que abrir.
            pendienteCompartido = null;
            aviso("Los mensajes y claves de x39 son para el personal del Ayuntamiento. Actívalo desde Plenos › Activar acceso.");
            return;
        }
        String t = pendienteCompartido;
        pendienteCompartido = null;
        procesarTexto(t);
    }

    private void procesarTexto(String texto) {
        if (texto == null || texto.trim().isEmpty()) {
            aviso("No hay nada copiado. Copia primero el mensaje cifrado o la clave.");
            return;
        }
        String s = texto.trim();
        if (s.startsWith("X39ID1:") || s.startsWith("X39PK1:")) {
            abrirAgregar(s);
            return;
        }
        if (s.startsWith("X39INV1:")) {
            // Invitación del Ayuntamiento compartida desde otra app: si ya hay clave, sirve para acreditarla.
            invitacionInicial = s;
            pedirInvitacion(clavePublica != null);
            return;
        }
        if (!s.startsWith("X39MSG1:")) {
            aviso("Ese texto no es un mensaje ni una clave de x39.");
            return;
        }
        Almacen.Contacto c = abrirCapsula(s, true);
        if (c != null) abrirConversacion(c);
    }

    /**
     * Descifra una cápsula, comprueba la firma del remitente y guarda el mensaje en su conversación.
     * Devuelve el contacto, o null si se descartó. Con {@code interactivo} explica cada rechazo con un aviso;
     * en silencio (buzón) solo lo anota en el estado del buzón.
     */
    private Almacen.Contacto abrirCapsula(String s, boolean interactivo) {
        byte[] sk = null;
        byte[] salida = null;
        byte[] cuerpo = null;
        try {
            sk = boveda.claveSecreta();
            salida = X39Core.open(sk, s, System.currentTimeMillis() / 1000L, TTL_SEGUNDOS);
            byte[] cid = Arrays.copyOfRange(salida, 0, X39Core.CID_LEN);
            if (!boveda.registrarApertura(cid)) {
                rechazo(interactivo, "Este mensaje ya se abrió una vez. Por seguridad no se vuelve a mostrar.");
                return null;
            }
            cuerpo = Arrays.copyOfRange(salida, X39Core.CID_LEN, salida.length);
            boolean firmado = X39Core.estaFirmado(cuerpo);
            // Solo sirve para saber quién DICE enviarlo; lo que se guarda sale de la carga verificada.
            JSONObject declarado = Carga.leer(firmado ? X39Core.unverifiedPayload(cuerpo) : cuerpo);
            Almacen.Contacto c = almacen.porId(declarado.optString("de", ""));
            if (c == null) {
                if (interactivo) {
                    new AlertDialog.Builder(this)
                            .setTitle("Mensaje de alguien que no está en tus contactos")
                            .setMessage(declarado.optString("t", "") + "\n\nNo se puede comprobar quién lo envía. Añade a esa persona con su clave para guardar la conversación.")
                            .setPositiveButton("Entendido", null)
                            .show();
                } else {
                    estadoBuzon = "Descartado un mensaje de alguien que no está en tus contactos.";
                }
                return null;
            }
            String contenido = declarado.optString("t", "");
            boolean firmaVerificada = false;
            if (c.claveFirma != null) {
                if (!firmado) {
                    rechazo(interactivo, "Mensaje descartado: dice venir de " + c.nombre + ", pero no lleva firma y su clave sí firma. Podría ser una suplantación.");
                    return null;
                }
                byte[] cargaVerificada;
                try {
                    cargaVerificada = X39Core.verifySigned(c.claveFirma, clavePublica, cuerpo);
                } catch (RuntimeException e) {
                    rechazo(interactivo, "Mensaje descartado: la firma no es de " + c.nombre + " o el mensaje se ha manipulado.");
                    return null;
                }
                contenido = Carga.leer(cargaVerificada).optString("t", "");
                Arrays.fill(cargaVerificada, (byte) 0);
                firmaVerificada = true;
            }
            c.mensajes.add(new Almacen.Mensaje(false, contenido, System.currentTimeMillis(), !firmaVerificada));
            almacen.guardar();
            return c;
        } catch (Exception e) {
            rechazo(interactivo, Ui.mensaje(e));
            return null;
        } finally {
            if (sk != null) Arrays.fill(sk, (byte) 0);
            if (salida != null) Arrays.fill(salida, (byte) 0);
            if (cuerpo != null) Arrays.fill(cuerpo, (byte) 0);
        }
    }

    private void rechazo(boolean interactivo, String motivo) {
        if (interactivo) aviso(motivo);
        else estadoBuzon = motivo;
    }

    private void confirmarEliminar(Almacen.Contacto c) {
        new AlertDialog.Builder(this)
                .setTitle("Eliminar a " + c.nombre)
                .setMessage("Se borrarán el contacto y toda la conversación de este móvil. No se puede deshacer.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Eliminar", (d, w) -> {
                    almacen.eliminar(c);
                    try {
                        almacen.guardar();
                    } catch (Exception e) {
                        aviso(Ui.mensaje(e));
                    }
                    mostrarPestana(pestana);
                })
                .show();
    }

    /** Abre una web en el navegador del sistema. La app no necesita permiso de internet para esto. */
    private void abrirEnlace(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)));
        } catch (android.content.ActivityNotFoundException e) {
            aviso("No hay ningún navegador en este móvil. La dirección es " + url);
        }
    }

    private void compartir(String texto, String titulo) {
        Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, texto);
        startActivity(Intent.createChooser(send, titulo));
    }

    private void copiar(String etiqueta, String texto, boolean sensible) {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        ClipData clip = ClipData.newPlainText(etiqueta, texto);
        if (sensible && Build.VERSION.SDK_INT >= 33) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        cm.setPrimaryClip(clip);
        Toast.makeText(this, "Copiado", Toast.LENGTH_SHORT).show();
    }

    private String portapapeles() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        if (cm == null || !cm.hasPrimaryClip() || cm.getPrimaryClip() == null || cm.getPrimaryClip().getItemCount() == 0) {
            return null;
        }
        CharSequence t = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
        return t == null ? null : t.toString();
    }

    private void aviso(String texto) {
        new AlertDialog.Builder(this).setMessage(texto).setPositiveButton("Entendido", null).show();
    }

    private static final class Observador implements TextWatcher {
        private final Runnable cambio;

        Observador(Runnable cambio) {
            this.cambio = cambio;
        }

        @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
        @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
        @Override public void afterTextChanged(Editable s) { cambio.run(); }
    }
}
