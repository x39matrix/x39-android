package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.Arrays;
import java.util.List;

/**
 * x39 v0.2 · mensajería poscuántica sin servidor.
 * Chats, contactos con huella, conversaciones cifradas en el móvil, seguridad comprobada y wallet desactivada.
 * El transporte es manual (se comparte el texto X39MSG1 por cualquier app); el relé llega en la v0.3.
 */
public class MainActivity extends Activity {
    private static final long TTL_SEGUNDOS = 7L * 24 * 3600;
    private static final int REQ_DESBLOQUEO = 39;
    private static final long GRACIA_BLOQUEO_MS = 60_000;
    private static final String VERSION = "0.2.0";

    private enum Pestana { CHATS, CONTACTOS, WALLET, SEGURIDAD }

    private Boveda boveda;
    private Almacen almacen;
    private byte[] clavePublica;
    private String miId;
    private String errorInicio;

    private FrameLayout raiz;
    private Pestana pestana = Pestana.CHATS;
    private Runnable pantallaSecundaria;
    private boolean desbloqueado;
    private boolean esperandoDesbloqueo;
    private long ultimaSalida;
    private String pendienteCompartido;

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
        try {
            if (!boveda.tieneClaves()) {
                boveda.crearClaves();
            }
            clavePublica = boveda.clavePublica();
            miId = Almacen.idDeClave(clavePublica);
            almacen.cargar();
        } catch (Exception e) {
            errorInicio = Ui.mensaje(e);
        }
        guardarCompartido(getIntent());
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (esperandoDesbloqueo) return;
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
            mostrarPestana(pestana);
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
        if (pantallaSecundaria != null) pantallaSecundaria.run();
        else mostrarPestana(pestana);
        procesarPendiente();
    }

    private void mostrar(View contenido, boolean conNavegacion) {
        raiz.removeAllViews();
        LinearLayout col = Ui.columna(this);
        col.addView(contenido, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        if (conNavegacion) {
            col.addView(Ui.separador(this));
            col.addView(barraNavegacion(), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 72)));
        }
        raiz.addView(col, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        raiz.requestApplyInsets();
    }

    private void mostrarPestana(Pestana p) {
        pestana = p;
        pantallaSecundaria = null;
        View v;
        switch (p) {
            case CONTACTOS: v = pantallaContactos(); break;
            case WALLET: v = pantallaWallet(); break;
            case SEGURIDAD: v = pantallaSeguridad(); break;
            default: v = pantallaChats(); break;
        }
        mostrar(v, true);
    }

    private void abrirSecundaria(Runnable pantalla) {
        pantallaSecundaria = pantalla;
        pantalla.run();
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
        barra.setBackgroundColor(Ui.FONDO);
        barra.addView(itemNavegacion(Pestana.CHATS, Icono.Tipo.CHAT, "Chats"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.CONTACTOS, Icono.Tipo.CONTACTOS, "Contactos"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.WALLET, Icono.Tipo.WALLET, "Wallet"), Ui.peso(1));
        barra.addView(itemNavegacion(Pestana.SEGURIDAD, Icono.Tipo.ESCUDO, "Seguridad"), Ui.peso(1));
        return barra;
    }

    private View itemNavegacion(Pestana p, Icono.Tipo tipo, String etiqueta) {
        boolean activa = p == pestana && pantallaSecundaria == null;
        int color = activa ? Ui.ROJO : 0xFF8A8A90;
        LinearLayout item = Ui.columna(this);
        item.setGravity(Gravity.CENTER);
        item.setMinimumHeight(Ui.dp(this, 64));
        FrameLayout pastilla = new FrameLayout(this);
        pastilla.setPadding(Ui.dp(this, 18), Ui.dp(this, 4), Ui.dp(this, 18), Ui.dp(this, 4));
        if (activa) pastilla.setBackground(Ui.redondeado(this, Ui.ROJO_SUAVE, 14));
        pastilla.addView(Ui.icono(this, tipo, color, 22));
        item.addView(pastilla);
        TextView t = Ui.texto(this, etiqueta, 12, color, activa);
        t.setPadding(0, Ui.dp(this, 3), 0, 0);
        item.addView(t);
        item.setContentDescription(etiqueta);
        item.setOnClickListener(v -> mostrarPestana(p));
        Ui.clicable(item);
        return item;
    }

    // ------------------------------------------------------------------ pantallas

    private View pantallaChats() {
        FrameLayout marco = new FrameLayout(this);
        LinearLayout col = Ui.columna(this);

        LinearLayout cab = Ui.fila(this);
        cab.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 8), Ui.dp(this, 6));
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_launcher_frente);
        cab.addView(logo, new LinearLayout.LayoutParams(Ui.dp(this, 48), Ui.dp(this, 48)));
        cab.addView(Ui.texto(this, "x39", 24, Ui.TEXTO, true));
        cab.addView(new View(this), Ui.peso(1));
        cab.addView(Ui.botonIcono(this, Icono.Tipo.PEGAR, Ui.TEXTO, "Abrir mensaje copiado", v -> procesarTexto(portapapeles())));
        col.addView(cab);

        col.addView(franjaProteccion(), Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 16, 0, 16, 0));

        LinearLayout tit = Ui.fila(this);
        tit.setPadding(Ui.dp(this, 20), Ui.dp(this, 22), Ui.dp(this, 20), Ui.dp(this, 6));
        tit.addView(Ui.texto(this, "Chats", 17, Ui.TEXTO, true), Ui.peso(1));
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
        fab.setBackground(Ui.redondeado(this, Ui.ROJO, 18));
        fab.setElevation(Ui.dp(this, 6));
        ImageView mas = new ImageView(this);
        mas.setImageDrawable(new Icono(Icono.Tipo.MAS, 0xFFFFFFFF));
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
        f.setBackground(Ui.redondeado(this, Ui.SUPERFICIE, 16));
        FrameLayout caja = new FrameLayout(this);
        caja.setBackground(Ui.redondeado(this, Ui.ROJO_SUAVE, 12));
        caja.addView(Ui.icono(this, Icono.Tipo.ESCUDO_OK, Ui.ROJO, 20), new FrameLayout.LayoutParams(Ui.dp(this, 20), Ui.dp(this, 20), Gravity.CENTER));
        f.addView(caja, new LinearLayout.LayoutParams(Ui.dp(this, 38), Ui.dp(this, 38)));
        LinearLayout textos = Ui.columna(this);
        textos.setPadding(Ui.dp(this, 12), 0, 0, 0);
        textos.addView(Ui.texto(this, "Protección activa", 14, Ui.TEXTO, true));
        textos.addView(Ui.texto(this, "Poscuántico · sin internet · sin capturas", 12, Ui.SUAVE, false));
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
        col.addView(Ui.boton(this, "Compartir mi clave", true, v -> compartir(X39Core.publicKeyToText(clavePublica), "Compartir mi clave x39")));
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
            TextView chip = Ui.texto(this, "Sin verificar", 11, Ui.ROJO, false);
            chip.setPadding(Ui.dp(this, 6), Ui.dp(this, 1), Ui.dp(this, 6), Ui.dp(this, 1));
            android.graphics.drawable.GradientDrawable borde = new android.graphics.drawable.GradientDrawable();
            borde.setCornerRadius(Ui.dp(this, 6));
            borde.setStroke(Ui.dp(this, 1), 0x73E53935);
            chip.setBackground(borde);
            nombre.addView(chip, Ui.margen(this, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, 8, 0, 0, 0));
        }
        textos.addView(nombre);
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
        TextView sub = Ui.texto(this, c.verificado ? "Verificado · poscuántico" : "Sin verificar · toca para comparar la huella", 12, c.verificado ? Ui.SUAVE : Ui.ROJO, false);
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

        TextView aviso = Ui.texto(this, "Cifrado ML-KEM-1024 en este móvil. Envías compartiendo el texto cifrado por la app que elijas; recibes abriéndolo aquí.", 12, Ui.SUAVE, false);
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
        circulo.setColor(Ui.ROJO);
        enviar.setBackground(circulo);
        ImageView flecha = new ImageView(this);
        flecha.setImageDrawable(new Icono(Icono.Tipo.ENVIAR, 0xFFFFFFFF));
        enviar.addView(flecha, new FrameLayout.LayoutParams(Ui.dp(this, 20), Ui.dp(this, 20), Gravity.CENTER));
        enviar.setContentDescription("Cifrar y compartir");
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
        t.setTextIsSelectable(true);
        b.addView(t);
        String pie = Ui.hora(m.ts) + (m.saliente ? " · compartido cifrado" : "");
        TextView h = Ui.texto(this, pie, 11, m.saliente ? 0xA6FFFFFF : 0xFF7A7A80, false);
        h.setGravity(Gravity.END);
        b.addView(h, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        if (m.remitenteDeclarado) {
            TextView d = Ui.texto(this, "Remitente declarado, aún sin firma", 11, 0xFF7A7A80, false);
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
        View huella = Ui.huella(this, X39Core.fingerprint(clavePublica), 17);
        huella.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
        mia.addView(huella);
        LinearLayout botones = Ui.fila(this);
        TextView compartir = Ui.boton(this, "Compartir", true, v -> compartir(X39Core.publicKeyToText(clavePublica), "Compartir mi clave x39"));
        botones.addView(compartir, Ui.peso(1));
        TextView copiar = Ui.boton(this, "Copiar", false, v -> copiar("Clave x39", X39Core.publicKeyToText(clavePublica), false));
        LinearLayout.LayoutParams lpc = Ui.peso(1);
        lpc.setMargins(Ui.dp(this, 10), 0, 0, 0);
        botones.addView(copiar, lpc);
        mia.addView(botones);

        LinearLayout tit = Ui.fila(this);
        tit.setPadding(0, Ui.dp(this, 22), 0, Ui.dp(this, 8));
        tit.addView(Ui.texto(this, "Tus contactos", 17, Ui.TEXTO, true), Ui.peso(1));
        TextView anadir = Ui.texto(this, "Añadir", 15, Ui.ROJO, true);
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
            t.addView(Ui.texto(this, c.verificado ? "Verificado" : "Sin verificar", 13, c.verificado ? Ui.SUAVE : Ui.ROJO, false));
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

        col.addView(Ui.texto(this, "Su clave (X39PK1)", 13, Ui.SUAVE, true));
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
            try {
                byte[] pk = X39Core.publicKeyFromText(t);
                if (Arrays.equals(pk, clavePublica)) {
                    estado.setTextColor(Ui.ROJO);
                    estado.setText("⚠ Esa es tu propia clave.");
                    return;
                }
                estado.setTextColor(Ui.SUAVE);
                estado.setText("Clave válida. Su huella de seguridad:");
                huellaVista[0] = Ui.huella(this, X39Core.fingerprint(pk), 16);
                huellaCaja.addView(huellaVista[0]);
            } catch (RuntimeException e) {
                estado.setTextColor(Ui.ROJO);
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
                byte[] pk = X39Core.publicKeyFromText(t);
                if (Arrays.equals(pk, clavePublica)) { aviso("No puedes añadir tu propia clave como contacto."); return; }
                Almacen.Contacto c = almacen.agregar(n, t, pk);
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
        caja.setBackground(Ui.redondeado(this, Ui.SUPERFICIE, 18));
        caja.addView(Ui.huella(this, X39Core.fingerprint(c.clave), 20));
        col.addView(caja, Ui.margen(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 18, 0, 18));

        TextView estado = Ui.texto(this, c.verificado ? "Marcado como verificado." : "Todavía sin verificar.", 14, c.verificado ? Ui.SUAVE : Ui.ROJO, false);
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

    private View pantallaWallet() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = Ui.columna(this);
        col.setPadding(Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 16), Ui.dp(this, 24));
        col.addView(Ui.texto(this, "Wallet", 24, Ui.TEXTO, true));
        LinearLayout t = tarjeta(col, "Desactivada en esta versión");
        t.addView(Ui.icono(this, Icono.Tipo.WALLET, Ui.ROJO, 28));
        TextView d = Ui.texto(this,
                "La wallet será no custodial: la semilla se generará y quedará solo en este móvil. "
                        + "Ni x39 ni ningún administrador podrán mover tus fondos.\n\n"
                        + "Llegará después de la mensajería con relé y firma del remitente. "
                        + "En el piloto institucional permanece desactivada.", 14, Ui.TEXTO_2, false);
        d.setPadding(0, Ui.dp(this, 10), 0, 0);
        t.addView(d);
        sv.addView(col);
        return sv;
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
        filaEstado(lista, "Cifrado", "ML-KEM-1024 + AES-256-GCM", true);
        filaEstado(lista, "Claves en hardware", hw, !"Software".equals(hw) && !"Desconocido".equals(hw));
        filaEstado(lista, "Capturas de pantalla", "Bloqueadas", true);
        filaEstado(lista, "Acceso a internet", internet ? "Permitido" : "Sin permiso", !internet);
        filaEstado(lista, "Servicios de Google", "Ninguno", true);
        filaEstado(lista, "Copias en la nube", copias ? "Activadas" : "Desactivadas", !copias);
        filaEstado(lista, "Bloqueo al abrir", bloqueo ? "Bloqueo del móvil" : "Sin bloqueo de pantalla", bloqueo);
        filaEstado(lista, "Mensajes abiertos", boveda.aperturasRegistradas() + " (anti-replay)", true);

        LinearLayout huella = tarjeta(col, "Tu huella de seguridad");
        huella.addView(Ui.huella(this, X39Core.fingerprint(clavePublica), 17));

        LinearLayout aviso = Ui.columna(this);
        aviso.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        android.graphics.drawable.GradientDrawable borde = new android.graphics.drawable.GradientDrawable();
        borde.setColor(0x0FE53935);
        borde.setCornerRadius(Ui.dp(this, 18));
        borde.setStroke(Ui.dp(this, 1), 0x59E53935);
        aviso.setBackground(borde);
        LinearLayout avTit = Ui.fila(this);
        avTit.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.ROJO, 18));
        TextView avT = Ui.texto(this, "Lo que aún no está cubierto", 14, Ui.TEXTO, true);
        avT.setPadding(Ui.dp(this, 10), 0, 0, 0);
        avTit.addView(avT);
        aviso.addView(avTit);
        TextView avD = Ui.texto(this,
                "El remitente de un mensaje es declarado, no probado: la firma ML-DSA-87 llega en la v0.3. "
                        + "Tampoco hay todavía forward secrecy, relé automático ni auditoría externa del protocolo.", 13, Ui.TEXTO_2, false);
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
        col.addView(Ui.icono(this, Icono.Tipo.AVISO, Ui.ROJO, 32));
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
        card.setBackground(Ui.redondeado(this, Ui.SUPERFICIE, 18));
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
        f.addView(Ui.icono(this, bien ? Icono.Tipo.CHECK : Icono.Tipo.AVISO, bien ? Ui.TEXTO : Ui.ROJO, 15));
        TextView v = Ui.texto(this, valor, 14, bien ? Ui.TEXTO : Ui.ROJO, false);
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

    private void enviar(Almacen.Contacto c, EditText et) {
        String texto = et.getText().toString().trim();
        if (texto.isEmpty()) return;
        byte[] carga = null;
        try {
            long ahoraMs = System.currentTimeMillis();
            carga = Carga.crear(miId, texto, ahoraMs);
            String capsula = X39Core.seal(c.clave, carga, ahoraMs / 1000L);
            c.mensajes.add(new Almacen.Mensaje(true, texto, ahoraMs, false));
            almacen.guardar();
            et.setText("");
            compartir(capsula, "Enviar mensaje cifrado a " + c.nombre);
        } catch (Exception e) {
            aviso(Ui.mensaje(e));
        } finally {
            if (carga != null) Arrays.fill(carga, (byte) 0);
        }
    }

    private void guardarCompartido(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return;
        String texto = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (texto != null) pendienteCompartido = texto;
    }

    private void procesarPendiente() {
        if (pendienteCompartido == null || errorInicio != null) return;
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
        if (s.startsWith("X39PK1:")) {
            abrirAgregar(s);
            return;
        }
        if (!s.startsWith("X39MSG1:")) {
            aviso("Ese texto no es un mensaje ni una clave de x39.");
            return;
        }
        byte[] sk = null;
        byte[] salida = null;
        byte[] cuerpo = null;
        try {
            sk = boveda.claveSecreta();
            salida = X39Core.open(sk, s, System.currentTimeMillis() / 1000L, TTL_SEGUNDOS);
            byte[] cid = Arrays.copyOfRange(salida, 0, X39Core.CID_LEN);
            if (!boveda.registrarApertura(cid)) {
                aviso("Este mensaje ya se abrió una vez. Por seguridad no se vuelve a mostrar.");
                return;
            }
            cuerpo = Arrays.copyOfRange(salida, X39Core.CID_LEN, salida.length);
            JSONObject j = Carga.leer(cuerpo);
            String de = j.optString("de", "");
            String contenido = j.optString("t", "");
            Almacen.Contacto c = almacen.porId(de);
            if (c == null) {
                new AlertDialog.Builder(this)
                        .setTitle("Mensaje de alguien que no está en tus contactos")
                        .setMessage(contenido + "\n\nAñade a esa persona con su clave para guardar la conversación.")
                        .setPositiveButton("Entendido", null)
                        .show();
                return;
            }
            c.mensajes.add(new Almacen.Mensaje(false, contenido, System.currentTimeMillis(), true));
            almacen.guardar();
            abrirConversacion(c);
        } catch (Exception e) {
            aviso(Ui.mensaje(e));
        } finally {
            if (sk != null) Arrays.fill(sk, (byte) 0);
            if (salida != null) Arrays.fill(salida, (byte) 0);
            if (cuerpo != null) Arrays.fill(cuerpo, (byte) 0);
        }
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
