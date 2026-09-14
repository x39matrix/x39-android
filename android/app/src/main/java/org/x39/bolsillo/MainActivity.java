package org.x39.bolsillo;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** x39 Bolsillo v0.1: claves post-cuánticas, cifrar y abrir mensajes. Sin internet, sin Google, sin capturas. */
public class MainActivity extends Activity {
    // Paleta: ningún verde.
    private static final int FONDO = 0xFF0D0D0D;
    private static final int SUPERFICIE = 0xFF1A1A1A;
    private static final int ROJO = 0xFFE53935;
    private static final int TEXTO = 0xFFF2F2F2;
    private static final int TEXTO_SUAVE = 0xFF9E9E9E;

    /** Ventana para abrir un mensaje recibido por un canal manual (chat, correo, QR). */
    private static final long TTL_SEGUNDOS = 7L * 24 * 3600;

    private Boveda boveda;
    private byte[] clavePublica;
    private byte[] clavePublicaContacto;

    private TextView tvEstado;
    private TextView tvHuellaContacto;
    private TextView tvContador;
    private TextView tvResultado;
    private EditText etContacto;
    private EditText etMensaje;
    private EditText etRecibido;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Bloquea capturas, grabación de pantalla y la miniatura en «recientes».
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);

        boveda = new Boveda(this);
        setContentView(construirPantalla());

        try {
            if (!boveda.tieneClaves()) {
                boveda.crearClaves();
                estado("Claves post-cuánticas creadas en este móvil"
                        + (boveda.usaStrongBox() ? " (protegidas por StrongBox)." : " (protegidas por Android Keystore)."), false);
            }
            clavePublica = boveda.clavePublica();
            ((TextView) findViewById(R.id_huella_propia())).setText(X39Core.fingerprint(clavePublica));
        } catch (Exception e) {
            estado("No se pudieron preparar las claves: " + mensaje(e), true);
        }
        recibirCompartido(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        recibirCompartido(intent);
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Al salir de la app no queda texto en claro en pantalla.
        tvResultado.setText("");
        etMensaje.setText("");
    }

    // ---------------------------------------------------------------- acciones

    private void compartirMiClave() {
        try {
            compartir(X39Core.publicKeyToText(clavePublica), "Compartir mi clave x39");
        } catch (RuntimeException e) {
            estado(mensaje(e), true);
        }
    }

    private void copiarMiClave() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        cm.setPrimaryClip(ClipData.newPlainText("Clave x39", X39Core.publicKeyToText(clavePublica)));
        estado("Clave pública copiada.", false);
    }

    private void validarContacto(String texto) {
        clavePublicaContacto = null;
        if (texto.trim().isEmpty()) {
            tvHuellaContacto.setText("");
            return;
        }
        try {
            clavePublicaContacto = X39Core.publicKeyFromText(texto);
            tvHuellaContacto.setTextColor(TEXTO);
            tvHuellaContacto.setText("Huella del contacto (compárala con él):\n" + X39Core.fingerprint(clavePublicaContacto));
        } catch (RuntimeException e) {
            tvHuellaContacto.setTextColor(ROJO);
            tvHuellaContacto.setText("⚠ " + mensaje(e));
        }
    }

    private void cifrarYCompartir() {
        if (clavePublicaContacto == null) {
            estado("Pega primero una clave X39PK1 válida del contacto.", true);
            return;
        }
        byte[] texto = etMensaje.getText().toString().getBytes(StandardCharsets.UTF_8);
        if (texto.length == 0) {
            estado("Escribe un mensaje.", true);
            return;
        }
        try {
            String capsula = X39Core.seal(clavePublicaContacto, texto, ahora());
            etMensaje.setText("");
            compartir(capsula, "Enviar mensaje cifrado");
            estado("Mensaje cifrado. Solo tu contacto puede abrirlo.", false);
        } catch (RuntimeException e) {
            estado(mensaje(e), true);
        } finally {
            Arrays.fill(texto, (byte) 0);
        }
    }

    private void abrir() {
        String recibido = etRecibido.getText().toString();
        byte[] sk = null;
        byte[] salida = null;
        try {
            sk = boveda.claveSecreta();
            salida = X39Core.open(sk, recibido, ahora(), TTL_SEGUNDOS);
            byte[] cid = Arrays.copyOfRange(salida, 0, X39Core.CID_LEN);
            if (!boveda.registrarApertura(cid)) {
                tvResultado.setText("");
                estado("Este mensaje ya se abrió una vez (anti-replay). No se muestra de nuevo.", true);
                return;
            }
            tvResultado.setText(new String(salida, X39Core.CID_LEN, salida.length - X39Core.CID_LEN, StandardCharsets.UTF_8));
            etRecibido.setText("");
            estado("Mensaje auténtico y descifrado.", false);
        } catch (Exception e) {
            tvResultado.setText("");
            estado(mensaje(e), true);
        } finally {
            if (sk != null) Arrays.fill(sk, (byte) 0);
            if (salida != null) Arrays.fill(salida, (byte) 0);
        }
    }

    private void recibirCompartido(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return;
        String texto = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (texto == null) return;
        String t = texto.trim();
        if (t.startsWith("X39PK1:")) {
            etContacto.setText(t);
            estado("Clave de contacto recibida. Compara su huella.", false);
        } else if (t.startsWith("X39MSG1:")) {
            etRecibido.setText(t);
            estado("Mensaje cifrado recibido. Pulsa «Abrir».", false);
        } else {
            estado("El texto compartido no es de x39.", true);
        }
    }

    // ---------------------------------------------------------------- utilidades

    private void compartir(String texto, String titulo) {
        Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, texto);
        startActivity(Intent.createChooser(send, titulo));
    }

    private static long ahora() {
        return System.currentTimeMillis() / 1000L;
    }

    private static String mensaje(Exception e) {
        String m = e.getMessage();
        return (m == null || m.isEmpty()) ? e.getClass().getSimpleName() : m;
    }

    private void estado(String texto, boolean esError) {
        tvEstado.setTextColor(esError ? ROJO : TEXTO_SUAVE);
        tvEstado.setText(esError ? "⚠ " + texto : texto);
    }

    // ---------------------------------------------------------------- interfaz (sin XML, sin AndroidX)

    private View construirPantalla() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(FONDO);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int m = dp(20);
        col.setPadding(m, dp(28), m, dp(40));
        scroll.addView(col);

        TextView titulo = texto("x39", 34, ROJO, true);
        col.addView(titulo);
        col.addView(texto("Bolsillo · cifrado post-cuántico ML-KEM-1024 · sin internet", 13, TEXTO_SUAVE, false));

        tvEstado = texto("", 13, TEXTO_SUAVE, false);
        tvEstado.setPadding(0, dp(12), 0, 0);
        col.addView(tvEstado);

        // Mi clave
        LinearLayout mia = tarjeta(col, "Mi clave");
        mia.addView(texto("Huella de seguridad", 12, TEXTO_SUAVE, false));
        TextView huella = texto("…", 16, TEXTO, false);
        huella.setId(R.id_huella_propia());
        huella.setTypeface(Typeface.MONOSPACE);
        mia.addView(huella);
        LinearLayout filaClave = fila(mia);
        filaClave.addView(boton("Compartir", v -> compartirMiClave()), peso());
        filaClave.addView(boton("Copiar", v -> copiarMiClave()), peso());

        // Cifrar
        LinearLayout cifrar = tarjeta(col, "Cifrar para un contacto");
        etContacto = campo("Pega aquí la clave X39PK1 del contacto", 3);
        etContacto.addTextChangedListener(new Observador(this::validarContacto));
        cifrar.addView(etContacto);
        tvHuellaContacto = texto("", 13, TEXTO, false);
        tvHuellaContacto.setTypeface(Typeface.MONOSPACE);
        cifrar.addView(tvHuellaContacto);
        etMensaje = campo("Escribe el mensaje", 4);
        etMensaje.addTextChangedListener(new Observador(s -> tvContador.setText(
                s.getBytes(StandardCharsets.UTF_8).length + " bytes · cabe en un QR hasta " + X39Core.maxPlaintextForQr())));
        cifrar.addView(etMensaje);
        tvContador = texto("", 12, TEXTO_SUAVE, false);
        cifrar.addView(tvContador);
        cifrar.addView(boton("Cifrar y compartir", v -> cifrarYCompartir()));

        // Abrir
        LinearLayout abrir = tarjeta(col, "Abrir mensaje recibido");
        etRecibido = campo("Pega aquí el mensaje X39MSG1", 4);
        abrir.addView(etRecibido);
        abrir.addView(boton("Abrir", v -> abrir()));
        tvResultado = texto("", 17, TEXTO, false);
        tvResultado.setTextIsSelectable(false);
        tvResultado.setPadding(0, dp(12), 0, 0);
        abrir.addView(tvResultado);

        col.addView(texto("Capturas de pantalla bloqueadas. Las claves no salen de este móvil.", 11, TEXTO_SUAVE, false));
        return scroll;
    }

    private LinearLayout tarjeta(LinearLayout padre, String titulo) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(16));
        GradientDrawable fondo = new GradientDrawable();
        fondo.setColor(SUPERFICIE);
        fondo.setCornerRadius(dp(16));
        card.setBackground(fondo);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(18);
        padre.addView(card, lp);
        TextView t = texto(titulo, 18, TEXTO, true);
        t.setPadding(0, 0, 0, dp(8));
        card.addView(t);
        return card;
    }

    private LinearLayout fila(LinearLayout padre) {
        LinearLayout f = new LinearLayout(this);
        f.setOrientation(LinearLayout.HORIZONTAL);
        padre.addView(f);
        return f;
    }

    private LinearLayout.LayoutParams peso() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(0, 0, dp(8), 0);
        return lp;
    }

    private TextView texto(String s, int sp, int color, boolean negrita) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (negrita) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private EditText campo(String pista, int lineas) {
        EditText e = new EditText(this);
        e.setHint(pista);
        e.setHintTextColor(TEXTO_SUAVE);
        e.setTextColor(TEXTO);
        e.setMinLines(lineas);
        e.setGravity(Gravity.TOP);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        // Teclado en modo incógnito: que no aprenda lo que escribes.
        e.setImeOptions(e.getImeOptions() | 0x1000000 /* IME_FLAG_NO_PERSONALIZED_LEARNING */);
        return e;
    }

    private Button boton(String s, View.OnClickListener accion) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextColor(0xFFFFFFFF);
        GradientDrawable fondo = new GradientDrawable();
        fondo.setColor(ROJO);
        fondo.setCornerRadius(dp(12));
        b.setBackground(fondo);
        b.setOnClickListener(accion);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        b.setLayoutParams(lp);
        return b;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    /** Id estable para la vista de la huella propia sin archivos XML de ids. */
    private static final class R {
        static int id_huella_propia() {
            return 0x7f390001;
        }
    }

    private static final class Observador implements TextWatcher {
        interface Cambio { void en(String s); }
        private final Cambio cambio;
        Observador(Cambio c) { cambio = c; }
        @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
        @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
        @Override public void afterTextChanged(Editable s) { cambio.en(s.toString()); }
    }
}
