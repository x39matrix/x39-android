package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Rect;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.hardware.camera2.params.MeteringRectangle;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.util.Log;
import android.util.Range;
import android.util.Size;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.TextureView;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.DecodeHintType;
import com.google.zxing.FormatException;
import com.google.zxing.LuminanceSource;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.Result;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import org.x39matrix.evidencia.R;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lector de QR de identidad, sin AndroidX («Google 0»): cámara con Camera2 del propio Android y decodificación con
 * ZXing core (Java puro, Apache 2; no se conecta a nada ni pide permisos). Mismo comportamiento que el de
 * x39 Llamadas: 1920×1080, zoom 2×, enfoque y exposición en el centro (y al tocar), tope de exposición 1/30 s si la
 * cámara lo admite, tres intentos por fotograma (uno sin moiré), QR por partes y avisos «aléjate» / «más luz».
 *
 * Devuelve RESULTADO_TEXTO («X39ID1:…», ya comprobado si venía por partes) o RESULTADO_ERROR = "mezcla".
 */
public final class EscanerQrActivity extends Activity {
    static final String RESULTADO_TEXTO = "texto";
    static final String RESULTADO_ERROR = "error";
    private static final String TAG = "X39_QR";
    private static final int REQ_CAMARA = 1;

    private TextureView vista;
    private TextView aviso;
    private HandlerThread hiloCamara;
    private Handler manejador;
    private CameraDevice camara;
    private CameraCaptureSession sesion;
    private ImageReader lectorImg;
    private CaptureRequest.Builder peticion;
    private Size tam;
    private Rect sensor;
    /** Cuántas regiones de enfoque y exposición admite esta cámara (0 = ninguna: no se mandan). */
    private int regionesAf = 0, regionesAe = 0;

    private final ExecutorService analisis = Executors.newSingleThreadExecutor();
    private final AtomicBoolean ocupado = new AtomicBoolean(false);
    private volatile boolean hecho = false;

    private final QRCodeReader lector = new QRCodeReader();
    private final Map<DecodeHintType, Object> pistas = new EnumMap<>(DecodeHintType.class);
    private final QrPartes.Recolector partes = new QrPartes.Recolector();

    // Lo que dice la cámara en cada captura, para los avisos.
    private volatile float focoDioptrias = 0f;
    private volatile int iso = 0;
    private volatile long exposicionNs = 0L;
    private float focoMinimo = 0f;
    private String ultimoAvisoPantalla = "";
    private long ultimaEvaluacion = 0L;
    private long inicio = 0L;
    private int fotogramas = 0, localizadoSinLeer = 0, sinPatron = 0;
    private long ultimoResumen = 0L;

    @Override
    protected void attachBaseContext(android.content.Context base) {
        super.attachBaseContext(Idioma.envolver(base));
    }

    @Override
    protected void onCreate(Bundle estado) {
        super.onCreate(estado);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        pistas.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        pistas.put(DecodeHintType.CHARACTER_SET, "ISO-8859-1");
        pistas.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

        FrameLayout raiz = new FrameLayout(this);
        raiz.setBackgroundColor(0xFF141414);
        vista = new TextureView(this);
        raiz.addView(vista, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER));
        aviso = new TextView(this);
        aviso.setText(getString(R.string.x39_escaner_apunta));
        aviso.setTextColor(0xFFFFFFFF);
        aviso.setTextSize(15);
        aviso.setGravity(Gravity.CENTER);
        aviso.setBackgroundColor(0x99141414);
        aviso.setPadding(24, 40, 24, 40);
        raiz.addView(aviso, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        setContentView(raiz);
        vista.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, orr, ob) -> ajustarVista());
        vista.setOnTouchListener((v, ev) -> {
            if (ev.getAction() == MotionEvent.ACTION_UP) { enfocar(ev.getX() / v.getWidth(), ev.getY() / v.getHeight()); v.performClick(); }
            return true;
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMARA);
            return;
        }
        arrancar();
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] permisos, int[] res) {
        super.onRequestPermissionsResult(req, permisos, res);
        if (req == REQ_CAMARA && (res.length == 0 || res[0] != PackageManager.PERMISSION_GRANTED)) {
            aviso.setText(getString(R.string.x39_escaner_sin_camara));
        }
    }

    @Override
    protected void onPause() {
        cerrar();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        analisis.shutdown();
    }

    // ------------------------------------------------------------------ cámara

    private void arrancar() {
        if (camara != null) return;
        hiloCamara = new HandlerThread("x39-escaner");
        hiloCamara.start();
        manejador = new Handler(hiloCamara.getLooper());
        if (vista.isAvailable()) abrirCamara();
        else vista.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override public void onSurfaceTextureAvailable(SurfaceTexture s, int w, int h) { abrirCamara(); }
            @Override public void onSurfaceTextureSizeChanged(SurfaceTexture s, int w, int h) { ajustarVista(); }
            @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture s) { return true; }
            @Override public void onSurfaceTextureUpdated(SurfaceTexture s) { }
        });
    }

    private void cerrar() {
        try { if (sesion != null) sesion.close(); } catch (Exception ignorada) { }
        try { if (camara != null) camara.close(); } catch (Exception ignorada) { }
        try { if (lectorImg != null) lectorImg.close(); } catch (Exception ignorada) { }
        sesion = null; camara = null; lectorImg = null;
        if (hiloCamara != null) { hiloCamara.quitSafely(); hiloCamara = null; }
    }

    /** La trasera principal; si no hay trasera, la primera que haya. */
    private String elegirCamara(CameraManager cm) throws CameraAccessException {
        String[] ids = cm.getCameraIdList();
        for (String id : ids) {
            Integer f = cm.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING);
            if (f != null && f == CameraCharacteristics.LENS_FACING_BACK) return id;
        }
        return ids.length > 0 ? ids[0] : null;
    }

    /** El tamaño YUV más cercano a 1920×1080 que tenga la cámara (por defecto se leería a baja resolución). */
    private static Size elegirTamano(StreamConfigurationMap mapa) {
        Size mejor = new Size(1280, 720);
        long objetivo = 1920L * 1080L, dif = Long.MAX_VALUE;
        for (Size s : mapa.getOutputSizes(ImageFormat.YUV_420_888)) {
            if (s.getWidth() * 9 != s.getHeight() * 16 && s.getWidth() * 3 != s.getHeight() * 4) continue;
            long d = Math.abs((long) s.getWidth() * s.getHeight() - objetivo);
            if (d < dif) { dif = d; mejor = s; }
        }
        return mejor;
    }

    private void abrirCamara() {
        CameraManager cm = (CameraManager) getSystemService(CAMERA_SERVICE);
        try {
            String id = elegirCamara(cm);
            if (id == null) { aviso.setText(getString(R.string.x39_escaner_sin_camara)); return; }
            CameraCharacteristics car = cm.getCameraCharacteristics(id);
            StreamConfigurationMap mapa = car.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            tam = elegirTamano(mapa);
            sensor = car.get(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE);
            Integer raf = car.get(CameraCharacteristics.CONTROL_MAX_REGIONS_AF), rae = car.get(CameraCharacteristics.CONTROL_MAX_REGIONS_AE);
            regionesAf = raf == null ? 0 : raf; regionesAe = rae == null ? 0 : rae;
            Float fm = car.get(CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE);
            focoMinimo = fm == null ? 0f : fm;
            Log.i(TAG, "cámara " + id + ", análisis a " + tam.getWidth() + "×" + tam.getHeight() + ", enfoque mínimo " +
                    (focoMinimo > 0f ? Math.round(100f / focoMinimo) + " cm" : "foco fijo"));
            ajustarVista();
            lectorImg = ImageReader.newInstance(tam.getWidth(), tam.getHeight(), ImageFormat.YUV_420_888, 2);
            lectorImg.setOnImageAvailableListener(this::fotogramaNuevo, manejador);
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice c) { camara = c; crearSesion(car); }
                @Override public void onDisconnected(CameraDevice c) { c.close(); camara = null; }
                @Override public void onError(CameraDevice c, int e) {
                    Log.w(TAG, "error de cámara " + e); c.close(); camara = null;
                    runOnUiThread(() -> aviso.setText(getString(R.string.x39_escaner_sin_camara)));
                }
            }, manejador);
        } catch (Exception e) {
            Log.w(TAG, "no se pudo abrir la cámara: " + e.getMessage());
            aviso.setText(getString(R.string.x39_escaner_sin_camara));
        }
    }

    /**
     * Sin deformar en cualquier pantalla: TextureView estira la imagen de la cámara hasta sus bordes, y la pantalla
     * (p. ej. 1080×2392) es más alargada que la imagen (1920×1080 girada = 1080×1920). Se escala por igual en los dos
     * ejes hasta llenar la vista y se recorta lo que sobra por los lados (como la cámara del sistema).
     */
    private void ajustarVista() {
        runOnUiThread(() -> {
            int w = vista.getWidth(), h = vista.getHeight();
            if (w == 0 || h == 0 || tam == null) return;
            float iw = tam.getHeight(), ih = tam.getWidth();   // la imagen, ya en vertical
            float esc = Math.max(w / iw, h / ih);
            android.graphics.Matrix m = new android.graphics.Matrix();
            m.setScale(iw * esc / w, ih * esc / h, w / 2f, h / 2f);
            vista.setTransform(m);
        });
    }

    private void crearSesion(CameraCharacteristics car) {
        try {
            SurfaceTexture st = vista.getSurfaceTexture();
            st.setDefaultBufferSize(tam.getWidth(), tam.getHeight());
            Surface previa = new Surface(st);
            peticion = camara.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            peticion.addTarget(previa);
            peticion.addTarget(lectorImg.getSurface());
            peticion.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            // Tope de exposición: solo un rango que ESTA cámara admita (con mínimo ≥ 30 fps). Si no hay, sin tope.
            Range<Integer>[] rangos = car.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES);
            Range<Integer> tope = null;
            if (rangos != null) for (Range<Integer> r : rangos) {
                if (r.getLower() >= 30 && (tope == null || r.getLower() * 1000 + r.getUpper() < tope.getLower() * 1000 + tope.getUpper())) tope = r;
            }
            if (tope != null) peticion.set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, tope);
            Log.i(TAG, "tope de exposición: " + (tope != null ? "fotogramas " + tope + " → como mucho 1/" + tope.getLower() + " s" : "no admitido; sin tope"));
            aplicarZoom(car);
            aplicarRegion(0.5f, 0.5f);
            camara.createCaptureSession(Arrays.asList(previa, lectorImg.getSurface()), new CameraCaptureSession.StateCallback() {
                @Override public void onConfigured(CameraCaptureSession s) {
                    sesion = s;
                    repetir();
                }
                @Override public void onConfigureFailed(CameraCaptureSession s) {
                    Log.w(TAG, "no se pudo configurar la sesión de cámara");
                    runOnUiThread(() -> aviso.setText(getString(R.string.x39_escaner_sin_camara)));
                }
            }, manejador);
        } catch (Exception e) {
            Log.w(TAG, "no se pudo crear la sesión: " + e.getMessage());
        }
    }

    /** Zoom 2×: se aparta el móvil del QR (30-40 cm), enfoca mejor y hay menos moiré de la otra pantalla. */
    private void aplicarZoom(CameraCharacteristics car) {
        if (Build.VERSION.SDK_INT >= 30) {
            Range<Float> r = car.get(CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE);
            float z = r == null ? 1f : Math.min(2f, r.getUpper());
            peticion.set(CaptureRequest.CONTROL_ZOOM_RATIO, z);
            Log.i(TAG, "zoom " + z + "× (rango " + r + ")");
        } else if (sensor != null) {
            Float max = car.get(CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM);
            float z = max == null ? 1f : Math.min(2f, max);
            int w = Math.round(sensor.width() / z), h = Math.round(sensor.height() / z);
            peticion.set(CaptureRequest.SCALER_CROP_REGION, new Rect((sensor.width() - w) / 2, (sensor.height() - h) / 2,
                    (sensor.width() + w) / 2, (sensor.height() + h) / 2));
            Log.i(TAG, "zoom " + z + "× (recorte)");
        }
    }

    /** Enfoque y exposición en un punto de la imagen (0-1), si la cámara admite regiones. */
    private void aplicarRegion(float fx, float fy) {
        if (sensor == null) return;
        // La vista está en vertical y el sensor en horizontal: x de la pantalla = y del sensor.
        int cx = Math.round(fy * sensor.width()), cy = Math.round((1f - fx) * sensor.height());
        int m = Math.min(sensor.width(), sensor.height()) / 8;
        MeteringRectangle[] reg = {new MeteringRectangle(Math.max(0, cx - m), Math.max(0, cy - m), 2 * m, 2 * m, MeteringRectangle.METERING_WEIGHT_MAX)};
        if (regionesAf > 0) peticion.set(CaptureRequest.CONTROL_AF_REGIONS, reg);
        if (regionesAe > 0) peticion.set(CaptureRequest.CONTROL_AE_REGIONS, reg);
    }

    private void enfocar(float fx, float fy) {
        if (sesion == null || peticion == null) return;
        try {
            aplicarRegion(fx, fy);
            peticion.set(CaptureRequest.CONTROL_AF_TRIGGER, CaptureRequest.CONTROL_AF_TRIGGER_START);
            sesion.capture(peticion.build(), null, manejador);
            peticion.set(CaptureRequest.CONTROL_AF_TRIGGER, CaptureRequest.CONTROL_AF_TRIGGER_IDLE);
            repetir();
            Log.i(TAG, "enfoque tocado en " + Math.round(fx * 100) + "%," + Math.round(fy * 100) + "%");
        } catch (Exception e) {
            Log.w(TAG, "no se pudo enfocar: " + e.getMessage());
        }
    }

    private void repetir() {
        try {
            sesion.setRepeatingRequest(peticion.build(), new CameraCaptureSession.CaptureCallback() {
                @Override public void onCaptureCompleted(CameraCaptureSession s, CaptureRequest p, TotalCaptureResult r) {
                    Float f = r.get(CaptureResult.LENS_FOCUS_DISTANCE); if (f != null) focoDioptrias = f;
                    Integer i = r.get(CaptureResult.SENSOR_SENSITIVITY); if (i != null) iso = i;
                    Long e = r.get(CaptureResult.SENSOR_EXPOSURE_TIME); if (e != null) exposicionNs = e;
                }
            }, manejador);
        } catch (Exception e) {
            Log.w(TAG, "no se pudo iniciar la vista previa: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ análisis

    /** Se copia el plano Y y se analiza en otro hilo; mientras está ocupado, los fotogramas nuevos se descartan. */
    private void fotogramaNuevo(ImageReader r) {
        Image img = r.acquireLatestImage();
        if (img == null) return;
        try {
            if (hecho || !ocupado.compareAndSet(false, true)) return;
            Image.Plane p = img.getPlanes()[0];
            ByteBuffer b = p.getBuffer();
            byte[] datos = new byte[b.remaining()];
            b.get(datos);
            final int paso = p.getRowStride(), ancho = img.getWidth(), alto = img.getHeight();
            analisis.execute(() -> { try { analizar(datos, paso, ancho, alto); } finally { ocupado.set(false); } });
        } finally {
            img.close();
        }
    }

    private void analizar(byte[] datos, int paso, int ancho, int alto) {
        if (hecho) return;
        if (inicio == 0L) { inicio = SystemClock.elapsedRealtime(); Log.i(TAG, "analizando a " + ancho + "×" + alto); }
        fotogramas++;
        evaluarAvisos(brilloMedio(datos, paso, ancho, alto));
        try {
            Result res = decodificar(datos, paso, ancho, alto);
            String texto = res.getText();
            if (texto.startsWith(QrPartes.PREFIJO)) {
                String completo;
                try {
                    completo = partes.anadir(texto);
                } catch (IllegalArgumentException e) {
                    Log.w(TAG, "parte " + QrPartes.PREFIJO + " mal formada, se ignora: " + e.getMessage());
                    return;
                } catch (QrPartes.Mezcla e) {
                    hecho = true;
                    Log.w(TAG, "PARADA: partes de dos identidades distintas o conjunto que no cuadra");
                    runOnUiThread(() -> { setResult(RESULT_OK, new Intent().putExtra(RESULTADO_ERROR, "mezcla")); finish(); });
                    return;
                }
                Log.i(TAG, "partes leídas: " + partes.leidas() + " de " + partes.totales());
                ultimaEvaluacion = 0L;
                if (completo == null) return;
                Log.i(TAG, "QR por partes completo: " + partes.totales() + " partes");
                texto = completo;
            }
            if (!texto.startsWith("X39ID1:")) {
                Log.w(TAG, "QR leído pero no es una identidad de x39 (empieza por «" + texto.substring(0, Math.min(8, texto.length())) + "»)");
                return;
            }
            hecho = true;
            Log.i(TAG, "leído en " + (SystemClock.elapsedRealtime() - inicio) + " ms, " + fotogramas + " fotogramas, " + ancho + "×" + alto);
            final String fin = texto;
            runOnUiThread(() -> { setResult(RESULT_OK, new Intent().putExtra(RESULTADO_TEXTO, fin)); finish(); });
        } catch (NotFoundException e) {
            sinPatron++;
            long ahora = SystemClock.elapsedRealtime();
            if (ahora - ultimoResumen > 3000) {
                ultimoResumen = ahora;
                Log.i(TAG, "no localiza el patrón: " + sinPatron + " fotogramas sin QR, " + localizadoSinLeer + " localizados sin leer, " + (ahora - inicio) + " ms");
            }
        } catch (ChecksumException | FormatException e) {
            localizadoSinLeer++;
        } catch (Exception e) {
            Log.w(TAG, "fallo al analizar el fotograma: " + e);
        }
    }

    /** Luminancia reducida 2×2 (filtro paso bajo): quita el moiré de fotografiar la rejilla de otra pantalla. */
    private static final class Reducida extends LuminanceSource {
        private final byte[] px;
        Reducida(byte[] datos, int paso, int ancho, int alto) {
            super(ancho / 2, alto / 2);
            int w = ancho / 2, h = alto / 2;
            px = new byte[w * h];
            for (int y = 0; y < h; y++) {
                int f0 = 2 * y * paso, f1 = f0 + paso;
                for (int x = 0; x < w; x++) {
                    int c = 2 * x;
                    int s = (datos[f0 + c] & 0xff) + (datos[f0 + c + 1] & 0xff) + (datos[f1 + c] & 0xff) + (datos[f1 + c + 1] & 0xff);
                    px[y * w + x] = (byte) (s >> 2);
                }
            }
        }
        @Override public byte[] getRow(int y, byte[] row) {
            byte[] r = (row != null && row.length >= getWidth()) ? row : new byte[getWidth()];
            System.arraycopy(px, y * getWidth(), r, 0, getWidth());
            return r;
        }
        @Override public byte[] getMatrix() { return px; }
    }

    /** Tres intentos: completo; reducido 2×2; reducido con histograma. Si ninguno lee, el fallo más informativo. */
    private Result decodificar(byte[] datos, int paso, int ancho, int alto) throws ReaderException {
        ReaderException peor = NotFoundException.getNotFoundInstance();
        LuminanceSource completa = new PlanarYUVLuminanceSource(datos, paso, alto, 0, 0, Math.min(paso, ancho), alto, false);
        BinaryBitmap[] intentos;
        if (datos.length >= (alto - 1) * paso + ancho) {
            Reducida red = new Reducida(datos, paso, ancho, alto);
            intentos = new BinaryBitmap[]{new BinaryBitmap(new HybridBinarizer(completa)),
                    new BinaryBitmap(new HybridBinarizer(red)), new BinaryBitmap(new GlobalHistogramBinarizer(red))};
        } else {
            intentos = new BinaryBitmap[]{new BinaryBitmap(new HybridBinarizer(completa))};
        }
        for (BinaryBitmap b : intentos) {
            try { return lector.decode(b, pistas); }
            catch (ReaderException e) { if (!(e instanceof NotFoundException)) peor = e; }
            finally { lector.reset(); }
        }
        throw peor;
    }

    private static int brilloMedio(byte[] datos, int paso, int ancho, int alto) {
        long suma = 0; int n = 0;
        for (int y = 0; y < alto; y += 16) for (int x = 0; x < ancho; x += 16) {
            int i = y * paso + x;
            if (i < datos.length) { suma += datos[i] & 0xff; n++; }
        }
        return n == 0 ? 0 : (int) (suma / n);
    }

    /** Aviso en pantalla cada medio segundo: demasiado cerca > poca luz > progreso de partes > «apunta». */
    private void evaluarAvisos(int brillo) {
        long ahora = SystemClock.elapsedRealtime();
        if (ahora - ultimaEvaluacion < 500) return;
        ultimaEvaluacion = ahora;
        boolean cerca = focoMinimo > 0f && focoDioptrias >= focoMinimo * 0.97f;
        boolean oscuro = brillo < 60 || (iso >= 1600 && exposicionNs >= 30_000_000L);
        String texto;
        if (cerca) texto = getString(R.string.x39_escaner_alejate, Math.round(100f / focoMinimo));
        else if (oscuro) texto = getString(R.string.x39_escaner_mas_luz);
        else if (partes.leidas() > 0) texto = getString(R.string.x39_escaner_partes, partes.leidas(), partes.totales());
        else texto = getString(R.string.x39_escaner_apunta);
        if (texto.equals(ultimoAvisoPantalla)) return;
        ultimoAvisoPantalla = texto;
        Log.i(TAG, "aviso: " + texto + " (foco " + focoDioptrias + " dp, mínimo " + focoMinimo + " dp, brillo " + brillo + ", ISO " + iso + ", exposición " + exposicionNs / 1_000_000 + " ms)");
        runOnUiThread(() -> aviso.setText(texto));
    }
}
