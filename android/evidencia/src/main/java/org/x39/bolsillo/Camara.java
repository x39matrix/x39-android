package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.media.MediaRecorder;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Surface;
import android.view.TextureView;
import android.view.ViewGroup;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Cámara propia con Camera2 (sin AndroidX). Entrega los bytes JPEG tal cual salen del sensor:
 * sin pasar por la galería y sin ubicación (no se fija JPEG_GPS_LOCATION).
 * Vídeo (0.2): MediaRecorder sobre la misma cámara, a un archivo temporal privado que se sella y se borra.
 */
final class Camara {
    interface Resultado {
        void foto(byte[] jpeg);

        /** La grabación ha empezado de verdad (la cámara ya escribe). */
        void grabando();

        /** Vídeo terminado: archivo MP4 temporal (lo borra quien lo sella) y duración. */
        void video(File archivo, long duracionMs);

        void error(String motivo);
    }

    /** Límite de resolución: suficiente como evidencia y razonable para cifrar y firmar al instante. */
    private static final long MAX_PIXELES = 12_500_000L;

    private final Activity actividad;
    private final TextureView vista;
    private final Resultado resultado;
    private HandlerThread hilo;
    private Handler handler;
    private CameraDevice dispositivo;
    private CameraCaptureSession sesion;
    private ImageReader lector;
    private CaptureRequest.Builder peticionPreview;
    private Surface superficiePreview;
    private int orientacionSensor = 90;
    private Size tamPreview;
    private Size tamVideo;
    private boolean cerrada;
    private MediaRecorder grabadora;
    private File archivoVideo;
    private boolean grabando;
    private long inicioGrabacion;

    Camara(Activity actividad, TextureView vista, Resultado resultado) {
        this.actividad = actividad;
        this.vista = vista;
        this.resultado = resultado;
    }

    void abrir() {
        hilo = new HandlerThread("x39-camara");
        hilo.start();
        handler = new Handler(hilo.getLooper());
        if (vista.isAvailable()) {
            iniciar();
        } else {
            vista.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
                @Override public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) { iniciar(); }
                @Override public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {}
                @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture st) { return true; }
                @Override public void onSurfaceTextureUpdated(SurfaceTexture st) {}
            });
        }
    }

    private void iniciar() {
        if (actividad.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            fallo("sin permiso de cámara");
            return;
        }
        try {
            CameraManager cm = actividad.getSystemService(CameraManager.class);
            String id = null;
            String[] ids = cm.getCameraIdList();
            for (String c : ids) {
                Integer lado = cm.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (lado != null && lado == CameraCharacteristics.LENS_FACING_BACK) {
                    id = c;
                    break;
                }
            }
            if (id == null && ids.length > 0) id = ids[0];
            if (id == null) {
                fallo("este móvil no tiene cámara");
                return;
            }
            CameraCharacteristics car = cm.getCameraCharacteristics(id);
            Integer o = car.get(CameraCharacteristics.SENSOR_ORIENTATION);
            if (o != null) orientacionSensor = o;
            StreamConfigurationMap mapa = car.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            if (mapa == null) {
                fallo("la cámara no ofrece formatos");
                return;
            }
            Size jpeg = mayor(mapa.getOutputSizes(ImageFormat.JPEG));
            tamPreview = previewParecido(mapa.getOutputSizes(SurfaceTexture.class), jpeg);
            tamVideo = videoHastaFullHd(mapa.getOutputSizes(MediaRecorder.class));
            lector = ImageReader.newInstance(jpeg.getWidth(), jpeg.getHeight(), ImageFormat.JPEG, 2);
            lector.setOnImageAvailableListener(r -> {
                try (Image img = r.acquireNextImage()) {
                    if (img == null) return;
                    ByteBuffer b = img.getPlanes()[0].getBuffer();
                    byte[] datos = new byte[b.remaining()];
                    b.get(datos);
                    actividad.runOnUiThread(() -> resultado.foto(datos));
                }
            }, handler);
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice d) {
                    if (cerrada) {
                        d.close();
                        return;
                    }
                    dispositivo = d;
                    crearSesion();
                }

                @Override
                public void onDisconnected(CameraDevice d) {
                    d.close();
                    dispositivo = null;
                }

                @Override
                public void onError(CameraDevice d, int error) {
                    d.close();
                    dispositivo = null;
                    fallo("la cámara no está disponible (código " + error + ")");
                }
            }, handler);
        } catch (Exception e) {
            fallo(Ui.mensaje(e));
        }
    }

    @SuppressWarnings("deprecation")
    private void crearSesion() {
        try {
            SurfaceTexture st = vista.getSurfaceTexture();
            if (st == null) {
                fallo("la vista previa no está lista");
                return;
            }
            st.setDefaultBufferSize(tamPreview.getWidth(), tamPreview.getHeight());
            Surface superficie = new Surface(st);
            superficiePreview = superficie;
            actividad.runOnUiThread(this::ajustarVista);
            peticionPreview = dispositivo.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            peticionPreview.addTarget(superficie);
            peticionPreview.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            dispositivo.createCaptureSession(Arrays.asList(superficie, lector.getSurface()), new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    if (cerrada || dispositivo == null) return;
                    sesion = s;
                    try {
                        s.setRepeatingRequest(peticionPreview.build(), null, handler);
                    } catch (CameraAccessException | IllegalStateException e) {
                        fallo(Ui.mensaje(e));
                    }
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    fallo("no se pudo configurar la cámara");
                }
            }, handler);
        } catch (CameraAccessException | IllegalStateException e) {
            fallo(Ui.mensaje(e));
        }
    }

    /** Pantalla en vertical: la vista previa (apaisada en el sensor) se muestra con su proporción real. */
    private void ajustarVista() {
        int ancho = vista.getWidth();
        if (ancho == 0 || tamPreview == null) return;
        int largo = Math.max(tamPreview.getWidth(), tamPreview.getHeight());
        int corto = Math.min(tamPreview.getWidth(), tamPreview.getHeight());
        ViewGroup.LayoutParams lp = vista.getLayoutParams();
        lp.height = Math.round(ancho * (largo / (float) corto));
        vista.setLayoutParams(lp);
    }

    void disparar() {
        if (sesion == null || dispositivo == null) return;
        try {
            CaptureRequest.Builder b = dispositivo.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE);
            b.addTarget(lector.getSurface());
            b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            // App bloqueada en vertical: la orientación del JPEG es la del sensor.
            b.set(CaptureRequest.JPEG_ORIENTATION, orientacionSensor);
            b.set(CaptureRequest.JPEG_QUALITY, (byte) 95);
            sesion.capture(b.build(), null, handler);
        } catch (CameraAccessException | IllegalStateException e) {
            fallo(Ui.mensaje(e));
        }
    }

    boolean grabando() {
        return grabando;
    }

    long duracionGrabacionMs() {
        return grabando ? System.currentTimeMillis() - inicioGrabacion : 0;
    }

    /**
     * Empieza a grabar vídeo (H.264 hasta 1080p, AAC si hay permiso de micrófono) en `destino`.
     * La sesión de fotos se sustituye por una de grabación con la misma vista previa.
     */
    void grabar(File destino, boolean conAudio) {
        if (sesion == null || dispositivo == null || grabando || superficiePreview == null) return;
        try {
            @SuppressWarnings("deprecation")
            MediaRecorder r = new MediaRecorder();
            if (conAudio) r.setAudioSource(MediaRecorder.AudioSource.MIC);
            r.setVideoSource(MediaRecorder.VideoSource.SURFACE);
            r.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            r.setOutputFile(destino.getAbsolutePath());
            r.setVideoEncodingBitRate(8_000_000);
            r.setVideoFrameRate(30);
            r.setVideoSize(tamVideo.getWidth(), tamVideo.getHeight());
            r.setVideoEncoder(MediaRecorder.VideoEncoder.H264);
            if (conAudio) {
                r.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
                r.setAudioEncodingBitRate(128_000);
                r.setAudioSamplingRate(44_100);
            }
            // App bloqueada en vertical: el MP4 lleva la orientación del sensor como en las fotos.
            r.setOrientationHint(orientacionSensor);
            r.prepare();
            grabadora = r;
            archivoVideo = destino;
            sesion.close();
            sesion = null;
            CaptureRequest.Builder b = dispositivo.createCaptureRequest(CameraDevice.TEMPLATE_RECORD);
            b.addTarget(superficiePreview);
            b.addTarget(r.getSurface());
            b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_VIDEO);
            dispositivo.createCaptureSession(Arrays.asList(superficiePreview, r.getSurface()), new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    if (cerrada || dispositivo == null) return;
                    sesion = s;
                    try {
                        s.setRepeatingRequest(b.build(), null, handler);
                        r.start();
                        grabando = true;
                        inicioGrabacion = System.currentTimeMillis();
                        actividad.runOnUiThread(resultado::grabando);
                    } catch (Exception e) {
                        soltarGrabadora(true);
                        fallo("no se pudo empezar a grabar: " + Ui.mensaje(e));
                    }
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    soltarGrabadora(true);
                    fallo("no se pudo configurar la grabación");
                }
            }, handler);
        } catch (Exception e) {
            soltarGrabadora(true);
            fallo("no se pudo preparar la grabación: " + Ui.mensaje(e));
        }
    }

    /** Termina la grabación: entrega el archivo y vuelve a la vista previa de fotos. */
    void parar() {
        if (!grabando) return;
        grabando = false;
        final long duracion = System.currentTimeMillis() - inicioGrabacion;
        final File f = archivoVideo;
        try {
            if (sesion != null) sesion.stopRepeating();
        } catch (Exception ignorado) {
            // La sesión ya no repetía.
        }
        boolean valido;
        try {
            grabadora.stop();
            valido = true;
        } catch (RuntimeException e) {
            // Parar antes del primer fotograma: MediaRecorder no deja archivo válido.
            valido = false;
        }
        soltarGrabadora(!valido);
        try {
            if (sesion != null) sesion.close();
        } catch (Exception ignorado) {
            // Ya cerrada.
        }
        sesion = null;
        if (!cerrada && handler != null) handler.post(this::crearSesion);
        if (valido) {
            actividad.runOnUiThread(() -> resultado.video(f, duracion));
        } else {
            fallo("la grabación es demasiado corta");
        }
    }

    private void soltarGrabadora(boolean borrarArchivo) {
        if (grabadora != null) {
            try {
                grabadora.reset();
            } catch (Exception ignorado) {
                // Ya en reposo.
            }
            grabadora.release();
            grabadora = null;
        }
        if (borrarArchivo && archivoVideo != null) {
            //noinspection ResultOfMethodCallIgnored
            archivoVideo.delete();
        }
        if (borrarArchivo) archivoVideo = null;
        grabando = false;
    }

    void cerrar() {
        cerrada = true;
        if (grabando) {
            try {
                grabadora.stop();
            } catch (Exception ignorado) {
                // Grabación interrumpida: se descarta.
            }
            soltarGrabadora(true);
        }
        try {
            if (sesion != null) sesion.close();
        } catch (Exception ignorado) {
            // Ya cerrada.
        }
        sesion = null;
        if (dispositivo != null) dispositivo.close();
        dispositivo = null;
        if (lector != null) lector.close();
        lector = null;
        if (hilo != null) hilo.quitSafely();
        hilo = null;
    }

    private void fallo(String motivo) {
        actividad.runOnUiThread(() -> resultado.error(motivo));
    }

    private static Size mayor(Size[] tamanos) {
        Size mejor = null;
        Size mayorAbsoluto = null;
        for (Size s : tamanos) {
            long px = (long) s.getWidth() * s.getHeight();
            if (mayorAbsoluto == null || px > (long) mayorAbsoluto.getWidth() * mayorAbsoluto.getHeight()) mayorAbsoluto = s;
            if (px <= MAX_PIXELES && (mejor == null || px > (long) mejor.getWidth() * mejor.getHeight())) mejor = s;
        }
        return mejor != null ? mejor : mayorAbsoluto;
    }

    /** El tamaño de vídeo más grande hasta 1920×1080 (Full HD basta como evidencia y cifra rápido). */
    private static Size videoHastaFullHd(Size[] tamanos) {
        Size mejor = null;
        for (Size s : tamanos == null ? new Size[0] : tamanos) {
            if (s.getWidth() > 1920 || s.getHeight() > 1080) continue;
            if (mejor == null || (long) s.getWidth() * s.getHeight() > (long) mejor.getWidth() * mejor.getHeight()) mejor = s;
        }
        return mejor != null ? mejor : new Size(1280, 720);
    }

    /** La vista previa más grande hasta 1920×1080 con la misma proporción que la foto. */
    private static Size previewParecido(Size[] tamanos, Size foto) {
        Size mejor = null;
        for (Size s : tamanos) {
            boolean proporcion = Math.abs((long) s.getWidth() * foto.getHeight() - (long) s.getHeight() * foto.getWidth())
                    <= (long) foto.getWidth() * foto.getHeight() / 100;
            if (!proporcion || s.getWidth() > 1920 || s.getHeight() > 1080) continue;
            if (mejor == null || (long) s.getWidth() * s.getHeight() > (long) mejor.getWidth() * mejor.getHeight()) mejor = s;
        }
        return mejor != null ? mejor : tamanos[0];
    }
}
