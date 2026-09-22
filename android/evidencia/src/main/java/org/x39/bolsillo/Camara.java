package org.x39.bolsillo;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
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

import org.x39matrix.evidencia.R;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;

final class Camara {
    interface Resultado {
        void foto(byte[] jpeg);
        void grabando();
        void video(File archivo, long duracionMs);
        void error(String motivo);
    }

    private final Activity actividad;
    private final TextureView vista;
    private final Resultado resultado;
    private HandlerThread hilo;
    private Handler handler;
    private CameraDevice dispositivo;
    private CameraCaptureSession sesion;
    private ImageReader lector;
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
        cerrada = false;
        hilo = new HandlerThread("x39-camara");
        hilo.start();
        handler = new Handler(hilo.getLooper());

        vista.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override
            public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
                iniciar();
                vista.post(() -> ajustarTransformacion(w, h));
            }

            @Override
            public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {
                if (tamPreview != null) {
                    st.setDefaultBufferSize(
                            tamPreview.getWidth(),
                            tamPreview.getHeight()
                    );
                }
                ajustarTransformacion(w, h);
            }

            @Override
            public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
                return true;
            }

            @Override
            public void onSurfaceTextureUpdated(SurfaceTexture st) {
            }
        });

        if (vista.isAvailable()) {
            iniciar();
        }
    }

    private void iniciar() {
        if (cerrada || handler == null) return;

        try {
            CameraManager cm = (CameraManager)
                    actividad.getSystemService(Activity.CAMERA_SERVICE);

            String id = null;

            for (String c : cm.getCameraIdList()) {
                Integer lado = cm.getCameraCharacteristics(c).get(
                        CameraCharacteristics.LENS_FACING
                );

                if (lado != null &&
                        lado == CameraCharacteristics.LENS_FACING_BACK) {
                    id = c;
                    break;
                }
            }

            if (id == null) {
                resultado.error(actividad.getString(R.string.x39_cam_sin_trasera));
                return;
            }

            CameraCharacteristics car =
                    cm.getCameraCharacteristics(id);

            StreamConfigurationMap mapa = car.get(
                    CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP
            );

            if (mapa == null) {
                resultado.error(actividad.getString(R.string.x39_cam_sin_tamanos));
                return;
            }

            Size[] previews = mapa.getOutputSizes(SurfaceTexture.class);

            if (previews == null || previews.length == 0) {
                resultado.error(actividad.getString(R.string.x39_cam_sin_tamanos_disponibles));
                return;
            }

            tamPreview = elegirTamano(
                    previews,
                    vista.getWidth(),
                    vista.getHeight()
            );

            Size[] videos = mapa.getOutputSizes(MediaRecorder.class);

            tamVideo = elegirTamano(
                    videos,
                    tamPreview.getWidth(),
                    tamPreview.getHeight()
            );

            if (actividad.checkSelfPermission(Manifest.permission.CAMERA)
                    != PackageManager.PERMISSION_GRANTED) {
                resultado.error(actividad.getString(R.string.x39_cam_sin_permiso));
                return;
            }

            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice d) {
                    dispositivo = d;
                    abrirPreview();
                }

                @Override
                public void onDisconnected(CameraDevice d) {
                    d.close();
                    if (dispositivo == d) dispositivo = null;
                }

                @Override
                public void onError(CameraDevice d, int error) {
                    d.close();
                    if (dispositivo == d) dispositivo = null;
                    resultado.error(actividad.getString(R.string.x39_cam_error, error));
                }
            }, handler);

        } catch (CameraAccessException | SecurityException e) {
            resultado.error(
                    actividad.getString(R.string.x39_cam_no_abrir, e.getMessage())
            );
        }
    }

    private void abrirPreview() {
        if (dispositivo == null ||
                tamPreview == null ||
                !vista.isAvailable()) {
            return;
        }

        try {
            SurfaceTexture st = vista.getSurfaceTexture();

            st.setDefaultBufferSize(
                    tamPreview.getWidth(),
                    tamPreview.getHeight()
            );

            Surface superficie = new Surface(st);

            lector = ImageReader.newInstance(
                    tamPreview.getWidth(),
                    tamPreview.getHeight(),
                    ImageFormat.JPEG,
                    2
            );

            lector.setOnImageAvailableListener(r -> {
                Image imagen = null;

                try {
                    imagen = r.acquireLatestImage();

                    if (imagen == null) return;

                    ByteBuffer buffer =
                            imagen.getPlanes()[0].getBuffer();

                    byte[] jpeg = new byte[buffer.remaining()];
                    buffer.get(jpeg);

                    actividad.runOnUiThread(
                            () -> resultado.foto(jpeg)
                    );

                } finally {
                    if (imagen != null) imagen.close();
                }
            }, handler);

            CaptureRequest.Builder b =
                    dispositivo.createCaptureRequest(
                            CameraDevice.TEMPLATE_PREVIEW
                    );

            b.addTarget(superficie);

            dispositivo.createCaptureSession(
                    Arrays.asList(superficie, lector.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(
                                CameraCaptureSession s
                        ) {
                            if (dispositivo == null || cerrada) return;

                            sesion = s;

                            try {
                                b.set(
                                        CaptureRequest.CONTROL_AF_MODE,
                                        CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE
                                );

                                s.setRepeatingRequest(
                                        b.build(),
                                        null,
                                        handler
                                );

                                vista.post(() ->
                                        ajustarTransformacion(
                                                vista.getWidth(),
                                                vista.getHeight()
                                        )
                                );

                            } catch (CameraAccessException e) {
                                resultado.error(
                                        actividad.getString(R.string.x39_cam_no_iniciar_preview, e.getMessage())
                                );
                            }
                        }

                        @Override
                        public void onConfigureFailed(
                                CameraCaptureSession s
                        ) {
                            resultado.error(
                                    actividad.getString(R.string.x39_cam_no_configurar_preview)
                            );
                        }
                    },
                    handler
            );

        } catch (CameraAccessException | IllegalStateException e) {
            resultado.error(
                    actividad.getString(R.string.x39_cam_error_preview, e.getMessage())
            );
        }
    }

    boolean grabando() {
        return grabando;
    }

    long duracionGrabacionMs() {
        if (!grabando || inicioGrabacion == 0) return 0;
        return System.currentTimeMillis() - inicioGrabacion;
    }

    void disparar() {
        tomarFoto();
    }

    void grabar(File archivo, boolean usarMicrofono) {
        iniciarVideo(archivo);
    }

    void parar() {
        detenerVideo();
    }

    void tomarFoto() {
        if (dispositivo == null ||
                sesion == null ||
                lector == null) {
            return;
        }

        try {
            CaptureRequest.Builder b =
                    dispositivo.createCaptureRequest(
                            CameraDevice.TEMPLATE_STILL_CAPTURE
                    );

            b.addTarget(lector.getSurface());

            b.set(
                    CaptureRequest.CONTROL_AF_MODE,
                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE
            );

            sesion.capture(b.build(), null, handler);

        } catch (CameraAccessException | IllegalStateException e) {
            resultado.error(
                    actividad.getString(R.string.x39_cam_no_foto, e.getMessage())
            );
        }
    }

    void iniciarVideo(File archivo) {
        if (dispositivo == null ||
                tamVideo == null ||
                !vista.isAvailable() ||
                grabando) {
            return;
        }

        archivoVideo = archivo;
        grabadora = new MediaRecorder();

        try {
            grabadora.setVideoSource(
                    MediaRecorder.VideoSource.SURFACE
            );

            grabadora.setAudioSource(
                    MediaRecorder.AudioSource.MIC
            );

            grabadora.setOutputFormat(
                    MediaRecorder.OutputFormat.MPEG_4
            );

            grabadora.setOutputFile(
                    archivo.getAbsolutePath()
            );

            grabadora.setVideoEncodingBitRate(8_000_000);
            grabadora.setVideoFrameRate(30);
            grabadora.setVideoSize(
                    tamVideo.getWidth(),
                    tamVideo.getHeight()
            );

            grabadora.setVideoEncoder(
                    MediaRecorder.VideoEncoder.H264
            );

            grabadora.setAudioEncoder(
                    MediaRecorder.AudioEncoder.AAC
            );

            grabadora.prepare();

            SurfaceTexture st = vista.getSurfaceTexture();

            st.setDefaultBufferSize(
                    tamPreview.getWidth(),
                    tamPreview.getHeight()
            );

            Surface previewSurface = new Surface(st);
            Surface recorderSurface = grabadora.getSurface();

            CaptureRequest.Builder b =
                    dispositivo.createCaptureRequest(
                            CameraDevice.TEMPLATE_RECORD
                    );

            b.addTarget(previewSurface);
            b.addTarget(recorderSurface);

            dispositivo.createCaptureSession(
                    Arrays.asList(
                            previewSurface,
                            recorderSurface
                    ),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(
                                CameraCaptureSession s
                        ) {
                            if (dispositivo == null || cerrada) return;

                            sesion = s;

                            try {
                                b.set(
                                        CaptureRequest.CONTROL_AF_MODE,
                                        CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_VIDEO
                                );

                                s.setRepeatingRequest(
                                        b.build(),
                                        null,
                                        handler
                                );

                                grabadora.start();
                                grabando = true;
                                inicioGrabacion =
                                        System.currentTimeMillis();

                                actividad.runOnUiThread(
                                        resultado::grabando
                                );

                            } catch (
                                    CameraAccessException |
                                    IllegalStateException e
                            ) {
                                resultado.error(
                                        actividad.getString(R.string.x39_cam_no_iniciar_video, e.getMessage())
                                );
                                cancelarGrabacion();
                            }
                        }

                        @Override
                        public void onConfigureFailed(
                                CameraCaptureSession s
                        ) {
                            resultado.error(
                                    actividad.getString(R.string.x39_cam_no_configurar_grabacion)
                            );
                            cancelarGrabacion();
                        }
                    },
                    handler
            );

        } catch (Exception e) {
            resultado.error(
                    actividad.getString(R.string.x39_cam_error_preparar_video, e.getMessage())
            );
            cancelarGrabacion();
        }
    }

    void detenerVideo() {
        if (!grabando || grabadora == null) return;

        long duracion =
                System.currentTimeMillis() - inicioGrabacion;

        try {
            grabadora.stop();

        } catch (RuntimeException e) {
            resultado.error(
                    actividad.getString(R.string.x39_cam_grabacion_invalida, e.getMessage())
            );
            cancelarGrabacion();
            return;
        }

        grabadora.reset();
        grabadora.release();
        grabadora = null;
        grabando = false;

        resultado.video(archivoVideo, duracion);
        archivoVideo = null;

        abrirPreview();
    }

    private void cancelarGrabacion() {
        if (grabadora != null) {
            try {
                grabadora.reset();
            } catch (Exception ignored) {
            }

            try {
                grabadora.release();
            } catch (Exception ignored) {
            }
        }

        grabadora = null;
        grabando = false;
        archivoVideo = null;
    }

    private Size elegirTamano(
            Size[] disponibles,
            int anchoVista,
            int altoVista
    ) {
        if (disponibles == null || disponibles.length == 0) {
            return new Size(1280, 720);
        }

        if (anchoVista <= 0 || altoVista <= 0) {
            return disponibles[0];
        }

        double ratio =
                (double) anchoVista / altoVista;

        Size mejor = disponibles[0];
        double puntuacionMejor = Double.MAX_VALUE;

        for (Size s : disponibles) {
            double diferencia =
                    Math.abs(
                            (double) s.getWidth() / s.getHeight()
                                    - ratio
                    );

            long diferenciaTam =
                    Math.abs(
                            (long) s.getWidth() * s.getHeight()
                                    - (long) anchoVista * altoVista
                    );

            double puntuacion =
                    diferencia * 1_000_000d
                            + diferenciaTam;

            if (puntuacion < puntuacionMejor) {
                puntuacionMejor = puntuacion;
                mejor = s;
            }
        }

        return mejor;
    }

    private void ajustarTransformacion(
            int ancho,
            int alto
    ) {
        if (ancho <= 0 ||
                alto <= 0 ||
                tamPreview == null) {
            return;
        }

        int rotacion =
                actividad.getWindowManager()
                        .getDefaultDisplay()
                        .getRotation();

        int grados = 0;

        if (rotacion == Surface.ROTATION_90) {
            grados = 90;
        } else if (rotacion == Surface.ROTATION_180) {
            grados = 180;
        } else if (rotacion == Surface.ROTATION_270) {
            grados = 270;
        }

        float pw = tamPreview.getWidth();
        float ph = tamPreview.getHeight();

        if (grados == 90 || grados == 270) {
            float temporal = pw;
            pw = ph;
            ph = temporal;
        }

        float escala = Math.max(
                (float) ancho / pw,
                (float) alto / ph
        );

        float centroX = ancho / 2f;
        float centroY = alto / 2f;

        Matrix matrix = new Matrix();
        matrix.setScale(
                escala,
                escala,
                centroX,
                centroY
        );

        if (grados != 0) {
            matrix.postRotate(
                    grados,
                    centroX,
                    centroY
            );
        }

        vista.setTransform(matrix);
    }

    void cerrar() {
        cerrada = true;

        try {
            if (sesion != null) sesion.close();
        } catch (Exception ignored) {
        }

        try {
            if (dispositivo != null) dispositivo.close();
        } catch (Exception ignored) {
        }

        try {
            if (lector != null) lector.close();
        } catch (Exception ignored) {
        }

        cancelarGrabacion();

        if (hilo != null) {
            hilo.quitSafely();
        }

        sesion = null;
        dispositivo = null;
        lector = null;
    }
}
