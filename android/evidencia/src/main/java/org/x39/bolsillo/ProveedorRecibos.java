package org.x39.bolsillo;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Sirve, en solo lectura, los ficheros que el usuario decide compartir (recibo .json, prueba .ots, clave pública).
 * Solo desde la carpeta cache/compartir de la app; nunca el almacén de fotos. Sin AndroidX.
 */
public class ProveedorRecibos extends ContentProvider {

    static File carpeta(Context c) {
        File d = new File(c.getCacheDir(), "compartir");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    static Uri uri(Context c, String nombre) {
        return Uri.parse("content://" + c.getPackageName() + ".recibos/" + nombre);
    }

    private File fichero(Uri uri) throws FileNotFoundException {
        String nombre = uri.getLastPathSegment();
        if (nombre == null || !nombre.matches("[A-Za-z0-9._-]{1,80}")) throw new FileNotFoundException("nombre no permitido");
        File f = new File(carpeta(getContext()), nombre);
        if (!f.isFile()) throw new FileNotFoundException(nombre);
        return f;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor c = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        try {
            File f = fichero(uri);
            c.addRow(new Object[]{f.getName(), f.length()});
        } catch (FileNotFoundException ignorado) {
            // Cursor vacío.
        }
        return c;
    }

    @Override
    public String getType(Uri uri) {
        String n = uri.getLastPathSegment() == null ? "" : uri.getLastPathSegment();
        if (n.endsWith(".json")) return "application/json";
        if (n.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("solo lectura");
        return ParcelFileDescriptor.open(fichero(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }
}
