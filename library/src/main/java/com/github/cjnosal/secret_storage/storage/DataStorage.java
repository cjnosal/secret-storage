package com.github.cjnosal.secret_storage.storage;

import android.support.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface DataStorage {
    void store(@NonNull String id, @NonNull byte[] bytes) throws IOException;
    @NonNull byte[] load(@NonNull String id) throws IOException;

    @NonNull OutputStream write(@NonNull String id) throws IOException;
    void close(@NonNull OutputStream out) throws IOException;

    @NonNull InputStream read(@NonNull String id) throws IOException;
    void close(@NonNull InputStream in) throws IOException;

    boolean exists(@NonNull String id) throws IOException;
    void delete(@NonNull String id) throws IOException;
    void clear() throws IOException;
}
