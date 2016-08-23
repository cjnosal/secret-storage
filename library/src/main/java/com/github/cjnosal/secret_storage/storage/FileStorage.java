/*
 *    Copyright 2016 Conor Nosal
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.github.cjnosal.secret_storage.storage;

import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FileStorage implements DataStorage {

    File directory;

    public FileStorage(@NonNull String directoryPath) {
        this.directory = new File(directoryPath);
    }

    @Override
    public void store(@NonNull String id, @NonNull byte[] bytes) throws IOException {
        OutputStream fos = null;
        try {
            fos = write(id);
            fos.write(bytes);
        } finally {
            if (fos != null) {
                close(fos);
            }
        }
    }

    @Override
    public @NonNull byte[] load(@NonNull String id) throws IOException {
        InputStream fis = null;
        try {
            fis = read(id);
            return readAll(fis);
        } finally {
            if (fis != null) {
                close(fis);
            }
        }
    }

    private byte[] readAll(InputStream fis) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(fis.available());
        byte[] buffer = new byte[1024];
        int byteCount = fis.read(buffer);
        while(byteCount != -1) {
            bos.write(buffer, 0, byteCount);
            byteCount = fis.read(buffer);
        }
        byte[] bytes = bos.toByteArray();
        bos.close();
        return bytes;
    }

    @NonNull
    @Override
    public OutputStream write(@NonNull String id) throws IOException {
        if (!directory.exists() && !directory.mkdirs()) {
            throw new IOException("Unable to create directory " + directory.getPath());
        }

        File file = new File(directory, id);
        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Unable to create file " + file.getPath());
        }
        return new FileOutputStream(file);
    }

    @Override
    public void close(@NonNull OutputStream out) throws IOException {
        try {
            out.flush();
        } finally {
            out.close();
        }
    }

    @NonNull
    @Override
    public InputStream read(@NonNull String id) throws IOException {
        File file = new File(directory, id);
        return new FileInputStream(file);
    }

    @Override
    public void close(@NonNull InputStream in) throws IOException {
        in.close();
    }

    @Override
    public boolean exists(@NonNull String id) throws IOException {
        File f = new File(directory, id);
        return f.exists();
    }

    @Override
    public void delete(@NonNull String id) throws IOException {
        File f = new File(directory, id);
        if (!f.delete()) {
            throw new IOException("Failed to delete " + id);
        }
    }

    @Override
    public void clear() throws IOException {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File f : files) {
                    //noinspection ResultOfMethodCallIgnored - directory deletion will fail if it isn't empty
                    f.delete();
                }
            }
            if (!directory.delete()) {
                throw new IOException("Failed to clear " + directory.getName());
            }
        }
    }
}
