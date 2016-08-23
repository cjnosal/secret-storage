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

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;

import com.github.cjnosal.secret_storage.storage.encoding.Encoding;
import com.github.cjnosal.secret_storage.storage.util.PreferenceOutputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class PreferenceStorage implements DataStorage {

    SharedPreferences preferences;
    public PreferenceStorage(@NonNull Context context, @NonNull String file) {
        preferences = context.getSharedPreferences(file, Context.MODE_PRIVATE);
    }

    @Override
    public void store(@NonNull String id, @NonNull byte[] bytes) throws IOException {
        String encoded = Encoding.base64Encode(bytes);
        boolean success = preferences.edit().putString(id, encoded).commit();
        if (!success) {
            throw new IOException("Failed to save " + id + " to preferences");
        }
    }

    @Override
    public @NonNull byte[] load(@NonNull String id) throws IOException {
        String byteString = preferences.getString(id, null);
        if (byteString == null) {
            throw new IOException("Key " + id + " not present in preferences");
        }
        return Encoding.base64Decode(byteString);
    }

    @NonNull
    @Override
    public OutputStream write(@NonNull String id) throws IOException {
        return new PreferenceOutputStream(preferences, id);
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
        byte[] bytes = load(id);
        return new ByteArrayInputStream(bytes);
    }

    @Override
    public void close(@NonNull InputStream in) throws IOException {
        in.close();
    }

    @Override
    public boolean exists(@NonNull String id) throws IOException {
        return preferences.contains(id);
    }

    @Override
    public void delete(@NonNull String id) throws IOException {
        boolean success = preferences.edit().remove(id).commit();
        if (!success) {
            throw new IOException("Failed to delete " + id);
        }
    }

    @Override
    public void clear() throws IOException {
        boolean success = preferences.edit().clear().commit();
        if (!success) {
            throw new IOException("Failed to clear preferences");
        }
    }
}
