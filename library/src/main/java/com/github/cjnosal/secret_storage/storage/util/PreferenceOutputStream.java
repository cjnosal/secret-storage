package com.github.cjnosal.secret_storage.storage.util;

import android.content.SharedPreferences;

import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class PreferenceOutputStream extends ByteArrayOutputStream {

    private SharedPreferences preferences;
    private String id;

    public PreferenceOutputStream(SharedPreferences preferences, String id) {
        super();
        this.preferences = preferences;
        this.id = id;
    }

    @Override
    public void close() throws IOException {
        String encoded = Encoding.base64Encode(toByteArray());
        boolean success = preferences.edit().putString(id, encoded).commit();
        if (!success) {
            throw new IOException("Failed to save " + id + " to preferences");
        }
        super.close();
    }
}
