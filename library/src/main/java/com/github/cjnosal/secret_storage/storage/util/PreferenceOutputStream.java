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
