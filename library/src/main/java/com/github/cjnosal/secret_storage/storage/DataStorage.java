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
import android.support.annotation.StringDef;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

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

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            TYPE_DATA,
            TYPE_KEYS,
            TYPE_CONF
    })
    @interface Type {
    }

    String TYPE_DATA = "data";
    String TYPE_KEYS = "keys";
    String TYPE_CONF = "conf";
}
