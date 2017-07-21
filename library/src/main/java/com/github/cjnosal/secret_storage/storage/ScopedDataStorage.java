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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

public class ScopedDataStorage implements DataStorage {

    private final DataStorage storage;
    private String scope;

    public ScopedDataStorage(String scope, DataStorage storage) {
        this.scope = scope;
        this.storage = storage;
    }

    @Override
    public void store(@NonNull String id, @NonNull byte[] bytes) throws IOException {
        storage.store(getScopedId(id), bytes);
    }

    @NonNull
    @Override
    public byte[] load(@NonNull String id) throws IOException {
        return storage.load(getScopedId(id));
    }

    @NonNull
    @Override
    public OutputStream write(@NonNull String id) throws IOException {
        return storage.write(getScopedId(id));
    }

    @NonNull
    @Override
    public InputStream read(@NonNull String id) throws IOException {
        return storage.read(getScopedId(id));
    }

    @Override
    public boolean exists(@NonNull String id) {
        return storage.exists(getScopedId(id));
    }

    @Override
    public void delete(@NonNull String id) throws IOException {
        storage.delete(getScopedId(id));
    }

    @Override
    public void clear() throws IOException {
        Set<String> unscopedEntries = entries();
        for (String entry : unscopedEntries) {
            delete(entry);
        }
    }

    @Override
    public Set<String> entries() {
        Set<String> unscopedEntries = new HashSet<>();
        for (String scopedId : storage.entries()) {
            if (scopedId.startsWith(scope + getSeparator())) {
                unscopedEntries.add(getUnscopedId(scopedId));
            }
        }
        return unscopedEntries;
    }

    @Override
    public String getSeparator() {
        return storage.getSeparator();
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getScope() {
        return scope;
    }

    public String getScopedId(String id) {
        return scope + getSeparator() + id;
    }

    public String getUnscopedId(String scopedId) {
        String separator = getSeparator();
        return scopedId.substring(scopedId.indexOf(separator) + separator.length());
    }
}
