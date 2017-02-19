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

package com.github.cjnosal.secret_storage;

import android.content.Context;
import android.support.annotation.NonNull;

import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class PasswordProtectedSecretStorage extends SecretStorage {
    public PasswordProtectedSecretStorage(Context context, String storeId, DataStorage configStorage, DataStorage dataStorage, PasswordProtectedKeyManager keyManager) {
        super(context, storeId, configStorage, dataStorage, keyManager);
    }

    public void setPassword(@NonNull String password) throws GeneralSecurityException, IOException {
        ((PasswordProtectedKeyManager) keyManager).setPassword(password);
    }

    public void changePassword(@NonNull String oldPassword, @NonNull String newPassword) throws GeneralSecurityException, IOException {
        ((PasswordProtectedKeyManager) keyManager).changePassword(oldPassword, newPassword);
    }

    public void unlock(@NonNull String password) throws GeneralSecurityException, IOException {
        ((PasswordProtectedKeyManager) keyManager).unlock(password);
    }

    public void lock() {
        ((PasswordProtectedKeyManager) keyManager).lock();
    }

    public static class Builder extends SecretStorage.Builder {

        public Builder(Context context, String storeId) {
            super(context, storeId);
        }

        public PasswordProtectedSecretStorage.Builder configStorage(DataStorage configStorage) {
            this.configStorage = configStorage;
            return this;
        }

        public PasswordProtectedSecretStorage.Builder dataStorage(DataStorage dataStorage) {
            this.dataStorage = dataStorage;
            return this;
        }

        public PasswordProtectedSecretStorage.Builder keyManager(KeyManager keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        public PasswordProtectedSecretStorage build() throws IOException {
            validateArguments();
            return new PasswordProtectedSecretStorage(context, storeId, configStorage, dataStorage, (PasswordProtectedKeyManager) keyManager);
        }

        protected PasswordProtectedKeyManager selectKeyManager(int osVersion) {
            return new PasswordProtectedKeyManager.Builder()
                    .configStorage(configStorage)
                    .keyStorage(createStorage(DataStorage.TYPE_KEYS))
                    .defaultKeyWrapper(context, osVersion)
                    .defaultDataProtection(osVersion)
                    .build();
        }
    }
}
