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

package com.github.cjnosal.secret_storage.keymanager;

import android.support.annotation.NonNull;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class PasswordProtectedKeyManager extends KeyManager {
    public PasswordProtectedKeyManager(String storeId, ProtectionStrategy dataProtectionStrategy, Crypto crypto, DataStorage keyStorage, PasswordKeyWrapper keyWrapper) {
        super(storeId, dataProtectionStrategy, crypto, keyStorage, keyWrapper);
    }

    public void setPassword(@NonNull String password) throws GeneralSecurityException, IOException {
        ((PasswordKeyWrapper) keyWrapper).setPassword(password);
    }

    public void changePassword(@NonNull String oldPassword, @NonNull String newPassword) throws GeneralSecurityException, IOException {
        if (dataKeysExist()) {
            @KeyPurpose.DataSecrecy Key encryptionKey = loadDataEncryptionKey();
            @KeyPurpose.DataIntegrity Key signingKey = loadDataSigningKey();
            ((PasswordKeyWrapper) keyWrapper).changePassword(oldPassword, newPassword);
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        } else {
            ((PasswordKeyWrapper) keyWrapper).changePassword(oldPassword, newPassword);
        }
    }

    public void unlock(@NonNull String password) throws GeneralSecurityException, IOException {
        ((PasswordKeyWrapper) keyWrapper).unlock(password);
    }

    public void lock() {
        ((PasswordKeyWrapper) keyWrapper).lock();
    }
}
