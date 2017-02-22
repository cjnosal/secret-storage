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

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class PasswordProtectedKeyManager extends KeyManager {
    public PasswordProtectedKeyManager(ProtectionSpec dataProtectionSpec, DataStorage keyStorage, PasswordKeyWrapper keyWrapper, DataKeyGenerator dataKeyGenerator, KeyWrap keyWrap) {
        super(dataProtectionSpec, keyStorage, keyWrapper, dataKeyGenerator, keyWrap);
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

    public static class Builder extends KeyManager.Builder {

        private DataStorage configStorage;
        private Context keyWrapperContext;

        public Builder() {}

        public Builder defaultDataProtection(int osVersion) {
            this.defaultDataProtection = osVersion;
            return this;
        }

        public Builder defaultKeyWrapper(Context context, int osVersion) {
            this.keyWrapperContext = context;
            this.defaultKeyWrapper = osVersion;
            return this;
        }

        public Builder dataProtection(ProtectionSpec dataProtection) {
            this.dataProtection = dataProtection;
            return this;
        }

        public Builder keyWrapper(KeyWrapper keyWrapper) {
            this.keyWrapper = keyWrapper;
            return this;
        }

        public Builder defaultKeyStorage(Context context, String storeId) {
            this.keyStorageContext = context;
            this.storeId = storeId;
            return this;
        }

        public Builder keyStorage(DataStorage keyStorage) {
            this.keyStorage = keyStorage;
            return this;
        }

        public Builder configStorage(DataStorage configStorage) {
            this.configStorage = configStorage;
            return this;
        }

        public PasswordProtectedKeyManager build() {
            validate();
            return new PasswordProtectedKeyManager(dataProtection, keyStorage, (PasswordKeyWrapper) keyWrapper, dataKeyGenerator, keyWrap);
        }

        @Override
        protected void validate() {
            super.validate();
            if (configStorage == null) {
                if (storeId != null && keyStorageContext != null) {
                    configStorage = new PreferenceStorage(keyStorageContext, storeId);
                }
                else {
                    throw new IllegalArgumentException("Must provide either a DataStorage or a Context and storeId");
                }
            }
            if (!(keyWrapper instanceof PasswordKeyWrapper)) {
                throw new IllegalArgumentException("ObfuscationKeyManager requires a PasswordKeyWrapper or descendant");
            }
        }

        @Override
        protected void selectKeyWrapper() {
            if (defaultKeyWrapper >= Build.VERSION_CODES.JELLY_BEAN_MR2 && keyWrapperContext != null) {
                keyWrapper = new SignedPasswordKeyWrapper(
                        keyWrapperContext, new AndroidCrypto(), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordDeviceBindingSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(defaultDataProtection), configStorage);
            } else {
                keyWrapper = new PasswordKeyWrapper(
                        DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(defaultDataProtection), configStorage);
            }
        }
    }
}
