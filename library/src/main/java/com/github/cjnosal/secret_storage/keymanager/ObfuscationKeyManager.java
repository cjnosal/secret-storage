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

import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This KeyManager is NOT SECURE!
 * Should only be used when AndroidKeyStore is not available and a user password can not be requested.
 */
public class ObfuscationKeyManager extends PasswordProtectedKeyManager {

    public ObfuscationKeyManager(ProtectionSpec dataProtectionSpec, DataStorage keyStorage, PasswordKeyWrapper keyWrapper) {
        super(dataProtectionSpec, keyStorage, keyWrapper);
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        unlock();
        return super.encrypt(plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        unlock();
        return super.decrypt(cipherText);
    }

    public void rewrap(KeyWrapper newWrapper) throws GeneralSecurityException, IOException {
        unlock();
        super.rewrap(newWrapper);
    }

    public void copyTo(KeyManager other) throws GeneralSecurityException, IOException {
        unlock();
        super.copyTo(other);
    }

    private void unlock() throws IOException, GeneralSecurityException {
        PasswordKeyWrapper keyWrapper = (PasswordKeyWrapper) this.keyWrapper;
        if (!keyWrapper.isUnlocked()) {
            if (keyWrapper.isPasswordSet()) {
                keyWrapper.unlock("default_password");
            } else {
                keyWrapper.setPassword("default_password");
            }
        }
    }

    public static class Builder extends KeyManager.Builder {

        private DataStorage configStorage;

        public Builder() {}

        public Builder defaultDataProtection(int osVersion) {
            this.defaultDataProtection = osVersion;
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

        public ObfuscationKeyManager build() {
            validate();
            return new ObfuscationKeyManager(dataProtection, keyStorage, (PasswordKeyWrapper) keyWrapper);
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
            keyWrapper = new PasswordKeyWrapper(DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(defaultDataProtection), configStorage);
        }
    }
}
