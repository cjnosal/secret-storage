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

import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

/**
 * This KeyManager is NOT SECURE!
 * Should only be used when AndroidKeyStore is not available and a user password can not be requested.
 */
public class ObfuscationKeyManager extends PasswordProtectedKeyManager {

    public ObfuscationKeyManager(ProtectionSpec dataProtectionSpec, PasswordKeyWrapper keyWrapper, DataKeyGenerator dataKeyGenerator, KeyWrap keyWrap, DataStorage configStorage, KeyDerivationSpec keyDerivationSpec) {
        super(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
    }

    public byte[] wrapKey(String keyAlias, SecretKey key) throws GeneralSecurityException, IOException {
        unlock(keyAlias);
        return super.wrapKey(keyAlias, key);
    }

    public SecretKey unwrapKey(String keyAlias, byte[] wrappedKey) throws GeneralSecurityException, IOException {
        unlock(keyAlias);
        return super.unwrapKey(keyAlias, wrappedKey);
    }

    private void unlock(String keyAlias) throws IOException, GeneralSecurityException {
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        if (!keyWrapper.isUnlocked()) {
            PasswordEditor passwordEditor = new PasswordEditor(null, keyAlias);
            if (passwordEditor.isPasswordSet()) {
                passwordEditor.unlock("default_password");
            } else {
                passwordEditor.setPassword("default_password");
            }
        }
    }

    public static class Builder extends PasswordProtectedKeyManager.Builder {

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

        public Builder configStorage(DataStorage configStorage) {
            this.configStorage = configStorage;
            return this;
        }

        public ObfuscationKeyManager build() {
            validate();
            return new ObfuscationKeyManager(dataProtection, (PasswordKeyWrapper) keyWrapper, dataKeyGenerator, keyWrap, configStorage, keyDerivationSpec);
        }

        @Override
        protected void validate() {
            super.validate();
            if (!(keyWrapper instanceof PasswordKeyWrapper)) {
                throw new IllegalArgumentException("ObfuscationKeyManager requires a PasswordKeyWrapper or descendant");
            }
        }

        @Override
        protected void selectKeyWrapper() {
            keyWrapper = new PasswordKeyWrapper(DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec());
        }
    }
}
