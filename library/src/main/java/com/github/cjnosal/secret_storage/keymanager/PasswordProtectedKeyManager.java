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

import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.keywrap.PasswordWrapParams;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.security.auth.login.LoginException;

import static com.github.cjnosal.secret_storage.keymanager.KeyWrapper.getStorageField;

public class PasswordProtectedKeyManager extends KeyManager {
    private static final String ENC_SALT = "ENC_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    private final DataStorage configStorage;
    private final SecureRandom secureRandom;

    public PasswordProtectedKeyManager(ProtectionSpec dataProtectionSpec, PasswordKeyWrapper keyWrapper, DataKeyGenerator dataKeyGenerator, KeyWrap keyWrap, DataStorage configStorage) {
        super(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap);
        this.configStorage = configStorage;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public PasswordEditor getEditor(Rewrap rewrap, String storeId) {
        return new PasswordEditor(rewrap, storeId);
    }

    public void clear(String keyAlias) throws GeneralSecurityException, IOException {
        configStorage.delete(getStorageField(keyAlias, VERIFICATION));
        configStorage.delete(getStorageField(keyAlias, ENC_SALT));
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        keyWrapper.clear(keyAlias);
    }

    private void setPassword(String keyAlias, @NonNull String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            PasswordKeyWrapper passwordKeyWrapper = getKeyWrapper();
            byte[] salt = generateSalt();
            byte[] verification = passwordKeyWrapper.unlock(new PasswordWrapParams(keyAlias, password, salt));
            configStorage.store(getStorageField(keyAlias, ENC_SALT), salt);
            configStorage.store(getStorageField(keyAlias, VERIFICATION), verification);
        } else {
            throw new LoginException("Password already set. Use unlock.");
        }
    }

    private boolean verifyPassword(String keyAlias, String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(getStorageField(keyAlias, ENC_SALT));
        byte[] verification = configStorage.load(getStorageField(keyAlias, VERIFICATION));
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        return keyWrapper.verifyPassword(new PasswordWrapParams(keyAlias, password, encSalt, verification));
    }

    private void unlock(String keyAlias, @NonNull String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(getStorageField(keyAlias, ENC_SALT));
        byte[] verification = configStorage.load(getStorageField(keyAlias, VERIFICATION));
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        keyWrapper.unlock(new PasswordWrapParams(keyAlias, password, encSalt, verification));
    }

    private void lock() {
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        keyWrapper.lock();
    }

    private boolean isPasswordSet(String keyAlias) throws IOException {
        return configStorage.exists(getStorageField(keyAlias, ENC_SALT)) && configStorage.exists(getStorageField(keyAlias, VERIFICATION));
    }

    protected byte[] generateSalt() {
        PasswordKeyWrapper keyWrapper = getKeyWrapper();
        byte[] random = new byte[keyWrapper.getDerivationSpec().getKeySize() / 8];
        secureRandom.nextBytes(random);
        return random;
    }

    public static class Builder extends KeyManager.Builder {

        protected DataStorage configStorage;
        protected Context keyWrapperContext;
        protected KeyDerivationSpec keyDerivationSpec;
        protected String storeId;

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

        public Builder defaultConfigStorage(Context context, String storeId) {
            this.keyStorageContext = context;
            this.storeId = storeId;
            return this;
        }

        public Builder configStorage(DataStorage configStorage) {
            this.configStorage = configStorage;
            return this;
        }

        public Builder keyDerivationSpec(KeyDerivationSpec keyDerivationSpec) {
            this.keyDerivationSpec = keyDerivationSpec;
            return this;
        }

        public PasswordProtectedKeyManager build() {
            validate();
            return new PasswordProtectedKeyManager(dataProtection, (PasswordKeyWrapper) keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        }

        @Override
        protected void validate() {
            if (configStorage == null) {
                if (storeId != null && keyStorageContext != null) {
                    configStorage = new PreferenceStorage(keyStorageContext, storeId);
                }
                else {
                    throw new IllegalArgumentException("Must provide either a DataStorage or a Context and keyAlias");
                }
            }
            if (keyDerivationSpec == null) {
                keyDerivationSpec = DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec();
            }
            super.validate();
            if (!(keyWrapper instanceof PasswordKeyWrapper)) {
                throw new IllegalArgumentException("ObfuscationKeyManager requires a PasswordKeyWrapper or descendant");
            }
        }

        @Override
        protected void selectKeyWrapper() {
            if (defaultKeyWrapper >= Build.VERSION_CODES.JELLY_BEAN_MR2 && keyWrapperContext != null) {
                keyWrapper = new SignedPasswordKeyWrapper(
                        keyWrapperContext, keyDerivationSpec, DefaultSpecs.getPasswordDeviceBindingSpec());
            } else {
                keyWrapper = new PasswordKeyWrapper(
                        keyDerivationSpec);
            }
        }
    }

    public class PasswordEditor extends KeyManager.Editor {

        private Rewrap rewrap;
        private final String keyAlias;

        public PasswordEditor(Rewrap rewrap, String keyAlias) {
            this.rewrap = rewrap;
            this.keyAlias = keyAlias;
        }

        public void setPassword(String password) throws IOException, GeneralSecurityException {
            PasswordProtectedKeyManager.this.setPassword(keyAlias, password);
        }

        public void unlock(String password) throws GeneralSecurityException, IOException {
            PasswordProtectedKeyManager.this.unlock(keyAlias, password);
        }

        public void lock() {
            PasswordProtectedKeyManager.this.lock();
        }

        public void changePassword(@NonNull String oldPassword, @NonNull String newPassword) throws GeneralSecurityException, IOException {
            PasswordProtectedKeyManager.this.unlock(keyAlias, oldPassword);
            rewrap.unwrap();
            PasswordProtectedKeyManager.this.clear(keyAlias);
            PasswordProtectedKeyManager.this.setPassword(keyAlias, newPassword);
            rewrap.rewrap();
        }

        public boolean verifyPassword(String password) throws IOException, GeneralSecurityException {
            return PasswordProtectedKeyManager.this.verifyPassword(keyAlias, password);
        }

        public boolean isUnlocked() {
            PasswordKeyWrapper keyWrapper = getKeyWrapper();
            return keyWrapper.isUnlocked();
        }

        public boolean isPasswordSet() throws IOException {
            return PasswordProtectedKeyManager.this.isPasswordSet(keyAlias);
        }
    }
}
