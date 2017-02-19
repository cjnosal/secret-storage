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

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.KeyGenerator;

public class KeyManager {

    private ProtectionSpec dataProtectionSpec;
    private final ProtectionStrategy dataProtectionStrategy;
    private final DataStorage keyStorage;
    protected KeyWrapper keyWrapper;
    protected String storeId;

    public KeyManager(ProtectionSpec dataProtectionSpec, DataStorage keyStorage, KeyWrapper keyWrapper) {
        this.dataProtectionSpec = dataProtectionSpec;
        this.dataProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.keyStorage = keyStorage;
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();
    }

    public void setStoreId(String storeId) {
        this.storeId = storeId;
        this.keyWrapper.setStoreId(storeId);
    }

    public KeyWrapper getKeyWrapper() {
        return keyWrapper;
    }

    public ProtectionSpec getDataProtectionSpec() {
        return dataProtectionSpec;
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy Key encryptionKey;
        @KeyPurpose.DataIntegrity Key signingKey;
        if (dataKeysExist()) {
            encryptionKey = loadDataEncryptionKey();
            signingKey = loadDataSigningKey();
        }
        else {
            encryptionKey = generateDataEncryptionKey();
            signingKey = generateDataSigningKey();
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        }
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, dataProtectionSpec, plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy Key decryptionKey = loadDataEncryptionKey();
        @KeyPurpose.DataIntegrity Key verificationKey = loadDataSigningKey();
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, dataProtectionSpec, cipherText);
    }

    public void rewrap(KeyWrapper newWrapper) throws GeneralSecurityException, IOException {
        newWrapper.setStoreId(storeId);
        if (dataKeysExist()) {
            @KeyPurpose.DataSecrecy Key encryptionKey = loadDataEncryptionKey();
            @KeyPurpose.DataIntegrity Key signingKey = loadDataSigningKey();
            keyWrapper.clear();
            keyWrapper = newWrapper;
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        } else {
            keyWrapper = newWrapper;
        }
    }

    public void copyTo(KeyManager other) throws GeneralSecurityException, IOException {
        if (dataKeysExist()) {
            @KeyPurpose.DataSecrecy Key encryptionKey = loadDataEncryptionKey();
            @KeyPurpose.DataIntegrity Key signingKey = loadDataSigningKey();
            other.storeDataEncryptionKey(encryptionKey);
            other.storeDataSigningKey(signingKey);
        }
    }

    protected @KeyPurpose.DataSecrecy Key generateDataEncryptionKey() throws GeneralSecurityException, IOException {
        CipherSpec spec = dataProtectionSpec.getCipherSpec();
        KeyGenerator g = KeyGenerator.getInstance(spec.getKeygenAlgorithm());
        g.init(spec.getKeySize());
        return g.generateKey();
    }

    protected @KeyPurpose.DataIntegrity Key generateDataSigningKey() throws GeneralSecurityException, IOException {
        IntegritySpec spec = dataProtectionSpec.getIntegritySpec();
        KeyGenerator g = KeyGenerator.getInstance(spec.getKeygenAlgorithm());
        g.init(spec.getKeySize());
        return g.generateKey();
    }

    protected @KeyPurpose.DataSecrecy Key loadDataEncryptionKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(storeId + ":DS");
        return keyWrapper.unwrap(wrappedKey);
    }

    protected @KeyPurpose.DataIntegrity Key loadDataSigningKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(storeId + ":DI");
        return keyWrapper.unwrap(wrappedKey);
    }

    protected void storeDataEncryptionKey(@KeyPurpose.DataSecrecy Key key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyWrapper.wrap(key);
        keyStorage.store(storeId + ":DS", wrappedKey);
    }

    protected void storeDataSigningKey(@KeyPurpose.DataIntegrity Key key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyWrapper.wrap(key);
        keyStorage.store(storeId + ":DI", wrappedKey);
    }

    protected boolean dataKeysExist() throws GeneralSecurityException, IOException {
        return keyStorage.exists(storeId + ":DS") && keyStorage.exists(storeId + ":DI");
    }

    public static class Builder {

        protected int defaultDataProtection;
        protected ProtectionSpec dataProtection;

        protected int defaultKeyWrapper;
        protected KeyWrapper keyWrapper;

        protected Context keyStorageContext;
        protected String storeId;
        protected DataStorage keyStorage;

        public Builder() {}

        public Builder defaultDataProtection(int osVersion) {
            this.defaultDataProtection = osVersion;
            return this;
        }

        public Builder defaultKeyWrapper(int osVersion) {
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

        public KeyManager build() {
            validate();
            return new KeyManager(dataProtection, keyStorage, keyWrapper);
        }

        protected void validate() {
            if (keyStorage == null) {
                if (storeId != null && keyStorageContext != null) {
                    keyStorage = new PreferenceStorage(keyStorageContext, storeId);
                }
                else {
                    throw new IllegalArgumentException("Must provide either a DataStorage or a Context and storeId");
                }
            }
            if (dataProtection == null) {
                if (defaultDataProtection > 0) {
                    dataProtection = DefaultSpecs.getDataProtectionSpec(defaultDataProtection);
                }
                else {
                    throw new IllegalArgumentException("Must provide either a ProtectionSpec or OS version");
                }
            }
            if (keyWrapper == null) {
                selectKeyWrapper();
            }
        }

        protected void selectKeyWrapper() {
            if (defaultKeyWrapper > 0) {
                if (defaultKeyWrapper >= Build.VERSION_CODES.M) {
                    keyWrapper = new KeyStoreWrapper(new AndroidCrypto(), DefaultSpecs.getKeyStoreDataProtectionSpec());
                } else if (defaultKeyWrapper >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    keyWrapper = new AsymmetricKeyStoreWrapper(
                            keyStorageContext, new AndroidCrypto(), DefaultSpecs.getAsymmetricKeyProtectionSpec());
                } else {
                    throw new IllegalArgumentException("AndroidKeyStore not available. Use PasswordProtectedKeyManager or ObfuscationKeyManager");
                }
            } else {
                throw new IllegalArgumentException("Must provide either a KeyWrapper or OS version");
            }
        }
    }


}
