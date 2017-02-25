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

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public class KeyManager {

    private ProtectionSpec dataProtectionSpec;
    private DataKeyGenerator dataKeyGenerator;
    private KeyWrap keyWrap;
    private final ProtectionStrategy dataProtectionStrategy;
    protected KeyWrapper keyWrapper;
    protected String storeId;

    public KeyManager(ProtectionSpec dataProtectionSpec, KeyWrapper keyWrapper, DataKeyGenerator dataKeyGenerator, KeyWrap keyWrap) {
        this.dataProtectionSpec = dataProtectionSpec;
        this.dataKeyGenerator = dataKeyGenerator;
        this.keyWrap = keyWrap;
        this.dataProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();
    }

    public void setStoreId(String storeId) {
        this.storeId = storeId;
    }

    public KeyWrapper getKeyWrapper() {
        return keyWrapper;
    }

    public ProtectionSpec getDataProtectionSpec() {
        return dataProtectionSpec;
    }

    public byte[] encrypt(SecretKey encryptionKey, SecretKey signingKey, byte[] plainText) throws GeneralSecurityException, IOException {
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, dataProtectionSpec, plainText);
    }

    public byte[] decrypt(SecretKey decryptionKey, SecretKey verificationKey, byte[] cipherText) throws GeneralSecurityException, IOException {
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, dataProtectionSpec, cipherText);
    }

    public SecretKey generateDataEncryptionKey() throws GeneralSecurityException, IOException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getCipherSpec().getKeygenAlgorithm(), dataProtectionSpec.getCipherSpec().getKeySize());
    }

    public SecretKey generateDataSigningKey() throws GeneralSecurityException, IOException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegritySpec().getKeySize());
    }

    public byte[] wrapKey(SecretKey key) throws GeneralSecurityException, IOException {
        return keyWrap.wrap(keyWrapper.getKek(), key, keyWrapper.getWrapAlgorithm(), keyWrapper.getWrapAlgorithm());
    }

    public SecretKey unwrapKey(byte[] wrappedKey) throws GeneralSecurityException, IOException {
        return keyWrap.unwrap(keyWrapper.getKdk(), wrappedKey, keyWrapper.getWrapAlgorithm(), keyWrapper.getWrapParamAlgorithm(), dataProtectionSpec.getCipherSpec().getKeygenAlgorithm());
    }

    public static class Builder {

        protected int defaultDataProtection;
        protected ProtectionSpec dataProtection;

        protected int defaultKeyWrapper;
        protected KeyWrapper keyWrapper;

        protected Context keyStorageContext;
        protected String storeId;
        protected DataKeyGenerator dataKeyGenerator;
        protected KeyWrap keyWrap;

        public Builder() {}

        public Builder storeId(String storeId) {
            this.storeId = storeId;
            return this;
        }

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

        public Builder dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            this.dataKeyGenerator = dataKeyGenerator;
            return this;
        }

        public Builder keyWrap(KeyWrap keyWrap) {
            this.keyWrap = keyWrap;
            return this;
        }

        public KeyManager build() {
            validate();
            return new KeyManager(dataProtection, keyWrapper, dataKeyGenerator, keyWrap);
        }

        protected void validate() {
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
            if (dataKeyGenerator == null) {
                dataKeyGenerator = new DataKeyGenerator();
            }
            if (keyWrap == null) {
                keyWrap = new KeyWrap();
            }
        }

        protected void selectKeyWrapper() {
            if (defaultKeyWrapper > 0 && storeId != null) {
                if (defaultKeyWrapper >= Build.VERSION_CODES.M) {
                    keyWrapper = new KeyStoreWrapper(new AndroidCrypto(), DefaultSpecs.getKeyStoreDataProtectionSpec().getCipherSpec(), storeId);
                } else if (defaultKeyWrapper >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    keyWrapper = new AsymmetricKeyStoreWrapper(
                            keyStorageContext, new AndroidCrypto(), DefaultSpecs.getAsymmetricKeyProtectionSpec().getCipherSpec(), storeId);
                } else {
                    throw new IllegalArgumentException("AndroidKeyStore not available. Use PasswordProtectedKeyManager or ObfuscationKeyManager");
                }
            } else {
                throw new IllegalArgumentException("Must provide either a KeyWrapper, or OS version and store ID");
            }
        }
    }

    public <E extends KeyManager.Editor> E getEditor(Rewrap rewrap) {
        throw new UnsupportedOperationException("No editor available for this KeyManager");
    }

    public class Editor {
    }

    public interface Rewrap {
        void unwrap() throws GeneralSecurityException, IOException;
        void rewrap() throws GeneralSecurityException, IOException;
    }


}
