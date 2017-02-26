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

    private final ProtectionSpec dataProtectionSpec;
    private final DataKeyGenerator dataKeyGenerator;
    private final KeyWrap keyWrap;
    private final ProtectionStrategy dataProtectionStrategy;
    private final KeyWrapper keyWrapper;

    public KeyManager(ProtectionSpec dataProtectionSpec, KeyWrapper keyWrapper, DataKeyGenerator dataKeyGenerator, KeyWrap keyWrap) {
        this.dataProtectionSpec = dataProtectionSpec;
        this.dataKeyGenerator = dataKeyGenerator;
        this.keyWrap = keyWrap;
        this.dataProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();
    }

    public String getWrapAlgorithm() {
        return keyWrapper.getWrapAlgorithm();
    }

    public String getWrapParamAlgorithm() {
        return keyWrapper.getWrapParamAlgorithm();
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

    public SecretKey generateDataEncryptionKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getCipherSpec().getKeygenAlgorithm(), dataProtectionSpec.getCipherSpec().getKeySize());
    }

    public SecretKey generateDataSigningKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegritySpec().getKeySize());
    }

    public byte[] wrapKey(String keyAlias, SecretKey key) throws GeneralSecurityException, IOException {
        return keyWrap.wrap(keyWrapper.getKek(keyAlias), key, keyWrapper.getWrapAlgorithm(), keyWrapper.getWrapParamAlgorithm());
    }

    public SecretKey unwrapKey(String keyAlias, byte[] wrappedKey) throws GeneralSecurityException, IOException {
        return keyWrap.unwrap(keyWrapper.getKdk(keyAlias), wrappedKey, keyWrapper.getWrapAlgorithm(), keyWrapper.getWrapParamAlgorithm(), dataProtectionSpec.getCipherSpec().getKeygenAlgorithm());
    }

    public <E extends KeyManager.Editor> E getEditor(Rewrap rewrap, String storeId) {
        throw new UnsupportedOperationException("No editor available for this KeyManager");
    }

    public void clear(String keyAlias) throws GeneralSecurityException, IOException {
        keyWrapper.clear(keyAlias);
    }

    protected <KW extends KeyWrapper> KW getKeyWrapper() {
        return (KW) keyWrapper;
    }

    public static class Builder {

        protected int defaultDataProtection;
        protected ProtectionSpec dataProtection;

        private Context context;
        protected int defaultKeyWrapper;
        protected KeyWrapper keyWrapper;

        protected Context keyStorageContext;
        protected DataKeyGenerator dataKeyGenerator;
        protected KeyWrap keyWrap;

        public Builder() {}

        public Builder defaultDataProtection(int osVersion) {
            this.defaultDataProtection = osVersion;
            return this;
        }

        public Builder defaultKeyWrapper(Context context, int osVersion) {
            this.context = context;
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
            if (defaultKeyWrapper > 0) {
                if (defaultKeyWrapper >= Build.VERSION_CODES.M) {
                    keyWrapper = new KeyStoreWrapper(DefaultSpecs.getKeyStoreCipherSpec());
                } else if (defaultKeyWrapper >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    keyWrapper = new AsymmetricKeyStoreWrapper(DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context));
                } else {
                    throw new IllegalArgumentException("AndroidKeyStore not available. Use PasswordProtectedKeyManager or ObfuscationKeyManager");
                }
            } else {
                throw new IllegalArgumentException("Must provide either a KeyWrapper, or OS version");
            }
        }
    }

    public class Editor {
    }

    public interface Rewrap {
        void unwrap() throws GeneralSecurityException, IOException;
        void rewrap() throws GeneralSecurityException, IOException;
    }


}
