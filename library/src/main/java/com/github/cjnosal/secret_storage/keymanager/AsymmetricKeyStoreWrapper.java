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

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.Cipher;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class AsymmetricKeyStoreWrapper extends BaseKeyWrapper {

    private static final String ROOT_ENCRYPTION_KEY = "ROOT_ENCRYPTION_KEY";

    private final AndroidCrypto androidCrypto;
    private final CipherSpec rootKekProtectionSpec;
    private final Context context;
    private final KeyGenSpec rootKekSpec;

    // TODO refactor to extend KeyStoreWrapper to override symmetric key generation?

    public AsymmetricKeyStoreWrapper(Context context, CryptoConfig cryptoConfig, DataStorage configStorage, DataStorage keyStorage) {
        this(context, cryptoConfig.getIntermediateKeyProtectionSpec(), cryptoConfig.getIntermediateKekSpec(), cryptoConfig.getKeyStoreKeyProtectionSpec(), cryptoConfig.getKeyStoreKekSpec(), configStorage, keyStorage);
    }

    public AsymmetricKeyStoreWrapper(Context context, CipherSpec intermediateKeyProtectionSpec, KeyGenSpec intermediateKekSpec, CipherSpec keyStoreKeyProtectionSpec, KeyGenSpec keyStoreKekSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(intermediateKeyProtectionSpec, intermediateKekSpec, configStorage, keyStorage);
        this.context = context;
        this.rootKekSpec = keyStoreKekSpec;
        this.androidCrypto = new AndroidCrypto();
        this.rootKekProtectionSpec = keyStoreKeyProtectionSpec;
    }

    @Override
    protected void eraseConfig() throws GeneralSecurityException, IOException {
        super.eraseConfig();
        androidCrypto.deleteEntry(configStorage.getScopedId(ROOT_ENCRYPTION_KEY));
    }

    @Override
    void unlock(UnlockParams params) throws IOException, GeneralSecurityException {
        String storageField = configStorage.getScopedId(ROOT_ENCRYPTION_KEY);
        if (!intermediateKekExists()) {
            KeyPair encryptionKey = generateKeyPair();
            Key rootKek = encryptionKey.getPublic();
            Cipher kekCipher = keyWrap.initWrapCipher(rootKek, rootKekProtectionSpec.getCipherTransformation(), rootKekProtectionSpec.getParamsAlgorithm());
            finishUnlock(null, kekCipher);
        } else {
            Key rootKek = androidCrypto.loadPrivateKey(storageField);
            Cipher kekCipher = keyWrap.initUnwrapCipher(rootKek, rootKekProtectionSpec.getParamsAlgorithm(), rootKekProtectionSpec.getCipherTransformation(), getWrappedIntermediateKek());
            finishUnlock(kekCipher, null);
        }
    }

    private KeyPair generateKeyPair() throws GeneralSecurityException {
        return androidCrypto.generateKeyPair(context, configStorage.getScopedId(ROOT_ENCRYPTION_KEY),
                rootKekSpec.getKeygenAlgorithm());
    }

    public static class CryptoConfig {
        private final CipherSpec intermediateKeyProtectionSpec;
        private final KeyGenSpec intermediateKekSpec;
        private final CipherSpec keyStoreKeyProtectionSpec;
        private final KeyGenSpec keyStoreKekSpec;

        public CryptoConfig(CipherSpec intermediateKeyProtectionSpec, KeyGenSpec intermediateKekSpec, CipherSpec keyStoreKeyProtectionSpec, KeyGenSpec keyStoreKekSpec) {
            this.intermediateKeyProtectionSpec = intermediateKeyProtectionSpec;
            this.intermediateKekSpec = intermediateKekSpec;
            this.keyStoreKeyProtectionSpec = keyStoreKeyProtectionSpec;
            this.keyStoreKekSpec = keyStoreKekSpec;
        }

        public CipherSpec getIntermediateKeyProtectionSpec() {
            return intermediateKeyProtectionSpec;
        }

        public KeyGenSpec getIntermediateKekSpec() {
            return intermediateKekSpec;
        }

        public CipherSpec getKeyStoreKeyProtectionSpec() {
            return keyStoreKeyProtectionSpec;
        }

        public KeyGenSpec getKeyStoreKekSpec() {
            return keyStoreKekSpec;
        }
    }
}
