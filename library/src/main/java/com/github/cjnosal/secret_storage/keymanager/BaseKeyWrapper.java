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

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.ScopedDataStorage;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public abstract class BaseKeyWrapper implements KeyWrapper {

    // key storage
    private static final String WRAPPED_ENCRYPTION_KEY = "WRAPPED_ENCRYPTION_KEY";
    private static final String WRAPPED_SIGNING_KEY = "WRAPPED_SIGNING_KEY";
    private static final String WRAPPED_KEYWRAPPER_KEY = "WRAPPED_KEYWRAPPER_KEY";

    protected final KeyWrap keyWrap = new KeyWrap();
    protected final CipherSpec keyProtectionSpec;
    protected final KeyGenSpec kekGenSpec;
    protected final ScopedDataStorage configStorage;
    protected final ScopedDataStorage keyStorage;

    private KekProvider kekProvider;
    private SecretKey keyWrapperKek;

    public BaseKeyWrapper(CipherSpec keyProtectionSpec, KeyGenSpec kekGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        this.keyProtectionSpec = keyProtectionSpec;
        this.kekGenSpec = kekGenSpec;
        this.configStorage = new ScopedDataStorage("kek", configStorage);
        this.keyStorage = new ScopedDataStorage("dek", keyStorage);
        this.kekProvider = new KekProvider(new DataKeyGenerator());
    }

    public boolean isUnlocked() {
        return keyWrapperKek != null;
    }

    void lock() {
        keyWrapperKek = null;
    }

    // must call finishUnlock(String, Cipher, Cipher)
    abstract void unlock(UnlockParams params) throws IOException, GeneralSecurityException;

    public @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey(String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(WRAPPED_ENCRYPTION_KEY);
        return unwrapKey(keyWrapperKek, wrappedKey, keyType);
    }

    public @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey(String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(WRAPPED_SIGNING_KEY);
        return unwrapKey(keyWrapperKek, wrappedKey, keyType);
    }

    public void storeDataEncryptionKey(@KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(keyWrapperKek, key);
        keyStorage.store(WRAPPED_ENCRYPTION_KEY, wrappedKey);
    }

    public void storeDataSigningKey(@KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(keyWrapperKek, key);
        keyStorage.store(WRAPPED_SIGNING_KEY, wrappedKey);
    }

    public boolean dataKeysExist() {
        return keyStorage.exists(WRAPPED_ENCRYPTION_KEY) && keyStorage.exists(WRAPPED_SIGNING_KEY);
    }

    public KeyWrapper.Editor getEditor() {
        return new NoParamsEditor();
    }

    public void eraseConfig() throws GeneralSecurityException, IOException {
        configStorage.delete(WRAPPED_KEYWRAPPER_KEY);
        lock();
    }

    public void eraseKeys() throws GeneralSecurityException, IOException {
        keyStorage.delete(WRAPPED_ENCRYPTION_KEY);
        keyStorage.delete(WRAPPED_SIGNING_KEY);
    }

    // TODO can this be done on initialization?
    public void setStorageScope(String keyScope, String configScope) {
        keyStorage.setScope(keyScope);
        configStorage.setScope(configScope);
    }

    protected boolean kekExists() {
        return configStorage.exists(WRAPPED_KEYWRAPPER_KEY);
    }

    protected AlgorithmParameters getKekCipherParams() throws IOException, GeneralSecurityException {
        byte[] wrappedKey = configStorage.load(WRAPPED_KEYWRAPPER_KEY);
        byte[][] splitBytes = ByteArrayUtil.split(wrappedKey);

        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(keyProtectionSpec.getParamsAlgorithm());
            params.init(splitBytes[0]);
        }
        return params;
    }

    protected void finishUnlock(Cipher unwrapCipher, Cipher wrapCipher) throws GeneralSecurityException, IOException {
        if (unwrapCipher != null) {
            byte[] wrappedKey = configStorage.load(WRAPPED_KEYWRAPPER_KEY);
            keyWrapperKek = keyWrap.unwrap(unwrapCipher, wrappedKey, kekGenSpec.getKeygenAlgorithm());
        } else {
            keyWrapperKek = kekProvider.getSecretKey(kekGenSpec);
        }

        if (wrapCipher != null) {
            byte[] wrappedKey = keyWrap.wrap(wrapCipher, keyWrapperKek);
            configStorage.store(WRAPPED_KEYWRAPPER_KEY, wrappedKey);
        }
    }

    private byte[] wrapKey(Key kek, SecretKey key) throws GeneralSecurityException, IOException {
        return keyWrap.wrap(kek, key, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
    }

    private SecretKey unwrapKey(Key kek, byte[] wrappedKey, String keyType) throws GeneralSecurityException, IOException {
        return keyWrap.unwrap(kek, wrappedKey, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm(), keyType);
    }

    void setKekProvider(KekProvider provider) {
        this.kekProvider = provider;
    }

    SecretKey getIntermediateKek() {
        return keyWrapperKek;
    }

    abstract class BaseEditor implements KeyWrapper.Editor {
        public BaseEditor() {}

        public void lock() {
            BaseKeyWrapper.this.lock();
        }

        public boolean isUnlocked() {
            return BaseKeyWrapper.this.isUnlocked();
        }

        public void eraseConfig() throws GeneralSecurityException, IOException {
            BaseKeyWrapper.this.eraseConfig();
        }
    }

    public class NoParamsEditor extends BaseEditor {
        public NoParamsEditor() {}

        public void unlock() throws GeneralSecurityException, IOException {
            BaseKeyWrapper.this.unlock(new UnlockParams());
        }

        public void unlock(Listener listener) {
            try {
                unlock();
                listener.onSuccess();
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }
    }

    class UnlockParams {
    }
}
