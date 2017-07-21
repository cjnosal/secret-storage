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
    private static final String DATA_ENCRYPTION_KEY = "DATA_ENCRYPTION_KEY";
    private static final String DATA_SIGNING_KEY = "DATA_SIGNING_KEY";

    // config storage
    private static final String INTERMEDIATE_KEK = "INTERMEDIATE_KEK";

    protected final ScopedDataStorage configStorage;
    protected final KeyWrap keyWrap = new KeyWrap();

    private final CipherSpec dataKeyProtectionSpec;
    private final KeyGenSpec intermediateKekGenSpec;
    private final ScopedDataStorage keyStorage;

    private IntermediateKekProvider intermediateKekProvider;
    private SecretKey intermediateKek;

    public BaseKeyWrapper(CipherSpec dataKeyProtectionSpec, KeyGenSpec intermediateKekGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        this.dataKeyProtectionSpec = dataKeyProtectionSpec;
        this.intermediateKekGenSpec = intermediateKekGenSpec;
        this.configStorage = new ScopedDataStorage("kek", configStorage);
        this.keyStorage = new ScopedDataStorage("dek", keyStorage);
        this.intermediateKekProvider = new IntermediateKekProvider(new DataKeyGenerator());
    }

    private boolean isUnlocked() {
        return intermediateKek != null;
    }

    void lock() {
        intermediateKek = null;
    }

    // must call finishUnlock(String, Cipher, Cipher)
    abstract void unlock(UnlockParams params) throws IOException, GeneralSecurityException;

    public @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey(String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(DATA_ENCRYPTION_KEY);
        return unwrapKey(intermediateKek, wrappedKey, keyType);
    }

    public @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey(String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(DATA_SIGNING_KEY);
        return unwrapKey(intermediateKek, wrappedKey, keyType);
    }

    public void storeDataEncryptionKey(@KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(intermediateKek, key);
        keyStorage.store(DATA_ENCRYPTION_KEY, wrappedKey);
    }

    public void storeDataSigningKey(@KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new IllegalStateException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(intermediateKek, key);
        keyStorage.store(DATA_SIGNING_KEY, wrappedKey);
    }

    public boolean dataKeysExist() {
        return keyStorage.exists(DATA_ENCRYPTION_KEY) && keyStorage.exists(DATA_SIGNING_KEY);
    }

    public KeyWrapper.Editor getEditor() {
        return new NoParamsEditor();
    }

    protected void eraseConfig() throws GeneralSecurityException, IOException {
        configStorage.delete(INTERMEDIATE_KEK);
        lock();
    }

    public void eraseDataKeys() throws GeneralSecurityException, IOException {
        keyStorage.delete(DATA_ENCRYPTION_KEY);
        keyStorage.delete(DATA_SIGNING_KEY);
    }

    // TODO can this be done on initialization?
    public void setStorageScope(String keyScope, String configScope) {
        keyStorage.setScope(keyScope);
        configStorage.setScope(configScope);
    }

    protected boolean intermediateKekExists() {
        return configStorage.exists(INTERMEDIATE_KEK);
    }

    protected AlgorithmParameters getCipherParametersForEncryptedIntermediateKek() throws IOException, GeneralSecurityException {
        byte[] wrappedKey = configStorage.load(INTERMEDIATE_KEK);
        byte[][] splitBytes = ByteArrayUtil.split(wrappedKey);

        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(dataKeyProtectionSpec.getParamsAlgorithm());
            params.init(splitBytes[0]);
        }
        return params;
    }

    protected void finishUnlock(Cipher unwrapCipher, Cipher wrapCipher) throws GeneralSecurityException, IOException {
        if (unwrapCipher != null) {
            byte[] wrappedKey = configStorage.load(INTERMEDIATE_KEK);
            intermediateKek = keyWrap.unwrap(unwrapCipher, wrappedKey, intermediateKekGenSpec.getKeygenAlgorithm());
        } else {
            intermediateKek = intermediateKekProvider.getIntermediateKek(intermediateKekGenSpec);
        }

        if (wrapCipher != null) {
            byte[] wrappedKey = keyWrap.wrap(wrapCipher, intermediateKek);
            configStorage.store(INTERMEDIATE_KEK, wrappedKey);
        }
    }

    private byte[] wrapKey(Key kek, SecretKey key) throws GeneralSecurityException, IOException {
        return keyWrap.wrap(kek, key, dataKeyProtectionSpec.getCipherTransformation(), dataKeyProtectionSpec.getParamsAlgorithm());
    }

    private SecretKey unwrapKey(Key kek, byte[] wrappedKey, String keyType) throws GeneralSecurityException, IOException {
        return keyWrap.unwrap(kek, wrappedKey, dataKeyProtectionSpec.getCipherTransformation(), dataKeyProtectionSpec.getParamsAlgorithm(), keyType);
    }

    void setIntermediateKekProvider(IntermediateKekProvider provider) {
        this.intermediateKekProvider = provider;
    }

    SecretKey getIntermediateKek() {
        return intermediateKek;
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

        @Override
        public void setStorageScope(String keyScope, String configScope) {
            BaseKeyWrapper.this.setStorageScope(keyScope, configScope);
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
