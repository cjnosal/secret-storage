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
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.login.LoginException;

public abstract class BaseKeyWrapper implements KeyWrapper {

    // key storage
    private static final String WRAPPED_ENCRYPTION_KEY = "WRAPPED_ENCRYPTION_KEY";
    private static final String WRAPPED_SIGNING_KEY = "WRAPPED_SIGNING_KEY";
    private static final String WRAPPED_KEYWRAPPER_KEY = "WRAPPED_KEYWRAPPER_KEY";
    private static final String DELIMITER = "::";

    protected final KeyWrap keyWrap = new KeyWrap();
    protected final CipherSpec keyProtectionSpec;
    protected final KeyGenSpec kekGenSpec;
    protected final DataStorage configStorage;
    protected final DataStorage keyStorage;
    protected final DataKeyGenerator dataKeyGenerator;

    private SecretKey keyWrapperKek;

    public BaseKeyWrapper(CipherSpec keyProtectionSpec, KeyGenSpec kekGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        this.keyProtectionSpec = keyProtectionSpec;
        this.kekGenSpec = kekGenSpec;
        this.configStorage = configStorage;
        this.keyStorage = keyStorage;
        this.dataKeyGenerator = new DataKeyGenerator();
    }

    public boolean isUnlocked() {
        return keyWrapperKek != null;
    }

    void lock() {
        keyWrapperKek = null;
    }

    // must call finishUnlock(String, Cipher, Cipher)
    abstract void unlock(String keyAlias, UnlockParams params) throws IOException, GeneralSecurityException;

    public @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY));
        return unwrapKey(keyWrapperKek, wrappedKey, keyType);
    }

    public @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_SIGNING_KEY));
        return unwrapKey(keyWrapperKek, wrappedKey, keyType);
    }

    public void storeDataEncryptionKey(String storeId, @KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(keyWrapperKek, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY), wrappedKey);
    }

    public void storeDataSigningKey(String storeId, @KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        byte[] wrappedKey = wrapKey(keyWrapperKek, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_SIGNING_KEY), wrappedKey);
    }

    public boolean dataKeysExist(String storeId) {
        return keyStorage.exists(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY)) && keyStorage.exists(getStorageField(storeId, WRAPPED_SIGNING_KEY));
    }

    public KeyWrapper.Editor getEditor(String storeId) {
        return new NoParamsEditor(storeId);
    }

    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        eraseKeys(keyAlias);
    }

    public void eraseKeys(String keyAlias) throws GeneralSecurityException, IOException {
        lock();
        keyStorage.delete(getStorageField(keyAlias, WRAPPED_ENCRYPTION_KEY));
        keyStorage.delete(getStorageField(keyAlias, WRAPPED_SIGNING_KEY));
        keyStorage.delete(getStorageField(keyAlias, WRAPPED_KEYWRAPPER_KEY));
    }

    protected boolean kekExists(String keyAlias) {
        return keyStorage.exists(getStorageField(keyAlias, WRAPPED_KEYWRAPPER_KEY));
    }

    protected AlgorithmParameters getKekCipherParams(String keyAlias) throws IOException, GeneralSecurityException {
        byte[] wrappedKey = keyStorage.load(getStorageField(keyAlias, WRAPPED_KEYWRAPPER_KEY));
        byte[][] splitBytes = ByteArrayUtil.split(wrappedKey);

        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(keyProtectionSpec.getParamsAlgorithm());
            params.init(splitBytes[0]);
        }
        return params;
    }

    protected void finishUnlock(String keyAlias, Cipher unwrapCipher, Cipher wrapCipher) throws GeneralSecurityException, IOException {
        if (unwrapCipher != null) {
            byte[] wrappedKey = keyStorage.load(getStorageField(keyAlias, WRAPPED_KEYWRAPPER_KEY));
            keyWrapperKek = keyWrap.unwrap(unwrapCipher, wrappedKey, kekGenSpec.getKeygenAlgorithm());
        } else {
            keyWrapperKek = dataKeyGenerator.generateDataKey(kekGenSpec.getKeygenAlgorithm(), kekGenSpec.getKeySize());
        }

        if (wrapCipher != null) {
            byte[] wrappedKey = keyWrap.wrap(wrapCipher, keyWrapperKek);
            keyStorage.store(getStorageField(keyAlias, WRAPPED_KEYWRAPPER_KEY), wrappedKey);
        }
    }

    private byte[] wrapKey(Key kek, SecretKey key) throws GeneralSecurityException, IOException {
        return keyWrap.wrap(kek, key, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
    }

    private SecretKey unwrapKey(Key kek, byte[] wrappedKey, String keyType) throws GeneralSecurityException, IOException {
        return keyWrap.unwrap(kek, wrappedKey, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm(), keyType);
    }

    static String getStorageField(String storeId, String field) {
        return storeId + DELIMITER + field;
    }

    abstract class BaseEditor implements KeyWrapper.Editor {
        protected final String keyAlias;

        public BaseEditor(String keyAlias) {
            this.keyAlias = keyAlias;
        }

        public void lock() {
            BaseKeyWrapper.this.lock();
        }
    }

    public class NoParamsEditor extends BaseEditor {
        public NoParamsEditor(String keyAlias) {
            super(keyAlias);
        }

        public void unlock() throws GeneralSecurityException, IOException {
            BaseKeyWrapper.this.unlock(keyAlias, new UnlockParams());
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
