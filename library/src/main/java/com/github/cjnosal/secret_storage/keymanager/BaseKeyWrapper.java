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
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.SecretKey;
import javax.security.auth.login.LoginException;

import static com.github.cjnosal.secret_storage.storage.encoding.Encoding.utf8Decode;

public abstract class BaseKeyWrapper<E extends KeyWrapper.Editor> implements KeyWrapper<E> {

    // key storage
    private static final String WRAPPED_ENCRYPTION_KEY = "WRAPPED_ENCRYPTION_KEY";
    private static final String WRAPPED_SIGNING_KEY = "WRAPPED_SIGNING_KEY";

    // config storage
    private static final String KEY_PROTECTION = "KEY_PROTECTION";
    private static final String DELIMITER = "::";

    protected final KeyWrap keyWrap = new KeyWrap();
    protected final CipherSpec keyProtectionSpec;
    protected final DataStorage configStorage;
    protected final DataStorage keyStorage;

    public BaseKeyWrapper(CipherSpec keyProtectionSpec, DataStorage configStorage, DataStorage keyStorage) {
        this.keyProtectionSpec = keyProtectionSpec;
        this.configStorage = configStorage;
        this.keyStorage = keyStorage;
    }

    public boolean isUnlocked() {
        return true;
    }

    public @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY));
        return unwrapKey(storeId, wrappedKey, keyType);
    }

    public @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_SIGNING_KEY));
        return unwrapKey(storeId, wrappedKey, keyType);
    }

    public void storeDataEncryptionKey(String storeId, @KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = wrapKey(storeId, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY), wrappedKey);
    }

    public void storeDataSigningKey(String storeId, @KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = wrapKey(storeId, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_SIGNING_KEY), wrappedKey);
    }

    public boolean dataKeysExist(String storeId) {
        return keyStorage.exists(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY)) && keyStorage.exists(getStorageField(storeId, WRAPPED_SIGNING_KEY));
    }

    public E getEditor(String storeId, ReWrap reWrap) {
        throw new UnsupportedOperationException("No editor available for this KeyManager");
    }

    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        eraseKeys(keyAlias);
        configStorage.delete(getStorageField(keyAlias, KEY_PROTECTION));
    }

    public void eraseKeys(String keyAlias) throws GeneralSecurityException, IOException {
        keyStorage.delete(getStorageField(keyAlias, WRAPPED_ENCRYPTION_KEY));
        keyStorage.delete(getStorageField(keyAlias, WRAPPED_SIGNING_KEY));
    }

    protected byte[] wrapKey(String keyAlias, SecretKey key) throws GeneralSecurityException, IOException {
        checkProtectionSpec(keyAlias);
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        return keyWrap.wrap(getKek(keyAlias), key, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
    }

    protected SecretKey unwrapKey(String keyAlias, byte[] wrappedKey, String keyType) throws GeneralSecurityException, IOException {
        checkProtectionSpec(keyAlias);
        if (!isUnlocked()) {
            throw new LoginException("KeyWrapper not unlocked");
        }
        return keyWrap.unwrap(getKdk(keyAlias), wrappedKey, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm(), keyType);
    }

    protected abstract Key getKek(String keyAlias) throws GeneralSecurityException, IOException;
    protected abstract Key getKdk(String keyAlias) throws GeneralSecurityException, IOException;

    private void checkProtectionSpec(String storeId) throws IOException {
        if (configStorage.exists(getStorageField(storeId, KEY_PROTECTION))) {
            // TODO migrate on mismatch
            String storedStrategy = Encoding.utf8Encode(configStorage.load(getStorageField(storeId, KEY_PROTECTION)));
            String strategy = keyProtectionSpec.toString();
            if (!strategy.equals(storedStrategy)) {
                throw new IllegalArgumentException("Wrong key protection strategy (expected " + storedStrategy + " but was " + strategy);
            }
        } else {
            configStorage.store(getStorageField(storeId, KEY_PROTECTION), utf8Decode(keyProtectionSpec.toString()));
        }
    }

    static String getStorageField(String storeId, String field) {
        return storeId + DELIMITER + field;
    }

    public class Editor {
    }
}
