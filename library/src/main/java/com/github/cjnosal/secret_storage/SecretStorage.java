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

package com.github.cjnosal.secret_storage;

import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.defaults.DefaultStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.crypto.SecretKey;

import static com.github.cjnosal.secret_storage.storage.encoding.Encoding.utf8Decode;

public class SecretStorage {

    // config storage
    private static final String OS_VERSION = "OS_VERSION";
    private static final String DATA_PROTECTION = "DATA_PROTECTION";
    private static final String KEY_PROTECTION = "KEY_PROTECTION";

    // key storage
    private static final String WRAPPED_ENCRYPTION_KEY = "WRAPPED_ENCRYPTION_KEY";
    private static final String WRAPPED_SIGNING_KEY = "WRAPPED_SIGNING_KEY";
    private static final String DELIMITER = "::";

    private final String storeId;
    private final DataStorage dataStorage;
    private final DataStorage keyStorage;
    private KeyManager keyManager;

    public SecretStorage(String storeId, DataStorage dataStorage, DataStorage keyStorage, KeyManager keyManager) {
        this.storeId = storeId;
        this.dataStorage = dataStorage;
        this.keyStorage = keyStorage;
        this.keyManager = keyManager;
    }

    public void store(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        byte[] cipherText = encrypt(plainText);
        dataStorage.store(getStorageField(storeId, id), cipherText);
    }

    public byte[] load(String id) throws GeneralSecurityException, IOException {
        byte[] cipherText = dataStorage.load(getStorageField(storeId, id));
        return decrypt(cipherText);
    }

    // decrypt and copy all data to another SecretStorage instance
    public void copyTo(SecretStorage other) throws GeneralSecurityException, IOException {
        Set<String> entries = dataStorage.entries();
        for(String s : entries) {
            String key = getField(s);
            other.store(key, load(key));
        }
    }

    // decrypt and copy data encryption keys to another KeyManager instance
    public void rewrap(KeyManager other) throws IOException, GeneralSecurityException {
        if (!keyManager.getDataProtectionSpec().equals(other.getDataProtectionSpec())) {
            throw new IllegalArgumentException("Incompatible data protection strategy (expected " + keyManager.getDataProtectionSpec() + " but was " + other.getDataProtectionSpec());
        }
        if (dataKeysExist()) {
            @KeyPurpose.DataSecrecy SecretKey encryptionKey = loadDataEncryptionKey();
            @KeyPurpose.DataIntegrity SecretKey signingKey = loadDataSigningKey();
            keyStorage.clear();
            keyManager.clear(storeId);
            keyManager = other;
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        } else {
            keyStorage.clear();
            keyManager.clear(storeId);
            keyManager = other;
        }
    }

    public <E extends KeyManager.Editor> E getEditor() {
        return keyManager.getEditor(new RewrapImpl(), storeId);
    }

    private byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey encryptionKey;
        @KeyPurpose.DataIntegrity SecretKey signingKey;
        if (dataKeysExist()) {
            encryptionKey = loadDataEncryptionKey();
            signingKey = loadDataSigningKey();
        }
        else {
            encryptionKey = keyManager.generateDataEncryptionKey();
            signingKey = keyManager.generateDataSigningKey();
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        }
        return keyManager.encrypt(encryptionKey, signingKey, plainText);
    }

    private byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey decryptionKey = loadDataEncryptionKey();
        @KeyPurpose.DataIntegrity SecretKey verificationKey = loadDataSigningKey();
        return keyManager.decrypt(decryptionKey, verificationKey, cipherText);
    }

    private @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY));
        return keyManager.unwrapKey(storeId, wrappedKey);
    }

    private @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(getStorageField(storeId, WRAPPED_SIGNING_KEY));
        return keyManager.unwrapKey(storeId, wrappedKey);
    }

    private void storeDataEncryptionKey(@KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyManager.wrapKey(storeId, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY), wrappedKey);
    }

    private void storeDataSigningKey(@KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyManager.wrapKey(storeId, key);
        keyStorage.store(getStorageField(storeId, WRAPPED_SIGNING_KEY), wrappedKey);
    }

    private boolean dataKeysExist() {
        return keyStorage.exists(getStorageField(storeId, WRAPPED_ENCRYPTION_KEY)) && keyStorage.exists(getStorageField(storeId, WRAPPED_SIGNING_KEY));
    }

    private static String getStorageField(String storeId, String field) {
        return storeId + DELIMITER + field;
    }

    private static String getField(String storageField) {
        return storageField.substring(storageField.indexOf(DELIMITER) + DELIMITER.length());
    }

    public static class Builder {
        private Context context;
        private String storeId;
        private DataStorage configStorage;
        private DataStorage dataStorage;
        private DataStorage keyStorage;
        private KeyManager keyManager;
        private boolean withUserPassword;

        public Builder(Context context, String storeId) {
            this.context = context;
            this.storeId = storeId;
        }

        public Builder configStorage(DataStorage configStorage) {
            this.configStorage = configStorage;
            return this;
        }

        public Builder dataStorage(DataStorage dataStorage) {
            this.dataStorage = dataStorage;
            return this;
        }

        public Builder keyStorage(DataStorage keyStorage) {
            this.keyStorage = keyStorage;
            return this;
        }

        public Builder keyManager(KeyManager keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        public Builder withUserPassword(boolean withUserPassword) {
            this.withUserPassword = withUserPassword;
            return this;
        }

        public SecretStorage build() throws IOException {
            validateArguments();
            return new SecretStorage(storeId, dataStorage, keyStorage, keyManager);
        }

        private void validateArguments() throws IOException {
            if (context == null) {
                throw new IllegalArgumentException("Non-null Context required");
            }
            if (storeId == null || storeId.isEmpty()) {
                throw new IllegalArgumentException("Non-empty store ID required");
            }
            if (configStorage == null) {
                configStorage = createStorage(DataStorage.TYPE_CONF);
            }
            if (dataStorage == null) {
                dataStorage = createStorage(DataStorage.TYPE_DATA);
            }
            if (keyStorage == null) {
                keyStorage = createStorage(DataStorage.TYPE_KEYS);
            }
            if (keyManager == null) {
                int osVersion; // OS Version when store was created // TODO migrations
                if (configStorage.exists(getStorageField(storeId, OS_VERSION))) {
                    osVersion = DataEncoding.decodeInt(configStorage.load(getStorageField(storeId, OS_VERSION)));
                } else {
                    osVersion = Build.VERSION.SDK_INT;
                    configStorage.store(getStorageField(storeId, OS_VERSION), DataEncoding.encode(osVersion));
                }
                keyManager = selectKeyManager(osVersion);
            }
            if (configStorage.exists(getStorageField(storeId, DATA_PROTECTION))) {
                String storedStrategy = Encoding.utf8Encode(configStorage.load(getStorageField(storeId, DATA_PROTECTION)));
                String strategy = keyManager.getDataProtectionSpec().toString();
                if (!strategy.equals(storedStrategy)) {
                    throw new IllegalArgumentException("Wrong data protection strategy (expected " + storedStrategy + " but was " + strategy);
                }
            } else {
                configStorage.store(getStorageField(storeId, DATA_PROTECTION), utf8Decode(keyManager.getDataProtectionSpec().toString()));
            }
            if (configStorage.exists(getStorageField(storeId, KEY_PROTECTION))) {
                String storedStrategy = Encoding.utf8Encode(configStorage.load(getStorageField(storeId, KEY_PROTECTION)));
                String strategy = keyManager.getWrapAlgorithm();
                if (!strategy.equals(storedStrategy)) {
                    throw new IllegalArgumentException("Wrong key protection strategy (expected " + storedStrategy + " but was " + strategy);
                }
            } else {
                configStorage.store(getStorageField(storeId, KEY_PROTECTION), utf8Decode(keyManager.getWrapAlgorithm()));
            }
        }

        private KeyManager selectKeyManager(int osVersion) {
            return SecretStorage.selectKeyManager(context, osVersion, withUserPassword, configStorage);
        }

        private DataStorage createStorage(@DataStorage.Type String type) {
            return new DefaultStorage().createStorage(context, storeId, type);
        }
    }

    private final class RewrapImpl implements KeyManager.Rewrap {

        private SecretKey encryptionKey;
        private SecretKey signingKey;

        private RewrapImpl() {
        }

        @Override
        public void unwrap() throws GeneralSecurityException, IOException {
            if (dataKeysExist()) {
                encryptionKey = loadDataEncryptionKey();
                signingKey = loadDataSigningKey();
            }
        }

        @Override
        public void rewrap() throws GeneralSecurityException, IOException {
            if (encryptionKey != null && signingKey != null) {
                storeDataEncryptionKey(encryptionKey);
                storeDataSigningKey(signingKey);
                encryptionKey = null;
                signingKey = null;
            }
        }
    }

    static KeyManager selectKeyManager(Context context, int osVersion, boolean withUserPassword, DataStorage configStorage) {
            KeyManager.Builder builder;
            if (withUserPassword) {
                builder = new PasswordProtectedKeyManager.Builder()
                        .defaultKeyWrapper(context, osVersion)
                        .configStorage(configStorage);
            } else {
                if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    builder = new KeyManager.Builder()
                            .defaultKeyWrapper(osVersion);
                } else {
                    builder = new ObfuscationKeyManager.Builder()
                            .configStorage(configStorage);
                }
            }
            return builder
                    .defaultDataProtection(osVersion)
                    .build();
    }
}
