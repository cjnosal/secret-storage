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

import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultManagers;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.defaults.DefaultStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;

import static com.github.cjnosal.secret_storage.storage.encoding.Encoding.utf8Decode;

public class SecretStorage {

    protected Context context;
    protected String storeId;
    protected DataStorage configStorage;
    protected DataStorage dataStorage;
    protected KeyManager keyManager;

    public SecretStorage(Context context, String storeId, DataStorage configStorage, DataStorage dataStorage, KeyManager keyManager) {
        this.context = context;
        this.storeId = storeId;
        this.configStorage = configStorage;
        this.dataStorage = dataStorage;
        this.keyManager = keyManager;
    }

    public void store(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        byte[] cipherText = keyManager.encrypt(plainText);
        dataStorage.store(getStorageField(storeId, id), cipherText);
    }

    public byte[] load(String id) throws GeneralSecurityException, IOException {
        byte[] cipherText = dataStorage.load(getStorageField(storeId, id));
        return keyManager.decrypt(cipherText);
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
        keyManager.copyTo(other);
        keyManager = other;
    }

    public static class Builder {
        protected Context context;
        protected String storeId;
        protected DataStorage configStorage;
        protected DataStorage dataStorage;
        protected KeyManager keyManager;

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

        public Builder keyManager(KeyManager keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        public SecretStorage build() throws IOException, GeneralSecurityException {
            validateArguments();
            return new SecretStorage(context, storeId, configStorage, dataStorage, keyManager);
        }

        protected void validateArguments() throws IOException, GeneralSecurityException {
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
                String strategy = keyManager.getKeyWrapper().getKeyProtectionSpec().toString();
                if (!strategy.equals(storedStrategy)) {
                    throw new IllegalArgumentException("Wrong key protection strategy (expected " + storedStrategy + " but was " + strategy);
                }
            } else {
                configStorage.store(getStorageField(storeId, KEY_PROTECTION), utf8Decode(keyManager.getKeyWrapper().getKeyProtectionSpec().toString()));
            }
        }

        protected KeyManager selectKeyManager(int osVersion) throws GeneralSecurityException, IOException {
            // TODO refactor KeyManager to take storeId as a parameter instead of a field
            return new DefaultManagers().selectKeyManager(context, osVersion, configStorage, createStorage(DataStorage.TYPE_KEYS), storeId);
        }

        protected DataStorage createStorage(@DataStorage.Type String type) {
            return new DefaultStorage().createStorage(context, storeId, type);
        }
    }
  
    private static final String OS_VERSION = "OS_VERSION";
    private static final String DATA_PROTECTION = "DATA_PROTECTION";
    private static final String KEY_PROTECTION = "KEY_PROTECTION";
    private static final String DELIMITER = "::";
    
    private static String getStorageField(String storeId, String field) {
        return storeId + DELIMITER + field;
    }

    private static String getField(String storageField) {
        return storageField.substring(storageField.indexOf(DELIMITER) + DELIMITER.length());
    }
}
