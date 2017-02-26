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
import com.github.cjnosal.secret_storage.keymanager.AsymmetricKeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
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
    private static final String DELIMITER = "::";

    private final String storeId;
    private final DataStorage dataStorage;
    private final DataStorage configStorage;
    private final ProtectionSpec dataProtectionSpec;
    private final DataKeyGenerator dataKeyGenerator;
    private final ProtectionStrategy dataProtectionStrategy;
    private KeyWrapper keyWrapper;

    public SecretStorage(String storeId, DataStorage dataStorage, DataStorage configStorage, ProtectionSpec dataProtectionSpec, KeyWrapper keyWrapper) {
        this.storeId = storeId;
        this.dataStorage = dataStorage;
        this.configStorage = configStorage;
        this.dataProtectionSpec = dataProtectionSpec;
        this.dataKeyGenerator = new DataKeyGenerator();
        this.dataProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();
    }

    public void store(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        checkProtectionSpec();
        byte[] cipherText = encrypt(plainText);
        dataStorage.store(getStorageField(storeId, id), cipherText);
    }

    public byte[] load(String id) throws GeneralSecurityException, IOException {
        checkProtectionSpec();
        byte[] cipherText = dataStorage.load(getStorageField(storeId, id));
        return decrypt(cipherText);
    }

    // decrypt and copy all data to another SecretStorage instance
    public void copyTo(SecretStorage other) throws GeneralSecurityException, IOException {
        checkProtectionSpec();
        Set<String> entries = dataStorage.entries();
        for (String s : entries) {
            String key = getField(s);
            other.store(key, load(key));
        }
    }

    // decrypt and copy data encryption keys to another KeyManager instance
    public void rewrap(KeyWrapper other) throws IOException, GeneralSecurityException {
        checkProtectionSpec();
        if (keyWrapper.dataKeysExist(storeId)) {
            @KeyPurpose.DataSecrecy SecretKey encryptionKey = keyWrapper.loadDataEncryptionKey(storeId, dataProtectionSpec.getCipherSpec().getKeygenAlgorithm());
            @KeyPurpose.DataIntegrity SecretKey signingKey = keyWrapper.loadDataSigningKey(storeId, dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm());
            keyWrapper.eraseConfig(storeId);
            keyWrapper = other;
            keyWrapper.storeDataEncryptionKey(storeId, encryptionKey);
            keyWrapper.storeDataSigningKey(storeId, signingKey);
        } else {
            keyWrapper.eraseConfig(storeId);
            keyWrapper = other;
        }
    }

    public <E extends KeyWrapper.Editor> E getEditor() {
        return keyWrapper.getEditor(storeId, dataProtectionSpec.getCipherSpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm());
    }

    private void checkProtectionSpec() throws IOException {
        if (configStorage.exists(getStorageField(storeId, DATA_PROTECTION))) {
            String storedStrategy = Encoding.utf8Encode(configStorage.load(getStorageField(storeId, DATA_PROTECTION)));
            String strategy = dataProtectionSpec.toString();
            if (!strategy.equals(storedStrategy)) {
                throw new IllegalArgumentException("Wrong data protection strategy (expected " + storedStrategy + " but was " + strategy);
            }
        } else {
            configStorage.store(getStorageField(storeId, DATA_PROTECTION), utf8Decode(dataProtectionSpec.toString()));
        }
    }

    private byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey encryptionKey;
        @KeyPurpose.DataIntegrity SecretKey signingKey;
        if (keyWrapper.dataKeysExist(storeId)) {
            encryptionKey = keyWrapper.loadDataEncryptionKey(storeId, dataProtectionSpec.getCipherSpec().getKeygenAlgorithm());
            signingKey = keyWrapper.loadDataSigningKey(storeId, dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm());
        } else {
            encryptionKey = generateDataEncryptionKey();
            signingKey = generateDataSigningKey();
            keyWrapper.storeDataEncryptionKey(storeId, encryptionKey);
            keyWrapper.storeDataSigningKey(storeId, signingKey);
        }
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, dataProtectionSpec, plainText);
    }

    private byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey decryptionKey = keyWrapper.loadDataEncryptionKey(storeId, dataProtectionSpec.getCipherSpec().getKeygenAlgorithm());
        @KeyPurpose.DataIntegrity SecretKey verificationKey = keyWrapper.loadDataSigningKey(storeId, dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm());
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, dataProtectionSpec, cipherText);
    }

    private SecretKey generateDataEncryptionKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getCipherSpec().getKeygenAlgorithm(), dataProtectionSpec.getCipherSpec().getKeySize());
    }

    private SecretKey generateDataSigningKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getIntegritySpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegritySpec().getKeySize());
    }

    private static String getStorageField(String storeId, String field) {
        return storeId + DELIMITER + field;
    }

    private static String getField(String storageField) {
        return storageField.substring(storageField.indexOf(DELIMITER) + DELIMITER.length());
    }

    public static class Builder {
        // SecretStorage constructor params
        private String storeId;
        private DataStorage dataStorage;
        private DataStorage configStorage;
        private ProtectionSpec dataProtectionSpec;
        private KeyWrapper keyWrapper;

        // Used for choosing defaults
        private final Context context;
        private DataStorage keyStorage;
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

        public Builder keyWrapper(KeyWrapper keyWrapper) {
            this.keyWrapper = keyWrapper;
            return this;
        }

        public Builder withUserPassword(boolean withUserPassword) {
            this.withUserPassword = withUserPassword;
            return this;
        }

        public Builder dataProtectionSpec(ProtectionSpec dataProtectionSpec) {
            this.dataProtectionSpec = dataProtectionSpec;
            return this;
        }

        public SecretStorage build() throws IOException {
            validateArguments();
            return new SecretStorage(storeId, dataStorage, configStorage, dataProtectionSpec, keyWrapper);
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
            int osVersion; // OS Version when store was created // TODO migrations
            if (configStorage.exists(getStorageField(storeId, OS_VERSION))) {
                osVersion = DataEncoding.decodeInt(configStorage.load(getStorageField(storeId, OS_VERSION)));
            } else {
                osVersion = Build.VERSION.SDK_INT;
                configStorage.store(getStorageField(storeId, OS_VERSION), DataEncoding.encode(osVersion));
            }
            if (dataProtectionSpec == null) {
                dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(osVersion);
            }
            if (keyWrapper == null) {
                keyWrapper = selectKeyWrapper(osVersion);
            }

        }

        private KeyWrapper selectKeyWrapper(int osVersion) {
            return SecretStorage.selectKeyWrapper(context, osVersion, withUserPassword, configStorage, keyStorage);
        }

        private DataStorage createStorage(@DataStorage.Type String type) {
            return DefaultStorage.createStorage(context, storeId, type);
        }
    }

    static KeyWrapper selectKeyWrapper(Context context, int osVersion, boolean withUserPassword, DataStorage configStorage, DataStorage keyStorage) {
        if (withUserPassword) {
            if (osVersion >= Build.VERSION_CODES.M) {
                return new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.getStrongPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordDeviceBindingSpec(context),
                        DefaultSpecs.getStrongPasswordBasedKeyProtectionSpec(),
                        configStorage,
                        keyStorage
                );
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2 && context != null) {
                return new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordDeviceBindingSpec(context),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec(),
                        configStorage,
                        keyStorage
                );
            } else {
                return new PasswordKeyWrapper(
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec(),
                        configStorage,
                        keyStorage
                );
            }
        } else {
            if (osVersion >= Build.VERSION_CODES.M) {
                return new KeyStoreWrapper(
                        DefaultSpecs.getKeyStoreCipherSpec(),
                        configStorage,
                        keyStorage
                );
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                return new AsymmetricKeyStoreWrapper(
                        DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context),
                        configStorage,
                        keyStorage
                );
            } else {
                return new ObfuscationKeyWrapper(
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec(),
                        configStorage,
                        keyStorage
                );
            }
        }
    }
}
