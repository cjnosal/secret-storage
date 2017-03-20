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
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.AsymmetricKeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapperInitializer;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.DataProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.defaults.DefaultStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.crypto.SecretKey;

import static com.github.cjnosal.secret_storage.storage.encoding.Encoding.utf8Decode;

public class SecretStorage {

    // config storage
    private static final String OS_VERSION = "OS_VERSION";
    private static final String KEY_WRAPPER_TYPE = "KEY_WRAPPER_TYPE";
    private static final String SCHEMA_VERSION = "SCHEMA_VERSION";
    private static final String DATA_PROTECTION = "DATA_PROTECTION";
    private static final String DELIMITER = "::";

    private final String storeId;
    private final DataStorage dataStorage;
    private final DataStorage configStorage;
    private final DataProtectionSpec dataProtectionSpec;
    private final DataKeyGenerator dataKeyGenerator;
    private final ProtectionStrategy dataProtectionStrategy;
    private KeyWrapper keyWrapper;

    public SecretStorage(String storeId, DataStorage dataStorage, DataStorage configStorage, DataProtectionSpec dataProtectionSpec, KeyWrapper keyWrapper) {
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

    public @Result int storeValue(String id, byte[] plainText) {
        try {
            store(id, plainText);
            return Success;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return SecurityError;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        }
    }

    public @NonNull byte[] load(String id) throws GeneralSecurityException, IOException {
        checkProtectionSpec();
        byte[] cipherText = dataStorage.load(getStorageField(storeId, id));
        return decrypt(cipherText);
    }

    public @Nullable byte[] loadValue(String id) {
        try {
            return load(id);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
        return null;
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

    // decrypt and copy all data to another SecretStorage instance
    public @Result int copyValuesTo(SecretStorage other) {
        try {
            copyTo(other);
            return Success;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return SecurityError;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        }
    }

    // decrypt and copy data encryption keys to another KeyManager instance
    public void rewrap(KeyWrapperInitializer initializer) throws IOException, GeneralSecurityException {
        checkProtectionSpec();
        if (keyWrapper.dataKeysExist(storeId)) {
            @KeyPurpose.DataSecrecy SecretKey encryptionKey = keyWrapper.loadDataEncryptionKey(storeId, dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm());
            @KeyPurpose.DataIntegrity SecretKey signingKey = keyWrapper.loadDataSigningKey(storeId, dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm());
            keyWrapper = initializer.initKeyWrapper();
            keyWrapper.storeDataEncryptionKey(storeId, encryptionKey);
            keyWrapper.storeDataSigningKey(storeId, signingKey);
        } else {
            keyWrapper = initializer.initKeyWrapper();
        }
    }

    public @Result int rewrapValues(KeyWrapperInitializer initializer) {
        try {
            rewrap(initializer);
            return Success;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return SecurityError;
        }
    }

    public <E extends KeyWrapper.Editor> E getEditor() {
        return (E) keyWrapper.getEditor(storeId);
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
        @KeyPurpose.DataSecrecy SecretKey encryptionKey = prepareDataEncryptionKey();
        @KeyPurpose.DataIntegrity SecretKey signingKey = prepareDataSigningKey();
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, dataProtectionSpec, plainText);
    }

    private byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey decryptionKey = prepareDataEncryptionKey();
        @KeyPurpose.DataIntegrity SecretKey verificationKey = prepareDataSigningKey();
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, dataProtectionSpec, cipherText);
    }

    private SecretKey prepareDataEncryptionKey() throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey encryptionKey;
        if (keyWrapper.dataKeysExist(storeId)) {
            encryptionKey = keyWrapper.loadDataEncryptionKey(storeId, dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm());
        } else {
            encryptionKey = generateDataEncryptionKey();
            keyWrapper.storeDataEncryptionKey(storeId, encryptionKey);
        }
        return encryptionKey;
    }

    private SecretKey prepareDataSigningKey() throws GeneralSecurityException, IOException {
        @KeyPurpose.DataIntegrity SecretKey signingKey;
        if (keyWrapper.dataKeysExist(storeId)) {
            signingKey = keyWrapper.loadDataSigningKey(storeId, dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm());
        } else {
            signingKey = generateDataSigningKey();
            keyWrapper.storeDataSigningKey(storeId, signingKey);
        }
        return signingKey;
    }

    private SecretKey generateDataEncryptionKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm(), dataProtectionSpec.getCipherKeyGenSpec().getKeySize());
    }

    private SecretKey generateDataSigningKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegrityKeyGenSpec().getKeySize());
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
        private DataProtectionSpec dataProtectionSpec;
        private KeyWrapper keyWrapper;

        // Used for choosing defaults
        private final Context context;
        private DataStorage keyStorage;

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

        public Builder dataProtectionSpec(DataProtectionSpec dataProtectionSpec) {
            this.dataProtectionSpec = dataProtectionSpec;
            return this;
        }

        public SecretStorage build() {
            validateArguments();
            return new SecretStorage(storeId, dataStorage, configStorage, dataProtectionSpec, keyWrapper);
        }

        private void validateArguments() {
            if (context == null) {
                throw new IllegalArgumentException("Non-null Context required");
            }
            if (storeId == null || storeId.isEmpty()) {
                throw new IllegalArgumentException("Non-empty store ID required");
            }
            if (keyWrapper == null) {
                throw new IllegalArgumentException("KeyWrapper required");
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
            if (dataProtectionSpec == null) {
                dataProtectionSpec = DefaultSpecs.getDefaultDataProtectionSpec();
            }
        }

        private DataStorage createStorage(@DataStorage.Type String type) {
            return DefaultStorage.createStorage(context, storeId, type);
        }
    }

    public static KeyWrapper selectKeyWrapper(Context context, String storeId, DataStorage configStorage, DataStorage keyStorage, boolean withUserPassword) throws IOException {
        int osVersion; // OS Version when store was created
        if (configStorage.exists(getStorageField(storeId, OS_VERSION))) {
            osVersion = DataEncoding.decodeInt(configStorage.load(getStorageField(storeId, OS_VERSION)));
        } else {
            osVersion = Build.VERSION.SDK_INT;
            configStorage.store(getStorageField(storeId, OS_VERSION), DataEncoding.encode(osVersion));
        }

        @KeyWrapperType int wrapperType = 0;
        if (configStorage.exists(getStorageField(storeId, KEY_WRAPPER_TYPE))) {
            wrapperType = DataEncoding.decodeInt(configStorage.load(getStorageField(storeId, KEY_WRAPPER_TYPE)));
        }
        int schema = 0;
        if (configStorage.exists(getStorageField(storeId, SCHEMA_VERSION))) {
            schema = DataEncoding.decodeInt(configStorage.load(getStorageField(storeId, SCHEMA_VERSION)));
        }
        if (wrapperType == 0) {
            // new secret storage: use os version and availability of user password to select a key wrapper type
            wrapperType = SecretStorage.selectKeyWrapper(osVersion, withUserPassword);
            schema = SecretStorage.getCurrentSchema(wrapperType);

            // TODO sign wrapperType/schema to prevent downgrade attacks?
            configStorage.store(getStorageField(storeId, KEY_WRAPPER_TYPE), DataEncoding.encode(wrapperType));
            configStorage.store(getStorageField(storeId, SCHEMA_VERSION), DataEncoding.encode(schema));
        }
        return SecretStorage.instantiateKeyWrapper(context, wrapperType, schema, configStorage, keyStorage);
    }

    static @KeyWrapperType int selectKeyWrapper(int osVersion, boolean withUserPassword) {
        // TODO select based on available algorithms instead of osVersion
        @KeyWrapperType int wrapperType;
        if (withUserPassword) {
            if (osVersion >= Build.VERSION_CODES.M) {
                wrapperType = SignedPassword;
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                wrapperType = SignedPassword;
            } else {
                wrapperType = Password;
            }
        } else {
            if (osVersion >= Build.VERSION_CODES.M) {
                wrapperType = KeyStore;
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                wrapperType = AsymmetricKeyStore;
            } else {
                wrapperType = Obfuscation;
            }
        }
        return wrapperType;
    }

    static int getCurrentSchema(@KeyWrapperType int wrapperType) {
        int schema;
        switch (wrapperType) {
            case SignedPassword:
                schema = 2;
                break;
            default:
                schema = 1;
                break;
        }
        return schema;
    }

    static KeyWrapper instantiateKeyWrapper(Context context, @KeyWrapperType int wrapperType, int schema, DataStorage configStorage, DataStorage keyStorage) throws IOException {

        // instantiate a key wrapper based on selected/stored wrapperType and schema
        if (wrapperType == Obfuscation) {
            if (schema == 1) {
                return new ObfuscationKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage,
                        keyStorage
                );
            }
        } else if (wrapperType == Password) {
            if (schema == 1) {
                return new PasswordKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage,
                        keyStorage
                );
            }
        } else if (wrapperType == SignedPassword) {
            if (schema == 1) {
                return new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getSha256WithRsaSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        DefaultSpecs.getRsa2048KeyGenSpec(),
                        configStorage,
                        keyStorage
                );
            } else if (schema == 2) {
                return new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.get8192RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes256KeyGenSpec(),
                        DefaultSpecs.getSha384WithEcdsaSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        DefaultSpecs.getEc384KeyGenSpec(),
                        configStorage,
                        keyStorage
                );
            }
        } else if (wrapperType == AsymmetricKeyStore) {
            if (schema == 1) {
                return new AsymmetricKeyStoreWrapper(
                        context,
                        DefaultSpecs.getAesWrapSpec(),
                        DefaultSpecs.getAes256KeyGenSpec(),
                        DefaultSpecs.getRsaEcbPkcs1Spec(),
                        DefaultSpecs.getRsa2048KeyGenSpec(),
                        configStorage,
                        keyStorage
                );
            }
        } else if (wrapperType == KeyStore) {
            if (schema == 1) {
                return new KeyStoreWrapper(
                        DefaultSpecs.getAesGcmCipherSpec(),
                        DefaultSpecs.getKeyStoreAes256GcmKeyGenSpec(),
                        configStorage,
                        keyStorage
                );
            }
        }
        throw new IllegalArgumentException("Invalid key wrapper/schema combination (wrapper:" + wrapperType + " schema:" + schema);
    }

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            Obfuscation,
            Password,
            SignedPassword,
            AsymmetricKeyStore,
            KeyStore
    })
    @interface KeyWrapperType {}

    static final int Obfuscation = 1;
    static final int Password = 2;
    static final int SignedPassword = 3;
    static final int AsymmetricKeyStore = 4;
    static final int KeyStore = 5;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            Success,
            IoError,
            SecurityError
    })
    public @interface Result {}

    public static final int Success = 0;
    public static final int IoError = 1;
    public static final int SecurityError = 2;
}
