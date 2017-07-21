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

import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapperInitializer;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.strategy.DataProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.crypto.SecretKey;

public class SecretStorage {

    private final @Nullable DataStorage dataStorage;
    private final DataProtectionSpec dataProtectionSpec;
    private final DataKeyGenerator dataKeyGenerator;
    private final ProtectionStrategy dataProtectionStrategy;
    private KeyWrapper keyWrapper;

    public SecretStorage(@Nullable DataStorage dataStorage, DataProtectionSpec dataProtectionSpec, KeyWrapper keyWrapper) {
        this.dataStorage = dataStorage;
        this.dataProtectionSpec = dataProtectionSpec;
        this.dataKeyGenerator = new DataKeyGenerator();
        this.dataProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();
    }

    public void store(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        if (dataStorage == null) {
            throw new UnsupportedOperationException("SecretStorage was not configured with data storage");
        }
        byte[] cipherText = encrypt(plainText);
        dataStorage.store(id, cipherText);
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
        if (dataStorage == null) {
            throw new UnsupportedOperationException("SecretStorage was not configured with data storage");
        }
        byte[] cipherText = dataStorage.load(id);
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

    public boolean exists(String id) {
        if (dataStorage == null) {
            return false;
        }
        return dataStorage.exists(id);
    }

    public void delete(String id) throws IOException {
        if (dataStorage == null) {
            throw new UnsupportedOperationException("SecretStorage was not configured with data storage");
        }
        dataStorage.delete(id);
    }

    public @Result int deleteValue(String id) {
        try {
            delete(id);
            return Success;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        }
    }

    // erase encrypted data and wrapped keys
    public void clear() throws IOException, GeneralSecurityException {
        if (dataStorage != null) {
            dataStorage.clear();
        }
        keyWrapper.eraseDataKeys();
    }

    // erase encrypted data and wrapped keys
    public @Result int clearValues() {
        try {
            clear();
            return Success;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return SecurityError;
        }
    }

    // erase encrypted data, wrapped keys, configuration, keystore values
    public void reset() throws IOException, GeneralSecurityException {
        clear();
        keyWrapper.eraseConfig();
        keyWrapper.eraseDataKeys();
    }

    // erase encrypted data, wrapped keys, configuration, keystore values
    public @Result int resetValues() {
        try {
            reset();
            return Success;
        } catch (IOException e) {
            e.printStackTrace();
            return IoError;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return SecurityError;
        }
    }

    // decrypt and copy all data to another SecretStorage instance
    public void copyTo(SecretStorage other) throws GeneralSecurityException, IOException {
        if (dataStorage == null) {
            throw new UnsupportedOperationException("SecretStorage was not configured with data storage");
        }
        Set<String> entries = dataStorage.entries();
        for (String s : entries) {
            other.store(s, load(s));
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
        if (keyWrapper.dataKeysExist()) {
            @KeyPurpose.DataSecrecy SecretKey encryptionKey = keyWrapper.loadDataEncryptionKey(dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm());
            @KeyPurpose.DataIntegrity SecretKey signingKey = keyWrapper.loadDataSigningKey(dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm());
            keyWrapper = initializer.initKeyWrapper();
            keyWrapper.storeDataEncryptionKey(encryptionKey);
            keyWrapper.storeDataSigningKey(signingKey);
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
        return (E) keyWrapper.getEditor();
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey encryptionKey = prepareDataEncryptionKey();
        @KeyPurpose.DataIntegrity SecretKey signingKey = prepareDataSigningKey();
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, dataProtectionSpec, plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey decryptionKey = prepareDataEncryptionKey();
        @KeyPurpose.DataIntegrity SecretKey verificationKey = prepareDataSigningKey();
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, dataProtectionSpec, cipherText);
    }

    public @Nullable byte[] encryptValue(byte[] plainText) {
        try {
            return encrypt(plainText);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public @Nullable byte[] decryptValue(byte[] cipherText) {
        try {
            return decrypt(cipherText);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SecretKey prepareDataEncryptionKey() throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy SecretKey encryptionKey;
        if (keyWrapper.dataKeysExist()) {
            encryptionKey = keyWrapper.loadDataEncryptionKey(dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm());
        } else {
            encryptionKey = generateDataEncryptionKey();
            keyWrapper.storeDataEncryptionKey(encryptionKey);
        }
        return encryptionKey;
    }

    private SecretKey prepareDataSigningKey() throws GeneralSecurityException, IOException {
        @KeyPurpose.DataIntegrity SecretKey signingKey;
        if (keyWrapper.dataKeysExist()) {
            signingKey = keyWrapper.loadDataSigningKey(dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm());
        } else {
            signingKey = generateDataSigningKey();
            keyWrapper.storeDataSigningKey(signingKey);
        }
        return signingKey;
    }

    private SecretKey generateDataEncryptionKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getCipherKeyGenSpec().getKeygenAlgorithm(), dataProtectionSpec.getCipherKeyGenSpec().getKeySize());
    }

    private SecretKey generateDataSigningKey() throws GeneralSecurityException {
        return dataKeyGenerator.generateDataKey(dataProtectionSpec.getIntegrityKeyGenSpec().getKeygenAlgorithm(), dataProtectionSpec.getIntegrityKeyGenSpec().getKeySize());
    }

    public static class Builder {
        private DataStorage dataStorage;
        private DataProtectionSpec dataProtectionSpec;
        private KeyWrapper keyWrapper;

        public Builder() {
        }

        public Builder dataStorage(DataStorage dataStorage) {
            this.dataStorage = dataStorage;
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
            return new SecretStorage(dataStorage, dataProtectionSpec, keyWrapper);
        }

        private void validateArguments() {
            if (keyWrapper == null) {
                throw new IllegalArgumentException("KeyWrapper required");
            }
            if (dataProtectionSpec == null) {
                throw new IllegalArgumentException("DataProtectionSpec required");
            }
        }
    }

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
