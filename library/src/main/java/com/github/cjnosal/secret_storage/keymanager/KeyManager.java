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
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class KeyManager {

    private final ProtectionStrategy dataProtectionStrategy;
    private final Crypto crypto;
    private final DataStorage keyStorage;
    private KeyWrapper keyWrapper;
    private final String storeId;

    public KeyManager(String storeId, ProtectionStrategy dataProtectionStrategy, Crypto crypto, DataStorage keyStorage, KeyWrapper keyWrapper) throws GeneralSecurityException, IOException {
        this.storeId = storeId;
        this.dataProtectionStrategy = dataProtectionStrategy;
        this.crypto = crypto;
        this.keyStorage = keyStorage;
        this.keyWrapper = keyWrapper;
        PRNGFixes.apply();

        if (dataProtectionStrategy.getCipherStrategy() instanceof AsymmetricCipherStrategy) {
            throw new IllegalArgumentException("Must provide SymmetricCipherStrategy for data secrecy");
        }
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof SignatureStrategy) {
            throw new IllegalArgumentException("Must provide MacStrategy for data integrity");
        }

        keyWrapper.attach();
    }

    public KeyWrapper getKeyWrapper() {
        return keyWrapper;
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy Key encryptionKey;
        @KeyPurpose.DataIntegrity Key signingKey;
        if (dataKeysExist()) {
            encryptionKey = loadDataEncryptionKey();
            signingKey = loadDataSigningKey();
        }
        else {
            encryptionKey = generateDataEncryptionKey();
            signingKey = generateDataSigningKey();
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        }
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        @KeyPurpose.DataSecrecy Key decryptionKey = loadDataEncryptionKey();
        @KeyPurpose.DataIntegrity Key verificationKey = loadDataSigningKey();
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, cipherText);
    }

    public void rewrap(KeyWrapper newWrapper) throws GeneralSecurityException, IOException {
        if (dataKeysExist()) {
            @KeyPurpose.DataSecrecy Key encryptionKey = loadDataEncryptionKey();
            @KeyPurpose.DataIntegrity Key signingKey = loadDataSigningKey();
            keyWrapper.clear();
            keyWrapper = newWrapper;
            keyWrapper.attach();
            storeDataEncryptionKey(encryptionKey);
            storeDataSigningKey(signingKey);
        } else {
            keyWrapper = newWrapper;
            keyWrapper.attach();
        }
    }

    private @KeyPurpose.DataSecrecy Key generateDataEncryptionKey() throws GeneralSecurityException, IOException {
        CipherSpec spec = dataProtectionStrategy.getCipherStrategy().getSpec();
        return crypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeySize());
    }

    private @KeyPurpose.DataIntegrity Key generateDataSigningKey() throws GeneralSecurityException, IOException {
        IntegritySpec spec = dataProtectionStrategy.getIntegrityStrategy().getSpec();
        return crypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeySize());
    }

    private @KeyPurpose.DataSecrecy Key loadDataEncryptionKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(storeId + ":DS");
        return keyWrapper.unwrap(wrappedKey);
    }

    private @KeyPurpose.DataIntegrity Key loadDataSigningKey() throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyStorage.load(storeId + ":DI");
        return keyWrapper.unwrap(wrappedKey);
    }

    private void storeDataEncryptionKey(@KeyPurpose.DataSecrecy Key key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyWrapper.wrap(key);
        keyStorage.store(storeId + ":DS", wrappedKey);
    }

    private void storeDataSigningKey(@KeyPurpose.DataIntegrity Key key) throws GeneralSecurityException, IOException {
        byte[] wrappedKey = keyWrapper.wrap(key);
        keyStorage.store(storeId + ":DI", wrappedKey);
    }

    private boolean dataKeysExist() throws GeneralSecurityException, IOException {
        return keyStorage.exists(storeId + ":DS") && keyStorage.exists(storeId + ":DI");
    }


}
