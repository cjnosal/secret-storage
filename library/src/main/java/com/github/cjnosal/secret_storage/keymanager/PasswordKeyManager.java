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

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;

public class PasswordKeyManager extends KeyManager {

    private static final String ENC_SALT = "ENC_SALT";
    private static final String SIG_SALT = "SIG_SALT";
    private static final String VER_SALT = "VER_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    protected final Crypto crypto;
    protected final KeyDerivationSpec derivationSpec;
    protected final ProtectionStrategy keyProtectionStrategy;
    protected final DataStorage keyStorage;
    protected final DataStorage configStorage;
    protected final KeyEncoding keyEncoding = new KeyEncoding();

    protected Key derivedEncKey;
    protected Key derivedSigKey;

    public PasswordKeyManager(Crypto crypto, String storeId, ProtectionStrategy dataProtectionStrategy, KeyDerivationSpec derivationSpec, ProtectionStrategy keyProtectionStrategy, DataStorage keyStorage, DataStorage configStorage) throws GeneralSecurityException, IOException {
        super(storeId, dataProtectionStrategy);
        this.crypto = crypto;
        this.derivationSpec = derivationSpec;
        this.keyProtectionStrategy = keyProtectionStrategy;
        this.keyStorage = keyStorage;
        this.configStorage = configStorage;

        if (keyProtectionStrategy.getCipherStrategy() instanceof AsymmetricCipherStrategy ||
                keyProtectionStrategy.getIntegrityStrategy() instanceof SignatureStrategy) {
            throw new IllegalArgumentException("PasswordKeyManager needs symmetric strategy for key protection");
        }
    }

    public void setPassword(String password) throws IOException, GeneralSecurityException {
        if (isPasswordSet()) {
            throw new LoginException("Password already set. Use unlock or changePassword.");
        }
        deriveAndStoreKeys(password);
    }

    protected void deriveAndStoreKeys(String password) throws IOException, GeneralSecurityException {
        byte[] encSalt = generateSalt();
        byte[] sigSalt = generateSalt();
        byte[] verSalt = generateSalt();
        derivedEncKey = generateKek(password, encSalt);
        derivedSigKey = generateKek(password, sigSalt);

        configStorage.store(storeId + ":" + VERIFICATION, generateKek(password, verSalt).getEncoded());
        configStorage.store(storeId + ":" + ENC_SALT, encSalt);
        configStorage.store(storeId + ":" + SIG_SALT, sigSalt);
        configStorage.store(storeId + ":" + VER_SALT, verSalt);
    }

    public void unlock(String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new LoginException("No password set. Use setPassword.");
        }
        if (!verifyPassword(password)) {
            throw new LoginException("Wrong password");
        }
        byte[] encSalt = configStorage.load(storeId + ":" + ENC_SALT);
        byte[] sigSalt = configStorage.load(storeId + ":" + SIG_SALT);
        derivedEncKey = generateKek(password, encSalt);
        derivedSigKey = generateKek(password, sigSalt);
    }

    public void changePassword(String oldPassword, String newPassword) throws IOException, GeneralSecurityException {
        unlock(oldPassword);
        Key encryptionKey = loadEncryptionKey(storeId);
        Key signingKey = loadSigningKey(storeId);
        Key decryptionKey = loadDecryptionKey(storeId);
        Key verificationKey = loadVerificationKey(storeId);

        deriveAndStoreKeys(newPassword);
        wrapAndStoreKey(storeId, encryptionKey, "E");
        wrapAndStoreKey(storeId, decryptionKey, "D");
        wrapAndStoreKey(storeId, signingKey, "S");
        wrapAndStoreKey(storeId, verificationKey, "V");
    }

    public void lock() {
        derivedEncKey = null;
        derivedSigKey = null;
    }

    public boolean isUnlocked() {
        return derivedEncKey != null && derivedSigKey != null;
    }

    @Override
    public Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        return generateEncryptionKey(dataProtectionStrategy.getCipherStrategy(), keyId);
    }

    @Override
    public Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException {
        return generateSigningKey(dataProtectionStrategy.getIntegrityStrategy(), keyId);
    }

    @Override
    protected Key loadEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        return loadAndUnwrapKey(keyId, "E");
    }

    @Override
    protected Key loadSigningKey(String keyId) throws GeneralSecurityException, IOException {
        return loadAndUnwrapKey(keyId, "S");
    }

    @Override
    public Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException {
        return loadAndUnwrapKey(keyId, "D");
    }

    @Override
    public Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException {
        return loadAndUnwrapKey(keyId, "V");
    }

    private Key generateEncryptionKey(CipherStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        CipherSpec cipherSpec = strategy.getSpec();
        if (strategy instanceof SymmetricCipherStrategy) {
            SecretKey encryptionKey = crypto.generateSecretKey(cipherSpec.getKeygenAlgorithm(), cipherSpec.getKeySize());
            wrapAndStoreKey(keyId, encryptionKey, "E");
            wrapAndStoreKey(keyId, encryptionKey, "D");
            return encryptionKey;
        } else {
            KeyPair encryptionKey = crypto.generateKeyPair(cipherSpec.getKeygenAlgorithm(), cipherSpec.getKeySize());
            wrapAndStoreKey(keyId, encryptionKey.getPublic(), "E");
            wrapAndStoreKey(keyId, encryptionKey.getPrivate(), "D");
            return encryptionKey.getPublic();
        }
    }

    private void wrapAndStoreKey(String keyId, Key key, String suffix) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        byte[] wrappedDecKey = keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(key));
        keyStorage.store(keyId + ":" + suffix, wrappedDecKey);
    }

    private Key loadAndUnwrapKey(String keyId, String suffix) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        byte[] wrappedVerKey = keyStorage.load(keyId + ":" + suffix);
        return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(derivedEncKey, derivedSigKey, wrappedVerKey));
    }

    private Key generateSigningKey(IntegrityStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        IntegritySpec integritySpec = strategy.getSpec();
        if (strategy instanceof MacStrategy) {
            SecretKey signingKey = crypto.generateSecretKey(integritySpec.getKeygenAlgorithm(), integritySpec.getKeySize());
            wrapAndStoreKey(keyId, signingKey, "S");
            wrapAndStoreKey(keyId, signingKey, "V");
            return signingKey;
        } else {
            KeyPair signingKey = crypto.generateKeyPair(integritySpec.getKeygenAlgorithm(), integritySpec.getKeySize());
            wrapAndStoreKey(keyId, signingKey.getPrivate(), "S");
            wrapAndStoreKey(keyId, signingKey.getPublic(), "V");
            return signingKey.getPrivate();
        }
    }

    protected byte[] generateSalt() {
        return crypto.generateBytes(derivationSpec.getKeySize() / 8);
    }

    protected Key generateKek(String password, byte[] salt) throws IOException, GeneralSecurityException {
        Key tmp = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, salt, derivationSpec.getRounds());
        return new SecretKeySpec(tmp.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());
    }

    public boolean verifyPassword(String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] verSalt = configStorage.load(storeId + ":" + VER_SALT);
        byte[] verification = configStorage.load(storeId + ":" + VERIFICATION);
        Key key = generateKek(password, verSalt);
        return MessageDigest.isEqual(key.getEncoded(), verification);
    }

    public boolean isPasswordSet() throws IOException {
        return configStorage.exists(storeId + ":" + VER_SALT) && configStorage.exists(storeId + ":" + VERIFICATION);
    }

    @Override
    protected boolean keysExist(String keyId) throws GeneralSecurityException, IOException {
        return keyStorage.exists(keyId + ":" + "E") && keyStorage.exists(keyId + ":" + "D") && keyStorage.exists(keyId + ":" + "S") && keyStorage.exists(keyId + ":" + "V");
    }
}
