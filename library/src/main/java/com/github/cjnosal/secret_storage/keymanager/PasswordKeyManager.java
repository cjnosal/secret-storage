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
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

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
    private static final String VERIFICATION = "VERIFICATION";

    protected final Crypto crypto;
    protected final KeyDerivationSpec derivationSpec;
    protected final ProtectionStrategy keyProtectionStrategy;
    protected final DataStorage keyStorage;
    protected final DataStorage configStorage;
    protected final KeyEncoding keyEncoding = new KeyEncoding();

    protected Key derivedEncKey;
    protected Key derivedSigKey;

    public PasswordKeyManager(Crypto crypto, ProtectionStrategy dataProtectionStrategy, KeyDerivationSpec derivationSpec, ProtectionStrategy keyProtectionStrategy, DataStorage keyStorage, DataStorage configStorage) throws GeneralSecurityException, IOException {
        super(dataProtectionStrategy);
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

    public void unlock(String password) throws IOException, GeneralSecurityException {
        generateKek(password);
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
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return generateEncryptionKey(dataProtectionStrategy.getCipherStrategy(), keyId);
    }

    @Override
    public Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return generateSigningKey(dataProtectionStrategy.getIntegrityStrategy(), keyId);
    }

    @Override
    public Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        byte[] wrappedDecKey = keyStorage.load(keyId + "E");
        return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(derivedEncKey, derivedSigKey, wrappedDecKey));
    }

    @Override
    public Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        byte[] wrappedVerKey = keyStorage.load(keyId + "S");
        return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(derivedEncKey, derivedSigKey, wrappedVerKey));
    }

    private Key generateEncryptionKey(CipherStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        CipherSpec cipherSpec = strategy.getSpec();
        if (strategy instanceof SymmetricCipherStrategy) {
            SecretKey encryptionKey = crypto.generateSecretKey(cipherSpec.getKeygenAlgorithm(), cipherSpec.getKeySize());
            byte[] wrappedDecKey = keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(encryptionKey));
            keyStorage.store(keyId + "E", wrappedDecKey);
            return encryptionKey;
        } else {
            KeyPair encryptionKey = crypto.generateKeyPair(cipherSpec.getKeygenAlgorithm(), cipherSpec.getKeySize());
            byte[] wrappedDecKey = keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(encryptionKey.getPrivate()));
            keyStorage.store(keyId + "E", wrappedDecKey);
            return encryptionKey.getPublic();
        }
    }

    private Key generateSigningKey(IntegrityStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        IntegritySpec integritySpec = strategy.getSpec();
        if (strategy instanceof MacStrategy) {
            SecretKey signingKey = crypto.generateSecretKey(integritySpec.getKeygenAlgorithm(), integritySpec.getKeySize());
            byte[] wrappedVerKey = keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(signingKey));
            keyStorage.store(keyId + "S", wrappedVerKey);
            return signingKey;
        } else {
            KeyPair signingKey = crypto.generateKeyPair(integritySpec.getKeygenAlgorithm(), integritySpec.getKeySize());
            byte[] wrappedVerKey = keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(signingKey.getPublic()));
            keyStorage.store(keyId + "S", wrappedVerKey);
            return signingKey.getPrivate();
        }
    }

    protected void generateKek(String password) throws IOException, GeneralSecurityException {

        byte[] encSalt;
        byte[] sigSalt;
        byte[] verification = null;

        // TODO explicitly distinguish between creating and unlocking a store instead of automatic recreation
        if (configStorage.exists(ENC_SALT) && configStorage.exists(SIG_SALT) && configStorage.exists(VERIFICATION)) {
            encSalt = configStorage.load(ENC_SALT);
            sigSalt = configStorage.load(SIG_SALT);
            verification = configStorage.load(VERIFICATION);
        } else {
            // TODO bit/byte conveniences
            encSalt = crypto.generateBytes(derivationSpec.getKeySize() / 8);
            sigSalt = crypto.generateBytes(derivationSpec.getKeySize() / 8);
            configStorage.store(ENC_SALT, encSalt);
            configStorage.store(SIG_SALT, sigSalt);
        }
        Key tmp = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, encSalt, derivationSpec.getRounds());
        derivedEncKey = new SecretKeySpec(tmp.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());

        tmp = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, sigSalt, derivationSpec.getRounds());
        derivedSigKey = new SecretKeySpec(tmp.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());

        byte[] checkPassword = generateVerification(derivedEncKey, derivedSigKey, encSalt, sigSalt);
        if (verification == null) {
            configStorage.store(VERIFICATION, checkPassword);
        } else {
            boolean correctPasword = MessageDigest.isEqual(checkPassword, verification);
            if (!correctPasword) {
                throw new LoginException("Wrong password");
            }
        }
    }

    protected byte[] generateVerification(Key enc, Key sig, byte[] encSalt, byte[] sigSalt) throws GeneralSecurityException {
        String keyBytes = Encoding.base64Encode(ByteArrayUtil.join(enc.getEncoded(), sig.getEncoded()));
        byte[]  saltBytes = ByteArrayUtil.join(encSalt, sigSalt);
        Key tmp = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), keyBytes, saltBytes, derivationSpec.getRounds());
        return tmp.getEncoded();
    }
}
