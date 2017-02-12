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
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;

public class PasswordKeyWrapper extends KeyWrapper {

    private static final String ENC_SALT = "ENC_SALT";
    private static final String SIG_SALT = "SIG_SALT";
    private static final String VER_SALT = "VER_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    protected final Crypto crypto;
    protected final String storeId;
    protected final KeyDerivationSpec derivationSpec;
    protected final ProtectionStrategy keyProtectionStrategy;
    protected final DataStorage configStorage;
    protected final KeyEncoding keyEncoding = new KeyEncoding();

    protected Key derivedEncKey;
    protected Key derivedSigKey;
    protected byte[] verification;
    private String password;
    private boolean attached;

    public PasswordKeyWrapper(Crypto crypto, String storeId, KeyDerivationSpec derivationSpec, ProtectionStrategy keyProtectionStrategy, DataStorage configStorage) throws GeneralSecurityException, IOException {
        this.crypto = crypto;
        this.storeId = storeId;
        this.derivationSpec = derivationSpec;
        this.keyProtectionStrategy = keyProtectionStrategy;
        this.configStorage = configStorage;

        if (keyProtectionStrategy.getCipherStrategy() instanceof AsymmetricCipherStrategy ||
                keyProtectionStrategy.getIntegrityStrategy() instanceof SignatureStrategy) {
            throw new IllegalArgumentException("PasswordKeyWrapper needs symmetric strategy for key protection");
        }
    }

    @Override
    public void attach() throws IOException, GeneralSecurityException {
        attached = true;
        if (password != null) {
            if (!isPasswordSet()) {
                deriveAndStoreKeys(password);
            } else {
                unlock(password);
            }
        }
    }

    public void setPassword(String password) throws IOException, GeneralSecurityException {
        this.password = password;
        if (attached) {
            if (password != null) {
                if (!isPasswordSet()) {
                    deriveAndStoreKeys(password);
                } else {
                    unlock(password);
                }
            }
        }
    }

    protected void deriveAndStoreKeys(String password) throws IOException, GeneralSecurityException {
        byte[] encSalt = generateSalt();
        byte[] sigSalt = generateSalt();
        byte[] verSalt = generateSalt();
        derivedEncKey = generateKek(password, encSalt);
        derivedSigKey = generateKek(password, sigSalt);
        verification = generateKek(password, verSalt).getEncoded();

        configStorage.store(storeId + ":" + VERIFICATION, verification);
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

    public void lock() {
        derivedEncKey = null;
        derivedSigKey = null;
    }

    public boolean isUnlocked() {
        return derivedEncKey != null && derivedSigKey != null;
    }

    @Override
    public byte[] wrap(@KeyPurpose.Data Key key) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return keyProtectionStrategy.encryptAndSign(derivedEncKey, derivedSigKey, keyEncoding.encodeKey(key));
    }

    @Override
    public @KeyPurpose.Data Key unwrap(byte[] wrappedKey) throws GeneralSecurityException, IOException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(derivedEncKey, derivedSigKey, wrappedKey));
    }

    @Override
    public void clear() throws GeneralSecurityException, IOException {
        configStorage.delete(storeId + ":" + VERIFICATION);
        configStorage.delete(storeId + ":" + ENC_SALT);
        configStorage.delete(storeId + ":" + SIG_SALT);
        configStorage.delete(storeId + ":" + VER_SALT);
    }

    protected byte[] generateSalt() {
        return crypto.generateBytes(derivationSpec.getKeySize() / 8);
    }

    protected Key generateKek(String password, byte[] salt) throws IOException, GeneralSecurityException {
        Key tmp = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, salt, derivationSpec.getRounds());
        return new SecretKeySpec(tmp.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());
    }

    public boolean verifyPassword(String password) throws IOException, GeneralSecurityException {
        if (configStorage.entries().isEmpty()) {
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
}
