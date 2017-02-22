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

import android.support.annotation.NonNull;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.login.LoginException;

public class PasswordKeyWrapper extends KeyWrapper {

    private static final String ENC_SALT = "ENC_SALT";
    private static final String SIG_SALT = "SIG_SALT";
    private static final String VER_SALT = "VER_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    protected final SecureRandom secureRandom;
    protected final KeyDerivationSpec derivationSpec;
    protected final ProtectionStrategy keyProtectionStrategy;
    protected final DataStorage configStorage;
    protected final KeyEncoding keyEncoding = new KeyEncoding();

    protected Key derivedEncKey;
    protected Key derivedSigKey;
    protected byte[] verification;

    public PasswordKeyWrapper(KeyDerivationSpec derivationSpec, ProtectionSpec keyProtectionSpec, DataStorage configStorage) {
        super(keyProtectionSpec);
        this.secureRandom = new SecureRandom();
        this.derivationSpec = derivationSpec;
        this.keyProtectionStrategy = new ProtectionStrategy(new SymmetricCipherStrategy(), new MacStrategy());
        this.configStorage = configStorage;
    }

    @Override
    String getWrapAlgorithm() {
        return SecurityAlgorithms.Cipher_AESWRAP;
    }

    @Override
    String getWrapParamAlgorithm() {
        return SecurityAlgorithms.AlgorithmParameters_AES;
    }

    public Key getKek() throws LoginException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return derivedEncKey;
    }

    @Override
    Key getKdk() throws IOException, GeneralSecurityException {
        return getKek();
    }

    public void setPassword(@NonNull String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            deriveAndStoreKeys(password);
        } else {
            throw new LoginException("Password already set. Use unlock.");
        }
    }

    public void changePassword(@NonNull String oldPassword, @NonNull String newPassword) throws GeneralSecurityException, IOException {
        if (verifyPassword(oldPassword)) {
            clear();
            setPassword(newPassword);
        } else {
            throw new LoginException("Wrong password");
        }
    }

    protected void deriveAndStoreKeys(String password) throws IOException, GeneralSecurityException {
        byte[] encSalt = generateSalt();
        byte[] sigSalt = generateSalt();
        byte[] verSalt = generateSalt();
        derivedEncKey = generateKek(password, encSalt);
        derivedSigKey = generateKek(password, sigSalt);
        verification = generateKek(password, verSalt).getEncoded();

        configStorage.store(getStorageField(storeId, VERIFICATION), verification);
        configStorage.store(getStorageField(storeId, ENC_SALT), encSalt);
        configStorage.store(getStorageField(storeId, SIG_SALT), sigSalt);
        configStorage.store(getStorageField(storeId, VER_SALT), verSalt);
    }

    public void unlock(String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new LoginException("No password set. Use setPassword.");
        }
        if (!verifyPassword(password)) {
            throw new LoginException("Wrong password");
        }
        byte[] encSalt = configStorage.load(getStorageField(storeId, ENC_SALT));
        byte[] sigSalt = configStorage.load(getStorageField(storeId, SIG_SALT));
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
    public void clear() throws GeneralSecurityException, IOException {
        configStorage.delete(getStorageField(storeId, VERIFICATION));
        configStorage.delete(getStorageField(storeId, ENC_SALT));
        configStorage.delete(getStorageField(storeId, SIG_SALT));
        configStorage.delete(getStorageField(storeId, VER_SALT));
    }

    protected byte[] generateSalt() {
        byte[] random = new byte[derivationSpec.getKeySize() / 8];
        secureRandom.nextBytes(random);
        return random;
    }

    protected Key generateKek(String password, byte[] salt) throws IOException, GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, derivationSpec.getRounds(), derivationSpec.getKeySize());
        return factory.generateSecret(spec);
    }

    public boolean verifyPassword(String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] verSalt = configStorage.load(getStorageField(storeId, VER_SALT));
        byte[] verification = configStorage.load(getStorageField(storeId, VERIFICATION));
        Key key = generateKek(password, verSalt);
        return MessageDigest.isEqual(key.getEncoded(), verification);
    }

    public boolean isPasswordSet() throws IOException {
        return configStorage.exists(getStorageField(storeId, VER_SALT)) && configStorage.exists(getStorageField(storeId, VERIFICATION));
    }
}
