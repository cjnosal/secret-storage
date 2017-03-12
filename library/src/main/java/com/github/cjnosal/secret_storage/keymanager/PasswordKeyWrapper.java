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

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;

public class PasswordKeyWrapper extends BaseKeyWrapper<PasswordKeyWrapper.PasswordEditor> {

    private static final String ENC_SALT = "ENC_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    final SecureRandom secureRandom;

    final KeyDerivationSpec derivationSpec;
    final KeyGenSpec keyGenSpec;
    private Key derivedEncKey;

    public PasswordKeyWrapper(KeyDerivationSpec derivationSpec, KeyGenSpec keyGenSpec, CipherSpec keyProtectionSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyProtectionSpec, configStorage, keyStorage);
        this.derivationSpec = derivationSpec;
        this.keyGenSpec = keyGenSpec;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        super.eraseConfig(keyAlias);
        lock();
        configStorage.delete(getStorageField(keyAlias, VERIFICATION));
        configStorage.delete(getStorageField(keyAlias, ENC_SALT));
    }

    @Override
    public PasswordEditor getEditor(String storeId, ReWrap reWrap) {
        return new PasswordEditor(storeId, reWrap);
    }

    @Override
    protected Key getKek(String keyAlias) throws LoginException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return derivedEncKey;
    }

    @Override
    protected Key getKdk(String keyAlias) throws IOException, GeneralSecurityException {
        return getKek(keyAlias);
    }

    void setPassword(String keyAlias, @NonNull String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            byte[] salt = generateSalt();
            byte[] generated = derive(keyAlias, password, salt);
            byte[] verification = getVerification(generated);

            derivedEncKey = getDerivedEncKey(generated);
            configStorage.store(getStorageField(keyAlias, ENC_SALT), salt);
            configStorage.store(getStorageField(keyAlias, VERIFICATION), verification);
        } else {
            throw new LoginException("Password already set. Use unlock.");
        }
    }

    void unlock(String keyAlias, @NonNull String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(getStorageField(keyAlias, ENC_SALT));
        byte[] verification = configStorage.load(getStorageField(keyAlias, VERIFICATION));

        byte[] generated = derive(keyAlias, password, encSalt);
        if (!MessageDigest.isEqual(verification, getVerification(generated))) {
            throw new LoginException("Wrong password");
        }
        derivedEncKey = getDerivedEncKey(generated);
    }

    boolean isPasswordSet(String keyAlias) {
        return configStorage.exists(getStorageField(keyAlias, ENC_SALT)) && configStorage.exists(getStorageField(keyAlias, VERIFICATION));
    }

    public boolean isUnlocked() {
        return derivedEncKey != null;
    }

    byte[] derive(String keyAlias, String password, byte[] salt) throws GeneralSecurityException, IOException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, derivationSpec.getRounds(), keyGenSpec.getKeySize() * 2);
        return factory.generateSecret(spec).getEncoded();
    }

    private boolean verifyPassword(String keyAlias, String password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet(keyAlias)) {
            throw new LoginException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(getStorageField(keyAlias, ENC_SALT));
        byte[] verification = configStorage.load(getStorageField(keyAlias, VERIFICATION));

        byte[] generated = derive(keyAlias, password, encSalt);
        return MessageDigest.isEqual(getVerification(generated), verification);
    }

    private byte[] generateSalt() {
        byte[] random = new byte[keyGenSpec.getKeySize() / 8];
        secureRandom.nextBytes(random);
        return random;
    }

    private void lock() {
        derivedEncKey = null;
    }

    private Key getDerivedEncKey(byte[] generated) {
        return new SecretKeySpec(generated, keyGenSpec.getKeySize()/8, keyGenSpec.getKeySize()/8, keyGenSpec.getKeygenAlgorithm());
    }

    private byte[] getVerification(byte[] generated) {
        return Arrays.copyOfRange(generated, 0, keyGenSpec.getKeySize()/8);
    }

    public class PasswordEditor extends KeyWrapper.Editor {

        private final String keyAlias;
        private final ReWrap reWrap;

        PasswordEditor(String keyAlias, ReWrap reWrap) {
            this.keyAlias = keyAlias;
            this.reWrap = reWrap;
        }

        public void setPassword(String password) throws IOException, GeneralSecurityException {
            PasswordKeyWrapper.this.setPassword(keyAlias, password);
        }

        public void unlock(String password) throws GeneralSecurityException, IOException {
            PasswordKeyWrapper.this.unlock(keyAlias, password);
        }

        public void lock() {
            PasswordKeyWrapper.this.lock();
        }

        public void changePassword(final @NonNull String oldPassword, final @NonNull String newPassword) throws GeneralSecurityException, IOException {
            PasswordKeyWrapper.this.unlock(keyAlias, oldPassword);
            reWrap.rewrap(new KeyWrapperInitializer() {

                @Override
                public KeyWrapper initKeyWrapper() throws IOException, GeneralSecurityException {
                    PasswordKeyWrapper.this.eraseConfig(keyAlias);
                    PasswordKeyWrapper.this.setPassword(keyAlias, newPassword);
                    return PasswordKeyWrapper.this;
                }
            });
        }

        public boolean verifyPassword(String password) throws IOException, GeneralSecurityException {
            return PasswordKeyWrapper.this.verifyPassword(keyAlias, password);
        }

        public boolean isUnlocked() {
            return PasswordKeyWrapper.this.isUnlocked();
        }

        public boolean isPasswordSet() {
            return PasswordKeyWrapper.this.isPasswordSet(keyAlias);
        }
    }
}
