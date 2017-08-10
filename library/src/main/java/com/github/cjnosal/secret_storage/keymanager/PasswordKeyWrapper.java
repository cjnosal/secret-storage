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

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordKeyWrapper extends BaseKeyWrapper {

    private static final String ENC_SALT = "ENC_SALT";
    private static final String VERIFICATION = "VERIFICATION";

    final SecureRandom secureRandom;

    final KeyDerivationSpec derivationSpec;
    final KeyGenSpec keyGenSpec;
    final CipherSpec intermediateKekProtectionSpec;

    public PasswordKeyWrapper(CryptoConfig config, DataStorage configStorage, DataStorage keyStorage) {
        this(config.getDerivationSpec(), config.getKeyGenSpec(), config.getKeyProtectionSpec(), configStorage, keyStorage);
    }

    public PasswordKeyWrapper(KeyDerivationSpec derivationSpec, KeyGenSpec keyGenSpec, CipherSpec keyProtectionSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyProtectionSpec, keyGenSpec, configStorage, keyStorage);
        this.intermediateKekProtectionSpec = keyProtectionSpec;
        this.derivationSpec = derivationSpec;
        this.keyGenSpec = keyGenSpec;
        this.secureRandom = new SecureRandom();
    }

    @Override
    protected void eraseConfig() throws GeneralSecurityException, IOException {
        super.eraseConfig();
        configStorage.delete(VERIFICATION);
        configStorage.delete(ENC_SALT);
    }

    @Override
    public KeyWrapper.Editor getEditor() {
        return new PasswordEditor();
    }

    void setPassword(@NonNull char[] password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            Key rootKek = deriveNewRootKek(password);
            Cipher kekCipher = keyWrap.initWrapCipher(rootKek, intermediateKekProtectionSpec.getCipherTransformation(), intermediateKekProtectionSpec.getParamsAlgorithm());
            finishUnlock(null, kekCipher);
        } else {
            throw new PasswordAlreadySetException("Password already set. Use unlock.");
        }
    }

    @NonNull
    private Key deriveNewRootKek(@NonNull char[] password) throws GeneralSecurityException, IOException {
        byte[] salt = generateSalt();
        byte[] generated = derive(password, salt);
        byte[] verification = getVerification(generated);
        configStorage.store(ENC_SALT, salt);
        configStorage.store(VERIFICATION, verification);

        return getRootKek(generated);
    }

    @Override
    void unlock(UnlockParams params) throws IOException, GeneralSecurityException {
        Key rootKek = deriveRootKek(((PasswordParams) params).getPassword());
        Cipher kekCipher = keyWrap.initUnwrapCipher(rootKek, intermediateKekProtectionSpec.getParamsAlgorithm(), intermediateKekProtectionSpec.getCipherTransformation(), getWrappedIntermediateKek());
        finishUnlock(kekCipher, null);
    }

    @NonNull
    private Key deriveRootKek(char[] password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new PasswordNotSetException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(ENC_SALT);
        byte[] verification = configStorage.load(VERIFICATION);

        byte[] generated = derive(password, encSalt);
        if (!MessageDigest.isEqual(verification, getVerification(generated))) {
            throw new WrongPasswordException("Wrong password");
        }
        return getRootKek(generated);
    }

    boolean isPasswordSet() {
        return configStorage.exists(ENC_SALT) && configStorage.exists(VERIFICATION);
    }

    byte[] derive(char[] password, byte[] salt) throws GeneralSecurityException, IOException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());
        PBEKeySpec spec = new PBEKeySpec(password, salt, derivationSpec.getRounds(), keyGenSpec.getKeySize() * 2);
        try {
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            for (int i = 0; i < password.length; i++) {
                password[i] = ' ';
            }
        }
    }

    private boolean verifyPassword(char[] password) throws IOException, GeneralSecurityException {
        if (!isPasswordSet()) {
            throw new PasswordNotSetException("No password set. Use setPassword.");
        }
        byte[] encSalt = configStorage.load(ENC_SALT);
        byte[] verification = configStorage.load(VERIFICATION);

        byte[] generated = derive(password, encSalt);
        return MessageDigest.isEqual(getVerification(generated), verification);
    }

    private byte[] generateSalt() {
        byte[] random = new byte[keyGenSpec.getKeySize() / 8];
        secureRandom.nextBytes(random);
        return random;
    }

    private Key getRootKek(byte[] generated) {
        return new SecretKeySpec(generated, keyGenSpec.getKeySize()/8, keyGenSpec.getKeySize()/8, keyGenSpec.getKeygenAlgorithm());
    }

    private byte[] getVerification(byte[] generated) {
        return Arrays.copyOfRange(generated, 0, keyGenSpec.getKeySize()/8);
    }

    public class PasswordEditor extends BaseEditor {

        PasswordEditor() {
            super();
        }

        public void setPassword(char[] password) throws IOException, GeneralSecurityException {
            PasswordKeyWrapper.this.setPassword(password);
        }

        public void setPassword(char[] password, Listener listener) {
            try {
                setPassword(password);
                listener.onSuccess();
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public void unlock(char[] password) throws GeneralSecurityException, IOException {
            PasswordKeyWrapper.this.unlock(new PasswordParams(password));
        }

        public void unlock(char[] password, Listener listener) {
            try {
                unlock(password);
                listener.onSuccess();
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public void changePassword(final @NonNull char[] oldPassword, final @NonNull char[] newPassword) throws GeneralSecurityException, IOException {
            if (!isPasswordSet()) {
                throw new PasswordNotSetException("No password set. Use setPassword.");
            }
            Key oldKey = PasswordKeyWrapper.this.deriveRootKek(oldPassword);

            configStorage.delete(VERIFICATION);
            configStorage.delete(ENC_SALT);

            Key newKey = PasswordKeyWrapper.this.deriveNewRootKek(newPassword);
            Cipher wrapCipher = keyWrap.initWrapCipher(newKey, intermediateKekProtectionSpec.getCipherTransformation(), intermediateKekProtectionSpec.getParamsAlgorithm());
            Cipher unwrapCipher = keyWrap.initUnwrapCipher(oldKey, intermediateKekProtectionSpec.getParamsAlgorithm(), intermediateKekProtectionSpec.getCipherTransformation(), getWrappedIntermediateKek());
            finishUnlock(unwrapCipher, wrapCipher);
        }

        public void changePassword(final @NonNull char[] oldPassword, final @NonNull char[] newPassword, Listener listener) {
            try {
                changePassword(oldPassword, newPassword);
                listener.onSuccess();
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public boolean verifyPassword(char[] password) throws GeneralSecurityException, IOException {
            return PasswordKeyWrapper.this.verifyPassword(password);
        }

        public void verifyPassword(char[] password, Listener listener) {
            try {
                if (verifyPassword(password)) {
                    listener.onSuccess();
                } else {
                    throw new WrongPasswordException("Wrong password");
                }
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public boolean isPasswordSet() {
            return PasswordKeyWrapper.this.isPasswordSet();
        }
    }

    class PasswordParams extends UnlockParams {
        private char[] password;

        public PasswordParams(char[] password) {
            this.password = password;
        }

        public char[] getPassword() {
            return password;
        }
    }

    public class WrongPasswordException extends GeneralSecurityException {
        public WrongPasswordException(String message) {
            super(message);
        }
    }
    public class PasswordNotSetException extends GeneralSecurityException {
        public PasswordNotSetException(String message) {
            super(message);
        }
    }
    public class PasswordAlreadySetException extends GeneralSecurityException {
        public PasswordAlreadySetException(String message) {
            super(message);
        }
    }

    public static class CryptoConfig {
        private final KeyDerivationSpec derivationSpec;
        private final KeyGenSpec keyGenSpec;
        private final CipherSpec keyProtectionSpec;

        public CryptoConfig(KeyDerivationSpec derivationSpec, KeyGenSpec keyGenSpec, CipherSpec keyProtectionSpec) {
            this.derivationSpec = derivationSpec;
            this.keyGenSpec = keyGenSpec;
            this.keyProtectionSpec = keyProtectionSpec;
        }

        public KeyDerivationSpec getDerivationSpec() {
            return derivationSpec;
        }

        public KeyGenSpec getKeyGenSpec() {
            return keyGenSpec;
        }

        public CipherSpec getKeyProtectionSpec() {
            return keyProtectionSpec;
        }
    }
}
