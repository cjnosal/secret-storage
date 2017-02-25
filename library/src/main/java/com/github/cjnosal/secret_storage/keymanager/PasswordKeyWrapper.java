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

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.keywrap.PasswordWrapParams;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;

public class PasswordKeyWrapper extends KeyWrapper {

    protected final KeyDerivationSpec derivationSpec;

    protected Key derivedEncKey;

    public PasswordKeyWrapper(KeyDerivationSpec derivationSpec) {
        super();
        this.derivationSpec = derivationSpec;
    }

    @Override
    public String getWrapAlgorithm() {
        return SecurityAlgorithms.Cipher_AESWRAP;
    }

    @Override
    public String getWrapParamAlgorithm() {
        return SecurityAlgorithms.AlgorithmParameters_AES;
    }

    @Override
    public Key getKek(String keyAlias) throws LoginException {
        if (!isUnlocked()) {
            throw new LoginException("Not unlocked");
        }
        return derivedEncKey;
    }

    @Override
    Key getKdk(String keyAlias) throws IOException, GeneralSecurityException {
        return getKek(keyAlias);
    }

    @Override
    public void clear(String keyAlias) throws GeneralSecurityException, IOException {
    }

    public void lock() {
        derivedEncKey = null;
    }

    public boolean isUnlocked() {
        return derivedEncKey != null;
    }

    public byte[] unlock(PasswordWrapParams params) throws GeneralSecurityException, IOException {
        byte[] generated = derive(params);
        byte[] verification = getVerification(generated);
        if (params.getVerification() != null && !MessageDigest.isEqual(verification, params.getVerification())) {
            throw new LoginException("Wrong password");
        }
        derivedEncKey = getDerivedEncKey(generated);
        return verification;
    }

    public boolean verifyPassword(PasswordWrapParams params) throws IOException, GeneralSecurityException {
        byte[] generated = derive(params);
        return MessageDigest.isEqual(getVerification(generated), params.getVerification());
    }

    public KeyDerivationSpec getDerivationSpec() {
        return derivationSpec;
    }

    protected byte[] derive(PasswordWrapParams params) throws GeneralSecurityException, IOException {
        String password = params.getPassword();
        params.clearPassword();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), params.getSalt(), derivationSpec.getRounds(), derivationSpec.getKeySize() * 2);
        return factory.generateSecret(spec).getEncoded();
    }

    private Key getDerivedEncKey(byte[] generated) {
        return new SecretKeySpec(generated, derivationSpec.getKeySize()/8, derivationSpec.getKeySize()/8, derivationSpec.getKeyspecAlgorithm());
    }

    private byte[] getVerification(byte[] generated) {
        return Arrays.copyOfRange(generated, 0, derivationSpec.getKeySize()/8);
    }
}
