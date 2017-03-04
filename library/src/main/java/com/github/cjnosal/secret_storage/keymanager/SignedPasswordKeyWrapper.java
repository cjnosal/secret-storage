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

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class SignedPasswordKeyWrapper extends PasswordKeyWrapper {
    
    private static final String DEVICE_BINDING = "DEVICE_BINDING";

    private final Context context;
    private final KeyGenSpec integrityKeyGenSpec;
    private final AndroidCrypto androidCrypto;
    private final IntegritySpec derivationIntegritySpec;
    private final IntegrityStrategy derivationIntegrityStrategy;

    public SignedPasswordKeyWrapper(Context context, KeyDerivationSpec keyDerivationSpec, KeyGenSpec derivedKeyGenSpec, IntegritySpec derivationIntegritySpec, CipherSpec keyProtectionSpec, KeyGenSpec integrityKeyGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyDerivationSpec, derivedKeyGenSpec, keyProtectionSpec, configStorage, keyStorage);
        this.context = context;
        this.integrityKeyGenSpec = integrityKeyGenSpec;
        this.androidCrypto = new AndroidCrypto();
        this.derivationIntegritySpec = derivationIntegritySpec;
        this.derivationIntegrityStrategy = new SignatureStrategy();
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        super.eraseConfig(keyAlias);
        androidCrypto.deleteEntry(getStorageField(keyAlias, DEVICE_BINDING));
    }

    @Override
    protected byte[] derive(String keyAlias, String password, byte[] salt) throws GeneralSecurityException, IOException {

        PrivateKey signingKey;
        if (!isPasswordSet(keyAlias)) {
            signingKey = androidCrypto.generateKeyPair(
                    context,
                    getStorageField(keyAlias, DEVICE_BINDING),
                    integrityKeyGenSpec.getKeygenAlgorithm())
                    .getPrivate();
        } else {
            signingKey = androidCrypto.loadPrivateKey(getStorageField(keyAlias, DEVICE_BINDING));
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());

        PBEKeySpec firstSpec = new PBEKeySpec(password.toCharArray(), salt, derivationSpec.getRounds() / 2, keyGenSpec.getKeySize() * 2);
        byte[] firstHash = factory.generateSecret(firstSpec).getEncoded();
        byte[] signature = derivationIntegrityStrategy.sign(signingKey, derivationIntegritySpec, firstHash);
        String signatureString = Encoding.base64Encode(signature);

        PBEKeySpec secondSpec = new PBEKeySpec(signatureString.toCharArray(), salt, derivationSpec.getRounds() / 2, keyGenSpec.getKeySize() * 2);
        return factory.generateSecret(secondSpec).getEncoded();
    }

}
