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
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class SignedPasswordKeyWrapper extends PasswordKeyWrapper {

    private final Context context;
    private final AndroidCrypto androidCrypto;
    private final IntegritySpec derivationIntegritySpec;
    private final IntegrityStrategy derivationIntegrityStrategy;

    public SignedPasswordKeyWrapper(Context context, String storeId, AndroidCrypto androidCrypto, KeyDerivationSpec keyDerivationSpec, IntegritySpec derivationIntegritySpec, ProtectionSpec keyProtectionSpec, DataStorage configStorage) {
        super(storeId, keyDerivationSpec, keyProtectionSpec, configStorage);
        this.context = context;
        this.androidCrypto = androidCrypto;
        this.derivationIntegritySpec = derivationIntegritySpec;
        this.derivationIntegrityStrategy = new SignatureStrategy();
    }

    @Override
    protected void deriveAndStoreKeys(String password) throws IOException, GeneralSecurityException {
        androidCrypto.generateKeyPair(context, storeId + ":" + "D", derivationIntegritySpec.getKeygenAlgorithm()).getPrivate();
        super.deriveAndStoreKeys(password);
    }

    protected Key generateKek(String password, byte[] salt) throws IOException, GeneralSecurityException {
        PrivateKey signingKey = androidCrypto.loadPrivateKey(storeId + ":" + "D");
        SecretKeyFactory factory = SecretKeyFactory.getInstance(derivationSpec.getKeygenAlgorithm());

        PBEKeySpec firstSpec = new PBEKeySpec(password.toCharArray(), salt, derivationSpec.getRounds() / 2, derivationSpec.getKeySize());
        byte[] firstHash = factory.generateSecret(firstSpec).getEncoded();
        byte[] signature = derivationIntegrityStrategy.sign(signingKey, derivationIntegritySpec, firstHash);
        String signatureString = Encoding.base64Encode(signature);

        PBEKeySpec secondSpec = new PBEKeySpec(signatureString.toCharArray(), salt, derivationSpec.getRounds() / 2, derivationSpec.getKeySize());
        Key secondHash = factory.generateSecret(secondSpec);

        return new SecretKeySpec(secondHash.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());
    }

    @Override
    public void clear() throws GeneralSecurityException, IOException {
        super.clear();
        androidCrypto.deleteEntry(storeId + ":" + "D");
    }

}
