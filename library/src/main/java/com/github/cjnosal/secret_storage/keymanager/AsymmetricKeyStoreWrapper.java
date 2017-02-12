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

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class AsymmetricKeyStoreWrapper extends KeyWrapper {

    private Context context;
    private AndroidCrypto androidCrypto;
    private String storeId;
    private ProtectionStrategy keyProtectionStrategy;
    private KeyEncoding keyEncoding = new KeyEncoding();

    // TODO refactor to extend KeyStoreWrapper to override symmetric key generation?
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent

    public AsymmetricKeyStoreWrapper(Context context, AndroidCrypto androidCrypto, String storeId, ProtectionStrategy keyProtectionStrategy) throws GeneralSecurityException, IOException {
        this.context = context;
        this.androidCrypto = androidCrypto;
        this.storeId = storeId;
        this.keyProtectionStrategy = keyProtectionStrategy;

        if (keyProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy ||
                keyProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            throw new IllegalArgumentException("AsymmetricKeyStoreWrapper needs asymmetric strategy for key protection");
        }
    }

    @Override
    public void attach() throws IOException, GeneralSecurityException {
    }

    @Override
    public byte[] wrap(@KeyPurpose.Data Key key) throws GeneralSecurityException, IOException {
        @KeyPurpose.KeySecrecy Key encryptionKey;
        @KeyPurpose.KeyIntegrity Key signingKey;
        if (keysExist()) {
            encryptionKey = loadEncryptionKey();
            signingKey = loadSigningKey();
        }
        else {
            encryptionKey = generateEncryptionKey();
            signingKey = generateSigningKey();
        }
        return keyProtectionStrategy.encryptAndSign(encryptionKey, signingKey, keyEncoding.encodeKey(key));
    }

    @Override
    public Key unwrap(byte[] wrappedKey) throws GeneralSecurityException, IOException {
        @KeyPurpose.KeySecrecy Key decryptionKey = loadDecryptionKey();
        @KeyPurpose.KeyIntegrity Key verificationKey = loadVerificationKey();
        return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, wrappedKey));
    }

    @Override
    public void clear() throws GeneralSecurityException, IOException {
        androidCrypto.deleteEntry(storeId + ":" + "S");
        androidCrypto.deleteEntry(storeId + ":" + "E");
    }

    private Key generateEncryptionKey() throws GeneralSecurityException, IOException {
        return generateEncryptionKey(keyProtectionStrategy.getCipherStrategy());
    }

    private Key generateSigningKey() throws GeneralSecurityException, IOException {
        return generateSigningKey(keyProtectionStrategy.getIntegrityStrategy());
    }

    private boolean keysExist() throws GeneralSecurityException, IOException {
        return androidCrypto.hasEntry(storeId + ":" + "S") && androidCrypto.hasEntry(storeId + ":" + "E");
    }

    private Key generateEncryptionKey(CipherStrategy strategy) throws GeneralSecurityException, IOException {
        CipherSpec cipherSpec = strategy.getSpec();
        KeyPair encryptionKey = androidCrypto.generateKeyPair(context, storeId + ":" + "E", cipherSpec.getKeygenAlgorithm());
        return encryptionKey.getPublic();
    }

    private Key generateSigningKey(IntegrityStrategy strategy) throws GeneralSecurityException, IOException {
        IntegritySpec integritySpec = strategy.getSpec();
        KeyPair signingKey = androidCrypto.generateKeyPair(context, storeId + ":" + "S", integritySpec.getKeygenAlgorithm());
        return signingKey.getPrivate();
    }

    private Key loadEncryptionKey() throws GeneralSecurityException, IOException {
        KeyPair encryptionKey = androidCrypto.loadKeyPair(storeId + ":" + "E");
        return encryptionKey.getPublic();
    }

    private Key loadSigningKey() throws GeneralSecurityException, IOException {
        KeyPair encryptionKey = androidCrypto.loadKeyPair(storeId + ":" + "S");
        return encryptionKey.getPrivate();
    }

    private Key loadDecryptionKey() throws GeneralSecurityException, IOException {
        KeyPair encryptionKey = androidCrypto.loadKeyPair(storeId + ":" + "E");
        return encryptionKey.getPrivate();
    }

    private Key loadVerificationKey() throws GeneralSecurityException, IOException {
        KeyPair encryptionKey = androidCrypto.loadKeyPair(storeId + ":" + "S");
        return encryptionKey.getPublic();
    }
}
