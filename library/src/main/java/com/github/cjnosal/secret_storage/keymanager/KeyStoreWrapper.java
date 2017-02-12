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
import android.os.Build;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreWrapper extends KeyWrapper {

    // TODO backport KeyProperties
    // TODO map Ciphers to blocks/paddings/digests so KeyGenParameterSpecs can be created from CipherSpec/IntegritySpec
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent
    // TODO unlock with fingerprint

    private AndroidCrypto androidCrypto;
    private String storeId;
    private ProtectionStrategy keyProtectionStrategy;
    private final KeyEncoding keyEncoding = new KeyEncoding();

    public KeyStoreWrapper(AndroidCrypto androidCrypto, String storeId, ProtectionStrategy keyProtectionStrategy) {
        this.androidCrypto = androidCrypto;
        this.storeId = storeId;
        this.keyProtectionStrategy = keyProtectionStrategy;
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
        KeyStoreCipherSpec spec = (KeyStoreCipherSpec) keyProtectionStrategy.getCipherStrategy().getSpec();
        if (keyProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + "E"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + "E")).getPublic();
        }
    }

    private Key generateSigningKey() throws GeneralSecurityException, IOException {
        KeyStoreIntegritySpec spec = (KeyStoreIntegritySpec) keyProtectionStrategy.getIntegrityStrategy().getSpec();
        if (keyProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + "S"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + "S")).getPrivate();
        }
    }

    private Key loadEncryptionKey() throws GeneralSecurityException, IOException {
        if (keyProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + "E");
        } else {
            return androidCrypto.loadPublicKey(storeId + ":" + "E");
        }
    }

    private Key loadSigningKey() throws GeneralSecurityException, IOException {
        if (keyProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + "S");
        } else {
            return androidCrypto.loadPrivateKey(storeId + ":" + "S");
        }
    }

    private Key loadDecryptionKey() throws GeneralSecurityException, IOException {
        if (keyProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + "E");
        } else {
            return androidCrypto.loadPrivateKey(storeId + ":" + "E");
        }
    }

    private Key loadVerificationKey() throws GeneralSecurityException, IOException {
        if (keyProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + "S");
        } else {
            return androidCrypto.loadPublicKey(storeId + ":" + "S");
        }
    }

    private boolean keysExist() throws GeneralSecurityException, IOException {
        return androidCrypto.hasEntry(storeId + ":" + "S") && androidCrypto.hasEntry(storeId + ":" + "E");
    }
}
