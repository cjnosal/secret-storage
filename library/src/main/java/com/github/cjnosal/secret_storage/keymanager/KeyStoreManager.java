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

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreManager extends KeyManager {

    // TODO backport KeyProperties
    // TODO map Ciphers to blocks/paddings/digests so KeyGenParameterSpecs can be created from CipherSpec/IntegritySpec
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent
    // TODO unlock with fingerprint

    private AndroidCrypto androidCrypto;

    public KeyStoreManager(AndroidCrypto androidCrypto, String storeId, ProtectionStrategy dataProtectionStrategy) {
        super(storeId, dataProtectionStrategy);
        this.androidCrypto = androidCrypto;
    }

    @Override
    public Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        KeyStoreCipherSpec spec = (KeyStoreCipherSpec) dataProtectionStrategy.getCipherStrategy().getSpec();
        if (dataProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + keyId + ":" + "E"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + keyId + ":" + "E")).getPublic();
        }
    }

    @Override
    public Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException {
        KeyStoreIntegritySpec spec = (KeyStoreIntegritySpec) dataProtectionStrategy.getIntegrityStrategy().getSpec();
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + keyId + ":" + "S"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + ":" + keyId + ":" + "S")).getPrivate();
        }
    }

    @Override
    public Key loadEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + keyId + ":" + "E");
        } else {
            return androidCrypto.loadPublicKey(storeId + ":" + keyId + ":" + "E");
        }
    }

    @Override
    public Key loadSigningKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + keyId + ":" + "S");
        } else {
            return androidCrypto.loadPrivateKey(storeId + ":" + keyId + ":" + "S");
        }
    }

    @Override
    public Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + keyId + ":" + "E");
        } else {
            return androidCrypto.loadPrivateKey(storeId + ":" + keyId + ":" + "E");
        }
    }

    @Override
    public Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.loadSecretKey(storeId + ":" + keyId + ":" + "S");
        } else {
            return androidCrypto.loadPublicKey(storeId + ":" + keyId + ":" + "S");
        }
    }

    @Override
    protected boolean keysExist(String keyId) throws GeneralSecurityException, IOException {
        return androidCrypto.hasEntry(storeId + ":" + keyId + ":" + "S") && androidCrypto.hasEntry(storeId + ":" + keyId + ":" + "E");
    }
}
