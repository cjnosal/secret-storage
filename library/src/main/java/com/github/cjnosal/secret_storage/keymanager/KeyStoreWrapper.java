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
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyStoreKeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreWrapper extends BaseKeyWrapper {

    // TODO backport KeyProperties
    // TODO map Ciphers to blocks/paddings/digests so KeyGenParameterSpecs can be created from CipherSpec/IntegritySpec
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent
    // TODO unlock with fingerprint

    private static final String ENCRYPTION_KEY = "ENCRYPTION_KEY";

    private final AndroidCrypto androidCrypto;
    private final KeyGenSpec keyGenSpec;

    public KeyStoreWrapper(CipherSpec keyProtectionSpec, KeyGenSpec keyGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyProtectionSpec, configStorage, keyStorage);
        this.keyGenSpec = keyGenSpec;
        this.androidCrypto = new AndroidCrypto();
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        super.eraseConfig(keyAlias);
        androidCrypto.deleteEntry(getStorageField(keyAlias, ENCRYPTION_KEY));
    }

    @Override
    protected Key getKek(String keyAlias) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!androidCrypto.hasEntry(storageField)) {
            return androidCrypto.generateSecretKey(keyGenSpec.getKeygenAlgorithm(), getKeyGenParameterSpec(storageField));
        }
        return androidCrypto.loadSecretKey(storageField);
    }

    @Override
    protected Key getKdk(String keyAlias) throws IOException, GeneralSecurityException {
        return getKek(keyAlias);
    }

    private KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
        // recreate KeyGenParameterSpec with correct keyId for symmetric encryption
        KeyGenParameterSpec placeholder = ((KeyStoreKeyGenSpec)keyGenSpec).getKeyGenParameterSpec();
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        if (placeholder.getAlgorithmParameterSpec() != null) {
            builder.setAlgorithmParameterSpec(placeholder.getAlgorithmParameterSpec());
        }
        builder.setBlockModes(placeholder.getBlockModes());
        builder.setEncryptionPaddings(placeholder.getEncryptionPaddings());
        builder.setKeySize(placeholder.getKeySize());
        builder.setRandomizedEncryptionRequired(placeholder.isRandomizedEncryptionRequired());
        builder.setUserAuthenticationRequired(placeholder.isUserAuthenticationRequired());
        builder.setUserAuthenticationValidityDurationSeconds(placeholder.getUserAuthenticationValidityDurationSeconds());
        builder.setKeyValidityStart(placeholder.getKeyValidityStart());
        builder.setKeyValidityForConsumptionEnd(placeholder.getKeyValidityForConsumptionEnd());
        builder.setKeyValidityForOriginationEnd(placeholder.getKeyValidityForOriginationEnd());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(placeholder.isInvalidatedByBiometricEnrollment());
            builder.setUserAuthenticationValidWhileOnBody(placeholder.isUserAuthenticationValidWhileOnBody());
        }
        return builder.build();
    }
}
