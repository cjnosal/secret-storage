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

import javax.crypto.Cipher;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreWrapper extends BaseKeyWrapper {

    // TODO backport KeyProperties
    // TODO map Ciphers to blocks/paddings/digests so KeyGenParameterSpecs can be created from CipherSpec/IntegritySpec
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent
    // TODO unlock with fingerprint

    protected static final String ENCRYPTION_KEY = "ENCRYPTION_KEY";

    protected final AndroidCrypto androidCrypto;
    protected final KeyGenSpec keyGenSpec;

    public KeyStoreWrapper(CipherSpec keyProtectionSpec, KeyGenSpec keyGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyProtectionSpec, keyGenSpec, configStorage, keyStorage);
        this.keyGenSpec = keyGenSpec;
        this.androidCrypto = new AndroidCrypto();
    }

    @Override
    void unlock(String keyAlias, UnlockParams params) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!kekExists(keyAlias)) {
            Key kek = androidCrypto.generateSecretKey(keyGenSpec.getKeygenAlgorithm(), getKeyGenParameterSpec(storageField));
            Cipher kekCipher = keyWrap.initWrapCipher(kek, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
            finishUnlock(keyAlias, null, kekCipher);
        } else {
            Key kek = androidCrypto.loadSecretKey(storageField);
            Cipher kekCipher = keyWrap.initUnwrapCipher(kek, getKekCipherParams(keyAlias), keyProtectionSpec.getCipherTransformation());
            finishUnlock(keyAlias, kekCipher, null);
        }
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        super.eraseConfig(keyAlias);
        androidCrypto.deleteEntry(getStorageField(keyAlias, ENCRYPTION_KEY));
    }

    protected KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
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
