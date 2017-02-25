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
import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;

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
    private CipherSpec keyProtectionSpec;

    public KeyStoreWrapper(AndroidCrypto androidCrypto, CipherSpec keyProtectionSpec) {
        super();
        this.androidCrypto = androidCrypto;
        this.keyProtectionSpec = keyProtectionSpec;
    }

    @Override
    public String getWrapAlgorithm() {
        return SecurityAlgorithms.Cipher_AES_CBC_PKCS7Padding;
    }

    @Override
    public String getWrapParamAlgorithm() {
        return SecurityAlgorithms.AlgorithmParameters_AES;
    }

    @Override
    Key getKek(String keyAlias) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!androidCrypto.hasEntry(storageField)) {
            KeyStoreCipherSpec spec = (KeyStoreCipherSpec) keyProtectionSpec;
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storageField));
        }
        return androidCrypto.loadSecretKey(storageField);
    }

    @Override
    Key getKdk(String keyAlias) throws IOException, GeneralSecurityException {
        return getKek(keyAlias);
    }

    @Override
    public void clear(String keyAlias) throws GeneralSecurityException, IOException {
        androidCrypto.deleteEntry(getStorageField(keyAlias, ENCRYPTION_KEY));
    }
}
