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
import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class AsymmetricKeyStoreWrapper extends KeyWrapper {

    private final Context context;
    private final AndroidCrypto androidCrypto;
    private final CipherSpec keyProtectionSpec;

    // TODO refactor to extend KeyStoreWrapper to override symmetric key generation?
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent

    public AsymmetricKeyStoreWrapper(Context context, CipherSpec keyProtectionSpec) {
        super();
        this.context = context;
        this.androidCrypto = new AndroidCrypto();
        this.keyProtectionSpec = keyProtectionSpec;
    }

    @Override
    String getWrapAlgorithm() {
        return SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding;
    }

    @Override
    String getWrapParamAlgorithm() {
        return null;
    }

    @Override
    Key getKek(String keyAlias) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!androidCrypto.hasEntry(storageField)) {
            KeyPair encryptionKey = androidCrypto.generateKeyPair(context, getStorageField(keyAlias, ENCRYPTION_KEY), keyProtectionSpec.getKeygenAlgorithm());
            return encryptionKey.getPublic();
        }
        return androidCrypto.loadPublicKey(storageField);
    }

    @Override
    Key getKdk(String keyAlias) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!androidCrypto.hasEntry(storageField)) {
            KeyPair encryptionKey = androidCrypto.generateKeyPair(context, getStorageField(keyAlias, ENCRYPTION_KEY), keyProtectionSpec.getKeygenAlgorithm());
            return encryptionKey.getPrivate();
        }
        return androidCrypto.loadPrivateKey(storageField);
    }

    @Override
    void clear(String keyAlias) throws GeneralSecurityException, IOException {
        androidCrypto.deleteEntry(getStorageField(keyAlias, ENCRYPTION_KEY));
    }
}
