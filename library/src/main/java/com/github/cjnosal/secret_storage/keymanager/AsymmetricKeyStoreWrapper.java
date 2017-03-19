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
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.Cipher;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class AsymmetricKeyStoreWrapper extends BaseKeyWrapper {

    private static final String ENCRYPTION_KEY = "ENCRYPTION_KEY";

    private final AndroidCrypto androidCrypto;
    private final CipherSpec keyProtectionSpec;
    private final Context context;
    private final KeyGenSpec kekSpec;

    // TODO refactor to extend KeyStoreWrapper to override symmetric key generation?
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent

    public AsymmetricKeyStoreWrapper(Context context, CipherSpec intermediateKeyProtectionSpec, KeyGenSpec intermediateKekSpec, CipherSpec keyStoreKeyProtectionSpec, KeyGenSpec keyStoreKekSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(intermediateKeyProtectionSpec, intermediateKekSpec, configStorage, keyStorage);
        this.context = context;
        this.kekSpec = keyStoreKekSpec;
        this.androidCrypto = new AndroidCrypto();
        this.keyProtectionSpec = keyStoreKeyProtectionSpec;
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        super.eraseConfig(keyAlias);
        androidCrypto.deleteEntry(getStorageField(keyAlias, ENCRYPTION_KEY));
    }

    @Override
    void unlock(String keyAlias, UnlockParams params) throws IOException, GeneralSecurityException {
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!kekExists(keyAlias)) {
            KeyPair encryptionKey = generateKeyPair(keyAlias);
            Key kek = encryptionKey.getPublic();
            Cipher kekCipher = keyWrap.initWrapCipher(kek, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
            finishUnlock(keyAlias, null, kekCipher);
        } else {
            Key kek = androidCrypto.loadPrivateKey(storageField);
            Cipher kekCipher = keyWrap.initUnwrapCipher(kek, getKekCipherParams(keyAlias), keyProtectionSpec.getCipherTransformation());
            finishUnlock(keyAlias, kekCipher, null);
        }
    }

    private KeyPair generateKeyPair(String keyAlias) throws GeneralSecurityException {
        return androidCrypto.generateKeyPair(context, getStorageField(keyAlias, ENCRYPTION_KEY),
                kekSpec.getKeygenAlgorithm());
    }
}
