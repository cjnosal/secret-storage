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

package com.github.cjnosal.secret_storage.keymanager.defaults;

import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.AsymmetricKeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class DefaultManagers {

    public KeyManager selectKeyManager(Context context, int osVersion, DataStorage configStorage, DataStorage keyStorage, String storeId) throws GeneralSecurityException, IOException {
        KeyWrapper keyWrapper;

        if (osVersion >= Build.VERSION_CODES.M) {
            keyWrapper = new KeyStoreWrapper(new AndroidCrypto(), storeId, DefaultSpecs.getKeyStoreDataProtectionSpec());
        } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            keyWrapper = new AsymmetricKeyStoreWrapper(
                    context, new AndroidCrypto(), storeId, DefaultSpecs.getAsymmetricKeyProtectionSpec());
        } else {
            PasswordKeyWrapper manager = new PasswordKeyWrapper(
                    storeId, DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
            if (manager.isPasswordSet()) {
                manager.unlock("default_password");
            } else {
                manager.setPassword("default_password");
            }
            keyWrapper = manager;
        }
        return new KeyManager(storeId, DefaultSpecs.getDataProtectionSpec(osVersion), keyStorage, keyWrapper);
    }

    public PasswordProtectedKeyManager selectPasswordProtectedKeyManager(Context context, int osVersion, DataStorage configStorage, DataStorage keyStorage, String storeId) throws GeneralSecurityException, IOException {
        PasswordKeyWrapper keyWrapper;

        if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            keyWrapper = new SignedPasswordKeyWrapper(
                    context, storeId, new AndroidCrypto(), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordDeviceBindingSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
        } else {
            keyWrapper = new PasswordKeyWrapper(
                    storeId, DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
        }

        return new PasswordProtectedKeyManager(storeId, DefaultSpecs.getDataProtectionSpec(osVersion), keyStorage, keyWrapper);
    }
}
