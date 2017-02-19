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
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;

public class DefaultManagers {

    public KeyManager selectKeyManager(Context context, int osVersion, DataStorage configStorage, DataStorage keyStorage) {
        KeyWrapper keyWrapper;

        if (osVersion >= Build.VERSION_CODES.M) {
            keyWrapper = new KeyStoreWrapper(new AndroidCrypto(), DefaultSpecs.getKeyStoreDataProtectionSpec());
        } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            keyWrapper = new AsymmetricKeyStoreWrapper(
                    context, new AndroidCrypto(), DefaultSpecs.getAsymmetricKeyProtectionSpec());
        } else {
            PasswordKeyWrapper passwordKeyWrapper = new PasswordKeyWrapper(
                    DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
            return new ObfuscationKeyManager(DefaultSpecs.getDataProtectionSpec(osVersion), keyStorage, passwordKeyWrapper);
        }
        return new KeyManager(DefaultSpecs.getDataProtectionSpec(osVersion), keyStorage, keyWrapper);
    }

    public PasswordProtectedKeyManager selectPasswordProtectedKeyManager(Context context, int osVersion, DataStorage configStorage, DataStorage keyStorage) {
        PasswordKeyWrapper keyWrapper;

        if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            keyWrapper = new SignedPasswordKeyWrapper(
                    context, new AndroidCrypto(), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordDeviceBindingSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
        } else {
            keyWrapper = new PasswordKeyWrapper(
                    DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getPasswordBasedKeyProtectionSpec(osVersion), configStorage);
        }

        return new PasswordProtectedKeyManager(DefaultSpecs.getDataProtectionSpec(osVersion), keyStorage, keyWrapper);
    }
}
