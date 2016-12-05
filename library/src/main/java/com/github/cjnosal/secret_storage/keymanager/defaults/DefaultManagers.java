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

import com.github.cjnosal.secret_storage.keymanager.AsymmetricWrapKeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class DefaultManagers {
    public KeyManager selectDefaultManager(Context context, int osVersion, DataStorage configStorage, DataStorage keyStorage, String storeId, String userPassword) throws GeneralSecurityException, IOException {
        Crypto crypto = new Crypto();
        if (userPassword != null) {
            if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                PasswordKeyManager manager = new SignedPasswordKeyManager(
                        context, storeId, crypto, new AndroidCrypto(), DefaultStrategies.getDataProtectionStrategy(crypto, osVersion), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultStrategies.getPasswordDeviceBindingStragegy(crypto), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto, osVersion), keyStorage, configStorage);
                if (manager.isPasswordSet()) {
                    manager.unlock(userPassword);
                } else {
                    manager.setPassword(userPassword);
                }
                return manager;
            } else {
                PasswordKeyManager manager = new PasswordKeyManager(
                        crypto, storeId, DefaultStrategies.getDataProtectionStrategy(crypto, osVersion), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto, osVersion), keyStorage, configStorage);
                if (manager.isPasswordSet()) {
                    manager.unlock(userPassword);
                } else {
                    manager.setPassword(userPassword);
                }
                return manager;
            }
        } else {
            if (osVersion >= Build.VERSION_CODES.M) {
                return new KeyStoreManager(new AndroidCrypto(), storeId, DefaultStrategies.getKeyStoreDataProtectionStrategy(crypto));
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                return new AsymmetricWrapKeyStoreManager(
                        context, crypto, new AndroidCrypto(), storeId, DefaultStrategies.getDataProtectionStrategy(crypto, osVersion), keyStorage, DefaultStrategies.getAsymmetricKeyProtectionStrategy(crypto));
            } else {
                PasswordKeyManager manager = new PasswordKeyManager(
                        crypto, storeId, DefaultStrategies.getDataProtectionStrategy(crypto, osVersion), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto, osVersion), keyStorage, configStorage);
                if (manager.isPasswordSet()) {
                    manager.unlock("default_password");
                } else {
                    manager.setPassword("default_password");
                }
                return manager;
            }
        }
    }
}
