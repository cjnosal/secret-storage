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

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This KeyWrapper is NOT SECURE!
 * Should only be used when AndroidKeyStore is not available and a user password can not be requested.
 */
public class ObfuscationKeyWrapper extends PasswordKeyWrapper {

    public ObfuscationKeyWrapper(KeyDerivationSpec derivationSpec, KeyGenSpec keyGenSpec, CipherSpec keyProtectionSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(derivationSpec, keyGenSpec, keyProtectionSpec, configStorage, keyStorage);
    }

    @Override
    public KeyWrapper.Editor getEditor(String storeId) {
        return new NoParamsEditor(storeId);
    }

    void unlock(String keyAlias, UnlockParams unlockParams) throws IOException, GeneralSecurityException {
        char[] defaultPassword = new char[] {'d', 'e', 'f', 'a', 'u', 'l', 't', '_', 'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'i', 'o', 'n'};
        try {
            if (isPasswordSet(keyAlias)) {
                super.unlock(keyAlias, new PasswordParams(defaultPassword));
            } else {
                setPassword(keyAlias, defaultPassword);
            }
        } finally {
            for (int i = 0; i < defaultPassword.length; ++i) {
                defaultPassword[i] = ' ';
            }
        }
    }

}
