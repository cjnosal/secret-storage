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

import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This KeyManager is NOT SECURE!
 * Should only be used when AndroidKeyStore is not available and a user password can not be requested.
 */
public class ObfuscationKeyManager extends PasswordProtectedKeyManager {

    public ObfuscationKeyManager(ProtectionSpec dataProtectionSpec, DataStorage keyStorage, PasswordKeyWrapper keyWrapper) {
        super(dataProtectionSpec, keyStorage, keyWrapper);
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException, IOException {
        unlock();
        return super.encrypt(plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException, IOException {
        unlock();
        return super.decrypt(cipherText);
    }

    public void rewrap(KeyWrapper newWrapper) throws GeneralSecurityException, IOException {
        unlock();
        super.rewrap(newWrapper);
    }

    public void copyTo(KeyManager other) throws GeneralSecurityException, IOException {
        unlock();
        super.copyTo(other);
    }

    private void unlock() throws IOException, GeneralSecurityException {
        PasswordKeyWrapper keyWrapper = (PasswordKeyWrapper) this.keyWrapper;
        if (!keyWrapper.isUnlocked()) {
            if (keyWrapper.isPasswordSet()) {
                keyWrapper.unlock("default_password");
            } else {
                keyWrapper.setPassword("default_password");
            }
        }
    }
}
