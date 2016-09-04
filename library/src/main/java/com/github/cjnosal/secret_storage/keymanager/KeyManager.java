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

import com.github.cjnosal.secret_storage.keymanager.crypto.PRNGFixes;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public abstract class KeyManager {

    protected final ProtectionStrategy dataProtectionStrategy;

    public KeyManager(ProtectionStrategy dataProtectionStrategy) {
        this.dataProtectionStrategy = dataProtectionStrategy;
        PRNGFixes.apply();
    }

    public byte[] encrypt(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        Key encryptionKey = generateEncryptionKey(id);
        Key signingKey = generateSigningKey(id);
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, plainText);
    }

    public byte[] decrypt(String id, byte[] cipherText) throws GeneralSecurityException, IOException {
        Key decryptionKey = loadDecryptionKey(id);
        Key verificationKey = loadVerificationKey(id);
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, cipherText);
    }

    protected abstract Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException;

    protected abstract Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException;

    // TODO load encryption/signing key to allow reuse

    protected abstract Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException;

    protected abstract Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException;
}
