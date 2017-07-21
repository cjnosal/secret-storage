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

package com.github.cjnosal.secret_storage.keymanager.strategy;

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SignatureException;

public class ProtectionStrategy {

    protected final CipherStrategy cipherStrategy;
    protected final IntegrityStrategy integrityStrategy;

    public ProtectionStrategy(CipherStrategy cipherStrategy, IntegrityStrategy integrityStrategy) {
        this.cipherStrategy = cipherStrategy;
        this.integrityStrategy = integrityStrategy;
    }

    public CipherStrategy getCipherStrategy() {
        return cipherStrategy;
    }

    public IntegrityStrategy getIntegrityStrategy() {
        return integrityStrategy;
    }

    public byte[] encryptAndSign(String id, Key encryptionKey, Key signingKey, DataProtectionSpec dataProtectionSpec, byte[] plainText) throws GeneralSecurityException, IOException {
        byte[] cipherText = cipherStrategy.encrypt(encryptionKey, dataProtectionSpec.getCipherSpec(), plainText);
        byte[] meta = Encoding.utf8Decode(id);
        byte[] cipherTextWithMetadata = ByteArrayUtil.join(meta, cipherText);
        byte[] signature = integrityStrategy.sign(signingKey, dataProtectionSpec.getIntegritySpec(), cipherTextWithMetadata);

        return ByteArrayUtil.join(cipherTextWithMetadata, signature);
    }

    public byte[] verifyAndDecrypt(String id, Key decryptionKey, Key verificationKey, DataProtectionSpec dataProtectionSpec, byte[] cipherText) throws GeneralSecurityException, IOException {

        byte[][] signedDataAndSignature = ByteArrayUtil.split(cipherText);

        if (!integrityStrategy.verify(verificationKey, dataProtectionSpec.getIntegritySpec(), signedDataAndSignature[0], signedDataAndSignature[1])) {
            throw new SignatureException("Signature check failed");
        }

        byte[][] metadataAndCipherText = ByteArrayUtil.split(signedDataAndSignature[0]);
        if (!id.equals(new String(metadataAndCipherText[0]))) {
            throw new IOException("Metadata (id=" + metadataAndCipherText[0] + ") doesn't match requested id (" + id + ")");
        }

        return cipherStrategy.decrypt(decryptionKey, dataProtectionSpec.getCipherSpec(), metadataAndCipherText[1]);
    }
}
