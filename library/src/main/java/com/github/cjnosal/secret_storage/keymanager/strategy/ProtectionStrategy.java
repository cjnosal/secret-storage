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

import android.text.TextUtils;

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
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

    // TODO key and/or data ids should be signed by the mac?
    public byte[] encryptAndSign(Key encryptionKey, Key signingKey, byte[] plainText) throws GeneralSecurityException, IOException {

        byte[] cipherParams = Encoding.utf8Decode(
                cipherStrategy.getSpec().getCipherTransformation() + ":" + integrityStrategy.getSpec().getIntegrityTransformation());
        byte[] cipherText = cipherStrategy.encrypt(encryptionKey, plainText);
        byte[] parameterizedCipherText = ByteArrayUtil.join(cipherParams, cipherText);
        byte[] signature = integrityStrategy.sign(signingKey, parameterizedCipherText);

        return ByteArrayUtil.join(parameterizedCipherText, signature);
    }

    public byte[] verifyAndDecrypt(Key decryptionKey, Key verificationKey, byte[] cipherText) throws GeneralSecurityException, IOException {

        byte[][] signedData = ByteArrayUtil.split(cipherText);

        if (!integrityStrategy.verify(verificationKey, signedData[0], signedData[1])) {
            throw new SignatureException("Signature check failed");
        }

        byte[][] splitData = ByteArrayUtil.split(signedData[0]);
        TextUtils.SimpleStringSplitter paramSplitter = new TextUtils.SimpleStringSplitter(':');
        paramSplitter.setString(Encoding.utf8Encode(splitData[0]));
        String cipherParams = paramSplitter.next();
        String integrityParams = paramSplitter.next();

        if (!cipherParams.equals(cipherStrategy.getSpec().getCipherTransformation()) ||
                !integrityParams.equals(integrityStrategy.getSpec().getIntegrityTransformation())) {
            throw new InvalidAlgorithmParameterException("Wrong protection strategy for ciphertext");
        }

        return cipherStrategy.decrypt(decryptionKey, splitData[1]);
    }
}
