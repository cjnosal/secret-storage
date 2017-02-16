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

package com.github.cjnosal.secret_storage.keymanager.strategy.cipher;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

public abstract class CipherStrategy {
    protected Crypto crypto;
    protected CipherSpec spec;

    public CipherStrategy(Crypto crypto, CipherSpec spec) {
        this.crypto = crypto;
        this.spec = spec;
    }

    public CipherSpec getSpec() {
        return spec;
    }

    public byte[] encrypt(Key key, byte[] plainBytes) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, key, Cipher.getMaxAllowedParameterSpec(spec.getCipherTransformation()));
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        byte[] paramBytes;
        if (cipher.getParameters() != null) {
            paramBytes = cipher.getParameters().getEncoded();
        } else {
            paramBytes = new byte[0];
        }
        return ByteArrayUtil.join(paramBytes, encryptedBytes);
    }

    public byte[] decrypt(Key key, byte[] cipherText) throws GeneralSecurityException, IOException {
        byte[][] splitBytes = ByteArrayUtil.split(cipherText);

        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(spec.getCipherAlgorithm());
            params.init(splitBytes[0]);
        }
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        return cipher.doFinal(splitBytes[1]);
    }
}
