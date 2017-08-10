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

import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

public abstract class CipherStrategy {

    public CipherStrategy() {
    }

    public byte[] encrypt(Key key, CipherSpec cipherSpec, byte[] plainBytes) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance(cipherSpec.getCipherTransformation());
        AlgorithmParameterSpec algorithmParameterSpec = null;
        if (cipherSpec.getParameterSpecFactory() != null) {
            algorithmParameterSpec = cipherSpec.getParameterSpecFactory().newInstance();
        } else if (cipherSpec.getParamsAlgorithm() != null) {
            algorithmParameterSpec = Cipher.getMaxAllowedParameterSpec(cipherSpec.getCipherTransformation());
        }
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        byte[] paramBytes;
        if (cipher.getParameters() != null) {
            paramBytes = cipher.getParameters().getEncoded();
        } else {
            paramBytes = new byte[0];
        }
        return ByteArrayUtil.join(paramBytes, encryptedBytes);
    }

    public byte[] decrypt(Key key, CipherSpec cipherSpec, byte[] cipherText) throws GeneralSecurityException, IOException {
        byte[][] splitBytes = ByteArrayUtil.split(cipherText);

        Cipher cipher = Cipher.getInstance(cipherSpec.getCipherTransformation());
        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(cipherSpec.getParamsAlgorithm());
            params.init(splitBytes[0]);
        }
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        return cipher.doFinal(splitBytes[1]);
    }
}
