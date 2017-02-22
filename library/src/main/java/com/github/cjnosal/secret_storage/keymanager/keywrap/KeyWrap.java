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

package com.github.cjnosal.secret_storage.keymanager.keywrap;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KeyWrap {

    public byte[] wrap(Key kek, SecretKey secret, @SecurityAlgorithms.Cipher String algorithm, @SecurityAlgorithms.AlgorithmParameters String paramAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance(algorithm);
        AlgorithmParameterSpec algorithmParameterSpec = Cipher.getMaxAllowedParameterSpec(paramAlgorithm);
        cipher.init(Cipher.WRAP_MODE, kek, algorithmParameterSpec);
        byte[] wrappedKey = cipher.wrap(secret);
        byte[] paramBytes;
        if (cipher.getParameters() != null) {
            paramBytes = cipher.getParameters().getEncoded();
        } else {
            paramBytes = new byte[0];
        }
        return ByteArrayUtil.join(paramBytes, wrappedKey);
    }

    public Key unwrap(Key kek, byte[] cipherText, @SecurityAlgorithms.Cipher String algorithm, @SecurityAlgorithms.AlgorithmParameters String paramAlgorithm, @SecurityAlgorithms.KeyGenerator String keyAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[][] splitBytes = ByteArrayUtil.split(cipherText);

        Cipher cipher = Cipher.getInstance(algorithm);
        AlgorithmParameters params = null;
        if (splitBytes[0].length != 0) {
            params = AlgorithmParameters.getInstance(paramAlgorithm);
            params.init(splitBytes[0]);
        }
        cipher.init(Cipher.UNWRAP_MODE, kek, params);
        return cipher.unwrap(splitBytes[1], keyAlgorithm, Cipher.SECRET_KEY);
    }
}
