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

package com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricCipherStrategy extends CipherStrategy {

    public SymmetricCipherStrategy(Crypto crypto, CipherSpec spec) {
        super(crypto, spec);
    }

    @Override
    public byte[] encrypt(Key key, byte[] plainBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, key, Cipher.getMaxAllowedParameterSpec(spec.getCipherTransformation()));
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        return ByteArrayUtil.join(cipher.getIV(), encryptedBytes);
    }

    @Override
    public byte[] decrypt(Key key, byte[] cipherText) throws GeneralSecurityException {
        byte[][] splitBytes = ByteArrayUtil.split(cipherText);

        IvParameterSpec ivspec = new IvParameterSpec(splitBytes[0]);
        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        return cipher.doFinal(splitBytes[1]);
    }
}
