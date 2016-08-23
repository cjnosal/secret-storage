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

package com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SignatureStrategy extends IntegrityStrategy {

    public SignatureStrategy(Crypto crypto, IntegritySpec spec) {
        super(crypto, spec);
    }

    @Override
    public byte[] sign(Key key, byte[] plainBytes) throws GeneralSecurityException {
        return crypto.sign((PrivateKey)key, spec.getIntegrityTransformation(), plainBytes);
    }

    @Override
    public boolean verify(Key key, byte[] cipherText, byte[] signature) throws GeneralSecurityException {
        return crypto.verify((PublicKey)key, spec.getIntegrityTransformation(), cipherText, signature);
    }
}
