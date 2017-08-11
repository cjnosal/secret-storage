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

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public class IntermediateKekProvider {

    private final DataKeyGenerator generator;

    public IntermediateKekProvider(DataKeyGenerator generator) {
        this.generator = generator;
    }

    public @KeyPurpose.KeySecrecy
    SecretKey getIntermediateKek(KeyGenSpec spec) throws GeneralSecurityException {
        return generator.generateDataKey(spec.getKeygenAlgorithm(), spec.getKeySize());
    }
}
