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

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public abstract class KeyStoreCipherSpec extends CipherSpec {
    private final String keygenAlgorithm; // key or keypair generator

    public KeyStoreCipherSpec(String keygenAlgorithm, String cipherAlgorithm, String transformation) {
        super(transformation, cipherAlgorithm, 0, keygenAlgorithm);
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public int getKeySize() {
        KeyGenParameterSpec spec = getKeyGenParameterSpec("stub");
        return spec.getKeySize();
    }

    public abstract KeyGenParameterSpec getKeyGenParameterSpec(String keyId);
}
