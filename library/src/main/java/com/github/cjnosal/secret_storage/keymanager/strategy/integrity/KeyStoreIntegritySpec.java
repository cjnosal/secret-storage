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

package com.github.cjnosal.secret_storage.keymanager.strategy.integrity;

import android.annotation.TargetApi;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

import java.security.spec.AlgorithmParameterSpec;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public abstract class KeyStoreIntegritySpec extends IntegritySpec {

    public KeyStoreIntegritySpec(String transformation, @SecurityAlgorithms.KeySize int keySize, String keygenAlgorithm) {
        super(transformation, keySize, keygenAlgorithm);
    }

    public abstract AlgorithmParameterSpec getKeyGenParameterSpec(String keyId);
}
