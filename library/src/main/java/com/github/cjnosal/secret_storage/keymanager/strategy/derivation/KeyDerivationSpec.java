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

package com.github.cjnosal.secret_storage.keymanager.strategy.derivation;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

public class KeyDerivationSpec {
    private final int rounds;
    private final @SecurityAlgorithms.KeySize int keySize;
    private final @SecurityAlgorithms.SecretKeyFactory String keygenAlgorithm;
    private final @SecurityAlgorithms.SecretKeyFactory String keyspecAlgorithm;

    public KeyDerivationSpec(int rounds, @SecurityAlgorithms.KeySize int keySize, @SecurityAlgorithms.SecretKeyFactory String keygenAlgorithm, @SecurityAlgorithms.SecretKeyFactory String keyspecAlgorithm) {
        this.rounds = rounds;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
        this.keyspecAlgorithm = keyspecAlgorithm;
    }

    public int getRounds() {
        return rounds;
    }

    public @SecurityAlgorithms.KeySize int getKeySize() {
        return keySize;
    }

    public @SecurityAlgorithms.SecretKeyFactory String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    public @SecurityAlgorithms.SecretKeyFactory String getKeyspecAlgorithm() {
        return keyspecAlgorithm;
    }
}
