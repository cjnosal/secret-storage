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

package com.github.cjnosal.secret_storage.keymanager.strategy.keygen;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

public class KeyPairGenSpec {
    private final @SecurityAlgorithms.KeySize int keySize;
    private final @SecurityAlgorithms.KeyPairGenerator String keygenAlgorithm;

    public KeyPairGenSpec(int keySize, @SecurityAlgorithms.KeyPairGenerator String keygenAlgorithm) {
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public @SecurityAlgorithms.KeyPairGenerator String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        KeyPairGenSpec that = (KeyPairGenSpec) o;

        if (keySize != that.keySize) return false;
        return keygenAlgorithm != null ? keygenAlgorithm.equals(that.keygenAlgorithm) : that.keygenAlgorithm == null;

    }

    @Override
    public int hashCode() {
        int result = keySize;
        result = 31 * result + (keygenAlgorithm != null ? keygenAlgorithm.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "KeyGenSpec{" +
                "keySize=" + keySize +
                ", keygenAlgorithm='" + keygenAlgorithm + '\'' +
                '}';
    }
}
