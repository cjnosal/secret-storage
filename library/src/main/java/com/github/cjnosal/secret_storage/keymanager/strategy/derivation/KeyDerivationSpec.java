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
    private final @SecurityAlgorithms.SecretKeyFactory String keygenAlgorithm;

    public KeyDerivationSpec(int rounds, @SecurityAlgorithms.SecretKeyFactory String keygenAlgorithm) {
        this.rounds = rounds;
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public int getRounds() {
        return rounds;
    }

    public @SecurityAlgorithms.SecretKeyFactory String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        KeyDerivationSpec that = (KeyDerivationSpec) o;

        if (rounds != that.rounds) return false;
        return keygenAlgorithm != null ? keygenAlgorithm.equals(that.keygenAlgorithm) : that.keygenAlgorithm == null;

    }

    @Override
    public int hashCode() {
        int result = rounds;
        result = 31 * result + (keygenAlgorithm != null ? keygenAlgorithm.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "KeyDerivationSpec{" +
                "rounds=" + rounds +
                ", keygenAlgorithm='" + keygenAlgorithm + '\'' +
                '}';
    }
}
