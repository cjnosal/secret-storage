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

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

public class IntegritySpec {
    private final String cipherTransformation; // Mac or Signature
    private final @SecurityAlgorithms.KeySize int keySize;
    private final @SecurityAlgorithms.KeyGenerator String keygenAlgorithm;

    public IntegritySpec(String cipherTransformation, @SecurityAlgorithms.KeySize int keySize, @SecurityAlgorithms.KeyGenerator String keygenAlgorithm) {
        this.cipherTransformation = cipherTransformation;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public String getIntegrityTransformation() {
        return cipherTransformation;
    }

    public @SecurityAlgorithms.KeySize int getKeySize() {
        return keySize;
    }

    public @SecurityAlgorithms.KeyGenerator String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IntegritySpec that = (IntegritySpec) o;

        if (keySize != that.keySize) return false;
        if (cipherTransformation != null ? !cipherTransformation.equals(that.cipherTransformation) : that.cipherTransformation != null)
            return false;
        return keygenAlgorithm != null ? keygenAlgorithm.equals(that.keygenAlgorithm) : that.keygenAlgorithm == null;

    }

    @Override
    public int hashCode() {
        int result = cipherTransformation != null ? cipherTransformation.hashCode() : 0;
        result = 31 * result + keySize;
        result = 31 * result + (keygenAlgorithm != null ? keygenAlgorithm.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "IntegritySpec{" +
                "cipherTransformation='" + cipherTransformation + '\'' +
                ", keySize=" + keySize +
                ", keygenAlgorithm='" + keygenAlgorithm + '\'' +
                '}';
    }
}
