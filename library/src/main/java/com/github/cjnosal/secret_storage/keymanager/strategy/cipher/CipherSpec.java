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

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

public class CipherSpec {
    private final @SecurityAlgorithms.Cipher String cipherTransformation;
    private final @SecurityAlgorithms.AlgorithmParameters String cipherAlgorithm;
    private final @SecurityAlgorithms.KeySize int keySize;
    private final String keygenAlgorithm; // key or keypair generator

    public CipherSpec(@SecurityAlgorithms.Cipher String cipherTransformation, @SecurityAlgorithms.AlgorithmParameters String cipherAlgorithm, @SecurityAlgorithms.KeySize int keySize, String keygenAlgorithm) {
        this.cipherTransformation = cipherTransformation;
        this.cipherAlgorithm = cipherAlgorithm;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public @SecurityAlgorithms.Cipher String getCipherTransformation() {
        return cipherTransformation;
    }

    public @SecurityAlgorithms.AlgorithmParameters String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public @SecurityAlgorithms.KeySize int getKeySize() {
        return keySize;
    }

    public String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CipherSpec that = (CipherSpec) o;

        if (keySize != that.keySize) return false;
        if (cipherTransformation != null ? !cipherTransformation.equals(that.cipherTransformation) : that.cipherTransformation != null)
            return false;
        if (cipherAlgorithm != null ? !cipherAlgorithm.equals(that.cipherAlgorithm) : that.cipherAlgorithm != null)
            return false;
        return keygenAlgorithm != null ? keygenAlgorithm.equals(that.keygenAlgorithm) : that.keygenAlgorithm == null;

    }

    @Override
    public int hashCode() {
        int result = cipherTransformation != null ? cipherTransformation.hashCode() : 0;
        result = 31 * result + (cipherAlgorithm != null ? cipherAlgorithm.hashCode() : 0);
        result = 31 * result + keySize;
        result = 31 * result + (keygenAlgorithm != null ? keygenAlgorithm.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "CipherSpec{" +
                "cipherTransformation='" + cipherTransformation + '\'' +
                ", cipherAlgorithm='" + cipherAlgorithm + '\'' +
                ", keySize=" + keySize +
                ", keygenAlgorithm='" + keygenAlgorithm + '\'' +
                '}';
    }
}
