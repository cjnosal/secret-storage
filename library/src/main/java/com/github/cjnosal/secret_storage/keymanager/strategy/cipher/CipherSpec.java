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

import java.security.spec.AlgorithmParameterSpec;

public class CipherSpec {
    private final @SecurityAlgorithms.Cipher String cipherTransformation;
    private final @SecurityAlgorithms.AlgorithmParameters String cipherAlgorithm;
    private final @SecurityAlgorithms.KeySize int keySize;
    private final String keygenAlgorithm; // key or keypair generator
    private AlgorithmParameterSpec algorithmParameterSpec;

    public CipherSpec(@SecurityAlgorithms.Cipher String cipherTransformation, @SecurityAlgorithms.AlgorithmParameters String cipherAlgorithm, @SecurityAlgorithms.KeySize int keySize, String keygenAlgorithm) {
        this.cipherTransformation = cipherTransformation;
        this.cipherAlgorithm = cipherAlgorithm;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
        this.algorithmParameterSpec = null;
    }

    public CipherSpec(@SecurityAlgorithms.Cipher String cipherTransformation, @SecurityAlgorithms.AlgorithmParameters String cipherAlgorithm, @SecurityAlgorithms.KeySize int keySize, String keygenAlgorithm, AlgorithmParameterSpec algorithmParameterSpec) {
        this.cipherTransformation = cipherTransformation;
        this.cipherAlgorithm = cipherAlgorithm;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
        this.algorithmParameterSpec = algorithmParameterSpec;
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

    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }
}
