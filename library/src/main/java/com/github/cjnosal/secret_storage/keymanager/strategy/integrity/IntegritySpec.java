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
}
