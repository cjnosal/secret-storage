package com.github.cjnosal.secret_storage.keymanager.strategy.cipher;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

public class CipherSpec {
    private final @SecurityAlgorithms.Cipher String cipherTransformation;
    private final @SecurityAlgorithms.KeySize int keySize;
    private final String keygenAlgorithm; // key or keypair generator

    public CipherSpec(@SecurityAlgorithms.Cipher String cipherTransformation, @SecurityAlgorithms.KeySize int keySize, String keygenAlgorithm) {
        this.cipherTransformation = cipherTransformation;
        this.keySize = keySize;
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public @SecurityAlgorithms.Cipher String getCipherTransformation() {
        return cipherTransformation;
    }

    public @SecurityAlgorithms.KeySize int getKeySize() {
        return keySize;
    }

    public String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }
}
