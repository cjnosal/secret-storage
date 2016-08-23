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
