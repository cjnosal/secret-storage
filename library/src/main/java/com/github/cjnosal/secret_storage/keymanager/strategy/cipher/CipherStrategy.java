package com.github.cjnosal.secret_storage.keymanager.strategy.cipher;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

public abstract class CipherStrategy {
    protected Crypto crypto;
    protected CipherSpec spec;

    public CipherStrategy(Crypto crypto, CipherSpec spec) {
        this.crypto = crypto;
        this.spec = spec;
    }

    public CipherSpec getSpec() {
        return spec;
    }

    public abstract byte[] encrypt(Key key, byte[] plainBytes) throws GeneralSecurityException;

    public abstract byte[] decrypt(Key key, byte[] cipherText) throws GeneralSecurityException;
}
