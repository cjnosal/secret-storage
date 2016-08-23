package com.github.cjnosal.secret_storage.keymanager.strategy.integrity;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

public abstract class IntegrityStrategy {
    protected Crypto crypto;
    protected IntegritySpec spec;

    public IntegrityStrategy(Crypto crypto, IntegritySpec spec) {
        this.crypto = crypto;
        this.spec = spec;
    }

    public IntegritySpec getSpec() {
        return spec;
    }

    public abstract byte[] sign(Key key, byte[] plainBytes) throws GeneralSecurityException;

    public abstract boolean verify(Key key, byte[] cipherText, byte[] verification) throws GeneralSecurityException;
}
