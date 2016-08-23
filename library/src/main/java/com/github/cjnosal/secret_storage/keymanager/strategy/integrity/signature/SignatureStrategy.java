package com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SignatureStrategy extends IntegrityStrategy {

    public SignatureStrategy(Crypto crypto, IntegritySpec spec) {
        super(crypto, spec);
    }

    @Override
    public byte[] sign(Key key, byte[] plainBytes) throws GeneralSecurityException {
        return crypto.sign((PrivateKey)key, spec.getIntegrityTransformation(), plainBytes);
    }

    @Override
    public boolean verify(Key key, byte[] cipherText, byte[] signature) throws GeneralSecurityException {
        return crypto.verify((PublicKey)key, spec.getIntegrityTransformation(), cipherText, signature);
    }
}
