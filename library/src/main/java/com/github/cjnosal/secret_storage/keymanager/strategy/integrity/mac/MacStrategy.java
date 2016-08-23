package com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.SecretKey;

public class MacStrategy extends IntegrityStrategy {

    public MacStrategy(Crypto crypto, IntegritySpec spec) {
        super(crypto, spec);
    }

    @Override
    public byte[] sign(Key key, byte[] plainBytes) throws GeneralSecurityException {
        return crypto.sign((SecretKey) key, spec.getIntegrityTransformation(), plainBytes);
    }

    @Override
    public boolean verify(Key key, byte[] cipherText, byte[] mac) throws GeneralSecurityException {
        return crypto.verify((SecretKey)key, spec.getIntegrityTransformation(), cipherText, mac);
    }
}
