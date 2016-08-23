package com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

public class AsymmetricCipherStrategy extends CipherStrategy {

    public AsymmetricCipherStrategy(Crypto crypto, CipherSpec spec) {
        super(crypto, spec);
    }

    @Override
    public byte[] encrypt(Key key, byte[] plainBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, key, Cipher.getMaxAllowedParameterSpec(spec.getCipherTransformation()));
        return cipher.doFinal(plainBytes);
    }

    @Override
    public byte[] decrypt(Key key, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(spec.getCipherTransformation());
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }
}
