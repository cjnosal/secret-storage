package com.github.cjnosal.secret_storage.keymanager;

import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public abstract class KeyManager {

    protected final ProtectionStrategy dataProtectionStrategy;

    public KeyManager(ProtectionStrategy dataProtectionStrategy) {
        this.dataProtectionStrategy = dataProtectionStrategy;
    }

    public byte[] encrypt(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        Key encryptionKey = generateEncryptionKey(id);
        Key signingKey = generateSigningKey(id);
        return dataProtectionStrategy.encryptAndSign(encryptionKey, signingKey, plainText);
    }

    public byte[] decrypt(String id, byte[] cipherText) throws GeneralSecurityException, IOException {
        Key decryptionKey = loadDecryptionKey(id);
        Key verificationKey = loadVerificationKey(id);
        return dataProtectionStrategy.verifyAndDecrypt(decryptionKey, verificationKey, cipherText);
    }

    protected abstract Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException;

    protected abstract Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException;

    // TODO load encryption/signing key to allow reuse

    protected abstract Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException;

    protected abstract Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException;
}
