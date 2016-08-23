package com.github.cjnosal.secret_storage.keymanager;

import android.annotation.TargetApi;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreManager extends KeyManager {

    // TODO backport KeyProperties
    // TODO map Ciphers to blocks/paddings/digests so KeyGenParameterSpecs can be created from CipherSpec/IntegritySpec
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent
    // TODO unlock with fingerprint

    private AndroidCrypto androidCrypto;
    private String storeId;

    public KeyStoreManager(AndroidCrypto androidCrypto, String storeId, ProtectionStrategy dataProtectionStrategy) {
        super(dataProtectionStrategy);
        this.androidCrypto = androidCrypto;
        this.storeId = storeId;
    }

    @Override
    public Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        KeyStoreCipherSpec spec = (KeyStoreCipherSpec) dataProtectionStrategy.getCipherStrategy().getSpec();
        if (dataProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + keyId + "E"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + keyId + "E")).getPublic();
        }
    }

    @Override
    public Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException {
        KeyStoreIntegritySpec spec = (KeyStoreIntegritySpec) dataProtectionStrategy.getIntegrityStrategy().getSpec();
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.generateSecretKey(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + keyId + "S"));
        } else {
            return androidCrypto.generateKeyPair(spec.getKeygenAlgorithm(), spec.getKeyGenParameterSpec(storeId + keyId + "S")).getPrivate();
        }
    }

    @Override
    public Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy) {
            return androidCrypto.loadSecretKey(storeId + keyId + "E");
        } else {
            return androidCrypto.loadKeyPair(storeId + keyId + "E").getPrivate();
        }
    }

    @Override
    public Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException {
        if (dataProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            return androidCrypto.loadSecretKey(storeId + keyId + "S");
        } else {
            return androidCrypto.loadPublicKey(storeId + keyId + "S");
        }
    }
}
