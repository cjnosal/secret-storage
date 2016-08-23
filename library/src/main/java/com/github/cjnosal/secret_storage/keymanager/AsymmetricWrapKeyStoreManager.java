package com.github.cjnosal.secret_storage.keymanager;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.storage.encoding.KeyEncoding;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.SecretKey;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class AsymmetricWrapKeyStoreManager extends KeyManager {

    private Context context;
    private AndroidCrypto androidCrypto;
    private Crypto crypto;
    private String storeId;
    private DataStorage keyStorage;
    private ProtectionStrategy keyProtectionStrategy;
    private KeyEncoding keyEncoding = new KeyEncoding();

    private KeyPair signingKeys;
    private KeyPair encryptionKeys;

    // TODO refactor to extend KeyStoreManager to override symmetric key generation?
    // TODO expose parameter for setUserAuthenticationRequired to allow the app to use KeyGuardManager.createConfirmDeviceCredentialIntent

    public AsymmetricWrapKeyStoreManager(Context context, Crypto crypto, AndroidCrypto androidCrypto, String storeId, ProtectionStrategy dataProtectionStrategy, DataStorage keyStorage, ProtectionStrategy keyProtectionStrategy) throws GeneralSecurityException, IOException {
        super(dataProtectionStrategy);
        this.context = context;
        this.crypto = crypto;
        this.androidCrypto = androidCrypto;
        this.storeId = storeId;
        this.keyStorage = keyStorage;
        this.keyProtectionStrategy = keyProtectionStrategy;

        if (keyProtectionStrategy.getCipherStrategy() instanceof SymmetricCipherStrategy ||
                keyProtectionStrategy.getIntegrityStrategy() instanceof MacStrategy) {
            throw new IllegalArgumentException("AsymmetricWrapKeyStoreManager needs asymmetric strategy for key protection");
        }

        initWrappingKeys();
    }

    @Override
    public Key generateEncryptionKey(String keyId) throws GeneralSecurityException, IOException {
        return generateEncryptionKey(dataProtectionStrategy.getCipherStrategy(), keyId);
    }

    @Override
    public Key generateSigningKey(String keyId) throws GeneralSecurityException, IOException {
        return generateSigningKey(dataProtectionStrategy.getIntegrityStrategy(), keyId);
    }

    @Override
    public Key loadDecryptionKey(String keyId) throws GeneralSecurityException, IOException {
        return loadDecryptionKey(dataProtectionStrategy.getCipherStrategy(), keyId);
    }

    @Override
    public Key loadVerificationKey(String keyId) throws GeneralSecurityException, IOException {
        return loadVerificationKey(dataProtectionStrategy.getIntegrityStrategy(), keyId);
    }

    private Key generateEncryptionKey(CipherStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        CipherSpec cipherSpec = strategy.getSpec();
        if (strategy instanceof SymmetricCipherStrategy) {
            SecretKey encryptionKey = crypto.generateSecretKey(cipherSpec.getKeygenAlgorithm(), cipherSpec.getKeySize());
            byte[] wrappedDecKey = keyProtectionStrategy.encryptAndSign(encryptionKeys.getPublic(), signingKeys.getPrivate(), keyEncoding.encodeKey(encryptionKey));
            keyStorage.store(keyId + "E", wrappedDecKey);
            return encryptionKey;
        } else {
            KeyPair encryptionKey = androidCrypto.generateKeyPair(context, keyId + "E", cipherSpec.getKeygenAlgorithm());
            return encryptionKey.getPublic();
        }
    }

    private Key generateSigningKey(IntegrityStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        IntegritySpec integritySpec = strategy.getSpec();
        if (strategy instanceof MacStrategy) {
            SecretKey signingKey = crypto.generateSecretKey(integritySpec.getKeygenAlgorithm(), integritySpec.getKeySize());
            byte[] wrappedVerKey = keyProtectionStrategy.encryptAndSign(encryptionKeys.getPublic(), signingKeys.getPrivate(), keyEncoding.encodeKey(signingKey));
            keyStorage.store(keyId + "S", wrappedVerKey);
            return signingKey;
        } else {
            KeyPair signingKey = androidCrypto.generateKeyPair(context, keyId + "S", integritySpec.getKeygenAlgorithm());
            return signingKey.getPrivate();
        }
    }

    private Key loadDecryptionKey(CipherStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        if (strategy instanceof SymmetricCipherStrategy) {
            byte[] wrappedDecKey = keyStorage.load(keyId + "E");
            Key kek = encryptionKeys.getPrivate();
            Key ksk = signingKeys.getPublic();
            return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(kek, ksk, wrappedDecKey));
        } else {
            KeyPair encryptionKey = androidCrypto.loadKeyPair(keyId + "E");
            return encryptionKey.getPrivate();
        }
    }

    private Key loadVerificationKey(IntegrityStrategy strategy, String keyId) throws GeneralSecurityException, IOException {
        if (strategy instanceof MacStrategy) {
            byte[] wrappedDecKey = keyStorage.load(keyId + "S");
            Key kek = encryptionKeys.getPrivate();
            Key ksk = signingKeys.getPublic();
            return keyEncoding.decodeKey(keyProtectionStrategy.verifyAndDecrypt(kek, ksk, wrappedDecKey));
        } else {
            KeyPair encryptionKey = androidCrypto.loadKeyPair(keyId + "S");
            return encryptionKey.getPublic();
        }
    }

    private void initWrappingKeys() throws GeneralSecurityException, IOException {
        if (androidCrypto.hasEntry(storeId + "E") && androidCrypto.hasEntry(storeId + "S")) {
            encryptionKeys = androidCrypto.loadKeyPair(storeId + "E");
            signingKeys = androidCrypto.loadKeyPair(storeId + "S");
        } else {
            encryptionKeys = androidCrypto.generateKeyPair(context, storeId + "E", keyProtectionStrategy.getCipherStrategy().getSpec().getKeygenAlgorithm());
            signingKeys = androidCrypto.generateKeyPair(context, storeId + "S", keyProtectionStrategy.getIntegrityStrategy().getSpec().getKeygenAlgorithm());
        }
    }
}
