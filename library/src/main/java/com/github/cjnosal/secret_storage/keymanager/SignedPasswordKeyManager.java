package com.github.cjnosal.secret_storage.keymanager;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.spec.SecretKeySpec;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class SignedPasswordKeyManager extends PasswordKeyManager {
    private static final String ENC_SALT = "ENC_SALT";
    private static final String SIG_SALT = "SIG_SALT";

    private final Context context;
    private final String storeId;
    private final AndroidCrypto androidCrypto;
    private final IntegritySpec derivationSignatureSpec;

    public SignedPasswordKeyManager(Context context, String storeId, Crypto crypto, AndroidCrypto androidCrypto, ProtectionStrategy dataProtectionStrategy, KeyDerivationSpec keyDerivationSpec, IntegritySpec derivationSignatureSpec, ProtectionStrategy keyProtectionStrategy, DataStorage keyStorage, DataStorage configStorage) throws GeneralSecurityException, IOException {
        super(crypto, dataProtectionStrategy, keyDerivationSpec, keyProtectionStrategy, keyStorage, configStorage);
        this.context = context;
        this.storeId = storeId;
        this.androidCrypto = androidCrypto;
        this.derivationSignatureSpec = derivationSignatureSpec;

        if (keyProtectionStrategy.getCipherStrategy() instanceof AsymmetricCipherStrategy ||
                keyProtectionStrategy.getIntegrityStrategy() instanceof SignatureStrategy) {
            throw new IllegalArgumentException("PasswordKeyManager needs symmetric strategy for key protection");
        }

        // TODO check if derivationSignatureSpec is asymmetric
    }

    protected void generateKek(String password) throws IOException, GeneralSecurityException {

        byte[] encSalt;
        byte[] sigSalt;
        PrivateKey signingKey;
        if (configStorage.exists(ENC_SALT) && configStorage.exists(SIG_SALT) && androidCrypto.hasEntry(storeId + "D")) {
            encSalt = configStorage.load(ENC_SALT);
            sigSalt = configStorage.load(SIG_SALT);
            signingKey = androidCrypto.loadPrivateKey(storeId + "D");
        } else {
            encSalt = crypto.generateBytes(derivationSpec.getKeySize() / 8);
            sigSalt = crypto.generateBytes(derivationSpec.getKeySize() / 8);
            configStorage.store(ENC_SALT, encSalt);
            configStorage.store(SIG_SALT, sigSalt);
            signingKey = androidCrypto.generateKeyPair(context, storeId + "D", derivationSignatureSpec.getKeygenAlgorithm()).getPrivate();
        }

        byte[] firstHash = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, encSalt, derivationSpec.getRounds()).getEncoded();
        byte[] signature = crypto.sign(signingKey, derivationSignatureSpec.getIntegrityTransformation(), firstHash);
        String signatureString = Encoding.base64Encode(signature);

        Key secondHash = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), signatureString, encSalt, derivationSpec.getRounds());
        derivedEncKey = new SecretKeySpec(secondHash.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());

        firstHash = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), password, sigSalt, derivationSpec.getRounds()).getEncoded();
        signature = crypto.sign(signingKey, derivationSignatureSpec.getIntegrityTransformation(), firstHash); // TODO HMAC on M+
        signatureString = Encoding.base64Encode(signature);

        secondHash = crypto.deriveKey(derivationSpec.getKeygenAlgorithm(), derivationSpec.getKeySize(), signatureString, sigSalt, derivationSpec.getRounds());
        derivedSigKey = new SecretKeySpec(secondHash.getEncoded(), 0, derivationSpec.getKeySize() / 8, derivationSpec.getKeyspecAlgorithm());

        // TODO allow (and verify) user password
    }

}
