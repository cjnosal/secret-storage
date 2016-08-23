package com.github.cjnosal.secret_storage.keymanager.defaults;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;

public class DefaultStrategies {

    // TODO strongest supported ciphers for the device/os

    public static ProtectionStrategy getDataProtectionStrategy(Crypto crypto) {
        CipherStrategy cipher = new SymmetricCipherStrategy(crypto, DefaultSpecs.getAesCbcPkcs5CipherSpec());
        IntegrityStrategy integrity = new MacStrategy(crypto, DefaultSpecs.getHmacShaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }

    public static ProtectionStrategy getPasswordBasedKeyProtectionStrategy(Crypto crypto) {
        return getDataProtectionStrategy(crypto);
    }

    public static ProtectionStrategy getAsymmetricKeyProtectionStrategy(Crypto crypto) {
        CipherStrategy cipher = new AsymmetricCipherStrategy(crypto, DefaultSpecs.getRsaPKCS1CipherSpec());
        IntegrityStrategy integrity = new SignatureStrategy(crypto, DefaultSpecs.getShaRsaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }

    public static ProtectionStrategy getKeyStoreDataProtectionStrategy(Crypto crypto) {
        CipherStrategy cipher = new SymmetricCipherStrategy(crypto, DefaultSpecs.getKeyStoreAesCbcPkcs7CipherSpec());
        IntegrityStrategy integrity = new MacStrategy(crypto, DefaultSpecs.getKeyStoreHmacShaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }
}
