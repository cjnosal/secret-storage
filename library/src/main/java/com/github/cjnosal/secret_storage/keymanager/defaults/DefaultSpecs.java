package com.github.cjnosal.secret_storage.keymanager.defaults;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;

public class DefaultSpecs {

    public static CipherSpec getAesCbcPkcs5CipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_CBC_PKCS5Padding,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static CipherSpec getRsaPKCS1CipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding,
                SecurityAlgorithms.KEY_SIZE_RSA_2048,
                SecurityAlgorithms.KeyPairGenerator_RSA
        );
    }

    public static IntegritySpec getShaRsaIntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Signature_SHA512withRSA,
                SecurityAlgorithms.KEY_SIZE_RSA_2048,
                SecurityAlgorithms.KeyPairGenerator_RSA
        );
    }

    public static IntegritySpec getHmacShaIntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Mac_HMACSHA256,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static KeyDerivationSpec getPbkdf2WithHmacShaDerivationSpec() {
        return new KeyDerivationSpec(
                8192,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.SecretKeyFactory_PBKDF2WithHmacSHA1,
                SecurityAlgorithms.SecretKeyFactory_AES
        );
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreCipherSpec getKeyStoreAesCbcPkcs7CipherSpec() {
        return new KeyStoreCipherSpec(SecurityAlgorithms.KeyGenerator_AES, SecurityAlgorithms.Cipher_AES_CBC_PKCS7Padding) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setKeySize(SecurityAlgorithms.KEY_SIZE_AES_256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setRandomizedEncryptionRequired(false) // allow user-provided IV or let system generate
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreIntegritySpec getKeyStoreShaRsaPssIntegritySpec() {
        return new KeyStoreIntegritySpec(SecurityAlgorithms.KeyPairGenerator_RSA, SecurityAlgorithms.Signature_SHA512withRSA_PSS) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setKeySize(SecurityAlgorithms.KEY_SIZE_RSA_2048)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                        .setDigests(KeyProperties.DIGEST_SHA512)
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreCipherSpec getKeyStoreRsaPkcs1CipherSpec() {
        return new KeyStoreCipherSpec(SecurityAlgorithms.KeyPairGenerator_RSA, SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(SecurityAlgorithms.KEY_SIZE_RSA_2048)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreIntegritySpec getKeyStoreHmacShaIntegritySpec() {
        return new KeyStoreIntegritySpec(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KeyProperties.KEY_ALGORITHM_HMAC_SHA256) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
                        .setKeySize(SecurityAlgorithms.KEY_SIZE_AES_128)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build();
            }
        };
    }

}
