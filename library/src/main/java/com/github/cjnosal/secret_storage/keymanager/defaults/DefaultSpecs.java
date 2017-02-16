/*
 *    Copyright 2016 Conor Nosal
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
                SecurityAlgorithms.AlgorithmParameters_AES,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static CipherSpec getAesGcmCipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_GCM_NoPadding,
                SecurityAlgorithms.AlgorithmParameters_GCM,
                SecurityAlgorithms.KEY_SIZE_AES_256,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static CipherSpec getRsaPKCS1CipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding,
                null,
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
        return new KeyStoreCipherSpec(SecurityAlgorithms.KeyGenerator_AES, SecurityAlgorithms.AlgorithmParameters_AES, SecurityAlgorithms.Cipher_AES_CBC_PKCS7Padding) {

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
        return new KeyStoreCipherSpec(SecurityAlgorithms.KeyPairGenerator_RSA, null, SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding) {

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
