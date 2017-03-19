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
import com.github.cjnosal.secret_storage.keymanager.strategy.DataProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyStoreKeyGenSpec;

/**
 * As of January 2016 the Commercial National Security Algorithm Suite recommends:
 *
 * RSA 3072 (key establishment, digital signature)
 * DH 3072 (key establishment)
 * ECDH 384 (key establishment)
 * ECDSA 384 (digital signature)
 * SHA 384 (integrity)
 * AES 256 (confidentiality)
 *
 */
public class DefaultSpecs {

    public static DataProtectionSpec getDataProtectionSpec(int osVersion) {
        CipherSpec cipher;
        IntegritySpec integrity;
        KeyGenSpec keygen;
        if (osVersion >= Build.VERSION_CODES.M) {
            // Use authenticated-encryption primitive when available
            // MacStrategy is redundant but avoids special handling for particular strategies
            cipher = getAesGcmCipherSpec();
            integrity = getHmacSha384IntegritySpec();
            keygen = getAes256KeyGenSpec();
        } else {
            cipher = getAesCbcPkcs5CipherSpec();
            integrity = getHmacSha256IntegritySpec();
            keygen = getAes128KeyGenSpec();
        }
        return new DataProtectionSpec(cipher, integrity, keygen, keygen);
    }

    public static KeyGenSpec getAes128KeyGenSpec() {
        return new KeyGenSpec(SecurityAlgorithms.KEY_SIZE_AES_128, SecurityAlgorithms.KeyGenerator_AES);
    }

    public static KeyGenSpec getAes256KeyGenSpec() {
        return new KeyGenSpec(SecurityAlgorithms.KEY_SIZE_AES_256, SecurityAlgorithms.KeyGenerator_AES);
    }

    public static KeyGenSpec getRsa2048KeyGenSpec() {
        return new KeyGenSpec(SecurityAlgorithms.KEY_SIZE_RSA_2048, SecurityAlgorithms.KeyPairGenerator_RSA);
    }

    public static KeyGenSpec getEc384KeyGenSpec() {
        return new KeyGenSpec(SecurityAlgorithms.KEY_SIZE_EC_384, SecurityAlgorithms.KeyPairGenerator_EC);
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyGenSpec getKeyStoreAes256GcmKeyGenSpec() {
        // KeyAlias and purpose will be set by KeyStoreWrapper
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("placeholder", 0)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(SecurityAlgorithms.KEY_SIZE_AES_256)
                .setRandomizedEncryptionRequired(true)
                .build();

        return new KeyStoreKeyGenSpec(spec, SecurityAlgorithms.KeyGenerator_AES);
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyGenSpec getFingerprintKeyStoreAes256GcmKeyGenSpec() {
        // KeyAlias and purpose will be set by KeyStoreWrapper
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("placeholder", 0)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(SecurityAlgorithms.KEY_SIZE_AES_256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
                .build();

        return new KeyStoreKeyGenSpec(spec, SecurityAlgorithms.KeyGenerator_AES);
    }

    public static CipherSpec getAesCbcPkcs5CipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_CBC_PKCS5Padding,
                SecurityAlgorithms.AlgorithmParameters_AES
        );
    }

    public static CipherSpec getAesGcmCipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_GCM_NoPadding,
                SecurityAlgorithms.AlgorithmParameters_GCM
        );
    }

    public static CipherSpec getAesWrapSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AESWRAP,
                SecurityAlgorithms.AlgorithmParameters_AES
        );
    }

    public static CipherSpec getRsaEcbPkcs1Spec() {
        return new CipherSpec(SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding, null);
    }

    public static IntegritySpec getHmacSha256IntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Mac_HMACSHA256
        );
    }

    public static IntegritySpec getHmacSha384IntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Mac_HMACSHA384
        );
    }

    public static IntegritySpec getSha256WithRsaSpec() {
        return new IntegritySpec(SecurityAlgorithms.Signature_SHA256withRSA);
    }

    public static IntegritySpec getSha384WithEcdsaSpec() {
        return new IntegritySpec(SecurityAlgorithms.Signature_SHA384withECDSA);
    }

    public static KeyDerivationSpec get4096RoundPBKDF2WithHmacSHA1() {
        return new KeyDerivationSpec(
                4096,
                SecurityAlgorithms.SecretKeyFactory_PBKDF2WithHmacSHA1
        );
    }

    public static KeyDerivationSpec get8192RoundPBKDF2WithHmacSHA1() {
        return new KeyDerivationSpec(
                8192,
                SecurityAlgorithms.SecretKeyFactory_PBKDF2WithHmacSHA1
        );
    }

}
