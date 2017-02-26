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
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

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

    public static ProtectionSpec getDataProtectionSpec(int osVersion) {
        CipherSpec cipher;
        IntegritySpec integrity;
        if (osVersion >= Build.VERSION_CODES.M) {
            // Use authenticated-encryption primitive when available
            // MacStrategy is redundant but avoids special handling for particular strategies
            cipher = getAesGcmCipherSpec();
            integrity = getStrongHmacShaIntegritySpec();
        } else {
            cipher = getAesCbcPkcs5CipherSpec();
            integrity = getHmacShaIntegritySpec();
        }
        return new ProtectionSpec(cipher, integrity);
    }

    public static CipherSpec getAesCbcPkcs5CipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_CBC_PKCS5Padding,
                SecurityAlgorithms.AlgorithmParameters_AES,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static CipherSpec getAesGcmCipherSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AES_GCM_NoPadding,
                SecurityAlgorithms.AlgorithmParameters_GCM,
                SecurityAlgorithms.KEY_SIZE_AES_256,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static IntegritySpec getHmacShaIntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Mac_HMACSHA256,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static IntegritySpec getStrongHmacShaIntegritySpec() {
        return new IntegritySpec(
                SecurityAlgorithms.Mac_HMACSHA384,
                SecurityAlgorithms.KEY_SIZE_AES_256,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static KeyDerivationSpec getPasswordDerivationSpec() {
        return new KeyDerivationSpec(
                4096,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.SecretKeyFactory_PBKDF2WithHmacSHA1,
                SecurityAlgorithms.SecretKeyFactory_AES
        );
    }

    public static KeyDerivationSpec getStrongPasswordDerivationSpec() {
        return new KeyDerivationSpec(
                8192,
                SecurityAlgorithms.KEY_SIZE_AES_256,
                SecurityAlgorithms.SecretKeyFactory_PBKDF2WithHmacSHA1,
                SecurityAlgorithms.SecretKeyFactory_AES
        );
    }

    public static IntegritySpec getPasswordDeviceBindingSpec(Context context) {
        return getAsymmetricKeyStoreIntegritySpec(context);
    }

    public static CipherSpec getPasswordBasedKeyProtectionSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AESWRAP,
                SecurityAlgorithms.AlgorithmParameters_AES,
                SecurityAlgorithms.KEY_SIZE_AES_128,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    public static CipherSpec getStrongPasswordBasedKeyProtectionSpec() {
        return new CipherSpec(
                SecurityAlgorithms.Cipher_AESWRAP,
                SecurityAlgorithms.AlgorithmParameters_AES,
                SecurityAlgorithms.KEY_SIZE_AES_256,
                SecurityAlgorithms.KeyGenerator_AES
        );
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static KeyStoreCipherSpec getAsymmetricKeyStoreCipherSpec(final Context context) {
        return new KeyStoreCipherSpec(SecurityAlgorithms.Cipher_RSA_ECB_PKCS1Padding, null, SecurityAlgorithms.KEY_SIZE_RSA_2048, SecurityAlgorithms.KeyPairGenerator_RSA) {

            @Override
            public AlgorithmParameterSpec getKeyGenParameterSpec(String keyId) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 10);
                return new KeyPairGeneratorSpec.Builder(context)
                                .setAlias(keyId)
                                .setSubject(new X500Principal("CN=" + keyId))
                                .setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                                .setStartDate(start.getTime())
                                .setEndDate(end.getTime())
                                .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static KeyStoreIntegritySpec getAsymmetricKeyStoreIntegritySpec(final Context context) {
        return new KeyStoreIntegritySpec(SecurityAlgorithms.Signature_SHA256withRSA, SecurityAlgorithms.KEY_SIZE_RSA_2048, SecurityAlgorithms.KeyPairGenerator_RSA) {

            @Override
            public AlgorithmParameterSpec getKeyGenParameterSpec(String keyId) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 10);
                return new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(keyId)
                        .setSubject(new X500Principal("CN=" + keyId))
                        .setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreCipherSpec getKeyStoreCipherSpec() {
        return new KeyStoreCipherSpec(SecurityAlgorithms.Cipher_AES_GCM_NoPadding, SecurityAlgorithms.AlgorithmParameters_GCM, SecurityAlgorithms.KEY_SIZE_AES_256, SecurityAlgorithms.KeyGenerator_AES) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setKeySize(getKeySize())
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreIntegritySpec getKeyStoreSignatureSpec() {
        return new KeyStoreIntegritySpec(SecurityAlgorithms.Signature_SHA384withECDSA, SecurityAlgorithms.KEY_SIZE_EC_384, SecurityAlgorithms.KeyPairGenerator_EC) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setKeySize(getKeySize())
                        .setDigests(KeyProperties.DIGEST_SHA384)
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreCipherSpec getKeyStoreKeyWrapSpec() {
        return new KeyStoreCipherSpec(SecurityAlgorithms.Cipher_RSA_ECB_OAEPWithSHA_384AndMGF1Padding, null, SecurityAlgorithms.KEY_SIZE_RSA_3072, SecurityAlgorithms.KeyPairGenerator_RSA) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(getKeySize())
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build();
            }
        };
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static KeyStoreIntegritySpec getKeyStoreMessageDigestSpec() {
        return new KeyStoreIntegritySpec(KeyProperties.KEY_ALGORITHM_HMAC_SHA384, SecurityAlgorithms.KEY_SIZE_AES_256, KeyProperties.KEY_ALGORITHM_HMAC_SHA384) {

            @Override
            public KeyGenParameterSpec getKeyGenParameterSpec(String keyId) {
                return new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
                        .setKeySize(getKeySize())
                        .setDigests(KeyProperties.DIGEST_SHA384)
                        .build();
            }
        };
    }

}
