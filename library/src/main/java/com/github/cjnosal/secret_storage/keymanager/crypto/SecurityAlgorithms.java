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

package com.github.cjnosal.secret_storage.keymanager.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.support.annotation.IntDef;
import android.support.annotation.StringDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

public class SecurityAlgorithms {

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KEY_FORMAT_X509,
            KEY_FORMAT_PKCS8,
            KEY_FORMAT_RAW
    })
    public @interface KeyFormat {
    }

    public static final String KEY_FORMAT_X509 = "X.509";
    public static final String KEY_FORMAT_PKCS8 = "PKCS#8";
    public static final String KEY_FORMAT_RAW = "RAW";

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            KEY_SIZE_AES_128,
            KEY_SIZE_AES_192,
            KEY_SIZE_AES_256,
            KEY_SIZE_RSA_512,
            KEY_SIZE_RSA_768,
            KEY_SIZE_RSA_1024,
            KEY_SIZE_RSA_2048,
            KEY_SIZE_RSA_3072,
            KEY_SIZE_RSA_4096,
            KEY_SIZE_EC_224,
            KEY_SIZE_EC_256,
            KEY_SIZE_EC_384,
            KEY_SIZE_EC_521,
            KEY_SIZE_HMAC_160,
            KEY_SIZE_HMAC_224,
            KEY_SIZE_HMAC_256,
            KEY_SIZE_HMAC_384,
            KEY_SIZE_HMAC_512
    })
    public @interface KeySize {
    }

    public static final int KEY_SIZE_AES_128 = 128;
    public static final int KEY_SIZE_AES_192 = 192;
    public static final int KEY_SIZE_AES_256 = 256;
    @Deprecated public static final int KEY_SIZE_RSA_512 = 512; // recommended length 2048+
    @Deprecated public static final int KEY_SIZE_RSA_768 = 768; // recommended length 2048+
    @Deprecated public static final int KEY_SIZE_RSA_1024 = 1024; // recommended length 2048+
    public static final int KEY_SIZE_RSA_2048 = 2048;
    public static final int KEY_SIZE_RSA_3072 = 3072;
    public static final int KEY_SIZE_RSA_4096 = 4096;
    public static final int KEY_SIZE_EC_224 = 224;
    public static final int KEY_SIZE_EC_256 = 256;
    public static final int KEY_SIZE_EC_384 = 384;
    public static final int KEY_SIZE_EC_521 = 521;
    public static final int KEY_SIZE_HMAC_160 = 160;
    public static final int KEY_SIZE_HMAC_224 = 224;
    public static final int KEY_SIZE_HMAC_256 = 256;
    public static final int KEY_SIZE_HMAC_384 = 384;
    public static final int KEY_SIZE_HMAC_512 = 512;
    // TODO define key sizes for more ciphers

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            BLOCK_SIZE_AES_128
    })
    public @interface BlockSize {
    }

    public static final int BLOCK_SIZE_AES_128 = 128; // IV must match block size for block modes (e.g. CBC)
    // TODO define block sizes for more ciphers

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            IV_SIZE_AES_96,
            IV_SIZE_AES_128
    })
    public @interface IVSize {
    }

    public static final int IV_SIZE_AES_96 = 96; // GCM stream mode recommends 96 bit IV for performance reasons
    public static final int IV_SIZE_AES_128 = 128; // IV must match block size for block modes (e.g. CBC)
    // TODO define iv sizes for more ciphers

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({
            TAG_SIZE_GCM_32,
            TAG_SIZE_GCM_64,
            TAG_SIZE_GCM_96,
            TAG_SIZE_GCM_104,
            TAG_SIZE_GCM_112,
            TAG_SIZE_GCM_120,
            TAG_SIZE_GCM_128
    })
    @TargetApi(Build.VERSION_CODES.KITKAT) public @interface TagSize {
    }

    public static final int TAG_SIZE_GCM_32 = 32; // for audio/video streams where packets can be discarded
    public static final int TAG_SIZE_GCM_64 = 64; // for audio/video streams where packets can be discarded
    public static final int TAG_SIZE_GCM_96 = 96;
    public static final int TAG_SIZE_GCM_104 = 104;
    public static final int TAG_SIZE_GCM_112 = 112;
    public static final int TAG_SIZE_GCM_120 = 120;
    public static final int TAG_SIZE_GCM_128 = 128;

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            MASK_MGF1
    })
    public @interface MaskGeneration {
    }

    public static final String MASK_MGF1 = "MGF1"; // for RSA OAEP

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            SecurityProvider_AndroidKeyStore,    // Version 1.0 Android KeyStore security provider
            SecurityProvider_AndroidKeyStoreBCWorkaround,    // Version 1.0 Android KeyStore security provider to work around Bouncy Castle
            SecurityProvider_AndroidOpenSSL,    // Version 1.0 Android's OpenSSL-backed security provider
            SecurityProvider_BC,    // Version 1.52 BouncyCastle Security Provider v1.52
            SecurityProvider_Crypto,    // Version 1.0 HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)
            SecurityProvider_GmsCore_OpenSSL,	// Version 1.0 Android's OpenSSL-backed security provider
            SecurityProvider_HarmonyJSSE    // Version 1.0 Harmony JSSE Provider
    })
    public @interface SecurityProvider {
    }

    public static final String SecurityProvider_AndroidKeyStore = "AndroidKeyStore";
    public static final String SecurityProvider_AndroidKeyStoreBCWorkaround = "AndroidKeyStoreBCWorkaround";
    public static final String SecurityProvider_AndroidOpenSSL = "AndroidOpenSSL";
    public static final String SecurityProvider_BC = "BC";
    @Deprecated public static final String SecurityProvider_Crypto = "Crypto"; // provides legacy SHA1PRNG, replaced by OpenSSL
    public static final String SecurityProvider_GmsCore_OpenSSL = "GmsCore_OpenSSL"; // if installed with GMS's ProviderInstaller
    @Deprecated public static final String SecurityProvider_HarmonyJSSE = "HarmonyJSSE"; // provides legacy SSLv3 and TLS1.0 SSLContext, replaced by OpenSSL

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            SecurityService_AlgorithmParameterGenerator,    // BC
            SecurityService_AlgorithmParameters,    // BC
            SecurityService_CertPathBuilder,    // BC
            SecurityService_CertPathValidator,    // BC
            SecurityService_CertStore,    // BC
            SecurityService_CertificateFactory,    // AndroidOpenSSL, BC
            SecurityService_Cipher,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL, BC
            SecurityService_KeyAgreement,    // AndroidOpenSSL, BC
            SecurityService_KeyFactory,    // AndroidKeyStore, AndroidOpenSSL, BC
            SecurityService_KeyGenerator,    // AndroidKeyStore, BC
            SecurityService_KeyManagerFactory,    // HarmonyJSSE
            SecurityService_KeyPairGenerator,    // AndroidKeyStore, AndroidOpenSSL, BC
            SecurityService_KeyStore,    // AndroidKeyStore, BC, HarmonyJSSE
            SecurityService_Mac,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL, BC
            SecurityService_MessageDigest,    // AndroidOpenSSL, BC
            SecurityService_SSLContext,    // AndroidOpenSSL
            SecurityService_SecretKeyFactory,    // AndroidKeyStore, BC
            SecurityService_SecureRandom,    // AndroidOpenSSL, Crypto
            SecurityService_Signature,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL, BC
            SecurityService_TrustManagerFactory    // HarmonyJSSE
    })
    public @interface SecurityService {
    }

    public static final String SecurityService_AlgorithmParameterGenerator = "AlgorithmParameterGenerator";
    public static final String SecurityService_AlgorithmParameters = "AlgorithmParameters";
    public static final String SecurityService_CertPathBuilder = "CertPathBuilder";
    public static final String SecurityService_CertPathValidator = "CertPathValidator";
    public static final String SecurityService_CertStore = "CertStore";
    public static final String SecurityService_CertificateFactory = "CertificateFactory";
    public static final String SecurityService_Cipher = "Cipher";
    public static final String SecurityService_KeyAgreement = "KeyAgreement";
    public static final String SecurityService_KeyFactory = "KeyFactory";
    public static final String SecurityService_KeyGenerator = "KeyGenerator";
    public static final String SecurityService_KeyManagerFactory = "KeyManagerFactory";
    public static final String SecurityService_KeyPairGenerator = "KeyPairGenerator";
    public static final String SecurityService_KeyStore = "KeyStore";
    public static final String SecurityService_Mac = "Mac";
    public static final String SecurityService_MessageDigest = "MessageDigest";
    public static final String SecurityService_SSLContext = "SSLContext";
    public static final String SecurityService_SecretKeyFactory = "SecretKeyFactory";
    public static final String SecurityService_SecureRandom = "SecureRandom";
    public static final String SecurityService_Signature = "Signature";
    public static final String SecurityService_TrustManagerFactory = "TrustManagerFactory";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            AlgorithmParameterGenerator_DH,    // BC
            AlgorithmParameterGenerator_DSA    // BC
    })
    public @interface AlgorithmParameterGenerator {
    }

    public static final String AlgorithmParameterGenerator_DH = "DH";
    public static final String AlgorithmParameterGenerator_DSA = "DSA";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            AlgorithmParameters_AES,    // BC
            AlgorithmParameters_BLOWFISH,    // BC
            AlgorithmParameters_DES,    // BC
            AlgorithmParameters_DESEDE,    // BC
            AlgorithmParameters_DH,    // BC
            AlgorithmParameters_DSA,    // BC
            AlgorithmParameters_GCM,    // BC
            AlgorithmParameters_OAEP,    // BC
            AlgorithmParameters_PKCS12PBE    // BC
    })
    public @interface AlgorithmParameters {
    }

    public static final String AlgorithmParameters_AES = "AES";
    public static final String AlgorithmParameters_BLOWFISH = "BLOWFISH";
    public static final String AlgorithmParameters_DES = "DES";
    public static final String AlgorithmParameters_DESEDE = "DESEDE";
    public static final String AlgorithmParameters_DH = "DH";
    public static final String AlgorithmParameters_DSA = "DSA";
    public static final String AlgorithmParameters_GCM = "GCM";
    public static final String AlgorithmParameters_OAEP = "OAEP";
    public static final String AlgorithmParameters_PKCS12PBE = "PKCS12PBE";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            CertPathBuilder_PKIX    // BC
    })
    public @interface CertPathBuilder {
    }

    public static final String CertPathBuilder_PKIX = "PKIX";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            CertPathValidator_PKIX    // BC
    })
    public @interface CertPathValidator {
    }

    public static final String CertPathValidator_PKIX = "PKIX";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            CertStore_Collection    // BC
    })
    public @interface CertStore {
    }

    public static final String CertStore_Collection = "Collection";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            CertificateFactory_X_509,    // BC
            CertificateFactory_X509    // AndroidOpenSSL
    })
    public @interface CertificateFactory {
    }

    public static final String CertificateFactory_X_509 = "X.509";
    public static final String CertificateFactory_X509 = "X509";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            Cipher_AES,    // BC
            Cipher_AES_CBC_NoPadding,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Cipher_AES_CBC_PKCS5Padding,    // AndroidOpenSSL
            Cipher_AES_CBC_PKCS7Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_AES_CTR_NoPadding,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Cipher_AES_ECB_NoPadding,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Cipher_AES_ECB_PKCS5Padding,    // AndroidOpenSSL
            Cipher_AES_ECB_PKCS7Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_AES_GCM_NOPADDING,    // BC
            Cipher_AES_GCM_NoPadding,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Cipher_AESWRAP,    // BC
            Cipher_ARC4,    // AndroidOpenSSL, BC
            Cipher_BLOWFISH,    // BC
            Cipher_DES,    // BC
            Cipher_DESEDE,    // BC
            Cipher_DESEDE_CBC_NoPadding,    // AndroidOpenSSL
            Cipher_DESEDE_CBC_PKCS5Padding,    // AndroidOpenSSL
            Cipher_DESEDEWRAP,    // BC
            Cipher_PBEWITHMD5AND128BITAES_CBC_OPENSSL,    // BC
            Cipher_PBEWITHMD5AND192BITAES_CBC_OPENSSL,    // BC
            Cipher_PBEWITHMD5AND256BITAES_CBC_OPENSSL,    // BC
            Cipher_PBEWITHMD5ANDDES,    // BC
            Cipher_PBEWITHMD5ANDRC2,    // BC
            Cipher_PBEWITHSHA1ANDDES,    // BC
            Cipher_PBEWITHSHA1ANDRC2,    // BC
            Cipher_PBEWITHSHA256AND128BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHA256AND192BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHA256AND256BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHAAND128BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHAAND128BITRC2_CBC,    // BC
            Cipher_PBEWITHSHAAND128BITRC4,    // BC
            Cipher_PBEWITHSHAAND192BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHAAND2_KEYTRIPLEDES_CBC,    // BC
            Cipher_PBEWITHSHAAND256BITAES_CBC_BC,    // BC
            Cipher_PBEWITHSHAAND3_KEYTRIPLEDES_CBC,    // BC
            Cipher_PBEWITHSHAAND40BITRC2_CBC,    // BC
            Cipher_PBEWITHSHAAND40BITRC4,    // BC
            Cipher_PBEWITHSHAANDTWOFISH_CBC,    // BC
            Cipher_RSA,    // BC
            Cipher_RSA_ECB_NoPadding,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Cipher_RSA_ECB_OAEPPadding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_OAEPWithSHA_1AndMGF1Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_OAEPWithSHA_224AndMGF1Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_OAEPWithSHA_256AndMGF1Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_OAEPWithSHA_384AndMGF1Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_OAEPWithSHA_512AndMGF1Padding,    // AndroidKeyStoreBCWorkaround
            Cipher_RSA_ECB_PKCS1Padding    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
    })
    public @interface Cipher {
    }

    @Deprecated public static final String Cipher_AES = "AES"; // alias to Cipher_AES_ECB_NoPadding
    public static final String Cipher_AES_CBC_NoPadding = "AES/CBC/NoPadding";
    public static final String Cipher_AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";
    public static final String Cipher_AES_CBC_PKCS7Padding = "AES/CBC/PKCS7Padding";
    public static final String Cipher_AES_CTR_NoPadding = "AES/CTR/NoPadding";
    @Deprecated public static final String Cipher_AES_ECB_NoPadding = "AES/ECB/NoPadding"; // ECB is insecure for symmetric ciphers
    @Deprecated public static final String Cipher_AES_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding"; // ECB is insecure for symmetric ciphers
    @Deprecated public static final String Cipher_AES_ECB_PKCS7Padding = "AES/ECB/PKCS7Padding"; // ECB is insecure for symmetric ciphers
    public static final String Cipher_AES_GCM_NOPADDING = "AES/GCM/NOPADDING";
    public static final String Cipher_AES_GCM_NoPadding = "AES/GCM/NoPadding";
    public static final String Cipher_AESWRAP = "AESWRAP";
    public static final String Cipher_ARC4 = "ARC4";
    public static final String Cipher_BLOWFISH = "BLOWFISH";
    public static final String Cipher_DES = "DES";
    public static final String Cipher_DESEDE = "DESEDE";
    public static final String Cipher_DESEDE_CBC_NoPadding = "DESEDE/CBC/NoPadding";
    public static final String Cipher_DESEDE_CBC_PKCS5Padding = "DESEDE/CBC/PKCS5Padding";
    public static final String Cipher_DESEDEWRAP = "DESEDEWRAP";
    public static final String Cipher_PBEWITHMD5AND128BITAES_CBC_OPENSSL = "PBEWITHMD5AND128BITAES-CBC-OPENSSL";
    public static final String Cipher_PBEWITHMD5AND192BITAES_CBC_OPENSSL = "PBEWITHMD5AND192BITAES-CBC-OPENSSL";
    public static final String Cipher_PBEWITHMD5AND256BITAES_CBC_OPENSSL = "PBEWITHMD5AND256BITAES-CBC-OPENSSL";
    public static final String Cipher_PBEWITHMD5ANDDES = "PBEWITHMD5ANDDES";
    public static final String Cipher_PBEWITHMD5ANDRC2 = "PBEWITHMD5ANDRC2";
    public static final String Cipher_PBEWITHSHA1ANDDES = "PBEWITHSHA1ANDDES";
    public static final String Cipher_PBEWITHSHA1ANDRC2 = "PBEWITHSHA1ANDRC2";
    public static final String Cipher_PBEWITHSHA256AND128BITAES_CBC_BC = "PBEWITHSHA256AND128BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHA256AND192BITAES_CBC_BC = "PBEWITHSHA256AND192BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHA256AND256BITAES_CBC_BC = "PBEWITHSHA256AND256BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHAAND128BITAES_CBC_BC = "PBEWITHSHAAND128BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHAAND128BITRC2_CBC = "PBEWITHSHAAND128BITRC2-CBC";
    public static final String Cipher_PBEWITHSHAAND128BITRC4 = "PBEWITHSHAAND128BITRC4";
    public static final String Cipher_PBEWITHSHAAND192BITAES_CBC_BC = "PBEWITHSHAAND192BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHAAND2_KEYTRIPLEDES_CBC = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
    public static final String Cipher_PBEWITHSHAAND256BITAES_CBC_BC = "PBEWITHSHAAND256BITAES-CBC-BC";
    public static final String Cipher_PBEWITHSHAAND3_KEYTRIPLEDES_CBC = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
    public static final String Cipher_PBEWITHSHAAND40BITRC2_CBC = "PBEWITHSHAAND40BITRC2-CBC";
    public static final String Cipher_PBEWITHSHAAND40BITRC4 = "PBEWITHSHAAND40BITRC4";
    public static final String Cipher_PBEWITHSHAANDTWOFISH_CBC = "PBEWITHSHAANDTWOFISH-CBC";
    public static final String Cipher_RSA = "RSA";
    public static final String Cipher_RSA_ECB_NoPadding = "RSA/ECB/NoPadding";
    public static final String Cipher_RSA_ECB_OAEPPadding = "RSA/ECB/OAEPPadding";
    public static final String Cipher_RSA_ECB_OAEPWithSHA_1AndMGF1Padding = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String Cipher_RSA_ECB_OAEPWithSHA_224AndMGF1Padding = "RSA/ECB/OAEPWithSHA-224AndMGF1Padding";
    public static final String Cipher_RSA_ECB_OAEPWithSHA_256AndMGF1Padding = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String Cipher_RSA_ECB_OAEPWithSHA_384AndMGF1Padding = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";
    public static final String Cipher_RSA_ECB_OAEPWithSHA_512AndMGF1Padding = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
    public static final String Cipher_RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyAgreement_DH,    // BC
            KeyAgreement_ECDH    // AndroidOpenSSL, BC
    })
    public @interface KeyAgreement {
    }

    public static final String KeyAgreement_DH = "DH";
    public static final String KeyAgreement_ECDH = "ECDH";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyFactory_DH,    // BC
            KeyFactory_DSA,    // BC
            KeyFactory_EC,    // AndroidOpenSSL, BC, AndroidKeyStore
            KeyFactory_RSA    // AndroidOpenSSL, BC, AndroidKeyStore
    })
    public @interface KeyFactory {
    }

    public static final String KeyFactory_DH = "DH";
    public static final String KeyFactory_DSA = "DSA";
    public static final String KeyFactory_EC = "EC";
    public static final String KeyFactory_RSA = "RSA";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyGenerator_AES,    // BC, AndroidKeyStore
            KeyGenerator_ARC4,    // BC
            KeyGenerator_BLOWFISH,    // BC
            KeyGenerator_DES,    // BC
            KeyGenerator_DESEDE,    // BC
            KeyGenerator_HMACMD5,    // BC
            KeyGenerator_HMACSHA1,    // BC
            KeyGenerator_HMACSHA224,    // BC
            KeyGenerator_HMACSHA256,    // BC
            KeyGenerator_HMACSHA384,    // BC
            KeyGenerator_HMACSHA512,    // BC
            KeyGenerator_HmacSHA1,    // AndroidKeyStore
            KeyGenerator_HmacSHA224,    // AndroidKeyStore
            KeyGenerator_HmacSHA256,    // AndroidKeyStore
            KeyGenerator_HmacSHA384,    // AndroidKeyStore
            KeyGenerator_HmacSHA512    // AndroidKeyStore
    })
    public @interface KeyGenerator {
    }

    public static final String KeyGenerator_AES = "AES";
    public static final String KeyGenerator_ARC4 = "ARC4";
    public static final String KeyGenerator_BLOWFISH = "BLOWFISH";
    public static final String KeyGenerator_DES = "DES";
    public static final String KeyGenerator_DESEDE = "DESEDE";
    public static final String KeyGenerator_HMACMD5 = "HMACMD5";
    public static final String KeyGenerator_HMACSHA1 = "HMACSHA1";
    public static final String KeyGenerator_HMACSHA224 = "HMACSHA224";
    public static final String KeyGenerator_HMACSHA256 = "HMACSHA256";
    public static final String KeyGenerator_HMACSHA384 = "HMACSHA384";
    public static final String KeyGenerator_HMACSHA512 = "HMACSHA512";
    public static final String KeyGenerator_HmacSHA1 = "HmacSHA1";
    public static final String KeyGenerator_HmacSHA224 = "HmacSHA224";
    public static final String KeyGenerator_HmacSHA256 = "HmacSHA256";
    public static final String KeyGenerator_HmacSHA384 = "HmacSHA384";
    public static final String KeyGenerator_HmacSHA512 = "HmacSHA512";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyManagerFactory_PKIX    // HarmonyJSSE
    })
    public @interface KeyManagerFactory {
    }

    @Deprecated public static final String KeyManagerFactory_PKIX = "PKIX";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyPairGenerator_DH,    // BC
            KeyPairGenerator_DSA,    // BC
            KeyPairGenerator_EC,    // AndroidOpenSSL, BC, AndroidKeyStore
            KeyPairGenerator_RSA    // AndroidOpenSSL, BC, AndroidKeyStore
    })
    public @interface KeyPairGenerator {
    }

    public static final String KeyPairGenerator_DH = "DH";
    public static final String KeyPairGenerator_DSA = "DSA";
    public static final String KeyPairGenerator_EC = "EC";
    public static final String KeyPairGenerator_RSA = "RSA";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            KeyStore_AndroidCAStore,    // HarmonyJSSE
            KeyStore_AndroidKeyStore,    // AndroidKeyStore
            KeyStore_BKS,    // BC
            KeyStore_BouncyCastle,    // BC
            KeyStore_PKCS12    // BC
    })
    public @interface KeyStore {
    }

    public static final String KeyStore_AndroidCAStore = "AndroidCAStore";
    public static final String KeyStore_AndroidKeyStore = "AndroidKeyStore";
    public static final String KeyStore_BKS = "BKS";
    public static final String KeyStore_BouncyCastle = "BouncyCastle";
    public static final String KeyStore_PKCS12 = "PKCS12";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            Mac_HMACMD5,    // BC
            Mac_HMACSHA1,    // BC
            Mac_HMACSHA224,    // BC
            Mac_HMACSHA256,    // BC
            Mac_HMACSHA384,    // BC
            Mac_HMACSHA512,    // BC
            Mac_HmacMD5,    // AndroidOpenSSL
            Mac_HmacSHA1,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Mac_HmacSHA224,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Mac_HmacSHA256,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Mac_HmacSHA384,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Mac_HmacSHA512,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Mac_PBEWITHHMACSHA,    // BC
            Mac_PBEWITHHMACSHA1    // BC
    })
    public @interface Mac {
    }

    public static final String Mac_HMACMD5 = "HMACMD5";
    public static final String Mac_HMACSHA1 = "HMACSHA1";
    public static final String Mac_HMACSHA224 = "HMACSHA224";
    public static final String Mac_HMACSHA256 = "HMACSHA256";
    public static final String Mac_HMACSHA384 = "HMACSHA384";
    public static final String Mac_HMACSHA512 = "HMACSHA512";
    public static final String Mac_HmacMD5 = "HmacMD5";
    public static final String Mac_HmacSHA1 = "HmacSHA1";
    public static final String Mac_HmacSHA224 = "HmacSHA224";
    public static final String Mac_HmacSHA256 = "HmacSHA256";
    public static final String Mac_HmacSHA384 = "HmacSHA384";
    public static final String Mac_HmacSHA512 = "HmacSHA512";
    public static final String Mac_PBEWITHHMACSHA = "PBEWITHHMACSHA";
    public static final String Mac_PBEWITHHMACSHA1 = "PBEWITHHMACSHA1";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            MessageDigest_MD5,    // AndroidOpenSSL, BC
            MessageDigest_SHA_1,    // AndroidOpenSSL, BC
            MessageDigest_SHA_224,    // AndroidOpenSSL, BC
            MessageDigest_SHA_256,    // AndroidOpenSSL, BC
            MessageDigest_SHA_384,    // AndroidOpenSSL, BC
            MessageDigest_SHA_512    // AndroidOpenSSL, BC
    })
    public @interface MessageDigest {
    }

    @Deprecated public static final String MessageDigest_MD5 = "MD5";
    @Deprecated public static final String MessageDigest_SHA_1 = "SHA-1";
    @Deprecated public static final String MessageDigest_SHA_224 = "SHA-224";
    public static final String MessageDigest_SHA_256 = "SHA-256";
    public static final String MessageDigest_SHA_384 = "SHA-384";
    public static final String MessageDigest_SHA_512 = "SHA-512";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            SSLContext_Default,    // AndroidOpenSSL
            SSLContext_SSL,    // AndroidOpenSSL
            SSLContext_SSLv3,    // AndroidOpenSSL
            SSLContext_TLS,    // AndroidOpenSSL
            SSLContext_TLSv1,    // AndroidOpenSSL
            SSLContext_TLSv1_1,    // AndroidOpenSSL
            SSLContext_TLSv1_2    // AndroidOpenSSL
    })
    public @interface SSLContext {
    }

    public static final String SSLContext_Default = "Default";
    @Deprecated public static final String SSLContext_SSL = "SSL";
    @Deprecated public static final String SSLContext_SSLv3 = "SSLv3";
    public static final String SSLContext_TLS = "TLS";
    @Deprecated public static final String SSLContext_TLSv1 = "TLSv1";
    public static final String SSLContext_TLSv1_1 = "TLSv1.1";
    public static final String SSLContext_TLSv1_2 = "TLSv1.2";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            SecretKeyFactory_AES,    // AndroidKeyStore
            SecretKeyFactory_DES,    // BC
            SecretKeyFactory_DESEDE,    // BC
            SecretKeyFactory_HmacSHA1,    // AndroidKeyStore
            SecretKeyFactory_HmacSHA224,    // AndroidKeyStore
            SecretKeyFactory_HmacSHA256,    // AndroidKeyStore
            SecretKeyFactory_HmacSHA384,    // AndroidKeyStore
            SecretKeyFactory_HmacSHA512,    // AndroidKeyStore
            SecretKeyFactory_PBEWITHHMACSHA1,    // BC
            SecretKeyFactory_PBEWITHMD5AND128BITAES_CBC_OPENSSL,    // BC
            SecretKeyFactory_PBEWITHMD5AND192BITAES_CBC_OPENSSL,    // BC
            SecretKeyFactory_PBEWITHMD5AND256BITAES_CBC_OPENSSL,    // BC
            SecretKeyFactory_PBEWITHMD5ANDDES,    // BC
            SecretKeyFactory_PBEWITHMD5ANDRC2,    // BC
            SecretKeyFactory_PBEWITHSHA1ANDDES,    // BC
            SecretKeyFactory_PBEWITHSHA1ANDRC2,    // BC
            SecretKeyFactory_PBEWITHSHA256AND128BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHA256AND192BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHA256AND256BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHAAND128BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHAAND128BITRC2_CBC,    // BC
            SecretKeyFactory_PBEWITHSHAAND128BITRC4,    // BC
            SecretKeyFactory_PBEWITHSHAAND192BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHAAND2_KEYTRIPLEDES_CBC,    // BC
            SecretKeyFactory_PBEWITHSHAAND256BITAES_CBC_BC,    // BC
            SecretKeyFactory_PBEWITHSHAAND3_KEYTRIPLEDES_CBC,    // BC
            SecretKeyFactory_PBEWITHSHAAND40BITRC2_CBC,    // BC
            SecretKeyFactory_PBEWITHSHAAND40BITRC4,    // BC
            SecretKeyFactory_PBEWITHSHAANDTWOFISH_CBC,    // BC
            SecretKeyFactory_PBKDF2WithHmacSHA1,    // BC
            SecretKeyFactory_PBKDF2WithHmacSHA1And8BIT    // BC
    })
    public @interface SecretKeyFactory {
    }

    public static final String SecretKeyFactory_AES = "AES";
    public static final String SecretKeyFactory_DES = "DES";
    public static final String SecretKeyFactory_DESEDE = "DESEDE";
    public static final String SecretKeyFactory_HmacSHA1 = "HmacSHA1";
    public static final String SecretKeyFactory_HmacSHA224 = "HmacSHA224";
    public static final String SecretKeyFactory_HmacSHA256 = "HmacSHA256";
    public static final String SecretKeyFactory_HmacSHA384 = "HmacSHA384";
    public static final String SecretKeyFactory_HmacSHA512 = "HmacSHA512";
    public static final String SecretKeyFactory_PBEWITHHMACSHA1 = "PBEWITHHMACSHA1";
    public static final String SecretKeyFactory_PBEWITHMD5AND128BITAES_CBC_OPENSSL = "PBEWITHMD5AND128BITAES-CBC-OPENSSL";
    public static final String SecretKeyFactory_PBEWITHMD5AND192BITAES_CBC_OPENSSL = "PBEWITHMD5AND192BITAES-CBC-OPENSSL";
    public static final String SecretKeyFactory_PBEWITHMD5AND256BITAES_CBC_OPENSSL = "PBEWITHMD5AND256BITAES-CBC-OPENSSL";
    public static final String SecretKeyFactory_PBEWITHMD5ANDDES = "PBEWITHMD5ANDDES";
    public static final String SecretKeyFactory_PBEWITHMD5ANDRC2 = "PBEWITHMD5ANDRC2";
    public static final String SecretKeyFactory_PBEWITHSHA1ANDDES = "PBEWITHSHA1ANDDES";
    public static final String SecretKeyFactory_PBEWITHSHA1ANDRC2 = "PBEWITHSHA1ANDRC2";
    public static final String SecretKeyFactory_PBEWITHSHA256AND128BITAES_CBC_BC = "PBEWITHSHA256AND128BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHA256AND192BITAES_CBC_BC = "PBEWITHSHA256AND192BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHA256AND256BITAES_CBC_BC = "PBEWITHSHA256AND256BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHAAND128BITAES_CBC_BC = "PBEWITHSHAAND128BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHAAND128BITRC2_CBC = "PBEWITHSHAAND128BITRC2-CBC";
    public static final String SecretKeyFactory_PBEWITHSHAAND128BITRC4 = "PBEWITHSHAAND128BITRC4";
    public static final String SecretKeyFactory_PBEWITHSHAAND192BITAES_CBC_BC = "PBEWITHSHAAND192BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHAAND2_KEYTRIPLEDES_CBC = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
    public static final String SecretKeyFactory_PBEWITHSHAAND256BITAES_CBC_BC = "PBEWITHSHAAND256BITAES-CBC-BC";
    public static final String SecretKeyFactory_PBEWITHSHAAND3_KEYTRIPLEDES_CBC = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
    public static final String SecretKeyFactory_PBEWITHSHAAND40BITRC2_CBC = "PBEWITHSHAAND40BITRC2-CBC";
    public static final String SecretKeyFactory_PBEWITHSHAAND40BITRC4 = "PBEWITHSHAAND40BITRC4";
    public static final String SecretKeyFactory_PBEWITHSHAANDTWOFISH_CBC = "PBEWITHSHAANDTWOFISH-CBC";
    public static final String SecretKeyFactory_PBKDF2WithHmacSHA1 = "PBKDF2WithHmacSHA1";
    public static final String SecretKeyFactory_PBKDF2WithHmacSHA1And8BIT = "PBKDF2WithHmacSHA1And8BIT";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            SecureRandom_SHA1PRNG    // AndroidOpenSSL, Crypto
    })
    public @interface SecureRandom {
    }

    public static final String SecureRandom_SHA1PRNG = "SHA1PRNG";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            Signature_ECDSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL, BC
            Signature_MD5WITHRSA,    // BC
            Signature_MD5WithRSA,    // AndroidOpenSSL
            Signature_MD5withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_NONEWITHDSA,    // BC
            Signature_NONEwithECDSA,    // AndroidKeyStoreBCWorkaround, BC
            Signature_NONEwithRSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Signature_SHA1WITHRSA,    // BC
            Signature_SHA1WithRSA,    // AndroidOpenSSL
            Signature_SHA1withDSA,    // BC
            Signature_SHA1withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_SHA1withRSA_PSS,    // AndroidKeyStoreBCWorkaround
            Signature_SHA224WITHDSA,    // BC
            Signature_SHA224WITHECDSA,    // BC
            Signature_SHA224WITHRSA,    // BC
            Signature_SHA224WithRSA,    // AndroidOpenSSL
            Signature_SHA224withECDSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Signature_SHA224withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_SHA224withRSA_PSS,    // AndroidKeyStoreBCWorkaround
            Signature_SHA256WITHDSA,    // BC
            Signature_SHA256WITHECDSA,    // BC
            Signature_SHA256WITHRSA,    // BC
            Signature_SHA256WithRSA,    // AndroidOpenSSL
            Signature_SHA256withECDSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Signature_SHA256withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_SHA256withRSA_PSS,    // AndroidKeyStoreBCWorkaround
            Signature_SHA384WITHECDSA,    // BC
            Signature_SHA384WITHRSA,    // BC
            Signature_SHA384WithRSA,    // AndroidOpenSSL
            Signature_SHA384withECDSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Signature_SHA384withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_SHA384withRSA_PSS,    // AndroidKeyStoreBCWorkaround
            Signature_SHA512WITHECDSA,    // BC
            Signature_SHA512WITHRSA,    // BC
            Signature_SHA512WithRSA,    // AndroidOpenSSL
            Signature_SHA512withECDSA,    // AndroidKeyStoreBCWorkaround, AndroidOpenSSL
            Signature_SHA512withRSA,    // AndroidKeyStoreBCWorkaround
            Signature_SHA512withRSA_PSS    // AndroidKeyStoreBCWorkaround
    })
    public @interface Signature {
    }

    public static final String Signature_ECDSA = "ECDSA";
    public static final String Signature_MD5WITHRSA = "MD5WITHRSA";
    public static final String Signature_MD5WithRSA = "MD5WithRSA";
    public static final String Signature_MD5withRSA = "MD5withRSA";
    public static final String Signature_NONEWITHDSA = "NONEWITHDSA";
    public static final String Signature_NONEwithECDSA = "NONEwithECDSA";
    public static final String Signature_NONEwithRSA = "NONEwithRSA";
    public static final String Signature_SHA1WITHRSA = "SHA1WITHRSA";
    public static final String Signature_SHA1WithRSA = "SHA1WithRSA";
    public static final String Signature_SHA1withDSA = "SHA1withDSA";
    public static final String Signature_SHA1withRSA = "SHA1withRSA";
    public static final String Signature_SHA1withRSA_PSS = "SHA1withRSA/PSS";
    public static final String Signature_SHA224WITHDSA = "SHA224WITHDSA";
    public static final String Signature_SHA224WITHECDSA = "SHA224WITHECDSA";
    public static final String Signature_SHA224WITHRSA = "SHA224WITHRSA";
    public static final String Signature_SHA224WithRSA = "SHA224WithRSA";
    public static final String Signature_SHA224withECDSA = "SHA224withECDSA";
    public static final String Signature_SHA224withRSA = "SHA224withRSA";
    public static final String Signature_SHA224withRSA_PSS = "SHA224withRSA/PSS";
    public static final String Signature_SHA256WITHDSA = "SHA256WITHDSA";
    public static final String Signature_SHA256WITHECDSA = "SHA256WITHECDSA";
    public static final String Signature_SHA256WITHRSA = "SHA256WITHRSA";
    public static final String Signature_SHA256WithRSA = "SHA256WithRSA";
    public static final String Signature_SHA256withECDSA = "SHA256withECDSA";
    public static final String Signature_SHA256withRSA = "SHA256withRSA";
    public static final String Signature_SHA256withRSA_PSS = "SHA256withRSA/PSS";
    public static final String Signature_SHA384WITHECDSA = "SHA384WITHECDSA";
    public static final String Signature_SHA384WITHRSA = "SHA384WITHRSA";
    public static final String Signature_SHA384WithRSA = "SHA384WithRSA";
    public static final String Signature_SHA384withECDSA = "SHA384withECDSA";
    public static final String Signature_SHA384withRSA = "SHA384withRSA";
    public static final String Signature_SHA384withRSA_PSS = "SHA384withRSA/PSS";
    public static final String Signature_SHA512WITHECDSA = "SHA512WITHECDSA";
    public static final String Signature_SHA512WITHRSA = "SHA512WITHRSA";
    public static final String Signature_SHA512WithRSA = "SHA512WithRSA";
    public static final String Signature_SHA512withECDSA = "SHA512withECDSA";
    public static final String Signature_SHA512withRSA = "SHA512withRSA";
    public static final String Signature_SHA512withRSA_PSS = "SHA512withRSA/PSS";

    @Retention(RetentionPolicy.SOURCE)
    @StringDef({
            TrustManagerFactory_PKIX    // HarmonyJSSE
    })
    public @interface TrustManagerFactory {
    }

    @Deprecated public static final String TrustManagerFactory_PKIX = "PKIX";

}