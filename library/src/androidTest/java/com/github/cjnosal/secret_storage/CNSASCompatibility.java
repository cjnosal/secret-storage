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

package com.github.cjnosal.secret_storage;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;

import org.junit.Ignore;
import org.junit.Test;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

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
public class CNSASCompatibility {

    @Test
    public void rsa3072_cipher() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(SecurityAlgorithms.KeyPairGenerator_RSA);
        keyPairGenerator.initialize(SecurityAlgorithms.KEY_SIZE_RSA_3072);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // KeyAgreement does not support RSA
        Cipher cipher = Cipher.getInstance(SecurityAlgorithms.Cipher_RSA);
        cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());

        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey secretKey = keyGenerator.generateKey();

        cipher.wrap(secretKey);
    }

    @Test
    public void rsa3072_signature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityAlgorithms.KeyPairGenerator_RSA);
        generator.initialize(SecurityAlgorithms.KEY_SIZE_RSA_3072);
        KeyPair keyPair = generator.generateKeyPair();

        Signature signature = Signature.getInstance(SecurityAlgorithms.Signature_SHA384withRSA); // renamed as of SDK 17 from SHA384WithRSAEncryption
        signature.initSign(keyPair.getPrivate());
        signature.update(keyPair.getPublic().getEncoded());
        signature.sign();
    }

    @Test
    @Ignore("Too slow to complete on emulator")
    public void dh3072_key_agreement() throws Exception {
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance(SecurityAlgorithms.AlgorithmParameterGenerator_DH);
        algorithmParameterGenerator.init(SecurityAlgorithms.KEY_SIZE_RSA_3072);

        AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
        AlgorithmParameterSpec algorithmParameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityAlgorithms.KeyPairGenerator_DH);
        generator.initialize(algorithmParameterSpec);

        KeyPair local = generator.generateKeyPair();
        KeyPair remote = generator.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance(SecurityAlgorithms.KeyAgreement_DH);
        keyAgreement.init(local.getPrivate());
        keyAgreement.doPhase(remote.getPublic(), true);
        keyAgreement.generateSecret();
    }

    @Test
    public void ec384_key_agreement() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityAlgorithms.KeyPairGenerator_EC);
        generator.initialize(SecurityAlgorithms.KEY_SIZE_EC_384);
        KeyPair local = generator.generateKeyPair();
        KeyPair remote = generator.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance(SecurityAlgorithms.KeyAgreement_ECDH);
        keyAgreement.init(local.getPrivate());
        keyAgreement.doPhase(remote.getPublic(), true);
        keyAgreement.generateSecret();
    }

    @Test
    public void ec384_signature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityAlgorithms.KeyPairGenerator_EC);
        generator.initialize(SecurityAlgorithms.KEY_SIZE_EC_384);
        KeyPair keyPair = generator.generateKeyPair();

        Signature signature = Signature.getInstance(SecurityAlgorithms.Signature_SHA384withECDSA);
        signature.initSign(keyPair.getPrivate());
        signature.update(keyPair.getPublic().getEncoded());
        signature.sign();
    }

    @Test
    public void sha384_integrity() throws Exception {
        MessageDigest digest = MessageDigest.getInstance(SecurityAlgorithms.MessageDigest_SHA_384);
        digest.update("Hello World".getBytes());
        digest.digest();

        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey secretKey = keyGenerator.generateKey();

        Mac mac = Mac.getInstance(SecurityAlgorithms.Mac_HMACSHA384);
        mac.init(secretKey);
        mac.update("Hello World".getBytes());
        mac.doFinal();
    }

    @Test
    public void aes256_cipher() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance(SecurityAlgorithms.Cipher_AES_CBC_PKCS7Padding);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        cipher.update("Hello World".getBytes());
        cipher.doFinal();
    }
}
