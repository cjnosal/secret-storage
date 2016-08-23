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

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Use Java Cryptographic Extensions for cryptographic operations
 */
public class Crypto {
    
    SecureRandom secureRandom;

    public Crypto() {
        secureRandom = new SecureRandom(); // seeded by system entropy
    }
    
    public SecretKey generateSecretKey(@SecurityAlgorithms.KeyGenerator String algorithm, @SecurityAlgorithms.KeySize int keySize) throws GeneralSecurityException {
        KeyGenerator g = KeyGenerator.getInstance(algorithm);
        g.init(keySize);
        return g.generateKey();
    }

    public SecretKey generateSecretKey(@SecurityAlgorithms.SecretKeyFactory String algorithm, SecretKeySpec spec) throws GeneralSecurityException {
        SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
        return f.generateSecret(spec);
    }

    public byte[] generateBytes(int length) {
        byte[] random = new byte[length];
        secureRandom.nextBytes(random);
        return random;
    }

    public IvParameterSpec generateIV(@SecurityAlgorithms.IVSize int size) {
        byte[] iv = generateBytes(size/8);
        return new IvParameterSpec(iv);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public GCMParameterSpec generateGCM(@SecurityAlgorithms.IVSize int ivSize, @SecurityAlgorithms.TagSize int tagSize) {
        byte[] iv = generateIV(ivSize).getIV();
        return new GCMParameterSpec(tagSize, iv);
    }

    public byte[] encrypt(Key key, AlgorithmParameterSpec spec, @SecurityAlgorithms.Cipher String cipherAlgorithm, byte[] plainBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plainBytes);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public byte[] encrypt(SecretKey key, AlgorithmParameterSpec spec, @SecurityAlgorithms.Cipher String cipherAlgorithm, byte[] plainBytes, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(plainBytes);
    }

    public byte[] decrypt(Key key, AlgorithmParameterSpec spec, @SecurityAlgorithms.Cipher String cipherAlgorithm, byte[] cipherBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherBytes);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public byte[] decrypt(SecretKey key, AlgorithmParameterSpec spec, @SecurityAlgorithms.Cipher String cipherAlgorithm, byte[] cipherBytes, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(cipherBytes);
    }

    public KeyPair generateKeyPair(@SecurityAlgorithms.KeyPairGenerator String algorithm, @SecurityAlgorithms.KeySize int keySize) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
        g.initialize(keySize);
        return g.generateKeyPair();
    }

    public byte[] sign(SecretKey key, @SecurityAlgorithms.Mac String macAlgorithm, byte[] cipherText) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlgorithm);
        mac.init(key);
        mac.update(cipherText);
        return mac.doFinal();
    }

    public boolean verify(SecretKey key, @SecurityAlgorithms.Mac String macAlgorithm, byte[] cipherText, byte[] mac) throws GeneralSecurityException {
        byte[] generatedMac = sign(key, macAlgorithm, cipherText);
        return MessageDigest.isEqual(generatedMac, mac);
    }

    public SecretKey deriveKey(@SecurityAlgorithms.SecretKeyFactory String algorithm, @SecurityAlgorithms.KeySize int keySize, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize);
        return factory.generateSecret(spec);
    }

    public byte[] sign(PrivateKey key, @SecurityAlgorithms.Signature String algorithm, byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    public boolean verify(PublicKey key, @SecurityAlgorithms.Signature String algorithm, byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    public boolean verify(Certificate cert, @SecurityAlgorithms.Signature String algorithm, byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(cert);
        sig.update(data);
        return sig.verify(signature);
    }


}
