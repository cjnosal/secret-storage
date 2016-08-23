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
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Use AndroidKeyStore for keypair operations and JCE for secret key operations
 */
public class AndroidCrypto {

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public KeyPair generateKeyPair(Context context, String id, @SecurityAlgorithms.KeyPairGenerator String algorithm) throws GeneralSecurityException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 10);
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, SecurityAlgorithms.SecurityProvider_AndroidKeyStore);
        g.initialize(
                new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(id)
                        .setSubject(new X500Principal("CN=" + id))
                        .setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build());
        return g.generateKeyPair();
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public KeyPair generateKeyPair(Context context, String id, @SecurityAlgorithms.KeyPairGenerator String algorithm, @SecurityAlgorithms.KeySize int keySize) throws GeneralSecurityException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 10);
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, SecurityAlgorithms.SecurityProvider_AndroidKeyStore);
        g.initialize(
                new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(id)
                        .setKeyType(algorithm)
                        .setKeySize(keySize)
                        .setSubject(new X500Principal("CN=" + id))
                        .setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build());
        return g.generateKeyPair();
    }

    @TargetApi(Build.VERSION_CODES.M)
    public KeyPair generateKeyPair(@SecurityAlgorithms.KeyPairGenerator String algorithm, KeyGenParameterSpec spec) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, SecurityAlgorithms.SecurityProvider_AndroidKeyStore);
        g.initialize(spec);
        return g.generateKeyPair();
    }

    @TargetApi(Build.VERSION_CODES.M)
    public SecretKey generateSecretKey(@SecurityAlgorithms.KeyGenerator String algorithm, KeyGenParameterSpec spec) throws GeneralSecurityException {
        KeyGenerator g = KeyGenerator.getInstance(algorithm, SecurityAlgorithms.SecurityProvider_AndroidKeyStore);
        g.init(spec);
        return g.generateKey();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private KeyStore.Entry loadKeyStoreEntry(String id) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        return store.getEntry(id, null);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public PrivateKey loadPrivateKey(String id) throws GeneralSecurityException, IOException {
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) loadKeyStoreEntry(id);
        return entry.getPrivateKey();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public PublicKey loadPublicKey(String id) throws GeneralSecurityException, IOException {
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) loadKeyStoreEntry(id);
        return entry.getCertificate().getPublicKey();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public KeyPair loadKeyPair(String id) throws GeneralSecurityException, IOException {
        return new KeyPair(loadPublicKey(id), loadPrivateKey(id));
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public Certificate loadTrustedCertificate(String id) throws GeneralSecurityException, IOException {
        KeyStore.TrustedCertificateEntry entry = (KeyStore.TrustedCertificateEntry) loadKeyStoreEntry(id);
        return entry.getTrustedCertificate();
    }

    @TargetApi(Build.VERSION_CODES.M)
    public SecretKey loadSecretKey(String id) throws GeneralSecurityException, IOException {
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) loadKeyStoreEntry(id);
        return entry.getSecretKey();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public Key loadKey(String id) throws GeneralSecurityException, IOException {
        KeyStore.Entry entry = loadKeyStoreEntry(id);
        if (entry instanceof KeyStore.PrivateKeyEntry) {
            return ((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
        } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
            return ((KeyStore.TrustedCertificateEntry)entry).getTrustedCertificate().getPublicKey();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry)entry).getSecretKey();
        }
        throw new IOException("Unexpected KeyStore.Entry type " + entry.getClass() + " for entry " + id);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void storeKeyStoreEntry(String id, KeyStore.Entry entry, KeyStore.ProtectionParameter param) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        store.setEntry(id, entry, param);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void storeKeyPair(String id, PrivateKey key, Certificate[] chain, KeyStore.ProtectionParameter param) throws GeneralSecurityException, IOException {
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(key, chain);
        storeKeyStoreEntry(id, entry, param);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void storeTrustedCertificate(String id, Certificate cert) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        store.setCertificateEntry(id, cert);
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void storeSecretKey(String id, SecretKey key, KeyStore.ProtectionParameter param) throws GeneralSecurityException, IOException {
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
        storeKeyStoreEntry(id, entry, param);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void deleteEntry(String id) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        store.deleteEntry(id);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public boolean hasEntry(String id) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        return store.containsAlias(id);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void clear() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(SecurityAlgorithms.KeyStore_AndroidKeyStore);
        store.load(null);
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            deleteEntry(aliases.nextElement());
        }
    }
}
