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

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.AsymmetricKeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.BaseKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapperInitializer;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.DataProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.AlgorithmParameterSpecFactory;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;
import com.github.cjnosal.secret_storage.storage.ScopedDataStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;

import static com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms.IV_SIZE_AES_128;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

public class SecretStorageTest {

    private Context context;
    private AndroidCrypto androidCrypto;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private DataStorage dataStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            androidCrypto = new AndroidCrypto();
        }
        configStorage = new PreferenceStorage(context, "testConfig");
        keyStorage = new PreferenceStorage(context, "testKeys");
        dataStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
        dataStorage.clear();
        configStorage.clear();
    }

    private DataProtectionSpec dataProtectionSpec() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return DefaultSpecs.getDefaultDataProtectionSpec();
        } else {
            return DefaultSpecs.getLegacyDataProtectionSpec();
        }
    }

    private SecretStorage.Builder defaultBuilder() {
        return new SecretStorage.Builder()
                .dataProtectionSpec(dataProtectionSpec())
                .dataStorage(dataStorage);
    }

    private ObfuscationKeyWrapper getObfuscationKeyWrapper(){
        return new ObfuscationKeyWrapper(
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getAesWrapSpec(),
                configStorage,
                keyStorage
        );
    }

    private PasswordKeyWrapper getPasswordKeyWrapper() {
        return new PasswordKeyWrapper(
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getAesWrapSpec(),
                configStorage,
                keyStorage
        );
    }

    private SignedPasswordKeyWrapper getSignedPasswordKeyWrapper() {
        return new SignedPasswordKeyWrapper(
                context,
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getSha256WithRsaSpec(),
                DefaultSpecs.getAesWrapSpec(),
                DefaultSpecs.getRsa2048KeyGenSpec(),
                configStorage,
                keyStorage
        );
    }

    private AsymmetricKeyStoreWrapper getAsymmetricKeyStoreWrapper() {
        return new AsymmetricKeyStoreWrapper(
                context,
                DefaultSpecs.getAesWrapSpec(),
                DefaultSpecs.getAes256KeyGenSpec(),
                DefaultSpecs.getRsaEcbPkcs1Spec(),
                DefaultSpecs.getRsa2048KeyGenSpec(),
                configStorage,
                keyStorage
        );
    }

    private KeyStoreWrapper getKeyStoreWrapper() {
        return new KeyStoreWrapper(
                DefaultSpecs.getAesGcmCipherSpec(),
                DefaultSpecs.getKeyStoreAes256GcmKeyGenSpec(),
                configStorage,
                keyStorage
        );
    }

    private List<KeyWrapper> supportedKeyWrappers() {
        List<KeyWrapper> wrappers = new ArrayList<>();
        wrappers.add(getObfuscationKeyWrapper());
        wrappers.add(getPasswordKeyWrapper());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            wrappers.add(getSignedPasswordKeyWrapper());
            wrappers.add(getAsymmetricKeyStoreWrapper());
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            wrappers.add(getKeyStoreWrapper());
        }
        return wrappers;
    }

    @Test
    public void copyTo() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = defaultBuilder()
                .dataStorage(new PreferenceStorage(context, "id"))
                .keyWrapper(getPasswordKeyWrapper())
                .build();
        secretStorage1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password".toCharArray());
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        configStorage = new PreferenceStorage(context, "newDestinationConfigs");
        keyStorage = new PreferenceStorage(context, "newDestinationKeys");
        keyStorage.clear();
        configStorage.clear();
        SecretStorage secretStorage2 = defaultBuilder()
                .dataStorage(new PreferenceStorage(context, "id2"))
                .keyWrapper(getObfuscationKeyWrapper())
                .build();
        ((BaseKeyWrapper.NoParamsEditor)secretStorage2.getEditor()).unlock();
        secretStorage1.copyTo(secretStorage2);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void rewrap() throws IOException, GeneralSecurityException {
        final List<KeyWrapper> keyWrappers = supportedKeyWrappers();

        for (final KeyWrapper k1 : keyWrappers) {

            for (final KeyWrapper k2 : keyWrappers) {

                if (k1 == k2) {
                    continue;
                }

                keyStorage.clear();
                dataStorage.clear();
                configStorage.clear();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    androidCrypto.clear();
                }

                final SecretStorage secretStorage = defaultBuilder()
                        .keyWrapper(k1)
                        .build();
                if (k1 instanceof PasswordKeyWrapper && !(k1 instanceof ObfuscationKeyWrapper)) {
                    PasswordKeyWrapper.PasswordEditor e = (PasswordKeyWrapper.PasswordEditor) k1.getEditor();
                    if (!e.isPasswordSet()) {
                        e.setPassword(("password" + keyWrappers.indexOf(k1)).toCharArray());
                    } else if (!e.isUnlocked()) {
                        e.unlock(("password" + keyWrappers.indexOf(k1)).toCharArray());
                    }
                } else {
                    ((BaseKeyWrapper.NoParamsEditor)k1.getEditor()).unlock();
                }
                secretStorage.store("my secret", "message".getBytes());

                secretStorage.rewrap(new KeyWrapperInitializer() {

                    @Override
                    public KeyWrapper initKeyWrapper() throws IOException, GeneralSecurityException {
                        k1.getEditor().eraseConfig();
                        if (k2 instanceof PasswordKeyWrapper && !(k2 instanceof ObfuscationKeyWrapper)) {
                            PasswordKeyWrapper.PasswordEditor e = (PasswordKeyWrapper.PasswordEditor)k2.getEditor();
                            if (!e.isPasswordSet()) {
                                e.setPassword(("password" + keyWrappers.indexOf(k2)).toCharArray());
                            } else if (!e.isUnlocked()) {
                                e.unlock(("password" + keyWrappers.indexOf(k2)).toCharArray());
                            }
                        } else {
                            ((BaseKeyWrapper.NoParamsEditor)k2.getEditor()).unlock();
                        }
                        return k2;
                    }
                });
                assertEquals(new String(secretStorage.load("my secret")), "message");
            }
        }
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            androidCrypto.clear();
        }

        KeyWrapper keyWrapper;
        DataStorage storage = new PreferenceStorage(context, "shared");
        storage.clear();
        configStorage = storage;
        keyStorage = storage;

        List<SecretStorage> stores = new ArrayList<>();

        dataStorage = new ScopedDataStorage("data1", storage);
        keyWrapper = getPasswordKeyWrapper();
        keyWrapper.getEditor().setStorageScope("k1", "c1");
        stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

        dataStorage = new ScopedDataStorage("data2", storage);
        keyWrapper = getPasswordKeyWrapper();
        keyWrapper.getEditor().setStorageScope("k2", "c2");
        stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            dataStorage = new ScopedDataStorage("data3", storage);
            keyWrapper = getSignedPasswordKeyWrapper();
            keyWrapper.getEditor().setStorageScope("k3", "c3");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

            dataStorage = new ScopedDataStorage("data4", storage);
            keyWrapper = getSignedPasswordKeyWrapper();
            keyWrapper.getEditor().setStorageScope("k4", "c4");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

            dataStorage = new ScopedDataStorage("data5", storage);
            keyWrapper = getAsymmetricKeyStoreWrapper();
            keyWrapper.getEditor().setStorageScope("k5", "c5");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

            dataStorage = new ScopedDataStorage("data6", storage);
            keyWrapper = getAsymmetricKeyStoreWrapper();
            keyWrapper.getEditor().setStorageScope("k6", "c6");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            dataStorage = new ScopedDataStorage("data7", storage);
            keyWrapper = getKeyStoreWrapper();
            keyWrapper.getEditor().setStorageScope("k7", "c7");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

            dataStorage = new ScopedDataStorage("data8", storage);
            keyWrapper = getKeyStoreWrapper();
            keyWrapper.getEditor().setStorageScope("k8", "c8");
            stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());
        }

        dataStorage = new ScopedDataStorage("data9", storage);
        keyWrapper = getObfuscationKeyWrapper();
        keyWrapper.getEditor().setStorageScope("k9", "c9");
        stores.add(defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

        dataStorage = new ScopedDataStorage("data10", storage);
        keyWrapper = getObfuscationKeyWrapper();
        keyWrapper.getEditor().setStorageScope("k10", "c10");
        stores.add( defaultBuilder().keyWrapper(keyWrapper).dataStorage(dataStorage).build());

        for (int i = 0; i < stores.size(); ++i) {
            SecretStorage store = stores.get(i);
            if (store.getEditor() instanceof PasswordKeyWrapper.PasswordEditor) {
                store.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword(("password" + i).toCharArray());
            } else {
                store.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
            }
        }

        for (int i = 0; i < stores.size(); ++i) {
            SecretStorage store = stores.get(i);
            store.store("secret", ("message" + i).getBytes());
            store.getEditor().lock();
        }

        for (int i = 0; i < stores.size(); ++i) {
            SecretStorage store = stores.get(i);
            if (store.getEditor() instanceof PasswordKeyWrapper.PasswordEditor) {
                store.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock(("password" + i).toCharArray());
            } else {
                store.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
            }
            assertEquals("message" + i, new String(store.load("secret")));
        }
    }

    @Test
    public void encryptWithExternalStorage() throws GeneralSecurityException, IOException {
        SecretStorage noDataStorage = new SecretStorage.Builder()
                .dataProtectionSpec(dataProtectionSpec())
                .keyWrapper(getObfuscationKeyWrapper())
                .build();

        noDataStorage.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();

        byte[] cipherText = noDataStorage.encrypt("message", "Hello World".getBytes());
        assertEquals("Hello World", new String(noDataStorage.decrypt("message", cipherText)));
    }

    @Test
    public void idMismatch() throws GeneralSecurityException, IOException {
        SecretStorage noDataStorage = new SecretStorage.Builder()
                .dataProtectionSpec(DefaultSpecs.getDefaultDataProtectionSpec())
                .keyWrapper(getObfuscationKeyWrapper())
                .build();

        noDataStorage.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();

        byte[] cipherText = noDataStorage.encrypt("message", "Hello World".getBytes());
        try {
            noDataStorage.decrypt("message2", cipherText);
            fail("Expected id mismatch");
        } catch(IOException e) {}
    }

    @Test
    public void metadataTampering() throws GeneralSecurityException, IOException {
        SecretStorage noDataStorage = new SecretStorage.Builder()
                .dataProtectionSpec(DefaultSpecs.getDefaultDataProtectionSpec())
                .keyWrapper(getObfuscationKeyWrapper())
                .build();

        noDataStorage.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();

        byte[] cipherText = noDataStorage.encrypt("message", "Hello World".getBytes());
        cipherText[8] = (byte)(cipherText[2] ^ 0xFF);
        try {
            noDataStorage.decrypt("message", cipherText);
            fail("Expected signature mismatch");
        } catch(SignatureException e) {}
    }

    @Test
    public void cipherParameterFactory() throws Exception {
        ObfuscationKeyWrapper.CryptoConfig defaultConfig = DefaultSpecs.getPasswordCryptoConfig();
        DataProtectionSpec defaultSpec = DefaultSpecs.getLegacyDataProtectionSpec();

        CipherSpec cipherSpec = new CipherSpec(defaultSpec.getCipherSpec().getCipherTransformation(),
                defaultSpec.getCipherSpec().getParamsAlgorithm(),
                new AlgorithmParameterSpecFactory() {
                    @Override
                    public AlgorithmParameterSpec newInstance() {
                        byte[] iv = new byte[IV_SIZE_AES_128/Byte.SIZE];
                        new SecureRandom().nextBytes(iv);
                        return new IvParameterSpec(iv);
                    }
                });

        ObfuscationKeyWrapper keyWrapper = new ObfuscationKeyWrapper(defaultConfig.getDerivationSpec(), defaultConfig.getKeyGenSpec(), cipherSpec, configStorage, keyStorage);
        DataProtectionSpec dataSpec = new DataProtectionSpec(cipherSpec, defaultSpec.getIntegritySpec(), defaultSpec.getCipherKeyGenSpec(), defaultSpec.getIntegrityKeyGenSpec());
        SecretStorage storage = new SecretStorage.Builder()
                .dataStorage(dataStorage)
                .dataProtectionSpec(dataSpec)
                .keyWrapper(keyWrapper)
                .build();

        storage.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        storage.store("secret", "message".getBytes());
        storage.getEditor().lock();

        storage.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        assertEquals("message", new String(storage.load("secret")));
    }
}