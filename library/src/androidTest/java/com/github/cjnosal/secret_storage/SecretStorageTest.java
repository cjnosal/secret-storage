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
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static junit.framework.Assert.assertEquals;

public class SecretStorageTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;
    DataStorage dataStorage;
    DataKeyGenerator dataKeyGenerator;
    KeyWrap keyWrap;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        dataKeyGenerator = new DataKeyGenerator();
        keyWrap = new KeyWrap();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testKeys");
        dataStorage = new FileStorage(context.getFilesDir() + "/testData");
        configStorage.clear();
        keyStorage.clear();
        dataStorage.clear();
        configStorage.clear();
        androidCrypto.clear();
        clearDataFor("id");
        clearDataFor("id2");
        clearDataFor("id3");
        clearDataFor("id4");
        clearDataFor("id5");
    }

    private void clearDataFor(String id) throws Exception {
        new FileStorage(context.getFilesDir() + File.separator + id + File.separator + DataStorage.TYPE_DATA).clear();
        new PreferenceStorage(context, id + DataStorage.TYPE_CONF).clear();
        new PreferenceStorage(context, id + DataStorage.TYPE_KEYS).clear();
    }

    @Test
    public void createWithPassword() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage = new SecretStorage.Builder(context, "id").withUserPassword(true).build();
        secretStorage.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("mysecret");
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void createWithoutPassword() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage = new SecretStorage.Builder(context, "id").build();
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void createWithManager() throws IOException, GeneralSecurityException {
        PasswordKeyWrapper wrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec()
        );

        PasswordProtectedKeyManager keyManager = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                wrapper,
                dataKeyGenerator,
                keyWrap,
                configStorage
        );

        SecretStorage secretStorage = new SecretStorage(context, "id", configStorage, dataStorage, keyStorage, keyManager);
        secretStorage.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password");
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void copyTo() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = new SecretStorage.Builder(context, "id")
                .withUserPassword(true)
                .build();
        secretStorage1.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password");
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        SecretStorage secretStorage2 = new SecretStorage.Builder(context, "id2").build();
        secretStorage1.copyTo(secretStorage2);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void rewrap() throws IOException, GeneralSecurityException {
        KeyManager obfuscationKeyManager = new ObfuscationKeyManager.Builder()
                .configStorage(configStorage)
                .defaultKeyWrapper(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
                .defaultDataProtection(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
                .build();
        SecretStorage secretStorage1 = new SecretStorage(context, "id", configStorage, dataStorage,
                keyStorage, obfuscationKeyManager);

        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        // ICS data encryption for compatibility, upgraded key wrapper using M's AndroidKeyStore
        KeyManager upgradedWrapping = new KeyManager(DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.ICE_CREAM_SANDWICH),
                new KeyStoreWrapper(new AndroidCrypto(), DefaultSpecs.getKeyStoreDataProtectionSpec().getCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        secretStorage1.rewrap(upgradedWrapping);

        assertEquals(new String(secretStorage1.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage1.load("mysecret2")), "message2");

        SecretStorage secretStorage2 = new SecretStorage(context, "id", configStorage, dataStorage,
                keyStorage, upgradedWrapping);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        PasswordProtectedKeyManager passwordKeyManager1 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new PasswordKeyWrapper(
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec()
                ), dataKeyGenerator, keyWrap, configStorage);

        PasswordProtectedKeyManager passwordKeyManager2 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new PasswordKeyWrapper(
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec()
                ), dataKeyGenerator, keyWrap, configStorage);

        PasswordProtectedKeyManager signedPasswordKeyManager1 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new SignedPasswordKeyWrapper(context, androidCrypto,
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordDeviceBindingSpec()), dataKeyGenerator, keyWrap, configStorage);

        PasswordProtectedKeyManager signedPasswordKeyManager2 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new SignedPasswordKeyWrapper(context, androidCrypto,
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordDeviceBindingSpec()), dataKeyGenerator, keyWrap, configStorage);

        KeyManager asymmetricWrapKeyStoreManager1 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new AsymmetricKeyStoreWrapper(context, androidCrypto,
                        DefaultSpecs.getAsymmetricKeyProtectionSpec().getCipherSpec()
        ),
                dataKeyGenerator,
                keyWrap);

        KeyManager asymmetricWrapKeyStoreManager2 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new AsymmetricKeyStoreWrapper(context, androidCrypto,
                DefaultSpecs.getAsymmetricKeyProtectionSpec().getCipherSpec()
        ),
                dataKeyGenerator,
                keyWrap);

        KeyManager keyStoreManager1 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new KeyStoreWrapper(androidCrypto,
                DefaultSpecs.getKeyStoreDataProtectionSpec().getCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        KeyManager keyStoreManager2 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new KeyStoreWrapper(androidCrypto,
                DefaultSpecs.getKeyStoreDataProtectionSpec().getCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        SecretStorage s1 = new SecretStorage(context, "id1", configStorage, dataStorage, keyStorage, passwordKeyManager1);
        SecretStorage s2 = new SecretStorage(context, "id2", configStorage, dataStorage, keyStorage, passwordKeyManager2);
        SecretStorage s3 = new SecretStorage(context, "id3", configStorage, dataStorage, keyStorage, signedPasswordKeyManager1);
        SecretStorage s4 = new SecretStorage(context, "id4", configStorage, dataStorage, keyStorage, signedPasswordKeyManager2);
        SecretStorage s5 = new SecretStorage(context, "id5", configStorage, dataStorage, keyStorage, asymmetricWrapKeyStoreManager1);
        SecretStorage s6 = new SecretStorage(context, "id6", configStorage, dataStorage, keyStorage, asymmetricWrapKeyStoreManager2);
        SecretStorage s7 = new SecretStorage(context, "id7", configStorage, dataStorage, keyStorage, keyStoreManager1);
        SecretStorage s8 = new SecretStorage(context, "id8", configStorage, dataStorage, keyStorage, keyStoreManager2);

        s1.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password");
        s2.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password2");
        s3.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password3");
        s4.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("password4");

        s1.store("secret1", "message1".getBytes());
        s2.store("secret1", "message2".getBytes());
        s3.store("secret1", "message3".getBytes());
        s4.store("secret1", "message4".getBytes());
        s5.store("secret1", "message5".getBytes());
        s6.store("secret1", "message6".getBytes());
        s7.store("secret1", "message7".getBytes());
        s8.store("secret1", "message8".getBytes());

        assertEquals("message1", new String(s1.load("secret1")));
        assertEquals("message2", new String(s2.load("secret1")));
        assertEquals("message3", new String(s3.load("secret1")));
        assertEquals("message4", new String(s4.load("secret1")));
        assertEquals("message5", new String(s5.load("secret1")));
        assertEquals("message6", new String(s6.load("secret1")));
        assertEquals("message7", new String(s7.load("secret1")));
        assertEquals("message8", new String(s8.load("secret1")));
    }

    @Test
    public void defaultBuilders() throws IOException {
        configStorage.store("id::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.JELLY_BEAN_MR1));
        SecretStorage storage = new SecretStorage.Builder(context, "id").build();
        assert(storage.keyManager instanceof ObfuscationKeyManager);

        configStorage.store("id2::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.JELLY_BEAN_MR2));
        storage = new SecretStorage.Builder(context, "id2").build();
        assert(storage.keyManager.getKeyWrapper() instanceof AsymmetricKeyStoreWrapper);

        configStorage.store("id3::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.M));
        storage = new SecretStorage.Builder(context, "id3").build();
        assert(storage.keyManager.getKeyWrapper() instanceof KeyStoreWrapper);

        configStorage.store("id4::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.JELLY_BEAN_MR1));
        storage = new SecretStorage.Builder(context, "id4").withUserPassword(true).build();
        assert(storage.keyManager instanceof PasswordProtectedKeyManager);
        assert(storage.keyManager.getKeyWrapper() instanceof PasswordKeyWrapper);

        configStorage.store("id5::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.JELLY_BEAN_MR2));
        storage = new SecretStorage.Builder(context, "id5").withUserPassword(true).build();
        assert(storage.keyManager instanceof PasswordProtectedKeyManager);
        assert(storage.keyManager.getKeyWrapper() instanceof SignedPasswordKeyWrapper);
    }

}