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
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultManagers;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

public class SecretStorageTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;
    DataStorage dataStorage;
    DefaultManagers defaultManagers;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testKeys");
        dataStorage = new FileStorage(context.getFilesDir() + "/testData");
        defaultManagers = new DefaultManagers();
        configStorage.clear();
        keyStorage.clear();
        dataStorage.clear();
        androidCrypto.clear();
        clearDataFor("id");
        clearDataFor("id2");
    }

    private void clearDataFor(String id) throws Exception {
        new FileStorage(context.getFilesDir() + File.separator + id + File.separator + DataStorage.TYPE_DATA).clear();
        new PreferenceStorage(context, id + DataStorage.TYPE_CONF).clear();
        new PreferenceStorage(context, id + DataStorage.TYPE_KEYS).clear();
    }

    @Test
    public void createWithPassword() throws IOException, GeneralSecurityException {
        PasswordProtectedSecretStorage secretStorage = new PasswordProtectedSecretStorage.Builder(context, "id").build();
        secretStorage.setPassword("mysecret");
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
        PasswordKeyWrapper passwordKeyManager = new PasswordKeyWrapper("id",
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec(Build.VERSION_CODES.KITKAT),
                configStorage);
        passwordKeyManager.setPassword("password");

        KeyManager keyManager = new KeyManager(
                "test",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                passwordKeyManager
        );

        SecretStorage secretStorage = new SecretStorage(context, "id", configStorage, dataStorage, keyManager);
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void copyTo() throws IOException, GeneralSecurityException {
        PasswordProtectedSecretStorage secretStorage1 = new PasswordProtectedSecretStorage.Builder(context, "id").build();
        secretStorage1.setPassword("password");
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        SecretStorage secretStorage2 = new SecretStorage.Builder(context, "id2").build();
        secretStorage1.copyTo(secretStorage2);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void rewrap() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = new SecretStorage(context, "id", configStorage, dataStorage,
                new DefaultManagers().selectKeyManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, keyStorage, "id"));
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        // ICS data encryption for compatibility, upgraded key wrapper using M's AndroidKeyStore
        KeyManager upgradedWrapping = new KeyManager("id", DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.ICE_CREAM_SANDWICH), keyStorage,
                new KeyStoreWrapper(new AndroidCrypto(), "id", DefaultSpecs.getKeyStoreDataProtectionSpec()));

        secretStorage1.rewrap(upgradedWrapping);

        assertEquals(new String(secretStorage1.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage1.load("mysecret2")), "message2");

        SecretStorage secretStorage2 = new SecretStorage(context, "id", configStorage, dataStorage,
                upgradedWrapping);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");

        SecretStorage secretStorage3 = new SecretStorage(context, "id", configStorage, dataStorage,
                new DefaultManagers().selectKeyManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, keyStorage, "id"));
        try {
            assertEquals(new String(secretStorage3.load("mysecret1")), "message1");
            fail("Expected decryption failure as data keys were rewrapped");
        } catch (GeneralSecurityException e) {}
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        PasswordProtectedKeyManager passwordKeyManager1 = new PasswordProtectedKeyManager(
                "id1",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new PasswordKeyWrapper("id1",
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec(Build.VERSION_CODES.KITKAT),
                configStorage));
        passwordKeyManager1.setPassword("password");

        PasswordProtectedKeyManager passwordKeyManager2 = new PasswordProtectedKeyManager(
                "id2",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new PasswordKeyWrapper("id2",
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec(Build.VERSION_CODES.KITKAT),
                configStorage));
        passwordKeyManager2.setPassword("password2");

        PasswordProtectedKeyManager signedPasswordKeyManager1 = new PasswordProtectedKeyManager(
                "id3",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new SignedPasswordKeyWrapper(context, "id3", androidCrypto,
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordDeviceBindingSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec(Build.VERSION_CODES.KITKAT),
                configStorage));
        signedPasswordKeyManager1.setPassword("password3");

        PasswordProtectedKeyManager signedPasswordKeyManager2 = new PasswordProtectedKeyManager(
                "id4",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new SignedPasswordKeyWrapper(context, "id4", androidCrypto,
                DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(),
                DefaultSpecs.getPasswordDeviceBindingSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec(Build.VERSION_CODES.KITKAT),
                configStorage));
        signedPasswordKeyManager2.setPassword("password4");

        KeyManager asymmetricWrapKeyStoreManager1 = new KeyManager(
                "id5",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new AsymmetricKeyStoreWrapper(context, androidCrypto, "id5",
                DefaultSpecs.getAsymmetricKeyProtectionSpec()
        ));

        KeyManager asymmetricWrapKeyStoreManager2 = new KeyManager(
                "id6",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new AsymmetricKeyStoreWrapper(context, androidCrypto, "id6",
                DefaultSpecs.getAsymmetricKeyProtectionSpec()
        ));

        KeyManager keyStoreManager1 = new KeyManager(
                "id7",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new KeyStoreWrapper(androidCrypto, "id7",
                DefaultSpecs.getKeyStoreDataProtectionSpec()));

        KeyManager keyStoreManager2 = new KeyManager(
                "id8",
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                keyStorage,
                new KeyStoreWrapper(androidCrypto, "id8",
                DefaultSpecs.getKeyStoreDataProtectionSpec()));

        SecretStorage s1 = new SecretStorage(context, "id1", configStorage, dataStorage, passwordKeyManager1);
        SecretStorage s2 = new SecretStorage(context, "id2", configStorage, dataStorage, passwordKeyManager2);
        SecretStorage s3 = new SecretStorage(context, "id3", configStorage, dataStorage, signedPasswordKeyManager1);
        SecretStorage s4 = new SecretStorage(context, "id4", configStorage, dataStorage, signedPasswordKeyManager2);
        SecretStorage s5 = new SecretStorage(context, "id5", configStorage, dataStorage, asymmetricWrapKeyStoreManager1);
        SecretStorage s6 = new SecretStorage(context, "id6", configStorage, dataStorage, asymmetricWrapKeyStoreManager2);
        SecretStorage s7 = new SecretStorage(context, "id7", configStorage, dataStorage, keyStoreManager1);
        SecretStorage s8 = new SecretStorage(context, "id8", configStorage, dataStorage, keyStoreManager2);

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

}