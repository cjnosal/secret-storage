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

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecretStorageTest {

    private Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    private AndroidCrypto androidCrypto;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private DataStorage dataStorage;
    private DataKeyGenerator dataKeyGenerator;
    private KeyWrap keyWrap;

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
        SecretStorage secretStorage = new SecretStorage.Builder(context, "id")
                .withUserPassword(true)
                .keyStorage(keyStorage)
                .dataStorage(dataStorage)
                .configStorage(configStorage)
                .build();
        secretStorage.<PasswordProtectedKeyManager.PasswordEditor>getEditor().setPassword("mysecret");
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void createWithoutPassword() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage = new SecretStorage.Builder(context, "id")
                .withUserPassword(false)
                .keyStorage(keyStorage)
                .dataStorage(dataStorage)
                .configStorage(configStorage)
                .build();
        secretStorage.store("mysecret", "message".getBytes());
        assertEquals(new String(secretStorage.load("mysecret")), "message");
    }

    @Test
    public void createWithManager() throws IOException, GeneralSecurityException {
        PasswordKeyWrapper wrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );

        PasswordProtectedKeyManager keyManager = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                wrapper,
                dataKeyGenerator,
                keyWrap,
                configStorage
        );

        SecretStorage secretStorage = new SecretStorage("id", dataStorage, keyStorage, keyManager);
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
                .defaultKeyWrapper(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH)
                .defaultDataProtection(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
                .build();
        SecretStorage secretStorage1 = new SecretStorage("id", dataStorage,
                keyStorage, obfuscationKeyManager);

        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        // ICS data encryption for compatibility, upgraded key wrapper using M's AndroidKeyStore
        KeyManager upgradedWrapping = new KeyManager(DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.ICE_CREAM_SANDWICH),
                new KeyStoreWrapper(DefaultSpecs.getKeyStoreCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        secretStorage1.rewrap(upgradedWrapping);

        assertEquals(new String(secretStorage1.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage1.load("mysecret2")), "message2");

        SecretStorage secretStorage2 = new SecretStorage("id", dataStorage,
                keyStorage, upgradedWrapping);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        PasswordProtectedKeyManager passwordKeyManager1 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new PasswordKeyWrapper(
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec()
                ),
                dataKeyGenerator,
                keyWrap,
                configStorage);

        PasswordProtectedKeyManager passwordKeyManager2 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new PasswordKeyWrapper(
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec()
                ),
                dataKeyGenerator,
                keyWrap,
                configStorage);

        PasswordProtectedKeyManager signedPasswordKeyManager1 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordDeviceBindingSpec(context),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec()
                ),
                dataKeyGenerator,
                keyWrap,
                configStorage);

        PasswordProtectedKeyManager signedPasswordKeyManager2 = new PasswordProtectedKeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new SignedPasswordKeyWrapper(
                        context,
                        DefaultSpecs.getPasswordDerivationSpec(),
                        DefaultSpecs.getPasswordDeviceBindingSpec(context),
                        DefaultSpecs.getPasswordBasedKeyProtectionSpec()
                ),
                dataKeyGenerator,
                keyWrap,
                configStorage);

        KeyManager asymmetricWrapKeyStoreManager1 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new AsymmetricKeyStoreWrapper(
                        DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context)),
                dataKeyGenerator,
                keyWrap);

        KeyManager asymmetricWrapKeyStoreManager2 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new AsymmetricKeyStoreWrapper(
                        DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context)),
                dataKeyGenerator,
                keyWrap);

        KeyManager keyStoreManager1 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new KeyStoreWrapper(DefaultSpecs.getKeyStoreCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        KeyManager keyStoreManager2 = new KeyManager(
                DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.KITKAT),
                new KeyStoreWrapper(DefaultSpecs.getKeyStoreCipherSpec()),
                dataKeyGenerator,
                keyWrap);

        SecretStorage s1 = new SecretStorage("id1", dataStorage, keyStorage, passwordKeyManager1);
        SecretStorage s2 = new SecretStorage("id2", dataStorage, keyStorage, passwordKeyManager2);
        SecretStorage s3 = new SecretStorage("id3", dataStorage, keyStorage, signedPasswordKeyManager1);
        SecretStorage s4 = new SecretStorage("id4", dataStorage, keyStorage, signedPasswordKeyManager2);
        SecretStorage s5 = new SecretStorage("id5", dataStorage, keyStorage, asymmetricWrapKeyStoreManager1);
        SecretStorage s6 = new SecretStorage("id6", dataStorage, keyStorage, asymmetricWrapKeyStoreManager2);
        SecretStorage s7 = new SecretStorage("id7", dataStorage, keyStorage, keyStoreManager1);
        SecretStorage s8 = new SecretStorage("id8", dataStorage, keyStorage, keyStoreManager2);

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
        KeyManager keyManager = SecretStorage.selectKeyManager(context, Build.VERSION_CODES.JELLY_BEAN_MR1, false, configStorage);
        assertTrue(keyManager instanceof ObfuscationKeyManager);

        keyManager = SecretStorage.selectKeyManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, false, configStorage);
        assertFalse(keyManager instanceof PasswordProtectedKeyManager);

        keyManager = SecretStorage.selectKeyManager(context, Build.VERSION_CODES.M, false, configStorage);
        assertFalse(keyManager instanceof PasswordProtectedKeyManager);

        keyManager = SecretStorage.selectKeyManager(context, Build.VERSION_CODES.JELLY_BEAN_MR1, true, configStorage);
        assertTrue(keyManager instanceof PasswordProtectedKeyManager);

        keyManager = SecretStorage.selectKeyManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, true, configStorage);
        assertTrue(keyManager instanceof PasswordProtectedKeyManager);
    }

}