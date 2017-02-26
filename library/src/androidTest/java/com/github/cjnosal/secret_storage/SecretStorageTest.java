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
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecretStorageTest {

    private Context context;
    private AndroidCrypto androidCrypto;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private DataStorage dataStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        configStorage = new PreferenceStorage(context, "testConfig");
        keyStorage = new PreferenceStorage(context, "testKeys");
        dataStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
        dataStorage.clear();
        configStorage.clear();
    }

    private SecretStorage.Builder defaultBuilder(String id) {
        return new SecretStorage.Builder(context, id)
                .keyStorage(keyStorage)
                .configStorage(configStorage)
                .dataStorage(dataStorage);
    }

    private ObfuscationKeyWrapper getObfuscationKeyWrapper() {
        return (ObfuscationKeyWrapper) SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, false, configStorage, keyStorage);
    }

    private PasswordKeyWrapper getPasswordKeyWrapper() {
        return  (PasswordKeyWrapper) SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, true, configStorage, keyStorage);
    }

    private SignedPasswordKeyWrapper getSignedPasswordKeyWrapper() {
        return  (SignedPasswordKeyWrapper) SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.KITKAT, true, configStorage, keyStorage);
    }

    private AsymmetricKeyStoreWrapper getAsymmetricKeyStoreWrapper() {
        return  (AsymmetricKeyStoreWrapper) SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.KITKAT, false, configStorage, keyStorage);
    }

    private KeyStoreWrapper getKeyStoreWrapper() {
        return  (KeyStoreWrapper) SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.M, false, configStorage, keyStorage);
    }

    @Test
    public void copyTo() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = defaultBuilder("id")
                .keyWrapper(getPasswordKeyWrapper())
                .build();
        secretStorage1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password");
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        SecretStorage secretStorage2 = defaultBuilder("id2")
                .keyWrapper(getObfuscationKeyWrapper())
                .build();
        secretStorage1.copyTo(secretStorage2);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void rewrap() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = defaultBuilder("id")
                .keyWrapper(getPasswordKeyWrapper())
                .build();
        secretStorage1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password");
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        secretStorage1.rewrap(getObfuscationKeyWrapper());

        assertEquals(new String(secretStorage1.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage1.load("mysecret2")), "message2");

        SecretStorage secretStorage2 = defaultBuilder("id")
                .keyWrapper(getObfuscationKeyWrapper())
                .build();

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        androidCrypto.clear();

        SecretStorage s1 = defaultBuilder("id1").keyWrapper(getPasswordKeyWrapper()).build();
        SecretStorage s2 = defaultBuilder("id2").keyWrapper(getPasswordKeyWrapper()).build();
        SecretStorage s3 = defaultBuilder("id3").keyWrapper(getSignedPasswordKeyWrapper()).build();
        SecretStorage s4 = defaultBuilder("id4").keyWrapper(getSignedPasswordKeyWrapper()).build();
        SecretStorage s5 = defaultBuilder("id5").keyWrapper(getAsymmetricKeyStoreWrapper()).build();
        SecretStorage s6 = defaultBuilder("id6").keyWrapper(getAsymmetricKeyStoreWrapper()).build();
        SecretStorage s7 = defaultBuilder("id7").keyWrapper(getKeyStoreWrapper()).build();
        SecretStorage s8 = defaultBuilder("id8").keyWrapper(getKeyStoreWrapper()).build();

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password");
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password2");
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password3");
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password4");

        s1.store("secret1", "message1".getBytes());
        s2.store("secret1", "message2".getBytes());
        s3.store("secret1", "message3".getBytes());
        s4.store("secret1", "message4".getBytes());
        s5.store("secret1", "message5".getBytes());
        s6.store("secret1", "message6".getBytes());
        s7.store("secret1", "message7".getBytes());
        s8.store("secret1", "message8".getBytes());

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password");
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password2");
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password3");
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password4");

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
        KeyWrapper keyManager = SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR1, false, configStorage, keyStorage);
        assertTrue(keyManager instanceof ObfuscationKeyWrapper);

        keyManager = SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR2, false, configStorage, keyStorage);
        assertTrue(keyManager instanceof AsymmetricKeyStoreWrapper);

        keyManager = SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.M, false, configStorage, keyStorage);
        assertTrue(keyManager instanceof KeyStoreWrapper);

        keyManager = SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR1, true, configStorage, keyStorage);
        assertTrue(keyManager instanceof PasswordKeyWrapper);

        keyManager = SecretStorage.selectKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR2, true, configStorage, keyStorage);
        assertTrue(keyManager instanceof SignedPasswordKeyWrapper);
    }

}