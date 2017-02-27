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

package com.github.cjnosal.secret_storage.keymanager;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AsymmetricKeyStoreWrapperTest {

    private Context context;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private AsymmetricKeyStoreWrapper subject;
    private KeyGenerator keyGenerator;
    private SecretKey enc;
    private SecretKey sig;
    private AndroidCrypto androidCrypto;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        androidCrypto.clear();
        configStorage = new PreferenceStorage(context, "testConfig");
        configStorage.clear();
        keyStorage = new PreferenceStorage(context, "testKeys");
        keyStorage.clear();

        subject = new AsymmetricKeyStoreWrapper(
                DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context),
                configStorage,
                keyStorage
        );

        keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        enc = keyGenerator.generateKey();
        sig = keyGenerator.generateKey();
    }

    @Test
    public void storeAndLoad() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        assertTrue(configStorage.exists("id::KEY_PROTECTION"));
        assertTrue(keyStorage.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertTrue(androidCrypto.hasEntry("id::ENCRYPTION_KEY"));

        subject.storeDataSigningKey("id", sig);
        assertTrue(keyStorage.exists("id::WRAPPED_SIGNING_KEY"));

        subject = new AsymmetricKeyStoreWrapper(
                DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context),
                configStorage,
                keyStorage
        );

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        SecretKey unwrappedSig = subject.loadDataSigningKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
    }

    @Test
    public void eraseConfig() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);

        subject.eraseConfig("id");

        assertFalse(configStorage.exists("id::KEY_PROTECTION"));
        assertFalse(keyStorage.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage.exists("id::WRAPPED_SIGNING_KEY"));
        assertFalse(androidCrypto.hasEntry("id::ENCRYPTION_KEY"));
    }

    @Test
    public void eraseKeys() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);

        subject.eraseKeys("id");

        assertFalse(keyStorage.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage.exists("id::WRAPPED_SIGNING_KEY"));
    }

    @Test
    public void keysExist() throws Exception {
        assertFalse(subject.dataKeysExist("id"));

        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);
        assertTrue(subject.dataKeysExist("id"));
    }

    @Test
    public void getEditor() throws Exception {
        try {
            subject.getEditor("test", SecurityAlgorithms.KeyGenerator_AES, SecurityAlgorithms.KeyGenerator_AES);
            fail("No editor available for this manager");
        } catch (UnsupportedOperationException expected) {}
    }

}