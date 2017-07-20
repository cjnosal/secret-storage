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

public class ObfuscationKeyWrapperTest {

    private Context context;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private ObfuscationKeyWrapper subject;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        configStorage = new PreferenceStorage(context, "testConfig");
        configStorage.clear();
        keyStorage = new PreferenceStorage(context, "testKeys");
        keyStorage.clear();

        subject = new ObfuscationKeyWrapper(
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getAesWrapSpec(),
                configStorage,
                keyStorage
        );
        BaseKeyWrapper.NoParamsEditor editor = (BaseKeyWrapper.NoParamsEditor) subject.getEditor();
        editor.unlock();
    }

    @Test
    public void storeAndLoad() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey enc = keyGenerator.generateKey();
        SecretKey sig = keyGenerator.generateKey();

        subject.storeDataEncryptionKey(enc);
        assertTrue(keyStorage.exists("dek:WRAPPED_ENCRYPTION_KEY"));
        assertTrue(configStorage.exists("kek:WRAPPED_KEYWRAPPER_KEY"));

        subject.storeDataSigningKey(sig);
        assertTrue(keyStorage.exists("dek:WRAPPED_SIGNING_KEY"));

        assertTrue(configStorage.exists("kek:ENC_SALT"));
        assertTrue(configStorage.exists("kek:VERIFICATION"));

        subject = new ObfuscationKeyWrapper(
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getAesWrapSpec(),
                configStorage,
                keyStorage
        );
        BaseKeyWrapper.NoParamsEditor editor = (BaseKeyWrapper.NoParamsEditor) subject.getEditor();
        editor.unlock();

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        SecretKey unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
    }

    @Test
    public void eraseConfig() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey enc = keyGenerator.generateKey();
        SecretKey sig = keyGenerator.generateKey();

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.eraseConfig();

        assertFalse(configStorage.exists("kek:ENC_SALT"));
        assertFalse(configStorage.exists("kek:VERIFICATION"));
        assertFalse(configStorage.exists("kek:WRAPPED_KEYWRAPPER_KEY"));
        assertTrue(keyStorage.exists("dek:WRAPPED_ENCRYPTION_KEY"));
        assertTrue(keyStorage.exists("dek:WRAPPED_SIGNING_KEY"));
    }

    @Test
    public void eraseKeys() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey enc = keyGenerator.generateKey();
        SecretKey sig = keyGenerator.generateKey();

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.eraseKeys();

        assertFalse(keyStorage.exists("dek:WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage.exists("dek:WRAPPED_SIGNING_KEY"));
        assertTrue(configStorage.exists("kek:ENC_SALT"));
        assertTrue(configStorage.exists("kek:VERIFICATION"));
        assertTrue(configStorage.exists("kek:WRAPPED_KEYWRAPPER_KEY"));
    }

    @Test
    public void keysExist() throws Exception {
        assertFalse(subject.dataKeysExist());
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        SecretKey enc = keyGenerator.generateKey();
        SecretKey sig = keyGenerator.generateKey();

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        assertTrue(subject.dataKeysExist());
    }
}
