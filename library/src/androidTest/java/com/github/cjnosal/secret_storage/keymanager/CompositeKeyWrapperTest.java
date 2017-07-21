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

import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CompositeKeyWrapperTest {

    private Context context;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private CompositeKeyWrapper subject;
    private KeyGenerator keyGenerator;
    private SecretKey enc;
    private SecretKey sig;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        configStorage = new PreferenceStorage(context, "testConfig");
        configStorage.clear();
        keyStorage = new PreferenceStorage(context, "testKeys");
        keyStorage.clear();

        List<KeyWrapper> keyWrappers = Arrays.<KeyWrapper>asList(
                new PasswordKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage,
                        keyStorage
                ),
                new PasswordKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage,
                        keyStorage
                )
        );

        subject = new CompositeKeyWrapper(keyWrappers);
        getFirstEditor().setPassword("password1".toCharArray());
        getSecondEditor().setPassword("password2".toCharArray());

        keyGenerator = KeyGenerator.getInstance(SecurityAlgorithms.KeyGenerator_AES);
        keyGenerator.init(SecurityAlgorithms.KEY_SIZE_AES_256);
        enc = keyGenerator.generateKey();
        sig = keyGenerator.generateKey();
    }

    private PasswordKeyWrapper.PasswordEditor getFirstEditor() {
        return (PasswordKeyWrapper.PasswordEditor) ((CompositeKeyWrapper.CompositeEditor)subject.getEditor()).getEditor(0);
    }

    private PasswordKeyWrapper.PasswordEditor getSecondEditor() {
        return (PasswordKeyWrapper.PasswordEditor) ((CompositeKeyWrapper.CompositeEditor)subject.getEditor()).getEditor(1);
    }

    @Test
    public void storeAndLoad() throws Exception {
        subject.storeDataEncryptionKey(enc);
        assertTrue(keyStorage.exists("shared:DATA_ENCRYPTION_KEY"));
        assertTrue(configStorage.exists("kek0:INTERMEDIATE_KEK"));
        assertTrue(configStorage.exists("kek1:INTERMEDIATE_KEK"));

        subject.storeDataSigningKey(sig);
        assertTrue(keyStorage.exists("shared:DATA_SIGNING_KEY"));

        assertTrue(configStorage.exists("kek0:ENC_SALT"));
        assertTrue(configStorage.exists("kek0:VERIFICATION"));
        assertTrue(configStorage.exists("kek1:ENC_SALT"));
        assertTrue(configStorage.exists("kek1:VERIFICATION"));

        getFirstEditor().lock();

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        SecretKey unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);

        getFirstEditor().unlock("password1".toCharArray());
        getSecondEditor().lock();

        unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
    }

    @Test
    public void eraseConfig() throws Exception {
        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.getEditor().eraseConfig();

        assertTrue(keyStorage.exists("shared:DATA_ENCRYPTION_KEY"));
        assertTrue(keyStorage.exists("shared:DATA_SIGNING_KEY"));
        assertFalse(configStorage.exists("kek0:INTERMEDIATE_KEK"));
        assertFalse(configStorage.exists("kek1:INTERMEDIATE_KEK"));
        assertFalse(configStorage.exists("kek0:ENC_SALT"));
        assertFalse(configStorage.exists("kek0:VERIFICATION"));
        assertFalse(configStorage.exists("kek1:ENC_SALT"));
        assertFalse(configStorage.exists("kek1:VERIFICATION"));
    }

    @Test
    public void eraseKeys() throws Exception {
        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.eraseDataKeys();

        assertFalse(keyStorage.exists("shared:DATA_ENCRYPTION_KEY"));
        assertFalse(keyStorage.exists("shared:DATA_SIGNING_KEY"));
        assertTrue(configStorage.exists("kek0:INTERMEDIATE_KEK"));
        assertTrue(configStorage.exists("kek1:INTERMEDIATE_KEK"));
        assertTrue(configStorage.exists("kek0:ENC_SALT"));
        assertTrue(configStorage.exists("kek0:VERIFICATION"));
        assertTrue(configStorage.exists("kek1:ENC_SALT"));
        assertTrue(configStorage.exists("kek1:VERIFICATION"));
    }

    @Test
    public void keysExist() throws Exception {
        assertFalse(subject.dataKeysExist());

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        assertTrue(subject.dataKeysExist());
    }

    @Test
    public void kekSharing() throws Exception {
        getFirstEditor().lock();
        getSecondEditor().lock();

        getFirstEditor().unlock("password1".toCharArray());
        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        getFirstEditor().lock();

        getSecondEditor().unlock("password2".toCharArray());
        SecretKey unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);
        SecretKey unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        getSecondEditor().lock();

        getFirstEditor().unlock("password1".toCharArray());
        unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);
        unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
        getFirstEditor().lock();
    }

    @Test
    public void resetWithUnlockedWrapper() throws Exception {
        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        getFirstEditor().eraseConfig();
        getFirstEditor().setPassword("password3".toCharArray());
        getSecondEditor().lock();

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);
        SecretKey unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
        getFirstEditor().lock();

        getSecondEditor().unlock("password2".toCharArray());
        unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);
        unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
        getSecondEditor().lock();
    }

}
