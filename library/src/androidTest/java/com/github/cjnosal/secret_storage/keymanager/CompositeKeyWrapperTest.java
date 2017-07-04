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
    private DataStorage configStorage1;
    private DataStorage configStorage2;
    private DataStorage keyStorage1;
    private DataStorage keyStorage2;
    private CompositeKeyWrapper subject;
    private KeyGenerator keyGenerator;
    private SecretKey enc;
    private SecretKey sig;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        configStorage1 = new PreferenceStorage(context, "testConfig1");
        configStorage1.clear();
        keyStorage1 = new PreferenceStorage(context, "testKeys1");
        keyStorage1.clear();
        configStorage2 = new PreferenceStorage(context, "testConfig2");
        configStorage2.clear();
        keyStorage2 = new PreferenceStorage(context, "testKeys2");
        keyStorage2.clear();

        List<KeyWrapper> keyWrappers = Arrays.<KeyWrapper>asList(
                new PasswordKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage1,
                        keyStorage1
                ),
                new PasswordKeyWrapper(
                        DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                        DefaultSpecs.getAes128KeyGenSpec(),
                        DefaultSpecs.getAesWrapSpec(),
                        configStorage2,
                        keyStorage2
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
        return (PasswordKeyWrapper.PasswordEditor) ((CompositeKeyWrapper.CompositeEditor)subject.getEditor("id")).getEditor(0);
    }

    private PasswordKeyWrapper.PasswordEditor getSecondEditor() {
        return (PasswordKeyWrapper.PasswordEditor) ((CompositeKeyWrapper.CompositeEditor)subject.getEditor("id")).getEditor(1);
    }

    @Test
    public void storeAndLoad() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        assertTrue(keyStorage1.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertTrue(keyStorage2.exists("id::WRAPPED_ENCRYPTION_KEY"));

        subject.storeDataSigningKey("id", sig);
        assertTrue(keyStorage1.exists("id::WRAPPED_SIGNING_KEY"));
        assertTrue(keyStorage2.exists("id::WRAPPED_SIGNING_KEY"));

        assertTrue(configStorage1.exists("id::ENC_SALT"));
        assertTrue(configStorage1.exists("id::VERIFICATION"));
        assertTrue(configStorage2.exists("id::ENC_SALT"));
        assertTrue(configStorage2.exists("id::VERIFICATION"));

        getFirstEditor().lock();

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        SecretKey unwrappedSig = subject.loadDataSigningKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);

        getFirstEditor().unlock("password1".toCharArray());
        getSecondEditor().lock();

        unwrappedEnc = subject.loadDataEncryptionKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        unwrappedSig = subject.loadDataSigningKey("id", SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
    }

    @Test
    public void eraseConfig() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);

        subject.eraseConfig("id");

        assertFalse(configStorage1.exists("id::ENC_SALT"));
        assertFalse(configStorage1.exists("id::VERIFICATION"));
        assertFalse(keyStorage1.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage1.exists("id::WRAPPED_SIGNING_KEY"));

        assertFalse(configStorage2.exists("id::ENC_SALT"));
        assertFalse(configStorage2.exists("id::VERIFICATION"));
        assertFalse(keyStorage2.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage2.exists("id::WRAPPED_SIGNING_KEY"));
    }

    @Test
    public void eraseKeys() throws Exception {
        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);

        subject.eraseKeys("id");

        assertFalse(keyStorage1.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage1.exists("id::WRAPPED_SIGNING_KEY"));
        assertFalse(keyStorage2.exists("id::WRAPPED_ENCRYPTION_KEY"));
        assertFalse(keyStorage2.exists("id::WRAPPED_SIGNING_KEY"));
    }

    @Test
    public void keysExist() throws Exception {
        assertFalse(subject.dataKeysExist("id"));

        subject.storeDataEncryptionKey("id", enc);
        subject.storeDataSigningKey("id", sig);
        assertTrue(subject.dataKeysExist("id"));
    }

}
