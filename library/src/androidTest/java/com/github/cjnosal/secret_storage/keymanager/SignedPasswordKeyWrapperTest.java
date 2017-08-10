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
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.SdkSuppress;

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

@SdkSuppress(minSdkVersion = Build.VERSION_CODES.JELLY_BEAN_MR2)
public class SignedPasswordKeyWrapperTest {

    private Context context;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private SignedPasswordKeyWrapper subject;
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

        subject = new SignedPasswordKeyWrapper(
                context,
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getSha256WithRsaSpec(),
                DefaultSpecs.getAesWrapSpec(),
                DefaultSpecs.getRsa2048KeyGenSpec(),
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
        subject.setPassword("password".toCharArray());

        subject.storeDataEncryptionKey(enc);
        assertTrue(keyStorage.exists("dek:DATA_ENCRYPTION_KEY"));
        assertTrue(configStorage.exists("kek:INTERMEDIATE_KEK"));
        assertTrue(androidCrypto.hasEntry("kek:DEVICE_BINDING"));

        subject.storeDataSigningKey(sig);
        assertTrue(keyStorage.exists("dek:DATA_SIGNING_KEY"));

        assertTrue(configStorage.exists("kek:ENC_SALT"));
        assertTrue(configStorage.exists("kek:VERIFICATION"));

        subject = new SignedPasswordKeyWrapper(
                context,
                DefaultSpecs.get4096RoundPBKDF2WithHmacSHA1(),
                DefaultSpecs.getAes128KeyGenSpec(),
                DefaultSpecs.getSha256WithRsaSpec(),
                DefaultSpecs.getAesWrapSpec(),
                DefaultSpecs.getRsa2048KeyGenSpec(),
                configStorage,
                keyStorage
        );
        ((PasswordKeyWrapper.PasswordEditor) subject.getEditor()).unlock("password".toCharArray());

        SecretKey unwrappedEnc = subject.loadDataEncryptionKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(enc, unwrappedEnc);

        SecretKey unwrappedSig = subject.loadDataSigningKey(SecurityAlgorithms.KeyGenerator_AES);
        assertEquals(sig, unwrappedSig);
    }

    @Test
    public void eraseConfig() throws Exception {
        subject.setPassword("password".toCharArray());

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.getEditor().eraseConfig();

        assertTrue(keyStorage.exists("dek:DATA_ENCRYPTION_KEY"));
        assertTrue(keyStorage.exists("dek:DATA_SIGNING_KEY"));
        assertFalse(configStorage.exists("kek:ENC_SALT"));
        assertFalse(configStorage.exists("kek:VERIFICATION"));
        assertFalse(configStorage.exists("kek:INTERMEDIATE_KEK"));
        assertFalse(androidCrypto.hasEntry("kek:DEVICE_BINDING"));
    }

    @Test
    public void eraseKeys() throws Exception {
        subject.setPassword("password".toCharArray());

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);

        subject.eraseDataKeys();

        assertFalse(keyStorage.exists("dek:DATA_ENCRYPTION_KEY"));
        assertFalse(keyStorage.exists("dek:DATA_SIGNING_KEY"));
        assertTrue(configStorage.exists("kek:ENC_SALT"));
        assertTrue(configStorage.exists("kek:VERIFICATION"));
        assertTrue(configStorage.exists("kek:INTERMEDIATE_KEK"));
        assertTrue(androidCrypto.hasEntry("kek:DEVICE_BINDING"));
    }

    @Test
    public void keysExist() throws Exception {
        subject.setPassword("password".toCharArray());
        assertFalse(subject.dataKeysExist());

        subject.storeDataEncryptionKey(enc);
        subject.storeDataSigningKey(sig);
        assertTrue(subject.dataKeysExist());
    }

    @Test
    public void getEditor_noPassword_setPassword() throws Exception {
        PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();
        assertFalse(editor.isPasswordSet());
        assertFalse(editor.isUnlocked());

        editor.setPassword("password".toCharArray());

        assertTrue(editor.isPasswordSet());
        assertTrue(editor.isUnlocked());
    }

    @Test
    public void getEditor_withPassword_setPasswordFails() throws Exception {
        PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();
        editor.setPassword("password".toCharArray());

        try {
            editor.setPassword("password2".toCharArray());
            fail("Password already set");
        } catch (PasswordKeyWrapper.PasswordAlreadySetException expected) {}
    }

    @Test
    public void getEditor_verifyPassword() throws Exception {
        PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();

        try {
            editor.verifyPassword("password".toCharArray());
            fail("Password not set");
        } catch (PasswordKeyWrapper.PasswordNotSetException expected) {}

        editor.setPassword("password".toCharArray());
        editor.lock();

        assertFalse(editor.verifyPassword("1234".toCharArray()));
        assertTrue(editor.verifyPassword("password".toCharArray()));
        assertFalse(editor.isUnlocked());
    }

    @Test
    public void getEditor_lock() throws Exception {
        PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();
        editor.setPassword("password".toCharArray());

        editor.lock();
        assertTrue(editor.isPasswordSet());
        assertFalse(editor.isUnlocked());
    }

    @Test
    public void getEditor_unlock() throws Exception {
        PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();

        try {
            editor.unlock("password".toCharArray());
            fail("Password not set");
        } catch (PasswordKeyWrapper.PasswordNotSetException expected) {}

        editor.setPassword("password".toCharArray());
        editor.lock();

        try {
            editor.unlock("password2".toCharArray());
            fail("Wrong password");
        } catch (PasswordKeyWrapper.WrongPasswordException expected) {}

        editor.unlock("password".toCharArray());
        assertTrue(editor.isUnlocked());
    }

    @Test
    public void getEditor_changePassword() throws Exception {
        final PasswordKeyWrapper.PasswordEditor editor = (PasswordKeyWrapper.PasswordEditor) subject.getEditor();

        try {
            editor.changePassword(null, "password".toCharArray());
            fail("Password not set");
        } catch (PasswordKeyWrapper.PasswordNotSetException expected) {}

        editor.setPassword("password".toCharArray());
        editor.lock();

        try {
            editor.changePassword("1234".toCharArray(), "password2".toCharArray());
            fail("Wrong password");
        } catch (PasswordKeyWrapper.WrongPasswordException expected) {}

        editor.changePassword("password".toCharArray(), "password2".toCharArray());
        assertTrue(editor.isUnlocked());
        assertTrue(editor.isPasswordSet());
        assertTrue(editor.verifyPassword("password2".toCharArray()));
    }


}
