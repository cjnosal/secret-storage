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

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import org.junit.Before;
import org.junit.Test;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.security.auth.login.LoginException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PasswordProtectedKeyManagerTest {

    private Context context;
    private PasswordKeyWrapper keyWrapper;
    private KeyWrap keyWrap;
    private DataKeyGenerator dataKeyGenerator;
    private ProtectionSpec dataProtectionSpec;
    private AndroidCrypto androidCrypto;
    private DataStorage configStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        keyWrap = new KeyWrap();
        dataKeyGenerator = new DataKeyGenerator();
        androidCrypto = new AndroidCrypto();
        configStorage = new PreferenceStorage(context, "test");
        configStorage.clear();
    }

    @Test
    public void defaultKeyWrapper_jbmr1_isPasswordKeyWrapper() {
        KeyManager subject = new PasswordProtectedKeyManager.Builder()
                .configStorage(configStorage)
                .defaultKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR1)
                .defaultDataProtection(Build.VERSION_CODES.JELLY_BEAN_MR1)
                .build();
        assertTrue(subject.getKeyWrapper() instanceof PasswordKeyWrapper);
    }

    @Test
    public void defaultKeyWrapper_jbmr2_isSignedPasswordKeyWrapper() throws Exception {
        androidCrypto.clear();
        KeyManager subject = new PasswordProtectedKeyManager.Builder()
                .configStorage(configStorage)
                .defaultKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR2)
                .defaultDataProtection(Build.VERSION_CODES.JELLY_BEAN_MR2)
                .build();
        assertTrue(subject.getKeyWrapper() instanceof SignedPasswordKeyWrapper);
    }

    @Test
    public void passwordKeyWrapper() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);

        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");
        editor.setPassword("1234");

        SecretKey enc = subject.generateDataEncryptionKey();
        SecretKey sig = subject.generateDataSigningKey();

        byte[] cipherText = subject.encrypt(enc, sig, "Hello World".getBytes());

        byte[] wrappedEnc = subject.wrapKey("test", enc);
        byte[] wrappedSig = subject.wrapKey("test", sig);

        enc = subject.unwrapKey("test", wrappedEnc);
        sig = subject.unwrapKey("test", wrappedSig);

        String decrypted = new String(subject.decrypt(enc, sig, cipherText));
        assertEquals("Hello World", decrypted);
    }

    @Test
    public void signedPasswordKeyWrapper() throws Exception {
        androidCrypto.clear();
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR2);
        keyWrapper = new SignedPasswordKeyWrapper(
                context,
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordDeviceBindingSpec(context),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec());
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);

        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");
        editor.setPassword("1234");

        SecretKey enc = subject.generateDataEncryptionKey();
        SecretKey sig = subject.generateDataSigningKey();

        byte[] cipherText = subject.encrypt(enc, sig, "Hello World".getBytes());

        byte[] wrappedEnc = subject.wrapKey("test", enc);
        byte[] wrappedSig = subject.wrapKey("test", sig);

        enc = subject.unwrapKey("test", wrappedEnc);
        sig = subject.unwrapKey("test", wrappedSig);

        String decrypted = new String(subject.decrypt(enc, sig, cipherText));
        assertEquals("Hello World", decrypted);
    }

    @Test
    public void passwordEditor_setPassword() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        SecretKey enc = subject.generateDataEncryptionKey();
        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");

        try {
            subject.wrapKey("test", enc);
            fail("KeyWrapper has no password");
        } catch (LoginException e) {}

        try {
            subject.unwrapKey("test", new byte[]{});
            fail("KeyWrapper has no password");
        } catch (LoginException e) {}

        editor.setPassword("1234");

        byte[] wrappedEnc = subject.wrapKey("test", enc);
        Key unwrappedEnc = subject.unwrapKey("test", wrappedEnc);

        assertEquals(enc, unwrappedEnc);

        try {
            editor.setPassword("1234");
            fail("KeyWrapper already has password");
        } catch (LoginException e) {}
    }

    @Test
    public void passwordEditor_unlock() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        SecretKey enc = subject.generateDataEncryptionKey();
        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");

        try {
            editor.unlock("1234");
            fail("KeyWrapper has no password");
        } catch (LoginException e) {}

        editor.setPassword("1234");
        editor.lock();

        try {
            subject.wrapKey("test", enc);
            fail("KeyWrapper locked");
        } catch (LoginException e) {}

        try {
            subject.unwrapKey("test", new byte[]{});
            fail("KeyWrapper locked");
        } catch (LoginException e) {}

        editor.unlock("1234");

        byte[] wrappedEnc = subject.wrapKey("test", enc);
        Key unwrappedEnc = subject.unwrapKey("test", wrappedEnc);

        assertEquals(enc, unwrappedEnc);
    }

    @Test
    public void passwordEditor_verify() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");

        try {
            editor.verifyPassword("1234");
            fail("KeyWrapper has no password");
        } catch (LoginException e) {}

        editor.setPassword("1234");
        editor.lock();

        assertFalse(editor.verifyPassword("4321"));
        assertTrue(editor.verifyPassword("1234"));
    }

    @Test
    public void passwordEditor_isPasswordSet() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");

        assertFalse(editor.isPasswordSet());

        editor.setPassword("1234");
        assertTrue(editor.isPasswordSet());

        editor.lock();
        assertTrue(editor.isPasswordSet());

        editor.unlock("1234");
        assertTrue(editor.isPasswordSet());

        subject.clear("test");
        assertFalse(editor.isPasswordSet());
    }

    @Test
    public void passwordEditor_isUnlocked() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        keyWrapper = new PasswordKeyWrapper(
                DefaultSpecs.getPasswordDerivationSpec(),
                DefaultSpecs.getPasswordBasedKeyProtectionSpec()
        );
        KeyManager subject = new PasswordProtectedKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage);
        PasswordProtectedKeyManager.PasswordEditor editor = subject.getEditor(null, "test");

        assertFalse(editor.isUnlocked());

        editor.setPassword("1234");
        assertTrue(editor.isUnlocked());

        editor.lock();
        assertFalse(editor.isUnlocked());

        editor.unlock("1234");
        assertTrue(editor.isUnlocked());

        subject.clear("test");
        assertFalse(editor.isUnlocked());
    }
}
