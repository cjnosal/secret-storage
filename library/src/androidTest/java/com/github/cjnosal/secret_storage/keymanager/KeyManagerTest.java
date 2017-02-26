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

import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KeyManagerTest {

    private Context context;
    private KeyWrapper keyWrapper;
    private KeyWrap keyWrap;
    private DataKeyGenerator dataKeyGenerator;
    private ProtectionSpec dataProtectionSpec;
    private AndroidCrypto androidCrypto;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        keyWrap = new KeyWrap();
        dataKeyGenerator = new DataKeyGenerator();
        androidCrypto = new AndroidCrypto();
        androidCrypto.clear();
    }

    @Test
    public void defaultKeyWrapper_jbmr1_throwsException() {
        try {
            KeyManager subject = new KeyManager.Builder()
                    .defaultKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR1)
                    .defaultDataProtection(Build.VERSION_CODES.JELLY_BEAN_MR1)
                    .build();
            fail("KeyManager should throw exception when keystore not available");
        } catch(IllegalArgumentException expected) {}
    }

    @Test
    public void defaultKeyWrapper_jbmr2_isAsymmetricKeyStoreWrapper() {
        KeyManager subject = new KeyManager.Builder()
                .defaultKeyWrapper(context, Build.VERSION_CODES.JELLY_BEAN_MR2)
                .defaultDataProtection(Build.VERSION_CODES.JELLY_BEAN_MR2)
                .build();
        assertTrue(subject.getKeyWrapper() instanceof AsymmetricKeyStoreWrapper);
    }

    @Test
    public void defaultKeyWrapper_m_isKeyStoreWrapper() {
        KeyManager subject = new KeyManager.Builder()
                .defaultKeyWrapper(context, Build.VERSION_CODES.M)
                .defaultDataProtection(Build.VERSION_CODES.M)
                .build();
        assertTrue(subject.getKeyWrapper() instanceof KeyStoreWrapper);
    }

    @Test
    public void asymmetricKeyStoreWrapper() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR2);
        keyWrapper = new AsymmetricKeyStoreWrapper(DefaultSpecs.getAsymmetricKeyStoreCipherSpec(context));
        KeyManager subject = new KeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap);

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
    public void keyStoreWrapper() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.M);
        keyWrapper = new KeyStoreWrapper(DefaultSpecs.getKeyStoreCipherSpec());
        KeyManager subject = new KeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap);

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
}
