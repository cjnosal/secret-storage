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

import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ObfuscationKeyManagerTest {

    private Context context;
    private PasswordKeyWrapper keyWrapper;
    private KeyWrap keyWrap;
    private DataKeyGenerator dataKeyGenerator;
    private ProtectionSpec dataProtectionSpec;
    private DataStorage configStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        keyWrap = new KeyWrap();
        dataKeyGenerator = new DataKeyGenerator();
        configStorage = new PreferenceStorage(context, "test");
        configStorage.clear();
    }

    @Test
    public void defaultKeyWrapper_isPasswordKeyWrapper() {
        KeyManager subject = new ObfuscationKeyManager.Builder()
                .configStorage(configStorage)
                .defaultKeyWrapper(Build.VERSION_CODES.JELLY_BEAN_MR1)
                .defaultDataProtection(Build.VERSION_CODES.JELLY_BEAN_MR1)
                .build();
        assertTrue(subject.getKeyWrapper() instanceof PasswordKeyWrapper);
    }

    @Test
    public void passwordKeyWrapper() throws Exception {
        dataProtectionSpec = DefaultSpecs.getDataProtectionSpec(Build.VERSION_CODES.JELLY_BEAN_MR1);
        KeyDerivationSpec derivationSpec = DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec();
        keyWrapper = new PasswordKeyWrapper(derivationSpec);
        KeyManager subject = new ObfuscationKeyManager(dataProtectionSpec, keyWrapper, dataKeyGenerator, keyWrap, configStorage, derivationSpec);

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
