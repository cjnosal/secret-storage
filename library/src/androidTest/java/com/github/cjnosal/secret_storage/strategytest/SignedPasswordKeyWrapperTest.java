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

package com.github.cjnosal.secret_storage.strategytest;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordProtectedKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.keywrap.KeyWrap;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

public class SignedPasswordKeyWrapperTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
        configStorage.clear();
        androidCrypto.clear();
    }

    @Test
    public void testSSSSA() throws Exception {
        KeyManager strat = createManager(
                getSymmetricCipherSpec(),
                getSymmetricIntegritySpec(),
                getSymmetricCipherSpec(),
                getSymmetricIntegritySpec(),
                getDerivationIntegritySpec()
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testChangePassword() throws Exception {
        PasswordProtectedKeyManager strat = createManager(
                getSymmetricCipherSpec(),
                getSymmetricIntegritySpec(),
                getSymmetricCipherSpec(),
                getSymmetricIntegritySpec(),
                getDerivationIntegritySpec()
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());

        strat.changePassword("default_password", "new_password");

        String plain = new String(strat.decrypt(cipher));
        assertEquals(plain, "Hello world");

        strat.lock();
        strat.unlock("new_password");

        plain = new String(strat.decrypt(cipher));
        assertEquals(plain, "Hello world");
    }

    private PasswordProtectedKeyManager createManager(CipherSpec dataCipher, IntegritySpec dataIntegrity, CipherSpec keyCipher, IntegritySpec keyIntegrity, IntegritySpec derivationIntegrity) throws IOException, GeneralSecurityException {

        SignedPasswordKeyWrapper wrapper = getWrapper(keyCipher, derivationIntegrity);
        PasswordProtectedKeyManager manager = new PasswordProtectedKeyManager(
                new ProtectionSpec(
                        dataCipher,
                        dataIntegrity
                ),
                keyStorage,
                wrapper,
                new DataKeyGenerator(),
                new KeyWrap(),
                configStorage
        );
        manager.setStoreId("test");
        manager.setPassword("default_password");
        return manager;
    }

    @NonNull
    private SignedPasswordKeyWrapper getWrapper(CipherSpec keyCipher, IntegritySpec derivationIntegrity) throws GeneralSecurityException, IOException {
        SignedPasswordKeyWrapper wrapper = new SignedPasswordKeyWrapper(
                context,
                androidCrypto,
                getDerivationSpec(),
                derivationIntegrity,
                "test"
        );
        return wrapper;
    }

    private static CipherSpec getSymmetricCipherSpec() {
        return DefaultSpecs.getAesCbcPkcs5CipherSpec();
    }

    private static IntegritySpec getSymmetricIntegritySpec() {
        return DefaultSpecs.getHmacShaIntegritySpec();
    }

    private static KeyDerivationSpec getDerivationSpec() {
        return DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec();
    }

    private static IntegritySpec getDerivationIntegritySpec() {
        return DefaultSpecs.getShaRsaIntegritySpec();
    }
}
