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
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class SignedPasswordKeyManagerTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;

    @Before
    public void setup() throws IOException {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        androidCrypto = new AndroidCrypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
    }

    @Test
    public void testSSSS() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testSSSA() throws Exception {
        try {
            KeyManager strat = createManager(
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec()),
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
            );
            fail("Expecting exception for asymmetric key protection");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    public void testSSAS() throws Exception {
        try {
            KeyManager strat = createManager(
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec()),
                    new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec())
            );
            fail("Expecting exception for asymmetric key protection");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    public void testSASS() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testASSS() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testAASS() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    private SignedPasswordKeyManager createManager(CipherStrategy dataCipher, IntegrityStrategy dataIntegrity, CipherStrategy keyCipher, IntegrityStrategy keyIntegrity) throws IOException, GeneralSecurityException {

        SignedPasswordKeyManager testStore = new SignedPasswordKeyManager(
                context,
                "testStore",
                crypto,
                androidCrypto,
                new ProtectionStrategy(
                        dataCipher,
                        dataIntegrity
                ),
                getDerivationSpec(),
                getDerivationIntegritySpec(),
                new ProtectionStrategy(
                        keyCipher,
                        keyIntegrity
                ),
                keyStorage,
                configStorage
        );
        testStore.unlock("default_password");
        return testStore;
    }

    private static CipherSpec getSymmetricCipherSpec() {
        return DefaultSpecs.getAesCbcPkcs5CipherSpec();
    }

    private static CipherSpec getAsymmetricCipherSpec() {
        return DefaultSpecs.getRsaPKCS1CipherSpec();
    }

    private static IntegritySpec getSymmetricIntegritySpec() {
        return DefaultSpecs.getHmacShaIntegritySpec();
    }

    private static IntegritySpec getAsymmetricIntegritySpec() {
        return DefaultSpecs.getShaRsaIntegritySpec();
    }

    private static KeyDerivationSpec getDerivationSpec() {
        return DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec();
    }

    private static IntegritySpec getDerivationIntegritySpec() {
        return DefaultSpecs.getShaRsaIntegritySpec();
    }
}
