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

import com.github.cjnosal.secret_storage.keymanager.AsymmetricWrapKeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class AsymmetricKeyStoreWrapKeyManagerTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    AndroidCrypto androidCrypto;
    DataStorage keyStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        androidCrypto = new AndroidCrypto();
        androidCrypto.clear();
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
    }

    @Test
    public void testSSAA() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

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
            fail("Expecting exception for symmetric key protection");
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
            fail("Expecting exception for symmetric key protection");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    public void testSAAA() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec()),
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testASAA() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testAAAA() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec()),
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

        assertEquals(plain, "Hello world");
    }

    private AsymmetricWrapKeyStoreManager createManager(CipherStrategy dataCipher, IntegrityStrategy dataIntegrity, CipherStrategy keyCipher, IntegrityStrategy keyIntegrity) throws IOException, GeneralSecurityException {

        return new AsymmetricWrapKeyStoreManager(
                context,
                crypto,
                androidCrypto,
                "testStore",
                new ProtectionStrategy(
                        dataCipher,
                        dataIntegrity
                ),
                keyStorage,
                new ProtectionStrategy(
                        keyCipher,
                        keyIntegrity
                )
        );
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
}
