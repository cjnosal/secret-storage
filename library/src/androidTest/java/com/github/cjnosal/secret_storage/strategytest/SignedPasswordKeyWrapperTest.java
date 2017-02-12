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
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
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

public class SignedPasswordKeyWrapperTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
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
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SignatureStrategy(crypto, getDerivationIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        String plain = new String(strat.decrypt(cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testChangePassword() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SignatureStrategy(crypto, getDerivationIntegritySpec())
        );

        byte[] cipher = strat.encrypt("Hello world".getBytes());
        PasswordKeyWrapper wrapper = getSignedPasswordKeyManager(new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec()),
                new SignatureStrategy(crypto, getDerivationIntegritySpec()), "new_password");

        strat.rewrap(wrapper);

        String plain = new String(strat.decrypt(cipher));
        assertEquals(plain, "Hello world");

        wrapper.lock();
        wrapper.unlock("new_password");

        plain = new String(strat.decrypt(cipher));
        assertEquals(plain, "Hello world");
    }

    private KeyManager createManager(CipherStrategy dataCipher, IntegrityStrategy dataIntegrity, CipherStrategy keyCipher, IntegrityStrategy keyIntegrity, IntegrityStrategy derivationIntegrityStrategy) throws IOException, GeneralSecurityException {

        SignedPasswordKeyWrapper passwordKeyManager = getSignedPasswordKeyManager(keyCipher, keyIntegrity, derivationIntegrityStrategy, "default_password");
        return new KeyManager(
                "test",
                new ProtectionStrategy(
                        dataCipher,
                        dataIntegrity
                ),
                crypto,
                keyStorage,
                passwordKeyManager
        );
    }

    @NonNull
    private SignedPasswordKeyWrapper getSignedPasswordKeyManager(CipherStrategy keyCipher, IntegrityStrategy keyIntegrity, IntegrityStrategy derivationIntegrityStrategy, String password) throws GeneralSecurityException, IOException {
        SignedPasswordKeyWrapper passwordKeyManager = new SignedPasswordKeyWrapper(
                context,
                "testStore",
                crypto,
                androidCrypto,
                getDerivationSpec(),
                derivationIntegrityStrategy,
                new ProtectionStrategy(
                        keyCipher,
                        keyIntegrity
                ),
                configStorage
        );
        passwordKeyManager.setPassword(password);
        return passwordKeyManager;
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
