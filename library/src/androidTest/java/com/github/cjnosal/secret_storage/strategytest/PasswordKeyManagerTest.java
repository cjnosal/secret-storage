package com.github.cjnosal.secret_storage.strategytest;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
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
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.derivation.KeyDerivationSpec;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.login.LoginException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class PasswordKeyManagerTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    DataStorage configStorage;
    DataStorage keyStorage;

    @Before
    public void setup() throws IOException {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        configStorage.clear();
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

    @Test
    public void testWrongPassword() throws Exception {
        try {
            PasswordKeyManager strat = createManager(
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec()),
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec())
            );
            strat.lock();
            strat.unlock("wild guess");
            fail("Expecting exception for wrong password");
        } catch (LoginException e) {
            // expected
        }
    }

    @Test
    public void testEncryptWhileLocked() throws Exception {
        try {
            PasswordKeyManager strat = createManager(
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec()),
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec())
            );
            strat.lock();

            strat.encrypt("t", "Hello world".getBytes());

            fail("Expecting exception for locked manager");
        } catch (LoginException e) {
            // expected
        }
    }

    @Test
    public void testDecryptWhileLocked() throws Exception {
        try {
            PasswordKeyManager strat = createManager(
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec()),
                    new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                    new MacStrategy(crypto, getSymmetricIntegritySpec())
            );
            strat.lock();

            strat.decrypt("t", "Hello world".getBytes());

            fail("Expecting exception for locked manager");
        } catch (LoginException e) {
            // expected
        }
    }

    private PasswordKeyManager createManager(CipherStrategy dataCipher, IntegrityStrategy dataIntegrity, CipherStrategy keyCipher, IntegrityStrategy keyIntegrity) throws IOException, GeneralSecurityException {

        PasswordKeyManager passwordKeyManager = new PasswordKeyManager(
                crypto,
                new ProtectionStrategy(
                        dataCipher,
                        dataIntegrity
                ),
                getDerivationSpec(),
                new ProtectionStrategy(
                        keyCipher,
                        keyIntegrity
                ),
                keyStorage,
                configStorage
        );
        passwordKeyManager.unlock("default_password");
        return passwordKeyManager;
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
}
