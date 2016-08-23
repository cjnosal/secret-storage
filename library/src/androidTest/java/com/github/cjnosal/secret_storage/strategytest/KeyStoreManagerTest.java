package com.github.cjnosal.secret_storage.strategytest;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.KeyStoreCipherSpec;
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
import com.github.cjnosal.secret_storage.keymanager.KeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.KeyStoreIntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreManagerTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    AndroidCrypto androidCrypto;
    DataStorage keyStorage;

    @Before
    public void setup() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        androidCrypto = new AndroidCrypto();
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
    }

    @Test
    public void testSS() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testSA() throws Exception {
        KeyManager strat = createManager(
                new SymmetricCipherStrategy(crypto, getSymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testAS() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new MacStrategy(crypto, getSymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    @Test
    public void testAA() throws Exception {
        KeyManager strat = createManager(
                new AsymmetricCipherStrategy(crypto, getAsymmetricCipherSpec()),
                new SignatureStrategy(crypto, getAsymmetricIntegritySpec())
        );

        byte[] cipher = strat.encrypt("t", "Hello world".getBytes());
        String plain = new String(strat.decrypt("t", cipher));

        assertEquals(plain, "Hello world");
    }

    private KeyStoreManager createManager(CipherStrategy dataCipher, IntegrityStrategy dataIntegrity) throws IOException, GeneralSecurityException {

        return new KeyStoreManager(
                androidCrypto,
                "test",
                new ProtectionStrategy(
                        dataCipher,
                        dataIntegrity
                )
        );
    }

    private static KeyStoreCipherSpec getSymmetricCipherSpec() {
        return DefaultSpecs.getKeyStoreAesCbcPkcs7CipherSpec();
    }

    private static KeyStoreCipherSpec getAsymmetricCipherSpec() {
        return DefaultSpecs.getKeyStoreRsaPkcs1CipherSpec();
    }

    private static KeyStoreIntegritySpec getSymmetricIntegritySpec() {
        return DefaultSpecs.getKeyStoreHmacShaIntegritySpec();
    }

    private static KeyStoreIntegritySpec getAsymmetricIntegritySpec() {
        return DefaultSpecs.getKeyStoreShaRsaPssIntegritySpec();
    }


}
