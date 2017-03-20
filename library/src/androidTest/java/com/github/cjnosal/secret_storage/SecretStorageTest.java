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

package com.github.cjnosal.secret_storage;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.AsymmetricKeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.BaseKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapperInitializer;
import com.github.cjnosal.secret_storage.keymanager.ObfuscationKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

public class SecretStorageTest {

    private Context context;
    private AndroidCrypto androidCrypto;
    private DataStorage configStorage;
    private DataStorage keyStorage;
    private DataStorage dataStorage;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        androidCrypto = new AndroidCrypto();
        configStorage = new PreferenceStorage(context, "testConfig");
        keyStorage = new PreferenceStorage(context, "testKeys");
        dataStorage = new FileStorage(context.getFilesDir() + "/testData");
        keyStorage.clear();
        dataStorage.clear();
        configStorage.clear();
    }

    private SecretStorage.Builder defaultBuilder(String id) {
        return new SecretStorage.Builder(context, id)
                .keyStorage(keyStorage)
                .configStorage(configStorage)
                .dataStorage(dataStorage);
    }

    private ObfuscationKeyWrapper getObfuscationKeyWrapper() throws IOException {
        return (ObfuscationKeyWrapper) SecretStorage.instantiateKeyWrapper(context, SecretStorage.Obfuscation, 1, configStorage, keyStorage);
    }

    private PasswordKeyWrapper getPasswordKeyWrapper() throws IOException {
        return (PasswordKeyWrapper) SecretStorage.instantiateKeyWrapper(context, SecretStorage.Password, 1, configStorage, keyStorage);
    }

    private SignedPasswordKeyWrapper getSignedPasswordKeyWrapper() throws IOException {
        return (SignedPasswordKeyWrapper) SecretStorage.instantiateKeyWrapper(context, SecretStorage.SignedPassword, 1, configStorage, keyStorage);
    }

    private AsymmetricKeyStoreWrapper getAsymmetricKeyStoreWrapper() throws IOException {
        return (AsymmetricKeyStoreWrapper) SecretStorage.instantiateKeyWrapper(context, SecretStorage.AsymmetricKeyStore, 1, configStorage, keyStorage);
    }

    private KeyStoreWrapper getKeyStoreWrapper() throws IOException {
        return (KeyStoreWrapper) SecretStorage.instantiateKeyWrapper(context, SecretStorage.KeyStore, 1, configStorage, keyStorage);
    }

    @Test
    public void copyTo() throws IOException, GeneralSecurityException {
        SecretStorage secretStorage1 = defaultBuilder("id")
                .keyWrapper(getPasswordKeyWrapper())
                .build();
        secretStorage1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password");
        secretStorage1.store("mysecret1", "message1".getBytes());
        secretStorage1.store("mysecret2", "message2".getBytes());

        SecretStorage secretStorage2 = defaultBuilder("id2")
                .keyWrapper(getObfuscationKeyWrapper())
                .build();
        ((BaseKeyWrapper.NoParamsEditor)secretStorage2.getEditor()).unlock();
        secretStorage1.copyTo(secretStorage2);

        assertEquals(new String(secretStorage2.load("mysecret1")), "message1");
        assertEquals(new String(secretStorage2.load("mysecret2")), "message2");
    }

    @Test
    public void rewrap() throws IOException, GeneralSecurityException {
        final List<KeyWrapper> keyWrappers = Arrays.<KeyWrapper>asList(
                getObfuscationKeyWrapper(),
                getPasswordKeyWrapper(),
                getSignedPasswordKeyWrapper(),
                getAsymmetricKeyStoreWrapper(),
                getKeyStoreWrapper()
        );

        for (final KeyWrapper k1 : keyWrappers) {

            for (final KeyWrapper k2 : keyWrappers) {

                if (k1 == k2) {
                    continue;
                }

                keyStorage.clear();
                dataStorage.clear();
                configStorage.clear();
                androidCrypto.clear();

                final SecretStorage secretStorage = defaultBuilder("id")
                        .keyWrapper(k1)
                        .build();
                if (k1 instanceof PasswordKeyWrapper && !(k1 instanceof ObfuscationKeyWrapper)) {
                    PasswordKeyWrapper.PasswordEditor e = (PasswordKeyWrapper.PasswordEditor) k1.getEditor("id");
                    if (!e.isPasswordSet()) {
                        e.setPassword("password" + keyWrappers.indexOf(k1));
                    } else if (!e.isUnlocked()) {
                        e.unlock("password" + keyWrappers.indexOf(k1));
                    }
                } else {
                    ((BaseKeyWrapper.NoParamsEditor)k1.getEditor("id")).unlock();
                }
                secretStorage.store("my secret", "message".getBytes());

                secretStorage.rewrap(new KeyWrapperInitializer() {

                    @Override
                    public KeyWrapper initKeyWrapper() throws IOException, GeneralSecurityException {
                        k1.eraseConfig("id");
                        if (k2 instanceof PasswordKeyWrapper && !(k2 instanceof ObfuscationKeyWrapper)) {
                            PasswordKeyWrapper.PasswordEditor e = (PasswordKeyWrapper.PasswordEditor)k2.getEditor("id");
                            if (!e.isPasswordSet()) {
                                e.setPassword("password" + keyWrappers.indexOf(k2));
                            } else if (!e.isUnlocked()) {
                                e.unlock("password" + keyWrappers.indexOf(k2));
                            }
                        } else {
                            ((BaseKeyWrapper.NoParamsEditor)k2.getEditor("id")).unlock();
                        }
                        return k2;
                    }
                });
                assertEquals(new String(secretStorage.load("my secret")), "message");
            }
        }
    }

    @Test
    public void sharedResourcesShouldNotInterfere() throws IOException, GeneralSecurityException {
        androidCrypto.clear();

        SecretStorage s1 = defaultBuilder("id1").keyWrapper(getPasswordKeyWrapper()).build();
        SecretStorage s2 = defaultBuilder("id2").keyWrapper(getPasswordKeyWrapper()).build();
        SecretStorage s3 = defaultBuilder("id3").keyWrapper(getSignedPasswordKeyWrapper()).build();
        SecretStorage s4 = defaultBuilder("id4").keyWrapper(getSignedPasswordKeyWrapper()).build();
        SecretStorage s5 = defaultBuilder("id5").keyWrapper(getAsymmetricKeyStoreWrapper()).build();
        SecretStorage s6 = defaultBuilder("id6").keyWrapper(getAsymmetricKeyStoreWrapper()).build();
        SecretStorage s7 = defaultBuilder("id7").keyWrapper(getKeyStoreWrapper()).build();
        SecretStorage s8 = defaultBuilder("id8").keyWrapper(getKeyStoreWrapper()).build();
        SecretStorage s9 = defaultBuilder("id9").keyWrapper(getObfuscationKeyWrapper()).build();
        SecretStorage s10 = defaultBuilder("id10").keyWrapper(getObfuscationKeyWrapper()).build();

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password");
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password2");
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password3");
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().setPassword("password4");
        s5.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s6.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s7.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s8.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s9.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s10.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();

        s1.store("secret1", "message1".getBytes());
        s2.store("secret1", "message2".getBytes());
        s3.store("secret1", "message3".getBytes());
        s4.store("secret1", "message4".getBytes());
        s5.store("secret1", "message5".getBytes());
        s6.store("secret1", "message6".getBytes());
        s7.store("secret1", "message7".getBytes());
        s8.store("secret1", "message8".getBytes());
        s9.store("secret1", "message9".getBytes());
        s10.store("secret1", "message10".getBytes());

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().lock();
        s5.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();
        s6.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();
        s7.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();
        s8.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();
        s9.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();
        s10.<BaseKeyWrapper.NoParamsEditor>getEditor().lock();

        s1.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password");
        s2.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password2");
        s3.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password3");
        s4.<PasswordKeyWrapper.PasswordEditor>getEditor().unlock("password4");
        s5.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s6.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s7.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s8.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s9.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();
        s10.<BaseKeyWrapper.NoParamsEditor>getEditor().unlock();

        assertEquals("message1", new String(s1.load("secret1")));
        assertEquals("message2", new String(s2.load("secret1")));
        assertEquals("message3", new String(s3.load("secret1")));
        assertEquals("message4", new String(s4.load("secret1")));
        assertEquals("message5", new String(s5.load("secret1")));
        assertEquals("message6", new String(s6.load("secret1")));
        assertEquals("message7", new String(s7.load("secret1")));
        assertEquals("message8", new String(s8.load("secret1")));
        assertEquals("message9", new String(s9.load("secret1")));
        assertEquals("message10", new String(s10.load("secret1")));
    }

    @Test
    public void defaultBuilders() throws IOException {
        int wrapperType;
        wrapperType = SecretStorage.selectKeyWrapper(Build.VERSION_CODES.JELLY_BEAN_MR1, false);
        assertEquals(SecretStorage.Obfuscation, wrapperType);

        wrapperType = SecretStorage.selectKeyWrapper(Build.VERSION_CODES.JELLY_BEAN_MR2, false);
        assertEquals(SecretStorage.AsymmetricKeyStore, wrapperType);

        wrapperType = SecretStorage.selectKeyWrapper(Build.VERSION_CODES.M, false);
        assertEquals(SecretStorage.KeyStore, wrapperType);

        wrapperType = SecretStorage.selectKeyWrapper(Build.VERSION_CODES.JELLY_BEAN_MR1, true);
        assertEquals(SecretStorage.Password, wrapperType);

        wrapperType = SecretStorage.selectKeyWrapper(Build.VERSION_CODES.JELLY_BEAN_MR2, true);
        assertEquals(SecretStorage.SignedPassword, wrapperType);
    }

    @Test
    public void defaultSchemas() throws IOException {
        int schema;
        schema = SecretStorage.getCurrentSchema(SecretStorage.Obfuscation);
        assertEquals(1, schema);

        schema = SecretStorage.getCurrentSchema(SecretStorage.AsymmetricKeyStore);
        assertEquals(1, schema);

        schema = SecretStorage.getCurrentSchema(SecretStorage.KeyStore);
        assertEquals(1, schema);

        schema = SecretStorage.getCurrentSchema(SecretStorage.Password);
        assertEquals(1, schema);

        schema = SecretStorage.getCurrentSchema(SecretStorage.SignedPassword);
        assertEquals(2, schema);
    }

    @Test // run on 18+ emulator
    public void savedKeyWrapperIgnoresOsVersion() throws Exception {
        configStorage.store("id::OS_VERSION", DataEncoding.encode(Build.VERSION_CODES.JELLY_BEAN_MR1)); // Selects Obfuscation
        KeyWrapper keyWrapper = SecretStorage.selectKeyWrapper(context, "id", configStorage, keyStorage, false);
        assertTrue(keyWrapper instanceof ObfuscationKeyWrapper);
    }

}