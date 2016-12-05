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
import android.os.Build;
import android.support.test.InstrumentationRegistry;

import com.github.cjnosal.secret_storage.keymanager.AsymmetricWrapKeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultManagers;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static junit.framework.Assert.assertEquals;

public class DefaultManagersTest {

    Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    Crypto crypto;
    AndroidCrypto androidCrypto;
    DataStorage configStorage;
    DataStorage keyStorage;
    DefaultManagers defaultManagers;

    @Before
    public void setup() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        androidCrypto = new AndroidCrypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        defaultManagers = new DefaultManagers();
        configStorage.clear();
        keyStorage.clear();
        androidCrypto.clear();
    }

    @Test
    public void M_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, configStorage, keyStorage, "id", null);
        assert(manager instanceof KeyStoreManager);
        byte[] e1 = manager.encrypt("1".getBytes());
        assertEquals(new String(manager.decrypt(e1)), "1");
    }

    @Test
    public void JB_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id", null);
        assert(manager instanceof AsymmetricWrapKeyStoreManager);
        byte[] e1 = manager.encrypt("1".getBytes());
        assertEquals(new String(manager.decrypt(e1)), "1");
    }

    @Test
    public void noKeyStore_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, keyStorage, "id", null);
        assert(manager instanceof PasswordKeyManager);
        byte[] e1 = manager.encrypt("1".getBytes());
        assertEquals(new String(manager.decrypt(e1)), "1");
    }

    @Test
    public void JB_Password() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id", "user secret");
        assert(manager instanceof SignedPasswordKeyManager);
        ((PasswordKeyManager)manager).unlock("user secret");
        byte[] e1 = manager.encrypt("1".getBytes());
        assertEquals(new String(manager.decrypt(e1)), "1");
    }

    @Test
    public void noKeyStore_Password() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, keyStorage, "id", "user secret");
        assert(manager instanceof PasswordKeyManager);
        ((PasswordKeyManager)manager).unlock("user secret");
        byte[] e1 = manager.encrypt("1".getBytes());
        assertEquals(new String(manager.decrypt(e1)), "1");
    }

    @Test
    public void keystore_interference() throws GeneralSecurityException, IOException {
        KeyStoreManager manager1 = (KeyStoreManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, configStorage, keyStorage, "id1", null);
        KeyStoreManager manager2 = (KeyStoreManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, configStorage, keyStorage, "id2", null);

        AsymmetricWrapKeyStoreManager manager3 = (AsymmetricWrapKeyStoreManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id3", null);
        AsymmetricWrapKeyStoreManager manager4 = (AsymmetricWrapKeyStoreManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id4", null);

        SignedPasswordKeyManager manager5 = (SignedPasswordKeyManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id5", "user secret");
        SignedPasswordKeyManager manager6 = (SignedPasswordKeyManager) defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, keyStorage, "id6", "user secret2");

        byte[] e1 = manager1.encrypt("1".getBytes());
        byte[] e2 = manager2.encrypt("2".getBytes());
        byte[] e3 = manager3.encrypt("3".getBytes());
        byte[] e4 = manager4.encrypt("4".getBytes());
        byte[] e5 = manager5.encrypt("5".getBytes());
        byte[] e6 = manager6.encrypt("6".getBytes());

        assertEquals(new String(manager1.decrypt(e1)), "1");
        assertEquals(new String(manager2.decrypt(e2)), "2");
        assertEquals(new String(manager3.decrypt(e3)), "3");
        assertEquals(new String(manager4.decrypt(e4)), "4");
        assertEquals(new String(manager5.decrypt(e5)), "5");
        assertEquals(new String(manager6.decrypt(e6)), "6");
    }

}
