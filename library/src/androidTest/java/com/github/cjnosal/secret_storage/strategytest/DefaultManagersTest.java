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
import org.junit.Ignore;
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
    public void setup() throws IOException {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        crypto = new Crypto();
        androidCrypto = new AndroidCrypto();
        configStorage = new FileStorage(context.getFilesDir() + "/testConfig");
        keyStorage = new FileStorage(context.getFilesDir() + "/testData");
        defaultManagers = new DefaultManagers();
        configStorage.clear();
    }

    @Test
    public void M_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, configStorage, "id", null);
        assert(manager instanceof KeyStoreManager);
        byte[] e1 = manager.encrypt("a", "1".getBytes());
        assertEquals(new String(manager.decrypt("a", e1)), "1");
    }

    @Test
    public void JB_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, "id", null);
        assert(manager instanceof AsymmetricWrapKeyStoreManager);
        byte[] e1 = manager.encrypt("a", "1".getBytes());
        assertEquals(new String(manager.decrypt("a", e1)), "1");
    }

    @Test
    public void noKeyStore_noPassword() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, "id", null);
        assert(manager instanceof PasswordKeyManager);
        ((PasswordKeyManager)manager).unlock("default_password");
        byte[] e1 = manager.encrypt("a", "1".getBytes());
        assertEquals(new String(manager.decrypt("a", e1)), "1");
    }

    @Test
    public void JB_Password() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, "id", "user secret");
        assert(manager instanceof SignedPasswordKeyManager);
        ((PasswordKeyManager)manager).unlock("user secret");
        byte[] e1 = manager.encrypt("a", "1".getBytes());
        assertEquals(new String(manager.decrypt("a", e1)), "1");
    }

    @Test
    public void noKeyStore_Password() throws GeneralSecurityException, IOException {
        KeyManager manager = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, "id", "user secret");
        assert(manager instanceof PasswordKeyManager);
        ((PasswordKeyManager)manager).unlock("user secret");
        byte[] e1 = manager.encrypt("a", "1".getBytes());
        assertEquals(new String(manager.decrypt("a", e1)), "1");
    }

    @Test
    @Ignore // TODO allow reused config file, or have SecretStorage setup storeId/config and storeId/data?
    public void config_interference() throws GeneralSecurityException, IOException {
        KeyManager manager1 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, configStorage, "id1", null);
        KeyManager manager2 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, "id2", null);
        KeyManager manager3 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, "id3", null);
        KeyManager manager4 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, configStorage, "id4", "user secret");
        KeyManager manager5 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.ICE_CREAM_SANDWICH, configStorage, "id5", "other user secret");

        byte[] e1 = manager1.encrypt("a", "1".getBytes());
        byte[] e2 = manager2.encrypt("a", "2".getBytes());
        byte[] e3 = manager3.encrypt("a", "3".getBytes());
        byte[] e4 =  manager4.encrypt("a", "4".getBytes());
        byte[] e5 = manager5.encrypt("a", "5".getBytes());

        assertEquals(new String(manager1.decrypt("a", e1)), "1");
        assertEquals(new String(manager2.decrypt("a", e2)), "2");
        assertEquals(new String(manager3.decrypt("a", e3)), "3");
        assertEquals(new String(manager4.decrypt("a", e4)), "4");
        assertEquals(new String(manager5.decrypt("a", e5)), "5");
    }

    @Test
    public void keystore_interference() throws GeneralSecurityException, IOException {
        // 3 managers that all make use of AndroidKeyStore - ensure they don't use each others' keys
        KeyManager manager1 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.M, new FileStorage(context.getFilesDir() + "/testConfig1"), "id1", null);
        KeyManager manager2 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, new FileStorage(context.getFilesDir() + "/testConfig2"), "id2", null);
        KeyManager manager3 = defaultManagers.selectDefaultManager(context, Build.VERSION_CODES.JELLY_BEAN_MR2, new FileStorage(context.getFilesDir() + "/testConfig4"), "id4", "user secret");

        byte[] e1 = manager1.encrypt("a", "1".getBytes());
        byte[] e2 = manager2.encrypt("a", "2".getBytes());
        byte[] e3 = manager3.encrypt("a", "3".getBytes());

        assertEquals(new String(manager1.decrypt("a", e1)), "1");
        assertEquals(new String(manager2.decrypt("a", e2)), "2");
        assertEquals(new String(manager3.decrypt("a", e3)), "3");
    }

}
