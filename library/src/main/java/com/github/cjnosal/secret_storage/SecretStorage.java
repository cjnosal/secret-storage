package com.github.cjnosal.secret_storage;

import android.content.Context;
import android.os.Build;
import android.support.annotation.Nullable;

import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultManagers;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.encoding.DataEncoding;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class SecretStorage {

    private Context context;
    private String storeId;
    private DataStorage configStorage;
    private KeyManager keyManager;
    private DataStorage dataStorage;

    // TODO test multiple instances of SecretStorage with same/different key managers to ensure no conflicts if different stores use same data ID

    public SecretStorage(Context context, String storeId, DataStorage configStorage, KeyManager keyManager, DataStorage dataStorage) throws IOException, GeneralSecurityException {
        this.context = context;
        this.storeId = storeId;
        this.configStorage = configStorage;
        this.keyManager = keyManager;
        this.dataStorage = dataStorage;
    }

    public SecretStorage(Context context, String storeId, DataStorage configStorage, DataStorage dataStorage, @Nullable String userPassword) throws IOException, GeneralSecurityException {
        this.context = context;
        this.storeId = storeId;
        this.configStorage = configStorage;
        this.keyManager = selectKeyManager(userPassword);
        this.dataStorage = dataStorage;
    }

    public void store(String id, byte[] plainText) throws GeneralSecurityException, IOException {
        byte[] cipherText = keyManager.encrypt(id, plainText);
        dataStorage.store(id, cipherText);
    }

    public byte[] load(String id) throws GeneralSecurityException, IOException {
        byte[] cipherText = dataStorage.load(id);
        return keyManager.decrypt(id, cipherText);
    }

    private KeyManager selectKeyManager(@Nullable String userPassword) throws IOException, GeneralSecurityException {
        int osVersion; // OS Version when store was created // TODO migrations
        if (configStorage.exists(storeId + "Version")) {
            osVersion = DataEncoding.decodeInt(configStorage.load(storeId + "Version"));
        } else {
            osVersion = Build.VERSION.SDK_INT;
            configStorage.store(storeId + "Version", DataEncoding.encode(osVersion));
        }

        return new DefaultManagers().selectDefaultManager(context, osVersion, configStorage, storeId, userPassword);
    }
}
