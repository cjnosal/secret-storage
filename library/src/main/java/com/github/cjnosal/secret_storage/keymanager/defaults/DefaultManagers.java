package com.github.cjnosal.secret_storage.keymanager.defaults;

import android.content.Context;
import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.AsymmetricWrapKeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.KeyManager;
import com.github.cjnosal.secret_storage.keymanager.KeyStoreManager;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyManager;
import com.github.cjnosal.secret_storage.keymanager.crypto.AndroidCrypto;
import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class DefaultManagers {
    public KeyManager selectDefaultManager(Context context, int osVersion, DataStorage configStorage, String storeId, String userPassword) throws GeneralSecurityException, IOException {
        Crypto crypto = new Crypto();
        if (userPassword != null) {
            if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                PasswordKeyManager manager = new SignedPasswordKeyManager(
                        context, storeId, crypto, new AndroidCrypto(), DefaultStrategies.getDataProtectionStrategy(crypto), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultSpecs.getShaRsaIntegritySpec(), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto), new PreferenceStorage(context, storeId + "keys"), configStorage);
                manager.unlock(userPassword);
                return manager;
            } else {
                PasswordKeyManager manager = new PasswordKeyManager(
                        crypto, DefaultStrategies.getDataProtectionStrategy(crypto), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto), new PreferenceStorage(context, storeId + "keys"), configStorage);
                manager.unlock(userPassword);
                return manager;
            }
        } else {
            if (osVersion >= Build.VERSION_CODES.M) {
                return new KeyStoreManager(new AndroidCrypto(), storeId, DefaultStrategies.getKeyStoreDataProtectionStrategy(crypto));
            } else if (osVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                return new AsymmetricWrapKeyStoreManager(
                        context, crypto, new AndroidCrypto(), storeId, DefaultStrategies.getDataProtectionStrategy(crypto), new PreferenceStorage(context, storeId + "keys"), DefaultStrategies.getAsymmetricKeyProtectionStrategy(crypto));
            } else {
                PasswordKeyManager manager = new PasswordKeyManager(
                        crypto, DefaultStrategies.getDataProtectionStrategy(crypto), DefaultSpecs.getPbkdf2WithHmacShaDerivationSpec(), DefaultStrategies.getPasswordBasedKeyProtectionStrategy(crypto), new PreferenceStorage(context, storeId + "keys"), configStorage);
                manager.unlock("default_password");
                return manager;
            }
        }
    }
}
