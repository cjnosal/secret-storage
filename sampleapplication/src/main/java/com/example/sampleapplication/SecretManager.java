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

package com.example.sampleapplication;

import android.content.Context;
import android.os.Build;
import android.support.v4.os.CancellationSignal;

import com.github.cjnosal.secret_storage.SecretStorage;
import com.github.cjnosal.secret_storage.keymanager.CompositeKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.FingerprintWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.SignedPasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.defaults.DefaultSpecs;
import com.github.cjnosal.secret_storage.keymanager.fingerprint.FingerprintStatus;
import com.github.cjnosal.secret_storage.keymanager.fingerprint.FingerprintUtil;
import com.github.cjnosal.secret_storage.keymanager.strategy.DataProtectionSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;
import com.github.cjnosal.secret_storage.storage.encoding.Encoding;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;

public class SecretManager {

    private final SecretStorage secretStorage;
    private final Context applicationContext;
    private CancellationSignal cancellationSignal;

    public SecretManager(Context applicationContext) {
        this.applicationContext = applicationContext;
        // Because a CompositeKeyWrapper is used, all KeyWrappers must share the same storage and key protection CipherSpec
        DataStorage configStorage = new PreferenceStorage(applicationContext, "config");
        DataStorage keyStorage = new PreferenceStorage(applicationContext, "keys");
        DataStorage dataStorage = new FileStorage(applicationContext.getFilesDir() + File.separator + "data");

        PasswordKeyWrapper passwordKeyWrapper;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            passwordKeyWrapper = new PasswordKeyWrapper(DefaultSpecs.getPasswordCryptoConfig(), configStorage, keyStorage);
        } else if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            passwordKeyWrapper = new SignedPasswordKeyWrapper(applicationContext, DefaultSpecs.getLegacySignedPasswordCryptoConfig(), configStorage, keyStorage);
        } else {
            passwordKeyWrapper = new SignedPasswordKeyWrapper(applicationContext, DefaultSpecs.getSignedPasswordCryptoConfig(), configStorage, keyStorage);
        }

        KeyWrapper keyWrapper;
        DataProtectionSpec dataProtectionSpec;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            FingerprintWrapper fingerprintWrapper = new FingerprintWrapper(DefaultSpecs.getFingerprintCryptoConfig(), configStorage, keyStorage);
            keyWrapper = new CompositeKeyWrapper(Arrays.<KeyWrapper>asList(passwordKeyWrapper, fingerprintWrapper));
            dataProtectionSpec = DefaultSpecs.getDefaultDataProtectionSpec();
        } else {
            keyWrapper = new CompositeKeyWrapper(Collections.<KeyWrapper>singletonList(passwordKeyWrapper));
            dataProtectionSpec = DefaultSpecs.getLegacyDataProtectionSpec();
        }

        secretStorage = new SecretStorage(
                dataStorage,
                dataProtectionSpec,
                keyWrapper);
    }

    //region manage password

    public void setPassword(String password) throws IOException, GeneralSecurityException {
        getPasswordEditor().setPassword(password.toCharArray());
    }

    public void changePassword(String oldPassword, String newPassword) throws GeneralSecurityException, IOException {
        getPasswordEditor().changePassword(oldPassword.toCharArray(), newPassword.toCharArray());
    }

    public void resetPassword(String password) throws IOException, GeneralSecurityException {
        getPasswordEditor().eraseConfig();
        getPasswordEditor().setPassword(password.toCharArray());
    }

    public boolean verifyPassword(String password) throws GeneralSecurityException, IOException {
        return getPasswordEditor().verifyPassword(password.toCharArray());
    }

    public void unlockWithPassword(String password) throws GeneralSecurityException, IOException {
        getPasswordEditor().unlock(password.toCharArray());
    }

    public boolean isPasswordAuthenticationEnabled() {
        return getPasswordEditor().isPasswordSet();
    }

    private PasswordKeyWrapper.PasswordEditor getPasswordEditor() {
        return getCompositeEditor().getEditor(0);
    }

    //endregion manage password

    //region manage fingerprint

    public void cancelFingerprintRequest() {
        if (cancellationSignal != null && !cancellationSignal.isCanceled()) {
            cancellationSignal.cancel();
        }
    }

    public void unlockWithFingerprint(final KeyWrapper.Listener listener) {
        cancellationSignal = new CancellationSignal();
        getFingerprintEditor().unlock(applicationContext, cancellationSignal, listener, null);
    }

    public void verifyFingerprint(final KeyWrapper.Listener listener) {
        cancellationSignal = new CancellationSignal();
        getFingerprintEditor().verify(applicationContext, cancellationSignal, listener, null);
    }

    public void disableFingerprintAuthentication() throws GeneralSecurityException, IOException {
        getFingerprintEditor().eraseConfig();
    }

    public boolean isFingerprintAuthenticationEnabled() {
        return getCompositeEditor().getKeyWrapperCount() == 2 && getFingerprintEditor().isInitialized();
    }

    private FingerprintWrapper.FingerprintEditor getFingerprintEditor() {
        return getCompositeEditor().getEditor(1);
    }

    //endregion manage fingerprint

    public void lock() {
        secretStorage.getEditor().lock();
    }

    public boolean isUnlocked() {
        return getCompositeEditor().isUnlocked();
    }

    public void clear() throws IOException, GeneralSecurityException {
        secretStorage.reset();
    }

    public void store(String secret) throws GeneralSecurityException, IOException {
        secretStorage.store("MY_SECRET", Encoding.utf8Decode(secret));
    }

    public String load() throws GeneralSecurityException, IOException {
        return Encoding.utf8Encode(secretStorage.load("MY_SECRET"));
    }

    public boolean hasSavedEntry() {
        return secretStorage.exists("MY_SECRET");
    }

    public boolean isAuthenticationInitialized() {
        return isPasswordAuthenticationEnabled() || isFingerprintAuthenticationEnabled();
    }

    private CompositeKeyWrapper.CompositeEditor getCompositeEditor() {
        return secretStorage.getEditor();
    }

    public FingerprintStatus checkFingerprintStatus(Context context) {
        return new FingerprintUtil().getFingerprintStatus(context);
    }
}