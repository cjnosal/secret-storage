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

package com.github.cjnosal.secret_storage.keymanager;

import com.github.cjnosal.secret_storage.annotations.KeyPurpose;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public interface KeyWrapper {

    @KeyPurpose.DataSecrecy SecretKey loadDataEncryptionKey(String keyType) throws GeneralSecurityException, IOException;

    @KeyPurpose.DataIntegrity SecretKey loadDataSigningKey(String keyType) throws GeneralSecurityException, IOException;

    void storeDataEncryptionKey(@KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException;

    void storeDataSigningKey(@KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException;

    boolean dataKeysExist();

    void eraseDataKeys() throws GeneralSecurityException, IOException;

    KeyWrapper.Editor getEditor();

    interface Editor {
        void lock();
        boolean isUnlocked();
        void eraseConfig() throws GeneralSecurityException, IOException;
        void setStorageScope(String keyScope, String configScope);
    }

    interface Listener {
        void onSuccess();
        void onError(Exception e);
    }
}
