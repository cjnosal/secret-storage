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
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.login.LoginException;

public class CompositeKeyWrapper implements KeyWrapper<CompositeKeyWrapper.CompositeEditor> {

    List<KeyWrapper> keyWrappers;

    public CompositeKeyWrapper(List<KeyWrapper> keyWrappers) {
        this.keyWrappers = keyWrappers;
    }

    @Override
    public boolean isUnlocked() {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.isUnlocked()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SecretKey loadDataEncryptionKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        return getUnlockedWrapper().loadDataEncryptionKey(storeId, keyType);
    }

    @Override
    public SecretKey loadDataSigningKey(String storeId, String keyType) throws GeneralSecurityException, IOException {
        return getUnlockedWrapper().loadDataSigningKey(storeId, keyType);
    }

    @Override
    public void storeDataEncryptionKey(String storeId, @KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        for (KeyWrapper kw : keyWrappers) {
            kw.storeDataEncryptionKey(storeId, key);
        }
    }

    @Override
    public void storeDataSigningKey(String storeId, @KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        for (KeyWrapper kw : keyWrappers) {
            kw.storeDataSigningKey(storeId, key);
        }
    }

    @Override
    public boolean dataKeysExist(String storeId) {
        return keyWrappers.get(0).dataKeysExist(storeId);
    }

    @Override
    public CompositeEditor getEditor(String storeId, ReWrap reWrap) {
        return new CompositeEditor(storeId, reWrap);
    }

    @Override
    public void eraseConfig(String keyAlias) throws GeneralSecurityException, IOException {
        for (KeyWrapper kw : keyWrappers) {
            kw.eraseConfig(keyAlias);
        }
    }

    @Override
    public void eraseKeys(String keyAlias) throws GeneralSecurityException, IOException {
        for (KeyWrapper kw : keyWrappers) {
            kw.eraseKeys(keyAlias);
        }
    }

    private KeyWrapper getUnlockedWrapper() throws LoginException {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.isUnlocked()) {
                return kw;
            }
        }
        throw new LoginException("No key wrappers are unlocked");
    }

    public class CompositeEditor extends KeyWrapper.Editor {

        private String storeId;
        private ReWrap reWrap;

        public CompositeEditor(String storeId, ReWrap reWrap) {
            this.storeId = storeId;
            this.reWrap = reWrap;
        }

        public <E extends KeyWrapper.Editor> E getEditor(int index) {
            return (E) CompositeKeyWrapper.this.keyWrappers.get(index).getEditor(storeId, reWrap);
        }
    }
}
