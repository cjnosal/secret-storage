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
import com.github.cjnosal.secret_storage.keymanager.data.DataKeyGenerator;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.SecretKey;

public class CompositeKeyWrapper implements KeyWrapper {

    private final List<KeyWrapper> keyWrappers;

    public CompositeKeyWrapper(List<KeyWrapper> keyWrappers) {
        this.keyWrappers = keyWrappers;
        KekProvider kekProvider = new CompositeKekProvider(new DataKeyGenerator());
        int index = 0;
        for (KeyWrapper kw : keyWrappers) {
            ((BaseKeyWrapper) kw).setKekProvider(kekProvider);
            ((BaseKeyWrapper) kw).setStorageScope("shared", "kek" + index);
            index++;
        }
        // TODO validate all keywrappers use same key storage, same key protection
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
        getUnlockedWrapper().storeDataEncryptionKey(storeId, key);
    }

    @Override
    public void storeDataSigningKey(String storeId, @KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        getUnlockedWrapper().storeDataSigningKey(storeId, key);
    }

    @Override
    public boolean dataKeysExist(String storeId) {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.dataKeysExist(storeId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public KeyWrapper.Editor getEditor(String storeId) {
        return new CompositeEditor(storeId);
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

    private KeyWrapper getUnlockedWrapper() throws GeneralSecurityException {
        boolean kekExists = hasKek();
        for (KeyWrapper kw : keyWrappers) {
            if (kw.isUnlocked() && (!kekExists || ((BaseKeyWrapper)kw).getIntermediateKek() != null)) {
                return kw;
            }
        }
        throw new GeneralSecurityException("No key wrappers are unlocked");
    }

    private boolean hasKek() {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.isUnlocked()) {
                SecretKey key = ((BaseKeyWrapper)kw).getIntermediateKek();
                if (key != null) {
                    return true;
                }
            }
        }
        return false;
    }

    public class CompositeEditor implements KeyWrapper.Editor {

        private String storeId;

        public CompositeEditor(String storeId) {
            this.storeId = storeId;
        }

        public <E extends KeyWrapper.Editor> E getEditor(int index) {
            return (E) CompositeKeyWrapper.this.keyWrappers.get(index).getEditor(storeId);
        }

        public int getKeyWrapperCount() {
            return CompositeKeyWrapper.this.keyWrappers.size();
        }

        @Override
        public void lock() {
            for (int i = 0; i < CompositeKeyWrapper.this.keyWrappers.size(); ++i) {
                getEditor(i).lock();
            }
        }

        @Override
        public boolean isUnlocked() {
            return CompositeKeyWrapper.this.isUnlocked();
        }

        @Override
        public void eraseConfig() throws GeneralSecurityException, IOException {
            for (int i = 0; i < CompositeKeyWrapper.this.keyWrappers.size(); ++i) {
                getEditor(i).eraseConfig();
            }
        }
    }

    private class CompositeKekProvider extends KekProvider {

        CompositeKekProvider(DataKeyGenerator generator) {
            super(generator);
        }

        @Override
        public SecretKey getSecretKey(KeyGenSpec spec) throws GeneralSecurityException {
            SecretKey secretKey;
            if (hasKek()) {
                secretKey = ((BaseKeyWrapper) getUnlockedWrapper()).getIntermediateKek();
            } else {
                secretKey = super.getSecretKey(spec);
            }
            return secretKey;
        }
    }
}
