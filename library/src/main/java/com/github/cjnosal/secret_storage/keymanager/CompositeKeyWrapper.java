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
        IntermediateKekProvider intermediateKekProvider = new CompositeIntermediateKekProvider(new DataKeyGenerator());
        for (KeyWrapper kw : keyWrappers) {
            ((BaseKeyWrapper) kw).setIntermediateKekProvider(intermediateKekProvider);
        }
        getEditor().setStorageScope("shared", "kek");
        // TODO validate all keywrappers use same key storage, same key protection
    }

    private boolean isUnlocked() {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.getEditor().isUnlocked()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SecretKey loadDataEncryptionKey(String keyType) throws GeneralSecurityException, IOException {
        return getUnlockedWrapper().loadDataEncryptionKey(keyType);
    }

    @Override
    public SecretKey loadDataSigningKey(String keyType) throws GeneralSecurityException, IOException {
        return getUnlockedWrapper().loadDataSigningKey(keyType);
    }

    @Override
    public void storeDataEncryptionKey(@KeyPurpose.DataSecrecy SecretKey key) throws GeneralSecurityException, IOException {
        getUnlockedWrapper().storeDataEncryptionKey(key);
    }

    @Override
    public void storeDataSigningKey(@KeyPurpose.DataIntegrity SecretKey key) throws GeneralSecurityException, IOException {
        getUnlockedWrapper().storeDataSigningKey(key);
    }

    @Override
    public boolean dataKeysExist() {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.dataKeysExist()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public KeyWrapper.Editor getEditor() {
        return new CompositeEditor();
    }

    @Override
    public void eraseDataKeys() throws GeneralSecurityException, IOException {
        for (KeyWrapper kw : keyWrappers) {
            kw.eraseDataKeys();
        }
    }

    private void setStorageScope(String keyScope, String configScope) {
        int index = 0;
        for (KeyWrapper kw : keyWrappers) {
            kw.getEditor().setStorageScope(keyScope, configScope + index);
            index++;
        }
    }

    private KeyWrapper getUnlockedWrapper() throws GeneralSecurityException {
        boolean kekExists = hasIntermediateKek();
        for (KeyWrapper kw : keyWrappers) {
            if (kw.getEditor().isUnlocked() && (!kekExists || ((BaseKeyWrapper)kw).getIntermediateKek() != null)) {
                return kw;
            }
        }
        throw new GeneralSecurityException("No key wrappers are unlocked");
    }

    private boolean hasIntermediateKek() {
        for (KeyWrapper kw : keyWrappers) {
            if (kw.getEditor().isUnlocked()) {
                SecretKey key = ((BaseKeyWrapper)kw).getIntermediateKek();
                if (key != null) {
                    return true;
                }
            }
        }
        return false;
    }

    public class CompositeEditor implements KeyWrapper.Editor {

        public CompositeEditor() {}

        public <E extends KeyWrapper.Editor> E getEditor(int index) {
            return (E) CompositeKeyWrapper.this.keyWrappers.get(index).getEditor();
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

        @Override
        public void setStorageScope(String keyScope, String configScope) {
            CompositeKeyWrapper.this.setStorageScope(keyScope, configScope);
        }
    }

    private class CompositeIntermediateKekProvider extends IntermediateKekProvider {

        CompositeIntermediateKekProvider(DataKeyGenerator generator) {
            super(generator);
        }

        @Override
        public SecretKey getIntermediateKek(KeyGenSpec spec) throws GeneralSecurityException {
            SecretKey intermediateKek;
            if (hasIntermediateKek()) {
                intermediateKek = ((BaseKeyWrapper) getUnlockedWrapper()).getIntermediateKek();
            } else {
                intermediateKek = super.getIntermediateKek(spec);
            }
            return intermediateKek;
        }
    }
}
