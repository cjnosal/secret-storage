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

package com.github.cjnosal.secret_storage.keymanager.strategy.keygen;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public class KeyStoreKeyGenSpec extends KeyGenSpec {

    private KeyGenParameterSpec keyGenParameterSpec;

    public KeyStoreKeyGenSpec(KeyGenParameterSpec keyGenParameterSpec, String keyGenAlgorithm) {
        super(keyGenParameterSpec.getKeySize(), keyGenAlgorithm);
        this.keyGenParameterSpec = keyGenParameterSpec;
    }

    public KeyGenParameterSpec getKeyGenParameterSpec() {
        return keyGenParameterSpec;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        KeyStoreKeyGenSpec that = (KeyStoreKeyGenSpec) o;

        return keyGenParameterSpec != null ? keyGenParameterSpec.equals(that.keyGenParameterSpec) : that.keyGenParameterSpec == null;

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (keyGenParameterSpec != null ? keyGenParameterSpec.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "KeyStoreKeyGenSpec{" +
                "keyGenParameterSpec=" + keyGenParameterSpec +
                '}';
    }
}
