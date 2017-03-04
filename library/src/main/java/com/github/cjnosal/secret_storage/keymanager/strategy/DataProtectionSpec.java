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

package com.github.cjnosal.secret_storage.keymanager.strategy;

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegritySpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;

public class DataProtectionSpec {
    private final CipherSpec cipherSpec;
    private final IntegritySpec integritySpec;
    private final KeyGenSpec cipherKeyGenSpec;
    private final KeyGenSpec integrityKeyGenSpec;

    public DataProtectionSpec(CipherSpec cipherSpec, IntegritySpec integritySpec, KeyGenSpec cipherKeyGenSpec, KeyGenSpec integrityKeyGenSpec) {
        this.cipherSpec = cipherSpec;
        this.integritySpec = integritySpec;
        this.cipherKeyGenSpec = cipherKeyGenSpec;
        this.integrityKeyGenSpec = integrityKeyGenSpec;
    }

    public CipherSpec getCipherSpec() {
        return cipherSpec;
    }

    public IntegritySpec getIntegritySpec() {
        return integritySpec;
    }

    public KeyGenSpec getCipherKeyGenSpec() {
        return cipherKeyGenSpec;
    }

    public KeyGenSpec getIntegrityKeyGenSpec() {
        return integrityKeyGenSpec;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DataProtectionSpec that = (DataProtectionSpec) o;

        if (cipherSpec != null ? !cipherSpec.equals(that.cipherSpec) : that.cipherSpec != null)
            return false;
        if (integritySpec != null ? !integritySpec.equals(that.integritySpec) : that.integritySpec != null)
            return false;
        if (cipherKeyGenSpec != null ? !cipherKeyGenSpec.equals(that.cipherKeyGenSpec) : that.cipherKeyGenSpec != null)
            return false;
        return integrityKeyGenSpec != null ? integrityKeyGenSpec.equals(that.integrityKeyGenSpec) : that.integrityKeyGenSpec == null;

    }

    @Override
    public int hashCode() {
        int result = cipherSpec != null ? cipherSpec.hashCode() : 0;
        result = 31 * result + (integritySpec != null ? integritySpec.hashCode() : 0);
        result = 31 * result + (cipherKeyGenSpec != null ? cipherKeyGenSpec.hashCode() : 0);
        result = 31 * result + (integrityKeyGenSpec != null ? integrityKeyGenSpec.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "DataProtectionSpec{" +
                "cipherSpec=" + cipherSpec +
                ", integritySpec=" + integritySpec +
                ", cipherKeyGenSpec=" + cipherKeyGenSpec +
                ", integrityKeyGenSpec=" + integrityKeyGenSpec +
                '}';
    }
}
