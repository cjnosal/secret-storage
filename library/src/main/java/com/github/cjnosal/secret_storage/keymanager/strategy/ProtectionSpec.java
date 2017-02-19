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

public class ProtectionSpec {
    private final CipherSpec cipherSpec;
    private final IntegritySpec integritySpec;

    public ProtectionSpec(CipherSpec cipherSpec, IntegritySpec integritySpec) {
        this.cipherSpec = cipherSpec;
        this.integritySpec = integritySpec;
    }

    public CipherSpec getCipherSpec() {
        return cipherSpec;
    }

    public IntegritySpec getIntegritySpec() {
        return integritySpec;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ProtectionSpec that = (ProtectionSpec) o;

        if (cipherSpec != null ? !cipherSpec.equals(that.cipherSpec) : that.cipherSpec != null)
            return false;
        return integritySpec != null ? integritySpec.equals(that.integritySpec) : that.integritySpec == null;

    }

    @Override
    public int hashCode() {
        int result = cipherSpec != null ? cipherSpec.hashCode() : 0;
        result = 31 * result + (integritySpec != null ? integritySpec.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ProtectionSpec{" +
                "cipherSpec=" + cipherSpec +
                ", integritySpec=" + integritySpec +
                '}';
    }
}
