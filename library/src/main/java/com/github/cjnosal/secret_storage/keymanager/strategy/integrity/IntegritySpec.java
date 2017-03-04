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

package com.github.cjnosal.secret_storage.keymanager.strategy.integrity;

public class IntegritySpec {
    private final String cipherTransformation; // Mac or Signature

    public IntegritySpec(String cipherTransformation) {
        this.cipherTransformation = cipherTransformation;
    }

    public String getIntegrityTransformation() {
        return cipherTransformation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IntegritySpec that = (IntegritySpec) o;

        return cipherTransformation != null ? cipherTransformation.equals(that.cipherTransformation) : that.cipherTransformation == null;

    }

    @Override
    public int hashCode() {
        return cipherTransformation != null ? cipherTransformation.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "IntegritySpec{" +
                "cipherTransformation='" + cipherTransformation + '\'' +
                '}';
    }
}
