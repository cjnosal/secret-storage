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

import java.security.GeneralSecurityException;
import java.security.Key;

public abstract class IntegrityStrategy {

    public IntegrityStrategy() {
    }

    public abstract byte[] sign(Key key, IntegritySpec integritySpec, byte[] plainBytes) throws GeneralSecurityException;

    public abstract boolean verify(Key key, IntegritySpec integritySpec, byte[] cipherText, byte[] verification) throws GeneralSecurityException;
}
