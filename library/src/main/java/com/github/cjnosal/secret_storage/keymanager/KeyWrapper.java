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
import java.security.Key;

public abstract class KeyWrapper {
    abstract byte[] wrap(@KeyPurpose.Data Key key) throws GeneralSecurityException, IOException;
    abstract @KeyPurpose.Data Key unwrap(byte[] wrappedKey) throws GeneralSecurityException, IOException;
    abstract void clear() throws GeneralSecurityException, IOException;
    abstract void attach() throws IOException, GeneralSecurityException;
}
