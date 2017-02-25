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

package com.github.cjnosal.secret_storage.keymanager.keywrap;

public class PasswordWrapParams {

    private String password;
    private byte[] verification;
    private final byte[] salt;
    private final String keyAlias;

    public PasswordWrapParams(String keyAlias, String password, byte[] salt) {
        this.keyAlias = keyAlias;
        this.password = password;
        this.salt = salt;
    }

    public PasswordWrapParams(String keyAlias, String password, byte[] salt, byte[] verification) {
        this.keyAlias = keyAlias;
        this.password = password;
        this.salt = salt;
        this.verification = verification;
    }

    public String getPassword() {
        return password;
    }

    public byte[] getVerification() {
        return verification;
    }

    public byte[] getSalt() {
        return salt;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void clearPassword() {
        this.password = null;
    }
}
