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

package com.github.cjnosal.secret_storage.annotations;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;


public class KeyPurpose {
    @Retention(RetentionPolicy.SOURCE)
    public @interface Data {}
    @Retention(RetentionPolicy.SOURCE)
    public @interface DataSecrecy {}
    @Retention(RetentionPolicy.SOURCE)
    public @interface DataIntegrity {}

    @Retention(RetentionPolicy.SOURCE)
    public @interface Key {}
    @Retention(RetentionPolicy.SOURCE)
    public @interface KeySecrecy {}
    @Retention(RetentionPolicy.SOURCE)
    public @interface KeyIntegrity {}
}
