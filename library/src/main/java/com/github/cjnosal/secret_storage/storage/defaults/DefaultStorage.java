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

package com.github.cjnosal.secret_storage.storage.defaults;

import android.content.Context;

import com.github.cjnosal.secret_storage.storage.DataStorage;
import com.github.cjnosal.secret_storage.storage.FileStorage;
import com.github.cjnosal.secret_storage.storage.PreferenceStorage;

import java.io.File;

public class DefaultStorage {
    public DataStorage createStorage(Context context, String storeId, @DataStorage.Type String type) {
        if (type.equals(DataStorage.TYPE_DATA)) {
            return new FileStorage(context.getFilesDir() + File.separator + storeId + File.separator + type);
        } else {
            return new PreferenceStorage(context, storeId + type);
        }
    }
}
