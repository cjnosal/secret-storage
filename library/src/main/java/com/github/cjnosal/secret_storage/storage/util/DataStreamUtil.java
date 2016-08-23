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

package com.github.cjnosal.secret_storage.storage.util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DataStreamUtil {

    public void writeByteArray(byte[] bytes, DataOutputStream ds) throws IOException {
        ds.writeInt(bytes.length);
        ds.write(bytes);
    }

    public byte[] readByteArray(DataInputStream ds) throws IOException {
        int length = ds.readInt();
        byte[] bytes = new byte[length];
        int bytesRead = ds.read(bytes);
        if (bytesRead != length) {
            throw new IOException("Length mismatch: expected " + length + " but was " + bytesRead);
        }
        return bytes;
    }
}
