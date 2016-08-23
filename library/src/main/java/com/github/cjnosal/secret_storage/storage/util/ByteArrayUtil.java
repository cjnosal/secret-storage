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

import java.nio.ByteBuffer;

public class ByteArrayUtil {
    public static byte[] join(byte[] first, byte[] second) {
        int joinedLength = first.length + second.length + Integer.SIZE * 2;
        ByteBuffer buffer = ByteBuffer.allocate(joinedLength);
        buffer.putInt(first.length);
        buffer.put(first);
        buffer.putInt(second.length);
        buffer.put(second);
        return buffer.array();
    }

    public static byte[][] split(byte[] joined) {
        byte[][] splitArrays = new byte[2][];
        ByteBuffer buffer = ByteBuffer.wrap(joined);

        int firstLength = buffer.getInt();
        splitArrays[0] = new byte[firstLength];
        buffer.get(splitArrays[0]);

        int secondLength = buffer.getInt();
        splitArrays[1] = new byte[secondLength];
        buffer.get(splitArrays[1]);

        return splitArrays;
    }
}
