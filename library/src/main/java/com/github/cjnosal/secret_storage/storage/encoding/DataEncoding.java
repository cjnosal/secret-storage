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

package com.github.cjnosal.secret_storage.storage.encoding;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.ShortBuffer;

public class DataEncoding {
    public static byte[] encode(byte value) {
        byte[] b = new byte[1];
        b[0] = value;
        return b;
    }
    public static byte decodeByte(byte[] value) {
        return value[0];
    }
    public static byte[] encode(char value) {
        ByteBuffer buffer = ByteBuffer.allocate(Character.SIZE/Byte.SIZE);
        buffer.putChar(value);
        return buffer.array();
    }
    public static char decodeChar(byte[] value) {
        CharBuffer buffer = ByteBuffer.wrap(value).asCharBuffer();
        return buffer.get();
    }
    public static byte[] encode(double value) {
        ByteBuffer buffer = ByteBuffer.allocate(Double.SIZE/Byte.SIZE);
        buffer.putDouble(value);
        return buffer.array();
    }
    public static double decodeDouble(byte[] value) {
        DoubleBuffer buffer = ByteBuffer.wrap(value).asDoubleBuffer();
        return buffer.get();
    }
    public static byte[] encode(float value) {
        ByteBuffer buffer = ByteBuffer.allocate(Float.SIZE/Byte.SIZE);
        buffer.putFloat(value);
        return buffer.array();
    }
    public static float decodeFloat(byte[] value) {
        FloatBuffer buffer = ByteBuffer.wrap(value).asFloatBuffer();
        return buffer.get();
    }
    public static byte[] encode(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE/Byte.SIZE);
        buffer.putLong(value);
        return buffer.array();
    }
    public static long decodeLong(byte[] value) {
        LongBuffer buffer = ByteBuffer.wrap(value).asLongBuffer();
        return buffer.get();
    }
    public static byte[] encode(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.SIZE/Byte.SIZE);
        buffer.putInt(value);
        return buffer.array();
    }
    public static int decodeInt(byte[] value) {
        IntBuffer buffer = ByteBuffer.wrap(value).asIntBuffer();
        return buffer.get();
    }
    public static byte[] encode(short value) {
        ByteBuffer buffer = ByteBuffer.allocate(Short.SIZE/Byte.SIZE);
        buffer.putShort(value);
        return buffer.array();
    }
    public static short decodeShort(byte[] value) {
        ShortBuffer buffer = ByteBuffer.wrap(value).asShortBuffer();
        return buffer.get();
    }
    // TODO collections
    // TODO streams
}
