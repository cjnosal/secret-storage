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
