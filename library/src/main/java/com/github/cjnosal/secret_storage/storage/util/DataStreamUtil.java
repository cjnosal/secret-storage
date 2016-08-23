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
