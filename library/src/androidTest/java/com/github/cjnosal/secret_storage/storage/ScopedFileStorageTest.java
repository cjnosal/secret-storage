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
package com.github.cjnosal.secret_storage.storage;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Set;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

public class ScopedFileStorageTest {

    FileStorage subject;
    private DataStorage scope1;
    private DataStorage scope2;

    @Before
    public void setup() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        subject = new FileStorage(context.getCacheDir() + "/test");
        subject.clear();
        scope1 = new ScopedDataStorage("1", subject);
        scope2 = new ScopedDataStorage("2", subject);
    }

    @Test
    public void storeAndLoad() throws IOException {
        scope1.store("storedKey", "storedValue1".getBytes());
        scope2.store("storedKey", "storedValue2".getBytes());
        assertEquals("storedValue1", new String(scope1.load("storedKey")));
        assertEquals("storedValue2", new String(scope2.load("storedKey")));
    }

    @Test
    public void writeAndRead() throws IOException {
        OutputStream os = scope1.write("streamedKey");
        byte[] encoded = "streamedValue1".getBytes();
        os.write(encoded);
        os.flush();
        os.close();

        os = scope2.write("streamedKey");
        encoded = "streamedValue2".getBytes();
        os.write(encoded);
        os.flush();
        os.close();

        byte[] readBytes = new byte[encoded.length];
        InputStream is = scope1.read("streamedKey");
        int count = is.read(readBytes);
        is.close();

        assertEquals(encoded.length, count);
        assertEquals("streamedValue1", new String(readBytes));

        readBytes = new byte[encoded.length];
        is = scope2.read("streamedKey");
        count = is.read(readBytes);
        is.close();

        assertEquals(encoded.length, count);
        assertEquals("streamedValue2", new String(readBytes));
    }

    @Test
    public void clear() throws IOException {
        scope1.store("storedKey", "storedValue1".getBytes());
        scope2.store("storedKey", "storedValue2".getBytes());
        scope1.clear();

        assertTrue(scope1.entries().isEmpty());
        assertFalse(scope2.entries().isEmpty());
    }

    @Test
    public void exists() throws IOException {
        scope1.store("storedKey", "storedValue".getBytes());
        assertTrue(scope1.exists("storedKey"));
        assertFalse(scope2.exists("storedKey"));
    }

    @Test
    public void delete() throws IOException {
        scope1.store("storedKey", "storedValue".getBytes());
        scope2.store("storedKey", "storedValue".getBytes());
        scope1.delete("storedKey");
        assertFalse(scope1.exists("storedKey"));
        assertTrue(scope2.exists("storedKey"));
    }

    @Test
    public void entries() throws IOException {
        scope1.store("storedKey1", "storedValue".getBytes());
        scope2.store("storedKey2", "storedValue".getBytes());

        Set<String> entries = scope1.entries();
        assertEquals(1, entries.size());
        assertTrue(entries.contains("storedKey1"));

        entries = scope2.entries();
        assertEquals(1, entries.size());
        assertTrue(entries.contains("storedKey2"));
    }
}
