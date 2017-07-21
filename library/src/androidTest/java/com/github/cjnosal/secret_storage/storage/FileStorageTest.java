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

public class FileStorageTest {

    private FileStorage subject;

    @Before
    public void setup() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        subject = new FileStorage(context.getCacheDir() + "/test");
        subject.clear();
    }

    @Test
    public void storeAndLoad() throws IOException {
        subject.store("storedKey", "storedValue".getBytes());
        assertEquals("storedValue", new String(subject.load("storedKey")));
    }

    @Test
    public void writeAndRead() throws IOException {
        OutputStream os = subject.write("streamedKey");
        byte[] encoded = "streamedValue".getBytes();
        os.write(encoded);
        os.flush();
        os.close();

        byte[] readBytes = new byte[encoded.length];
        InputStream is = subject.read("streamedKey");
        int count = is.read(readBytes);
        is.close();

        assertEquals(encoded.length, count);
        assertEquals("streamedValue", new String(readBytes));
    }

    @Test
    public void clear() throws IOException {
        subject.store("storedKey", "storedValue".getBytes());
        subject.clear();
        assertTrue(subject.entries().isEmpty());
    }

    @Test
    public void exists() throws IOException {
        assertFalse(subject.exists("storedKey"));
        subject.store("storedKey", "storedValue".getBytes());
        assertTrue(subject.exists("storedKey"));
    }

    @Test
    public void delete() throws IOException {
        subject.store("storedKey", "storedValue".getBytes());
        subject.delete("storedKey");
        assertFalse(subject.exists("storedKey"));
    }

    @Test
    public void entries() throws IOException {
        subject.store("storedKey", "storedValue".getBytes());
        OutputStream os = subject.write("streamedKey");
        os.write("streamedValue".getBytes());
        os.flush();
        os.close();

        Set<String> entries = subject.entries();
        assertEquals(2, entries.size());
        assertTrue(entries.contains("storedKey"));
        assertTrue(entries.contains("streamedKey"));
    }
}
