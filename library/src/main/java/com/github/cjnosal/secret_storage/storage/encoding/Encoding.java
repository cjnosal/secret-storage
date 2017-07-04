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

import android.util.Base64;

import java.io.UnsupportedEncodingException;

public class Encoding {
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public enum ByteEncoding {
        HEX,
        BASE64,
        UTF8
    }

    public static String encode(byte[] bytes, ByteEncoding encoding) {
        String encoded = null;
        switch (encoding) {
            case HEX:
                encoded = hexEncode(bytes);
                break;
            case BASE64:
                encoded = base64Encode(bytes);
                break;
            case UTF8:
                encoded = utf8Encode(bytes);
                break;
        }
        return encoded;
    }

    public static byte[] decode(String s, ByteEncoding encoding) {
        byte[] decoded = null;
        switch (encoding) {
            case HEX:
                decoded = hexDecode(s);
                break;
            case BASE64:
                decoded = base64Decode(s);
                break;
            case UTF8:
                decoded = utf8Decode(s);
                break;
        }
        return decoded;
    }

    public static String hexEncode(byte[] bytes) {
        return new String(hexEncodeChars(bytes));
    }

    public static char[] hexEncodeChars(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return hexChars;
    }

    public static byte[] hexDecode(String s) {
        byte[] bytes = new byte[s.length()/2];
        char[] chars = s.toUpperCase().toCharArray();
        for (int i = 0; i < bytes.length; ++i) {
            byte firstNibble = fromHex(chars[i*2]);
            byte secondNibble = fromHex(chars[i*2 + 1]);
            bytes[i] = (byte) ((firstNibble << 4) | secondNibble);
        }
        return bytes;
    }

    private static byte fromHex(char c) {
        byte charValue = 0;
        for (byte i = 0; i < hexArray.length; ++i) {
            if (c == hexArray[i]) {
                charValue = i;
            }
        }
        return charValue;
    }

    public static String base64Encode(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    public static byte[] base64Decode(String s) {
        return Base64.decode(s, Base64.NO_WRAP);
    }

    public static byte[] utf8Decode(String s) {
        byte[] decoded = null;
        try {
            decoded = s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
        }
        return decoded;
    }

    public static String utf8Encode(byte[] bytes) {
        String encoded = null;
        try {
            encoded = new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
        }
        return encoded;
    }
}
