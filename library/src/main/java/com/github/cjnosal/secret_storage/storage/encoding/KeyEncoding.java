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

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyEncoding {
    public byte[] encodeKey(Key key) throws GeneralSecurityException {
        String format = key.getFormat();
        String algorithm = key.getAlgorithm();
        if (format == null) {
            throw new GeneralSecurityException("Key of type " + algorithm + " can not be encoded");
        }
        byte[] encoded = key.getEncoded();
        return ByteArrayUtil.join(ByteArrayUtil.join(Encoding.utf8Decode(format), Encoding.utf8Decode(algorithm)), encoded);
    }

    public Key decodeKey(byte[] bytes) throws GeneralSecurityException {
        byte[][] firstSplit = ByteArrayUtil.split(bytes);
        byte[][] secondSplit = ByteArrayUtil.split(firstSplit[0]);

        String format = Encoding.utf8Encode(secondSplit[0]);
        String algorithm = Encoding.utf8Encode(secondSplit[1]);

        return decodeKey(format, algorithm, firstSplit[1]);
    }

    public PublicKey decodePublicKey(@SecurityAlgorithms.KeyFactory String algorithm, byte[] keyBytes) throws GeneralSecurityException {
        KeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory f = KeyFactory.getInstance(algorithm);
        return f.generatePublic(spec);
    }

    public PrivateKey decodePrivateKey(@SecurityAlgorithms.KeyFactory String algorithm, byte[] keyBytes) throws GeneralSecurityException {
        KeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory f = KeyFactory.getInstance(algorithm);
        return f.generatePrivate(spec);
    }

    public SecretKey decodeSecretKey(@SecurityAlgorithms.SecretKeyFactory String algorithm, byte[] keyBytes) throws GeneralSecurityException {
        return new SecretKeySpec(keyBytes, algorithm);
    }

    public Key decodeKey(@SecurityAlgorithms.KeyFormat String format, @SecurityAlgorithms.KeyFactory String algorithm, byte[] keyBytes) throws GeneralSecurityException {
        if (format.equals(SecurityAlgorithms.KEY_FORMAT_RAW)) {
            return decodeSecretKey(algorithm, keyBytes);
        } else if (format.equals(SecurityAlgorithms.KEY_FORMAT_X509)) {
            return decodePublicKey(algorithm, keyBytes);
        } else if (format.equals(SecurityAlgorithms.KEY_FORMAT_PKCS8)) {
            return decodePrivateKey(algorithm, keyBytes);
        }
        throw new IllegalArgumentException("Unsupported key format " + format);
    }
}
