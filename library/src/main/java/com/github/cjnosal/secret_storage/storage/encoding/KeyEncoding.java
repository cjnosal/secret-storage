package com.github.cjnosal.secret_storage.storage.encoding;

import com.github.cjnosal.secret_storage.keymanager.crypto.SecurityAlgorithms;
import com.github.cjnosal.secret_storage.storage.util.ByteArrayUtil;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
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

//    public KeyPair decodeKeyPair(@SecurityAlgorithms.KeyFormat String format, @SecurityAlgorithms.KeyFactory String algorithm, byte[] keyBytes) throws GeneralSecurityException {
//        KeySpec spec = format.equals(SecurityAlgorithms.KEY_FORMAT_X509) ? new X509EncodedKeySpec(keyBytes) : new PKCS8EncodedKeySpec(keyBytes);
//        return generateKeyPair(algorithm, spec);
//    }

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

    public PublicKey generatePublicKey(PrivateKey privateKey) throws GeneralSecurityException {
        KeyFactory f = KeyFactory.getInstance(privateKey.getAlgorithm());

        KeySpec spec;
        if (privateKey.getAlgorithm().equals(SecurityAlgorithms.KeyFactory_RSA)) {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
            spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
        } else if (privateKey.getAlgorithm().equals(SecurityAlgorithms.KeyFactory_EC)) {
            ECPrivateKey key = (ECPrivateKey) privateKey;
            spec = new ECPublicKeySpec(key.getParams().getGenerator(), key.getParams());
        } else if (privateKey.getAlgorithm().equals(SecurityAlgorithms.KeyFactory_DH)) {
            DHPrivateKey key = (DHPrivateKey) privateKey;
            throw new UnsupportedOperationException("Is x == y?");
//            DHPublicKeySpec spec = new DHPublicKeySpec(key.getX(), key.getParams().getP(), key.getParams().getG());
//            return f.generatePublic(spec);
        } else if (privateKey.getAlgorithm().equals(SecurityAlgorithms.KeyFactory_DSA)) {
            DSAPrivateKey key = (DSAPrivateKey) privateKey;
            throw new UnsupportedOperationException("Is x == y?");
//            DSAPublicKeySpec spec = new DSAPublicKeySpec(key.getX(), key.getParams().getP(), key.getParams().getQ(), key.getParams().getG());
//            return f.generatePublic(spec);

        } else {
            throw new UnsupportedOperationException("Unable to generate public key for " + privateKey.getFormat() + "/" + privateKey.getAlgorithm());
        }
        return f.generatePublic(spec);
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
