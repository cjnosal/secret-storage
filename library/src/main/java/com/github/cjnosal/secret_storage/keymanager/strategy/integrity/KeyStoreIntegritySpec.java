package com.github.cjnosal.secret_storage.keymanager.strategy.integrity;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public abstract class KeyStoreIntegritySpec extends IntegritySpec {
    private final String keygenAlgorithm; // key or keypair generator

    public KeyStoreIntegritySpec(String keygenAlgorithm, String transformation) {
        super(transformation, 0, keygenAlgorithm);
        this.keygenAlgorithm = keygenAlgorithm;
    }

    public String getKeygenAlgorithm() {
        return keygenAlgorithm;
    }

    @Override
    public int getKeySize() {
        KeyGenParameterSpec spec = getKeyGenParameterSpec("stub");
        return spec.getKeySize();
    }

    public abstract KeyGenParameterSpec getKeyGenParameterSpec(String keyId);
}
