package com.github.cjnosal.secret_storage.keymanager.crypto;

import android.os.Build;

import java.security.Key;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class KeyDestroyer {
    public static void destroy(Key key) throws DestroyFailedException {
        if (Build.VERSION.SDK_INT >= 26 && key instanceof Destroyable) { // TODO use Build.VERSION_CODES.O when available
            Destroyable destroyableKey = (Destroyable) key;
            if (!destroyableKey.isDestroyed()) {
                destroyableKey.destroy();
            }
        }
    }
}
