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

package com.github.cjnosal.secret_storage.keymanager;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;

import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherSpec;
import com.github.cjnosal.secret_storage.keymanager.strategy.keygen.KeyGenSpec;
import com.github.cjnosal.secret_storage.storage.DataStorage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

@TargetApi(Build.VERSION_CODES.M)
public class FingerprintWrapper extends KeyStoreWrapper {

    public FingerprintWrapper(CipherSpec keyProtectionSpec, KeyGenSpec keyGenSpec, DataStorage configStorage, DataStorage keyStorage) {
        super(keyProtectionSpec, keyGenSpec, configStorage, keyStorage);
    }

    @Override
    public Editor getEditor(String storeId) {
        return new FingerprintEditor(storeId);
    }

    @Override
    void unlock(String keyAlias, UnlockParams params) throws IOException, GeneralSecurityException {
        FingerprintParams fingerprintParams = (FingerprintParams) params;
        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(fingerprintParams.getContext());
        checkFingerprintStatus(fingerprintParams, fingerprintManagerCompat);

        FingerprintCallback fingerprintCallback;
        Cipher kekCipher;
        String storageField = getStorageField(keyAlias, ENCRYPTION_KEY);
        if (!kekExists(keyAlias)) {
            Key kek = androidCrypto.generateSecretKey(keyGenSpec.getKeygenAlgorithm(), getKeyGenParameterSpec(storageField));
            kekCipher = keyWrap.initWrapCipher(kek, keyProtectionSpec.getCipherTransformation(), keyProtectionSpec.getParamsAlgorithm());
            fingerprintCallback = new FingerprintCallback(keyAlias, fingerprintParams.getAuthenticationCallback(), fingerprintParams.getListener(), true);
        } else {
            Key kek = androidCrypto.loadSecretKey(storageField);
            kekCipher = keyWrap.initUnwrapCipher(kek, getKekCipherParams(keyAlias), keyProtectionSpec.getCipherTransformation());
            fingerprintCallback = new FingerprintCallback(keyAlias, fingerprintParams.getAuthenticationCallback(), fingerprintParams.getListener(), false);
        }

        fingerprintManagerCompat.authenticate(new FingerprintManagerCompat.CryptoObject(kekCipher), 0, fingerprintParams.getCancellationSignal(), fingerprintCallback, fingerprintParams.getHandler());
    }

    void verify(String keyAlias, UnlockParams params) throws IOException, GeneralSecurityException {
        FingerprintParams fingerprintParams = (FingerprintParams) params;
        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(fingerprintParams.getContext());
        checkFingerprintStatus(fingerprintParams, fingerprintManagerCompat);

        FingerprintCallback fingerprintCallback = new FingerprintCallback(keyAlias, fingerprintParams.getAuthenticationCallback(), fingerprintParams.getListener(), false);

        fingerprintManagerCompat.authenticate(null, 0, fingerprintParams.getCancellationSignal(), fingerprintCallback, fingerprintParams.getHandler());
    }

    private void checkFingerprintStatus(FingerprintParams fingerprintParams, FingerprintManagerCompat fingerprintManagerCompat) throws FingerprintException {
        KeyguardManager keyguardManager = (KeyguardManager) fingerprintParams.getContext().getSystemService(Context.KEYGUARD_SERVICE);

        if (!fingerprintManagerCompat.isHardwareDetected()) {
            throw new FingerprintException(Type.NoHardware, -1, "No fingerprint sensor on device");
        }
        if (!keyguardManager.isDeviceSecure()) {
            throw new FingerprintException(Type.NoLockscreen, -1, "User has not set up a lockscreen");
        }
        if (!fingerprintManagerCompat.hasEnrolledFingerprints()) {
            throw new FingerprintException(Type.NoFingerprint, -1, "User has not enrolled a fingerprint");
        }
    }

    private EnrollmentStatus getEnrollmentStatus(Context context) {
        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(context);
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return EnrollmentStatus.NOT_SUPPORTED;
        } else if (!fingerprintManagerCompat.isHardwareDetected()) {
            return EnrollmentStatus.NOT_SUPPORTED;
        } else if (!keyguardManager.isDeviceSecure()) {
            return EnrollmentStatus.NO_LOCKSCREEN;
        } else if (!fingerprintManagerCompat.hasEnrolledFingerprints()) {
            return EnrollmentStatus.NO_FINGER_ENROLLED;
        } else {
            return EnrollmentStatus.ENROLLED;
        }
    }

    public class FingerprintEditor extends BaseEditor {

        public FingerprintEditor(String keyAlias) {
            super(keyAlias);
        }

        public void unlock(@NonNull Context context, @NonNull CancellationSignal cancellationSignal, @NonNull FingerprintManagerCompat.AuthenticationCallback authenticationCallback, @Nullable Handler handler) throws IOException, GeneralSecurityException {
            FingerprintWrapper.this.unlock(keyAlias, new FingerprintParams(context, null, cancellationSignal, authenticationCallback, handler));
        }

        public void unlock(@NonNull Context context, @NonNull CancellationSignal cancellationSignal, @NonNull Listener listener, @Nullable Handler handler) {
            try {
                FingerprintWrapper.this.unlock(keyAlias, new FingerprintParams(context, listener, cancellationSignal, null, handler));
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public void verify(@NonNull Context context, @NonNull CancellationSignal cancellationSignal, @NonNull FingerprintManagerCompat.AuthenticationCallback authenticationCallback, @Nullable Handler handler) throws IOException, GeneralSecurityException {
            FingerprintWrapper.this.verify(keyAlias, new FingerprintParams(context, null, cancellationSignal, authenticationCallback, handler));
        }

        public void verify(@NonNull Context context, @NonNull CancellationSignal cancellationSignal, @NonNull Listener listener, @Nullable Handler handler) {
            try {
                FingerprintWrapper.this.verify(keyAlias, new FingerprintParams(context, listener, cancellationSignal, null, handler));
            } catch (GeneralSecurityException | IOException e) {
                listener.onError(e);
            }
        }

        public boolean isInitialized() {
            return kekExists(keyAlias);
        }

        public EnrollmentStatus getEnrollmentStatus(Context context) {
            return FingerprintWrapper.this.getEnrollmentStatus(context);
        }
    }

    class FingerprintCallback extends FingerprintManagerCompat.AuthenticationCallback {

        private final String keyAlias;
        private final FingerprintManagerCompat.AuthenticationCallback wrappedCallback;
        private Listener listener;
        private final boolean firstUnlock;

        public FingerprintCallback(String keyAlias, @Nullable FingerprintManagerCompat.AuthenticationCallback wrappedCallback, @Nullable Listener listener, boolean firstUnlock) {
            this.keyAlias = keyAlias;
            this.wrappedCallback = wrappedCallback;
            this.listener = listener;
            this.firstUnlock = firstUnlock;
        }

        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            if (wrappedCallback != null) {
                wrappedCallback.onAuthenticationError(errMsgId, errString);
            }
            if (listener != null) {
                listener.onError(new FingerprintException(Type.Error, errMsgId, errString));
            }
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            if (wrappedCallback != null) {
                wrappedCallback.onAuthenticationHelp(helpMsgId, helpString);
            }
            if (listener != null) {
                listener.onError(new FingerprintException(Type.Help, helpMsgId, helpString));
            }
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            try {
                FingerprintManagerCompat.CryptoObject cryptoObject = result.getCryptoObject();
                if (cryptoObject != null) {
                    if (firstUnlock) {
                        finishUnlock(keyAlias, null, cryptoObject.getCipher());
                    } else {
                        finishUnlock(keyAlias, cryptoObject.getCipher(), null);
                    }
                }
                if (wrappedCallback != null) {
                    wrappedCallback.onAuthenticationSucceeded(result);
                }
                if (listener != null) {
                    listener.onSuccess();
                }
            } catch (GeneralSecurityException | IOException e) {
                if (wrappedCallback != null) {
                    e.printStackTrace();
                    wrappedCallback.onAuthenticationError(-1, e.getMessage());
                }
                if (listener != null) {
                    listener.onError(e);
                }
            }
        }

        @Override
        public void onAuthenticationFailed() {
            if (wrappedCallback != null) {
                wrappedCallback.onAuthenticationFailed();
            }
            if (listener != null) {
                listener.onError(new FingerprintException(Type.Failure));
            }
        }
    }

    class FingerprintParams extends UnlockParams {
        private final Context context;
        private final Listener listener;
        private final CancellationSignal cancellationSignal;
        private final FingerprintManagerCompat.AuthenticationCallback authenticationCallback;
        private final Handler handler;

        public FingerprintParams(Context context, Listener listener, CancellationSignal cancellationSignal, FingerprintManagerCompat.AuthenticationCallback authenticationCallback, Handler handler) {
            this.context = context;
            this.listener = listener;
            this.cancellationSignal = cancellationSignal;
            this.authenticationCallback = authenticationCallback;
            this.handler = handler;
        }

        public Context getContext() {
            return context;
        }

        @Nullable
        public CancellationSignal getCancellationSignal() {
            return cancellationSignal;
        }

        @NonNull
        public FingerprintManagerCompat.AuthenticationCallback getAuthenticationCallback() {
            return authenticationCallback;
        }

        @Nullable
        public Handler getHandler() {
            return handler;
        }

        public Listener getListener() {
            return listener;
        }
    }

    public enum Type {
        Error,
        Help,
        Failure,
        NoHardware,
        NoFingerprint,
        NoLockscreen
    }

    public enum EnrollmentStatus {
        NOT_SUPPORTED,
        NO_LOCKSCREEN,
        NO_FINGER_ENROLLED,
        ENROLLED
    }

    public class FingerprintException extends GeneralSecurityException {
        private int messageId;
        private Type type;

        public FingerprintException(Type type) {
            super("Can't use fingerprint");
            this.type = type;
            this.messageId = -1;
        }

        public FingerprintException(Type type, int messageId, CharSequence message) {
            super(message.toString());
            this.type = type;
            this.messageId = messageId;
        }

        public int getMessageId() {
            return messageId;
        }

        public Type getType() {
            return type;
        }
    }
}
