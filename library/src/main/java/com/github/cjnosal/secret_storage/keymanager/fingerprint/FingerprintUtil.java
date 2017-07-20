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
package com.github.cjnosal.secret_storage.keymanager.fingerprint;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;

public class FingerprintUtil {
    public FingerprintStatus getFingerprintStatus(Context context) {
        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(context);
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return FingerprintStatus.NOT_SUPPORTED;
        } else if (!fingerprintManagerCompat.isHardwareDetected()) {
            return FingerprintStatus.NOT_SUPPORTED;
        } else if (!keyguardManager.isDeviceSecure()) {
            return FingerprintStatus.NO_LOCKSCREEN;
        } else if (!fingerprintManagerCompat.hasEnrolledFingerprints()) {
            return FingerprintStatus.NO_FINGER_ENROLLED;
        } else {
            return FingerprintStatus.ENROLLED;
        }
    }
}
