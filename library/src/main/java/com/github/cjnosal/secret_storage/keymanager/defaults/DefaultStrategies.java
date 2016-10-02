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

package com.github.cjnosal.secret_storage.keymanager.defaults;

import android.os.Build;

import com.github.cjnosal.secret_storage.keymanager.crypto.Crypto;
import com.github.cjnosal.secret_storage.keymanager.strategy.ProtectionStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.CipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.asymmetric.AsymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.cipher.symmetric.SymmetricCipherStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.IntegrityStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.mac.MacStrategy;
import com.github.cjnosal.secret_storage.keymanager.strategy.integrity.signature.SignatureStrategy;

public class DefaultStrategies {

    // TODO strongest supported ciphers for the device/os

    public static ProtectionStrategy getDataProtectionStrategy(Crypto crypto, int osVersion) {
        CipherStrategy cipher;
        if (osVersion >= Build.VERSION_CODES.LOLLIPOP) {
            // Use authenticated-encryption primitive when available
            // MacStrategy is redundant but avoids special handling for particular strategies
            cipher = new SymmetricCipherStrategy(crypto, DefaultSpecs.getAesGcmCipherSpec());
        } else {
            cipher = new SymmetricCipherStrategy(crypto, DefaultSpecs.getAesCbcPkcs5CipherSpec());
        }
        IntegrityStrategy integrity = new MacStrategy(crypto, DefaultSpecs.getHmacShaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }

    public static ProtectionStrategy getPasswordBasedKeyProtectionStrategy(Crypto crypto, int osVersion) {
        return getDataProtectionStrategy(crypto, osVersion);
    }

    public static ProtectionStrategy getAsymmetricKeyProtectionStrategy(Crypto crypto) {
        CipherStrategy cipher = new AsymmetricCipherStrategy(crypto, DefaultSpecs.getRsaPKCS1CipherSpec());
        IntegrityStrategy integrity = new SignatureStrategy(crypto, DefaultSpecs.getShaRsaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }

    public static ProtectionStrategy getKeyStoreDataProtectionStrategy(Crypto crypto) {
        CipherStrategy cipher = new SymmetricCipherStrategy(crypto, DefaultSpecs.getKeyStoreAesCbcPkcs7CipherSpec());
        IntegrityStrategy integrity = new MacStrategy(crypto, DefaultSpecs.getKeyStoreHmacShaIntegritySpec());
        return new ProtectionStrategy(cipher, integrity);
    }

    public static IntegrityStrategy getPasswordDeviceBindingStragegy(Crypto crypto) {
        return new SignatureStrategy(crypto, DefaultSpecs.getShaRsaIntegritySpec());
    }
}
