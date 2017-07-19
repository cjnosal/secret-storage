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

package com.example.sampleapplication;

import android.app.Dialog;
import android.os.Bundle;
import android.support.annotation.StringRes;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;
import android.widget.Toast;

import com.github.cjnosal.secret_storage.keymanager.FingerprintWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static android.hardware.fingerprint.FingerprintManager.FINGERPRINT_ERROR_CANCELED;
import static com.example.sampleapplication.AuthDialogUtil.showAuthDialog;

public class GatedActivity extends AppCompatActivity {

    private SecretManager secretManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_gated);

        secretManager = new SecretManager(getApplicationContext());
    }

    @Override
    protected void onResume() {
        super.onResume();
        final Dialog dialog = showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.AUTO, R.string.verify, R.string.verify_credential, R.string.submit, new AuthDialogUtil.AuthDialogListener() {
            @Override
            public void onSubmit(String password) {
                if (password.isEmpty()) {
                    showError(R.string.empty);
                } else {
                    try {
                        boolean verified = secretManager.verifyPassword(password);

                        if (verified) {
                            Toast.makeText(GatedActivity.this, R.string.password_verified, Toast.LENGTH_SHORT).show();
                            showGatedContent();
                        } else {
                            showError(R.string.wrong_password);
                            finish();
                        }
                    } catch (IOException | GeneralSecurityException e) {
                        e.printStackTrace();
                        showError(R.string.unexpected_error);
                        finish();
                    }
                }
            }
        });

        if (secretManager.isFingerprintAuthenticationEnabled()) {
            secretManager.verifyFingerprint(new KeyWrapper.Listener() {
                @Override
                public void onSuccess() {
                    Toast.makeText(GatedActivity.this, R.string.fingerprint_verified, Toast.LENGTH_SHORT).show();
                    dialog.dismiss();
                    showGatedContent();
                }

                @Override
                public void onError(Exception e) {
                    FingerprintWrapper.FingerprintException fe = (FingerprintWrapper.FingerprintException) e;
                    if (fe.getMessageId() != FINGERPRINT_ERROR_CANCELED) {
                        e.printStackTrace();
                        showError(fe);
                    }
                    if (fe.getType().equals(FingerprintWrapper.Type.Error) && !secretManager.isPasswordAuthenticationEnabled()) {
                        dialog.dismiss();
                        finish();
                    }
                }
            });
        }

        dialog.show();
    }

    private void showGatedContent() {
        ((TextView) findViewById(R.id.gate_status)).setText(R.string.gated_authorized);
    }

    @Override
    protected void onPause() {
        secretManager.lock();
        super.onPause();
    }

    private void showError(FingerprintWrapper.FingerprintException e) {
        Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
    }

    private void showError(@StringRes int error) {
        Toast.makeText(this, error, Toast.LENGTH_SHORT).show();
    }
}
