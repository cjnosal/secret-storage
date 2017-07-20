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
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.provider.Settings;
import android.support.annotation.StringRes;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.github.cjnosal.secret_storage.keymanager.FingerprintWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.fingerprint.FingerprintStatus;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static android.hardware.fingerprint.FingerprintManager.FINGERPRINT_ERROR_CANCELED;
import static com.example.sampleapplication.AuthDialogUtil.showAuthDialog;

public class SettingsActivity extends AppCompatActivity {

    private SecretManager secretManager;

    // password settings
    private EditText newPasswordField;
    private EditText oldPasswordField;
    private Button setPasswordButton;
    private Button changePasswordButton;
    private Button forgotPasswordButton;

    // fingerprint settings
    private TextView fingerprintStatusLabel;
    private Button securitySettingsButton;
    private CheckBox fingerprintEnabledCheckbox;

    // sample app settings
    private Button resetButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        secretManager = new SecretManager(getApplicationContext());
        bindViews();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updatePasswordStatus();
        updateFingerprintStatus();
    }

    @Override
    protected void onPause() {
        secretManager.lock();
        super.onPause();
    }

    //region click listeners

    private void onSetPasswordClicked() {
        String newPassword = newPasswordField.getText().toString();
        if (newPassword.isEmpty()) {
            showError(R.string.empty);
        } else if (secretManager.isFingerprintAuthenticationEnabled()) {
            final Dialog dialog = showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.FINGERPRINT, R.string.confirm, R.string.tap_to_confirm, R.string.cancel, new AuthDialogUtil.AuthDialogListener() {
                @Override
                public void onSubmit(String password) {
                }
            });

            secretManager.unlockWithFingerprint(new KeyWrapper.Listener() {
                @Override
                public void onSuccess() {
                    Toast.makeText(SettingsActivity.this, R.string.fingerprint_verified, Toast.LENGTH_SHORT).show();
                    setPassword();
                    dialog.dismiss();
                }

                @Override
                public void onError(Exception e) {
                    FingerprintWrapper.FingerprintException fe = (FingerprintWrapper.FingerprintException) e;
                    if (fe.getMessageId() != FINGERPRINT_ERROR_CANCELED) {
                        e.printStackTrace();
                        showError(fe);
                    }
                    if (fe.getType().equals(FingerprintWrapper.Type.Error)) {
                        dialog.dismiss();
                    }
                }
            });

        } else {
            setPassword();
        }
    }

    private void setPassword() {
        try {
            secretManager.setPassword(newPasswordField.getText().toString());
            updatePasswordStatus();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
            showError(R.string.unexpected_error);
        }
    }

    private void onChangePasswordClicked() {
        String oldPassword = oldPasswordField.getText().toString();
        String newPassword = newPasswordField.getText().toString();
        if (oldPassword.isEmpty() || newPassword.isEmpty()) {
            showError(R.string.empty);
        } else {
            try {
                secretManager.changePassword(oldPassword, newPassword);
            } catch (PasswordKeyWrapper.WrongPasswordException e) {
                showError(R.string.wrong_password);
            } catch (IOException | GeneralSecurityException e) {
                e.printStackTrace();
                showError(R.string.unexpected_error);
            }
        }
    }

    private void onForgotPasswordClicked() {
        if (secretManager.isFingerprintAuthenticationEnabled()) {

            final Dialog dialog = showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.FINGERPRINT, R.string.reset_password, R.string.tap_to_reset, R.string.cancel, new AuthDialogUtil.AuthDialogListener() {
                @Override
                public void onSubmit(String password) {
                }
            });

            secretManager.unlockWithFingerprint(new KeyWrapper.Listener() {
                @Override
                public void onSuccess() {
                    Toast.makeText(SettingsActivity.this, R.string.fingerprint_verified, Toast.LENGTH_SHORT).show();
                    String password = newPasswordField.getText().toString();
                    if (password.isEmpty()) {
                        showError(R.string.empty);
                    } else {
                        try {
                            secretManager.resetPassword(password);
                            updatePasswordStatus();
                        } catch (GeneralSecurityException | IOException e) {
                            e.printStackTrace();
                            showError(R.string.unexpected_error);
                        }
                    }
                    dialog.dismiss();
                }

                @Override
                public void onError(Exception e) {
                    FingerprintWrapper.FingerprintException fe = (FingerprintWrapper.FingerprintException) e;
                    if (fe.getMessageId() != FINGERPRINT_ERROR_CANCELED) {
                        e.printStackTrace();
                        showError(fe);
                    }
                    if (fe.getType().equals(FingerprintWrapper.Type.Error)) {
                        dialog.dismiss();
                    }
                }
            });
        } else {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.reset_password)
                    .setMessage(R.string.data_loss_warning)
                    .setPositiveButton(R.string.reset, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            String password = newPasswordField.getText().toString();
                            if (password.isEmpty()) {
                                showError(R.string.empty);
                            } else {
                                try {
                                    secretManager.clear();
                                    secretManager.resetPassword(password);
                                    updatePasswordStatus();
                                } catch (GeneralSecurityException | IOException e) {
                                    e.printStackTrace();
                                    showError(R.string.unexpected_error);
                                }
                            }
                        }
                    })
                    .create()
                    .show();
        }
    }

    private void onChooseScreenLockClicked() {
        PackageManager packageManager = getPackageManager();
        Intent securitySettings = new Intent(Settings.ACTION_SECURITY_SETTINGS);
        if (securitySettings.resolveActivity(packageManager) != null) {
            startActivity(securitySettings);
        } else {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    private void onResetClicked() {
        try {
            secretManager.clear();
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            showError(R.string.unexpected_error);
        }
        updateFingerprintStatus();
        updatePasswordStatus();
    }

    private void onEnableFingerprintCheckedChanged(boolean isChecked) {
        if (isChecked) {
            if (secretManager.isPasswordAuthenticationEnabled()) {
                showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.PASSWORD, R.string.unlock, R.string.verify_credential, R.string.submit, new AuthDialogUtil.AuthDialogListener() {
                    @Override
                    public void onSubmit(String password) {
                        if (password.isEmpty()) {
                            showError(R.string.empty);
                            fingerprintEnabledCheckbox.setChecked(false);
                        } else {
                            try {
                                boolean verified = secretManager.verifyPassword(password);

                                if (verified) {
                                    Toast.makeText(SettingsActivity.this, R.string.password_verified, Toast.LENGTH_SHORT).show();
                                    confirmFingerprint();
                                } else {
                                    showError(R.string.wrong_password);
                                    fingerprintEnabledCheckbox.setChecked(false);
                                }
                            } catch (IOException | GeneralSecurityException e) {
                                e.printStackTrace();
                                showError(R.string.unexpected_error);
                                fingerprintEnabledCheckbox.setChecked(false);
                            }
                        }
                    }
                });
            } else {
                confirmFingerprint();
            }

        } else {
            try {
                secretManager.disableFingerprintAuthentication();
                updateFingerprintStatus();
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                showError(R.string.unexpected_error);
            }
        }
    }

    private void confirmFingerprint() {
        final Dialog dialog = showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.FINGERPRINT, R.string.confirm, R.string.tap_to_confirm, R.string.cancel, new AuthDialogUtil.AuthDialogListener() {
            @Override
            public void onSubmit(String password) {
            }
        });

        secretManager.unlockWithFingerprint(new KeyWrapper.Listener() {
            @Override
            public void onSuccess() {
                Toast.makeText(SettingsActivity.this, R.string.fingerprint_verified, Toast.LENGTH_SHORT).show();
                dialog.dismiss();
                updateFingerprintStatus();
            }

            @Override
            public void onError(Exception e) {
                fingerprintEnabledCheckbox.setChecked(false);
                FingerprintWrapper.FingerprintException fe = (FingerprintWrapper.FingerprintException) e;
                if (fe.getMessageId() != FINGERPRINT_ERROR_CANCELED) {
                    e.printStackTrace();
                    showError(fe);
                }
                if (fe.getType().equals(FingerprintWrapper.Type.Error)) {
                    dialog.dismiss();
                }
            }
        });
    }

    //endregion click listeners

    private void updatePasswordStatus() {
        boolean passwordSet = secretManager.isPasswordAuthenticationEnabled();
        setPasswordButton.setEnabled(!passwordSet);
        changePasswordButton.setEnabled(passwordSet);
        forgotPasswordButton.setEnabled(passwordSet);
        oldPasswordField.setEnabled(passwordSet);
    }

    private void updateFingerprintStatus() {
        FingerprintStatus fingerprintStatus = secretManager.checkFingerprintStatus(this);

        switch (fingerprintStatus) {
            case NOT_SUPPORTED:
                fingerprintStatusLabel.setText(getString(R.string.fingerprint_status, getString(R.string.fingerprint_not_supported)));
                break;
            case NO_LOCKSCREEN:
                fingerprintStatusLabel.setText(getString(R.string.fingerprint_status, getString(R.string.no_lockscreen_set)));
                break;
            case NO_FINGER_ENROLLED:
                fingerprintStatusLabel.setText(getString(R.string.fingerprint_status, getString(R.string.no_fingerprint_enrolled)));
                break;
            case ENROLLED:
                fingerprintStatusLabel.setText(getString(R.string.fingerprint_status, getString(R.string.fingerprint_enrolled)));
                break;
        }

        boolean fingerprintSupported = !FingerprintStatus.NOT_SUPPORTED.equals(fingerprintStatus);
        securitySettingsButton.setEnabled(fingerprintSupported);
        fingerprintEnabledCheckbox.setEnabled(FingerprintStatus.ENROLLED.equals(fingerprintStatus));
        fingerprintEnabledCheckbox.setOnCheckedChangeListener(null);
        fingerprintEnabledCheckbox.setChecked(secretManager.isFingerprintAuthenticationEnabled());
        fingerprintEnabledCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                onEnableFingerprintCheckedChanged(isChecked);
            }
        });
    }

    private void bindViews() {
        setPasswordButton = (Button) findViewById(R.id.set_password);
        setPasswordButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onSetPasswordClicked();
            }
        });

        changePasswordButton = (Button) findViewById(R.id.change_password);
        changePasswordButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onChangePasswordClicked();
            }
        });

        forgotPasswordButton = (Button) findViewById(R.id.forgot_password);
        forgotPasswordButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onForgotPasswordClicked();
            }
        });

        oldPasswordField = (EditText) findViewById(R.id.old_password);
        newPasswordField = (EditText) findViewById(R.id.new_password);

        securitySettingsButton = (Button) findViewById(R.id.security_settings);
        securitySettingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onChooseScreenLockClicked();
            }
        });

        fingerprintStatusLabel = (TextView) findViewById(R.id.fingerprint_status);

        fingerprintEnabledCheckbox = (CheckBox) findViewById(R.id.enable_fingerprint);
        fingerprintEnabledCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                onEnableFingerprintCheckedChanged(isChecked);
            }
        });

        resetButton = (Button) findViewById(R.id.reset);
        resetButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onResetClicked();
            }
        });
    }

    private void showError(FingerprintWrapper.FingerprintException e) {
        Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
    }

    private void showError(@StringRes int error) {
        Toast.makeText(this, error, Toast.LENGTH_SHORT).show();
    }
}
