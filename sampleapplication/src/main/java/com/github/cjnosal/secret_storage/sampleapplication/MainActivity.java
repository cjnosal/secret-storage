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

package com.github.cjnosal.secret_storage.sampleapplication;

import android.app.Dialog;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.StringRes;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.github.cjnosal.secret_storage.keymanager.FingerprintWrapper;
import com.github.cjnosal.secret_storage.keymanager.KeyWrapper;
import com.github.cjnosal.secret_storage.keymanager.PasswordKeyWrapper;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static android.hardware.fingerprint.FingerprintManager.FINGERPRINT_ERROR_CANCELED;

public class MainActivity extends AppCompatActivity {

    private SecretManager secretManager;

    private View encryptedContainer;
    private Button unlockButton;
    private Button lockButton;
    private Button storeButton;
    private Button loadButton;
    private EditText secretField;
    private Button gatedContentButton;
    private Button settingsButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        secretManager = new SecretManager(getApplicationContext());
        bindViews();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateView();
        if (!secretManager.isAuthenticationInitialized()) {
            toast(R.string.not_initialized);
        }
    }

    @Override
    protected void onPause() {
        secretManager.lock();
        super.onPause();
    }

    //region click listeners

    private void onGatedContentClicked() {
        startActivity(new Intent(this, GatedActivity.class));
    }

    private void onSettingsClicked() {
        startActivity(new Intent(this, SettingsActivity.class));
    }

    private void onLockClicked() {
        secretManager.lock();
        updateView();
    }

    private void onUnlockClicked() {
        final Dialog dialog = AuthDialogUtil.showAuthDialog(this, secretManager, AuthDialogUtil.DialogAuth.AUTO, R.string.unlock, R.string.verify_credential, R.string.submit, new AuthDialogUtil.AuthDialogListener() {
            @Override
            public void onSubmit(String password) {
                if (password.isEmpty()) {
                    toast(R.string.empty);
                } else {
                    try {
                        secretManager.unlockWithPassword(password);
                        updateView();
                    } catch (PasswordKeyWrapper.WrongPasswordException e) {
                        e.printStackTrace();
                        toast(R.string.wrong_password);
                    } catch (IOException | GeneralSecurityException e) {
                        e.printStackTrace();
                        toast(R.string.unexpected_error);
                    }
                }
            }
        });

        if (secretManager.isFingerprintAuthenticationEnabled()) {
            secretManager.unlockWithFingerprint(new KeyWrapper.Listener() {
                @Override
                public void onSuccess() {
                    Toast.makeText(MainActivity.this, R.string.fingerprint_verified, Toast.LENGTH_SHORT).show();
                    dialog.dismiss();
                    updateView();
                }

                @Override
                public void onError(Exception e) {
                    FingerprintWrapper.FingerprintException fe = (FingerprintWrapper.FingerprintException) e;
                    if (fe.getMessageId() != FINGERPRINT_ERROR_CANCELED) {
                        e.printStackTrace();
                        toast(fe);
                    }
                    if (fe.getType().equals(FingerprintWrapper.Type.Error) && !secretManager.isPasswordAuthenticationEnabled()) {
                        dialog.dismiss();
                    }
                }
            });
        }

        dialog.show();
    }

    private void onStoreClicked() {
        String secret = secretField.getText().toString();
        if (secret.isEmpty()) {
            toast(R.string.empty);
        } else {
            try {
                secretManager.store(secret);
                secretField.setText("");
                toast(R.string.saved);
                updateView();
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
                toast(R.string.unexpected_error);
            }
        }
    }

    private void onLoadClicked() {
        try {
            secretField.setText(secretManager.load());
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            toast(R.string.unexpected_error);
        }
    }

    //endregion click listeners

    private void updateView() {
        boolean initialized = secretManager.isAuthenticationInitialized();
        boolean isUnlocked = secretManager.isUnlocked();
        lockButton.setEnabled(initialized && isUnlocked);
        unlockButton.setEnabled(initialized && !isUnlocked);
        gatedContentButton.setEnabled(initialized);
        encryptedContainer.setVisibility(initialized && isUnlocked ? View.VISIBLE : View.GONE);
        loadButton.setEnabled(secretManager.hasSavedEntry());
    }

    private void bindViews() {
        settingsButton = (Button) findViewById(R.id.settings);
        settingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onSettingsClicked();
            }
        });

        gatedContentButton = (Button) findViewById(R.id.gated_content);
        gatedContentButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onGatedContentClicked();
            }
        });

        lockButton = (Button) findViewById(R.id.lock);
        lockButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onLockClicked();
            }
        });

        unlockButton = (Button) findViewById(R.id.unlock);
        unlockButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onUnlockClicked();
            }
        });

        storeButton = (Button) findViewById(R.id.store);
        storeButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onStoreClicked();
            }
        });

        loadButton = (Button) findViewById(R.id.load);
        loadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onLoadClicked();
            }
        });

        secretField = (EditText) findViewById(R.id.secret);
        encryptedContainer = findViewById(R.id.encrypted_content);
    }

    private void toast(FingerprintWrapper.FingerprintException e) {
        Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
    }

    private void toast(@StringRes int error) {
        Toast.makeText(this, error, Toast.LENGTH_SHORT).show();
    }
}
