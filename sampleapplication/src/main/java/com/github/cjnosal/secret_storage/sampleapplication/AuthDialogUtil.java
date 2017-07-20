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
import android.content.Context;
import android.content.DialogInterface;
import android.support.annotation.StringRes;
import android.support.v7.app.AlertDialog;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;

public class AuthDialogUtil {
    public static Dialog showAuthDialog(final Context context, final SecretManager secretManager, DialogAuth authType, @StringRes int title, @StringRes int message, @StringRes int button, final AuthDialogListener listener) {
        final boolean showPassword = authType.equals(DialogAuth.PASSWORD) || (authType.equals(DialogAuth.AUTO) && secretManager.isPasswordAuthenticationEnabled());
        final boolean showFingerprint = authType.equals(DialogAuth.FINGERPRINT) || (authType.equals(DialogAuth.AUTO) && secretManager.isFingerprintAuthenticationEnabled());

        final View dialogLayout = LayoutInflater.from(context).inflate(R.layout.dialog_verify, null);
        dialogLayout.findViewById(R.id.verify_password).setVisibility(showPassword ? View.VISIBLE : View.GONE);
        dialogLayout.findViewById(R.id.verify_fingerprint).setVisibility(showFingerprint ? View.VISIBLE : View.GONE);
        dialogLayout.findViewById(R.id.or).setVisibility(showFingerprint && showPassword ? View.VISIBLE : View.GONE);

        AlertDialog.Builder builder = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialog) {
                        if (showFingerprint) {
                            secretManager.cancelFingerprintRequest();
                        }
                    }
                })
                .setView(dialogLayout);
        if (showPassword) {
            builder.setPositiveButton(button, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    String password = ((EditText) dialogLayout.findViewById(R.id.verify_password)).getText().toString();
                    listener.onSubmit(password);
                }
            });
        }
        AlertDialog dialog = builder.create();
        dialog.show();
        return dialog;
    }

    public interface AuthDialogListener {
        void onSubmit(String password);
    }

    public enum DialogAuth {
        PASSWORD,
        FINGERPRINT,
        AUTO
    }
}
