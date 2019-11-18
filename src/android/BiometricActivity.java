package de.niklasmerz.cordova.biometric;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.exxbrain.android.biometric.BiometricPrompt;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.concurrent.Executor;

public class BiometricActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 2;
    private PromptInfo mPromptInfo;
    private static final String CLIENT_SECRET = "clientSecret";
    private static final String TAG = "BiometricActivity";
    private KeyPair keyPair;


    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setTitle(null);
        int layout = getResources()
                .getIdentifier("biometric_activity", "layout", getPackageName());
        setContentView(layout);

        if (savedInstanceState != null) {
            return;
        }

        mPromptInfo = new PromptInfo.Builder(getIntent().getExtras()).build();

        try {
            String clientSecret = getIntent().getStringExtra(CLIENT_SECRET);
            if(clientSecret == null){
                authenticate(null);
            } else {
                keyPair = this.getKeyPair(CLIENT_SECRET);
                if(keyPair != null) authenticate(initSignature(keyPair));
            }
        }   catch (@SuppressLint("NewApi") KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, "Error during authenticate generate Key pair", e);
            this.finishWithError(PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getValue(), "Impronte digitali cambiate");
        } catch (Exception e) {
            Log.e(TAG, "Error during authenticate generate Key pair", e);
            this.finishWithError(PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getValue(), "Impronte digitali cambiate");
        }
    }

    private void authenticate(Signature signature) {
        final Handler handler = new Handler(Looper.getMainLooper());
        Executor executor = handler::post;

        BiometricPrompt biometricPrompt =
                new BiometricPrompt(this, executor, mAuthenticationCallback);

        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(mPromptInfo.getTitle())
                .setSubtitle(mPromptInfo.getSubtitle())
                .setDescription(mPromptInfo.getDescription());

        if (mPromptInfo.isDeviceCredentialAllowed()
                && Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) { // TODO: remove after fix https://issuetracker.google.com/issues/142740104
            promptInfoBuilder.setDeviceCredentialAllowed(true);
        } else {
            promptInfoBuilder.setNegativeButtonText(mPromptInfo.getCancelButtonTitle());
        }

        if(signature != null)
            biometricPrompt.authenticate(promptInfoBuilder.build(), new BiometricPrompt.CryptoObject(signature));
        /*else
            biometricPrompt.authenticate(promptInfoBuilder.build());*/
    }

    private BiometricPrompt.AuthenticationCallback mAuthenticationCallback =
            new BiometricPrompt.AuthenticationCallback() {

                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    onError(errorCode, errString);
                }

                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    finishWithSuccess();
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                }
            };


    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    private void showAuthenticationScreen() {
        KeyguardManager keyguardManager = ContextCompat
                .getSystemService(this, KeyguardManager.class);
        if (keyguardManager == null
                || android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        if (keyguardManager.isKeyguardSecure()) {
            Intent intent = keyguardManager
                    .createConfirmDeviceCredentialIntent(mPromptInfo.getTitle(), mPromptInfo.getDescription());
            this.startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            // Show a message that the user hasn't set up a lock screen.
            finishWithError(PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED);
        }
    }

    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode == Activity.RESULT_OK) {
                finishWithSuccess();
            } else {
                finishWithError(PluginError.BIOMETRIC_PIN_OR_PATTERN_DISMISSED);
            }
        }
    }

    private void onError(int errorCode, @NonNull CharSequence errString) {

        switch (errorCode)
        {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_CANCELED:
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                return;
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                // TODO: remove after fix https://issuetracker.google.com/issues/142740104
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.P && mPromptInfo.isDeviceCredentialAllowed()) {
                    showAuthenticationScreen();
                    return;
                }
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                break;
            case BiometricPrompt.ERROR_LOCKOUT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT.getValue(), errString.toString());
                break;
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT_PERMANENT.getValue(), errString.toString());
                break;
            default:
                finishWithError(errorCode, errString.toString());
        }
    }

    private void finishWithSuccess() {
        setResult(RESULT_OK);
        finish();
    }

    private void finishWithError(PluginError error) {
        finishWithError(error.getValue(), error.getMessage());
    }

    private void finishWithError(int code, String message) {
        Intent data = new Intent();
        data.putExtra("code", code);
        data.putExtra("message", message);
        setResult(RESULT_CANCELED, data);
        finish();
    }

    @Nullable
    private KeyPair getKeyPair(String keyName) throws Exception{
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    private Signature initSignature(KeyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        return signature;
    }
}
