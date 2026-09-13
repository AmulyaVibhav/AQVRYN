# Android Build Guide

## Architecture Overview

The Android version of SecureVault uses the same Python core as the desktop version (cryptography, vault, generator, TOTP, backup) with a Kivy-based mobile UI.

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Core logic | Python 3.11+ (shared with desktop) |
| Mobile UI | Kivy + KivyMD |
| Build tool | buildozer |
| Secure storage | Python-android-usb-serial or Android Keystore via Pyjnius |
| Biometric | Pyjnius → Android BiometricManager API |
| Packaging | buildozer → APK/AAB |

## Project Structure

```
android/
├── ui/
│   ├── login_screen.py       Master password / biometric unlock screen
│   ├── vault_screen.py       Entry list, search, categories
│   ├── entry_screen.py       Entry detail / editor
│   ├── generator_screen.py   Password generator
│   ├── settings_screen.py    Settings
│   └── totp_screen.py        TOTP display
├── application/
│   ├── android_app.py        Kivy app entry point
│   ├── biometric.py          Android biometric bridge (Pyjnius)
│   └── secure_storage.py     Android Keystore integration
├── buildozer.spec            Build configuration
└── README_android.md         Android-specific instructions
```

## Prerequisites

```bash
# Ubuntu/Debian build machine (recommended)
sudo apt-get install -y python3-pip build-essential git \
    python3-setuptools python3-wheel \
    zlib1g-dev libffi-dev libssl-dev \
    openjdk-17-jdk

pip install buildozer kivy kivymd
```

## buildozer.spec (key settings)

```ini
[app]
title = SecureVault
package.name = securevault
package.domain = org.securevault
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
requirements = python3,kivy,kivymd,cryptography,argon2-cffi,pyotp,sqlalchemy,pydantic,pyperclip
android.permissions = INTERNET,USE_BIOMETRIC,USE_FINGERPRINT
android.api = 33
android.minapi = 26
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
```

## Building

```bash
cd android/
buildozer android debug   # Build debug APK
buildozer android release  # Build release APK (requires signing)
```

Output APK: `bin/securevault-1.0.0-arm64-v8a_armeabi-v7a-debug.apk`

## Biometric Authentication

Biometrics on Android use the `BiometricManager` API via `Pyjnius`:

```python
from jnius import autoclass

BiometricManager = autoclass('androidx.biometric.BiometricManager')
BiometricPrompt = autoclass('androidx.biometric.BiometricPrompt')

# Biometric unlocks a key stored in Android Keystore
# The actual vault DEK is still protected by the master password
# Biometric only provides a convenience unlock that retrieves a
# stored token (NOT a replacement for the master password)
```

**Security note**: Biometric authentication does NOT replace the master password as the cryptographic key source. The master password must always be used for:
- Initial vault creation
- Vault key recovery
- Master password changes

Biometric only provides a convenience mechanism for subsequent unlocks by storing a session credential in Android Keystore.

## Android Keystore Integration

```python
from jnius import autoclass

KeyStore = autoclass('java.security.KeyStore')
KeyGenerator = autoclass('javax.crypto.KeyGenerator')
KeyGenParameterSpec = autoclass('android.security.keystore.KeyGenParameterSpec$Builder')
```

The Android Keystore can store the session token tied to biometric authentication. The vault DEK itself is still derived from the master password — the Keystore only holds an intermediate token.

## Security Considerations for Android

1. **Database location**: `getFilesDir()` — inaccessible without root
2. **Backup flag**: Set `android:allowBackup="false"` in `AndroidManifest.xml`
3. **Screenshot protection**: Set `FLAG_SECURE` on the main window
4. **Network security config**: Restrict cleartext traffic
5. **Export restrictions**: Enforce `android:exported="false"` for all components

## Limitations

- buildozer compilation requires Linux or macOS
- PyQt6 is not available on Android — Kivy is used instead
- Not all Python packages compile cleanly for ARM; test thoroughly
- Full Android Keystore integration requires Pyjnius and may need Java wrappers
