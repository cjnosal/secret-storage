# Secret Storage
Secret Storage is an Android library for encrypting and storing local secrets such as account credentials or authentication tokens.

A key-protection strategy will be selected to make use of a user password, AndroidKeyStore, or both.
## Gradle
### Jitpack
```
    allprojects {
        repositories {
            maven { url 'https://jitpack.io' }
        }
    }
    
    dependencies {
        compile 'com.github.cjnosal:secret-storage:v1.0-alpha.4'
    }
```
### Download aar file
```
    allprojects {
        repositories {
            flatDir {
                dirs 'libs'
            }
        }
    }
    dependencies {
        compile(name:'secret-storage', ext:'aar')
    }
```
## Setup
### Default key protection strategy and storage without a user password (insecure below jelly bean)
```
KeyWrapper keyWrapper = SecretStorage.selectKeyWrapper(context, "id", configStorage, keyStorage, false);
SecretStorage secretStorage = new SecretStorage.Builder(context, "storageId").keyWrapper(keyWrapper).build();
```
### Default key protection strategy and storage with a user password
```
KeyWrapper keyWrapper = SecretStorage.selectKeyWrapper(context, "id", configStorage, keyStorage, true);
SecretStorage secretStorage = new SecretStorage.Builder(context, "storageId").keyWrapper(keyWrapper).build();
```
### Overridden key protection strategy and storage
```
KeyWrapper keyWrapper = new SignedPasswordKeyWrapper(
    context,
    DefaultSpecs.getPasswordDerivationSpec(),
    DefaultSpecs.getPasswordDeviceBindingSpec(context),
    DefaultSpecs.getPasswordBasedKeyProtectionSpec(),
    configStorage,
    keyStorage);
                        
ProtectionSpec dataProtectionSpec = new ProtectionSpec(
    DefaultSpecs.getAesGcmCipherSpec(), 
    DefaultSpecs.getStrongHmacShaIntegritySpec());
    
DataStorage keyStorage = new PreferenceStorage(context, "keys");
DataStorage configStorage = new PreferenceStorage(context, "conf");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");

SecretStorage secretStorage = new new SecretStorage.Builder(context, id)
    .keyStorage(keyStorage)
    .configStorage(configStorage)
    .dataStorage(dataStorage)
    .keyWrapper(keyWrapper)
    .dataProtectionSpec(dataProtectionSpec)
    .build();
```

## Usage
### Unlock/Lock
SecretStorage must be unlocked before storing or loading values. Different KeyWrappers require different parameters to unlock.
#### KeyStoreWrapper/AsymmetricKeyStoreWrapper/ObfuscationKeyWrapper
```
secretStorage.getEditor().unlock();
```
#### PasswordKeyWrapper/SignedPasswordKeyWrapper
If no password has been set:
```
secretStorage.getEditor().setPassword(password);
```
If a password has been set:
```
secretStorage.getEditor().unlock(password);
```
#### FingerprintWrapper:
```
secretStorage.getEditor().unlock(context, cancellationSignal, listener, handler);
```
### Store/Load Data
```
secretStorage.store("mySecret", Encoding.utf8decode("sensitive materials"));
String mySecret = Encoding.utf8encode(secretStorage.load("mySecret"));
```
## Key Protection Strategies
User data is protected with encrypt-then-mac. The cipher and mac keys are then wrapped with an intermediate key-encryption-key which is held in memory while the KeyWrapper is unlocked. The intermediate key is in turn wrapped using the most secure method available.
### FingerprintWrapper (API >= 23)
Generate an AES key in the AndroidKeyStore, requiring fingerprint verification to unlock
### KeystoreWrapper (API >= 23 when configured without a user password)
Generate an AES key in the AndroidKeyStore
### AsymmetricKeyStoreWrapper (API >= 18 when configured without a user password)
Generate an RSA key pair in the AndroidKeyStore
### SignedPasswordKeyWrapper (API >= 18 when configured with a user password)
Derive an encryption key from the password using PBKDF2
Bind the derived key to the phone with an RSA key generated in the AndroidKeyStore
### PasswordKeyWrapper (API < 18 when configured with a user password) 
Derive an encryption key from the password using PBKDF2
### ObfuscationKeyWrapper (API < 18 when configured without a user password)
(INSECURE) Derive an encryption key from a hardcoded password using PBKDF2 
