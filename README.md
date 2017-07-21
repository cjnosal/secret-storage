# Secret Storage
Secret Storage is an Android library for encrypting and storing local secrets such as account credentials or authentication tokens.

A key-protection strategy can be selected to make use of a user password, AndroidKeyStore, or both.
## Gradle
### Jitpack
```
    allprojects {
        repositories {
            maven { url 'https://jitpack.io' }
        }
    }
    
    dependencies {
        compile 'com.github.cjnosal:secret-storage:v1.0-beta.6'
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

### Default key protection strategy
```
DataStorage keyStorage = new PreferenceStorage(context, "keys");
DataStorage configStorage = new PreferenceStorage(context, "conf");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");

KeyWrapper keyWrapper = new SignedPasswordKeyWrapper(
    context,
    DefaultSpecs.getSignedPasswordCryptoConfig(),
    configStorage,
    keyStorage);

ProtectionSpec dataProtectionSpec = DefaultSpecs.getDefaultDataProtectionSpec();

SecretStorage secretStorage = new new SecretStorage.Builder()
    .dataStorage(dataStorage)
    .keyWrapper(keyWrapper)
    .dataProtectionSpec(dataProtectionSpec)
    .build();
```

### Overridden key protection strategy and storage
```
DataStorage keyStorage = new PreferenceStorage(context, "keys");
DataStorage configStorage = new PreferenceStorage(context, "conf");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");

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

SecretStorage secretStorage = new new SecretStorage.Builder()
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
### Encrypt/Decrypt Data to be stored outside of SecretStorage
```
byte[] cipherText = secretStorage.encrypt(Encoding.utf8decode("sensitive materials"));
String mySecret = Encoding.utf8encode(secretStorage.decrypt(cipherText));
```
## Root Key Protection Strategies
### FingerprintWrapper (API >= 23)
Generate an AES key in the AndroidKeyStore, requiring fingerprint verification to unlock
### KeystoreWrapper (API >= 23)
Generate an AES key in the AndroidKeyStore
### AsymmetricKeyStoreWrapper (API >= 18)
Generate an RSA key pair in the AndroidKeyStore
### SignedPasswordKeyWrapper (API >= 18)
Derive an encryption key from the user's password using PBKDF2
Bind the derived key to the phone with an RSA key generated in the AndroidKeyStore
### PasswordKeyWrapper (API < 18)
Derive an encryption key from the user's password using PBKDF2
### ObfuscationKeyWrapper (API < 18)
(INSECURE) Derive an encryption key from a hardcoded password using PBKDF2

## Key Management

### First Unlock
- Root Key Encryption Key (KEK) is generated inside AndroidKeyStore or derived from user password
- Intermediate KEK is generated and retained in memory
- Intermediate KEK is wrapped by the Root KEK and stored in the KeyWrapper's configuration storage
- Root KEK is discarded from memory

### First Store
- Data Encryption Key (DEK) and Data Signing Key (DSK) are generated
- DEK and DSK are wrapped by the Intermediate KEK and stored in the KeyWrapper's key storage
- User data is encrypted with DEK, signed with DSK, and stored in the SecretStorage's data storage
- DEK and DSK are discarded from memory

### Lock
- Intermediate KEK is discarded from memory

### Unlock
- Root KEK is derived or AndroidKeyStore reference is loaded
- Intermediate KEK is unwrapped and retained in memory
- Root KEK is discarded from memory

### Load/Store
- DEK and DSK are unwrapped
- User data is verified and decrypted
- DEK and DSK are discarded from memory