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
SecretStorage secretStorage = new SecretStorage.Builder(context, "storageId").build();
```
### Default key protection strategy and storage with a user password
```
SecretStorage secretStorage = new SecretStorage.Builder(context, "storageId").withUserPassword(true).build();
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
### Store/Load Data
```
secretStorage.store("mySecret", Encoding.utf8decode("sensitive materials"));
String mySecret = Encoding.utf8encode(secretStorage.load("mySecret"));
```
### Manage user password
```
PasswordEditor editor = secretStorage.getEditor();
editor.setPassword("1234");
editor.lock();
editor.unlock("1234");
editor.changePassword("1234", "3456");
```
## Key Protection Strategies
User data is protected with encrypt-then-mac. The cipher and mac keys are then wrapped using the most secure method available.
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
