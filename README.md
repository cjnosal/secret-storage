# Secret Storage
Android library for encrypting and storing local secrets

A key-protection strategy will be selected to make use of
a user password, AndroidKeyStore, or both.

# Usage

## Gradle
```
allprojects {
    repositories {
        jcenter()
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

### Default key protection strategy and storage with a user password
```
SecretStorage secretStorage = new SecretStorage(context, "storageId", "user's password");
```

### Default key protection strategy and storage without a user password (insecure below jelly bean)
```
SecretStorage secretStorage = new SecretStorage(context, "storageId", null);
```

### Overridden key protection strategy and storage
```
KeyManager myCustomKeyManager = ...;
DataStorage configStorage = new PreferenceStorage(context, "conf");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");
SecretStorage secretStorage = new SecretStorage(context, "storageId", configStorage, myCustomKeyManager, dataStorage);
```

## Store/Load Data
```
byte[] mySecret = "message".getBytes();
secretStorage.store("id", mySecret);
mySecret = secretStorage.load("id");
```
