# Secret Storage
Android library for encrypting and storing local secrets

A key-protection strategy will be selected to make use of
a user password, AndroidKeyStore, or both.

# Usage

## Setup

### Default key protection strategy with a user password
```
DataStorage configStorage = new FileStorage(context.getFilesDir() + "/config");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");
SecretStorage secretStorage = new SecretStorage(context, "storageId", configStorage, dataStorage, "user's password");
```

### Default key protection strategy without a user password **insecure below jelly bean**
```
DataStorage configStorage = new FileStorage(context.getFilesDir() + "/config");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");
SecretStorage secretStorage = new SecretStorage(context, "storageId", configStorage, dataStorage, null);
```

### Overridden key protection strategy
```
KeyManager myCustomKeyManager = ...;
DataStorage configStorage = new FileStorage(context.getFilesDir() + "/config");
DataStorage dataStorage = new FileStorage(context.getFilesDir() + "/data");
SecretStorage secretStorage = new SecretStorage(context, "storageId", configStorage, myCustomKeyManager, dataStorage);
```

## Store/Load Data
```
byte[] mySecret = "message".getBytes();
secretStorage.store("id", mySecret);
mySecret = secretStorage.load("id");
```