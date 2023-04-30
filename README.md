# android-secure-import-samples
Secure import samples for Android

https://github.com/keiji/android-secure-import-samples/blob/main/app/src/main/java/dev/keiji/keypair_import/sample/MainViewModel.kt

```mermaid
sequenceDiagram
  title generate and import AES key
  participant App
  participant Cipher
  participant AndroidKeyStore
  Note left of App: aesKeyMaterial
  App->>AndroidKeyStore: generateKeyPairInKeyStore
  Note right of AndroidKeyStore: wrappingKeyPair(RSA key-pair)
  AndroidKeyStore->>App: publicKey
  Note left of App: generate aesKeyBytes and iv(Initialization Vector)
  App->>Cipher: init(ENCRYPT_MODE, publicKey, ... )
  App->>Cipher: encrypt(aesKeyByets)
  Cipher->>AndroidKeyStore: request encrypt by generated key-pair
  AndroidKeyStore->>Cipher: encrypted data
  Cipher->>App: encryptedEphemeralKeys
  App->>Cipher: init(ENCRYPT_MODE, aesKeyBytes, ... ) and iv
  App->>Cipher: encrypt(aesKeyByets)
  Cipher->>App: encryptedAesKey and GCM tag
  Note left of App: Create wrappedKeyMaterial
  App->>AndroidKeyStore: setEntry(wrappedKeyMaterial)

```

## Reference
* Import encrypted keys into secure hardware
  * https://developer.android.com/training/articles/keystore#ImportingEncryptedKeys
* Certificate extension data schema 
  * https://developer.android.com/training/articles/security-key-attestation#certificate_schema
* ImportWrappedKeyTest.java
  * https://android.googlesource.com/platform/cts/+/master/tests/tests/keystore/src/android/keystore/cts/ImportWrappedKeyTest.java
