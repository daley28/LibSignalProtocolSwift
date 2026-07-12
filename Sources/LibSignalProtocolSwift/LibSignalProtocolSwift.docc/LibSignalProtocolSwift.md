# ``LibSignalProtocolSwift``

A Swift implementation of the Signal Protocol for Apple platforms.

## Overview

LibSignalProtocolSwift provides the core building blocks needed to create Signal Protocol sessions, encrypt and decrypt one-to-one messages, exchange sender keys for group messaging, serialize protocol messages, and verify fingerprints.

The package is intended for educational and interoperability-focused use. Applications using it are responsible for durable key storage, message transport, identity verification policy, and operational security around cryptographic material.

## Installation

Add the package with Swift Package Manager and import the library target:

```swift
import LibSignalProtocolSwift
```

The package currently supports iOS 12.0+, macOS 10.15+, tvOS 12.0+, and watchOS 6.0+.

## Storage Responsibilities

The protocol requires local storage for identity keys, pre keys, signed pre keys, sessions, and optionally sender keys. Provide these capabilities by implementing ``KeyStore`` or ``GroupKeyStore`` for your application model.

## Crypto Provider

The default provider uses CommonCrypto through the package's C bridge. Advanced users can replace it by assigning a custom ``SignalCryptoProvider`` to ``SignalCrypto/provider``.

## Topics

### Session Messaging

- ``SessionCipher``
- ``SessionPreKeyBundle``
- ``CipherTextMessage``
- ``SignalMessage``
- ``PreKeySignalMessage``

### Group Messaging

- ``GroupCipher``
- ``GroupKeyStore``
- ``SenderKeyMessage``
- ``SenderKeyDistributionMessage``

### Local Storage

- ``KeyStore``
- ``IdentityKeyStore``
- ``PreKeyStore``
- ``SignedPreKeyStore``
- ``SessionStore``
- ``SenderKeyStore``

### Keys and Crypto

- ``SignalCrypto``
- ``SignalCryptoProvider``
- ``SignalCommonCrypto``
- ``SignalEncryptionScheme``
- ``KeyPair``
- ``PublicKey``
- ``PrivateKey``

### Fingerprints

- ``Fingerprint``
- ``DisplayableFingerprint``
- ``ScannableFingerprint``

### Errors

- ``SignalError``
- ``SignalErrorType``
