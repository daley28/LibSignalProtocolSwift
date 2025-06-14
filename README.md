# LibSignalProtocolSwift
[![Swift](https://github.com/daley28/LibSignalProtocolSwift/actions/workflows/swift.yml/badge.svg)](https://github.com/daley28/LibSignalProtocolSwift/actions/workflows/swift.yml)

A Swift implementation of the Signal Protocol. The [Signal Protocol](https://en.wikipedia.org/wiki/Signal_Protocol)
can be used for secure, end-to-end encrypted messaging in synchronous and asynchronous environments. It has
many desirable cryptographic features and can handle missing and out-of-order messages. The Signal protocol
is used by the [Signal Messenger](https://signal.org) as well as WhatsApp, Facebook, Skype and others. Additional
information can be found [here](https://signal.org/docs/).

## Purpose

This Swift library is intended for educational purposes only, in order to show the way the Signal Protocol works.
It somewhat mimics the functionality and structure of the [Signal Protocol C implementation](https://github.com/signalapp/libsignal-protocol-c).

## Fork Information

This is a fork of [christophhagen/LibSignalProtocolSwift](https://github.com/christophhagen/LibSignalProtocolSwift) with **full Swift Package Manager (SPM) support**. 

### Key Improvements in This Fork:

- ✅ **Native SPM Compatibility**: Complete Swift Package Manager support without CocoaPods dependencies
- ✅ **CommonCrypto Integration**: Custom C bridge that solves the notorious CommonCrypto + SPM compatibility issue
- ✅ **Modern Swift Support**: Updated for Swift 5.7+ with proper toolchain compatibility
- ✅ **Cross-Platform**: Full support for iOS, macOS, tvOS, watchOS
- ✅ **Zero Warnings**: Clean build with no compiler warnings or deprecated syntax
- ✅ **Updated Dependencies**: Modern SwiftProtobuf and other dependency versions

### Why This Fork?

The original repository had several SPM compatibility issues, particularly with CommonCrypto integration, which made it difficult to use with modern Swift Package Manager workflows. This fork addresses all those issues while maintaining full API compatibility with the original library.

**Credit**: All core Signal Protocol implementation credit goes to [Christoph Hagen](https://github.com/christophhagen) and the original [LibSignalProtocolSwift](https://github.com/christophhagen/LibSignalProtocolSwift) project.

## Installation

### Swift Package Manager (Recommended)

You can install `LibSignalProtocolSwift` through [Swift Package Manager](https://swift.org/package-manager/) by adding it to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/daley28/LibSignalProtocolSwift.git", from: "1.3.0")
]
```

Or add it through Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL: `https://github.com/daley28/LibSignalProtocolSwift.git`
3. Select the version you want to use

### CocoaPods

You can also install `LibSignalProtocolSwift` through [Cocoapods](https://cocoapods.org), by adding the following to your `Podfile`:

```ruby
pod 'LibSignalProtocolSwift', '~> 1.3'
```

### Importing

After installation the Framework can be accessed by importing it:

```swift
import LibSignalProtocolSwift
```

## Prerequisites

### Local storage
The Signal Protocol needs local storage for message keys, identities and other state information.
You can provide this functionality by implementing the protocol `KeyStore`, which requires
four delegates for the individual data stores:

- `IdentityKeyStore` for storing and retrieving identity keys
- `PreKeyStore` for storing and retrieving pre keys
- `SessionStore` for storing and retrieving the sessions
- `SignedPreKeyStore` for storing and retrieving signed pre keys

#### Optional
There is a feature for group updates, where only one administrator can send, and the others can only receive. If you want this functionality, then implement the `GroupKeyStore` protocol, with the additional delegate  `SenderKeyStore` for storing and retrieving sender keys.

### Sample implementation

You can have a look at the [test implementation](https://github.com/daley28/LibSignalProtocolSwift/tree/master/Tests/Test%20Implementation) for inspiration.

### Server for message delivery
The server that stores the messages for retrieval needs to store the following data for each `SignalAddress`:
- `Public Identity Key`: The public part of the identity key of the device
- `Signed Pre Key`: The current signed pre key
- `Pre Keys`: A number of unsigned pre keys
- `Messages`: The messages to deliver to that address, including the sender

## Usage

The standard process to establish an encrypted session between two devices (two distinct `SignalAddress`es) is usually as follows:

- Alice uploads her `Identity`  and a `SignedPreKey` to the server, as well as a number of unsigned `PreKey`s.
- Bob retrieves a `PreKeyBundle` from the server, consisting of Alice's `Identity`, the `SignedPreKey`, and one of the `PreKey`s (which is then deleted from the server).
- Bob creates a session by processing the `PreKeyBundle` and encrypting a `PreKeyMessage` which he uploads to the server.
- Alice receives Bob's `PreKeyMessage` from the server and decryptes the message.
- The encrypted session is established for both Alice and Bob.

### Creating identity and keys

Before any secure communication can happen, at least one user needs to upload all necessary ingredients for a `PreKeyBundle` to the server.

```swift
import LibSignalProtocolSwift

// Create the identity key at install time
let identity = try SignalCrypto.generateIdentityKeyPair()

// Store the data in the key store

// Get the public key from the store
let publicKey: Data = try bobStore.getPublicIdentityKey()

// Create pre keys and save them in the store
let preKeys: [Data] = try bobStore.createPreKeys(count: 10)

// Create a signed pre key and save it in the store
let signedPreKey: Data = try bobStore.updateSignedPrekey()

// Upload publicKey, preKeys, and signedPreKey to the server
```

### Creating a session from a PreKeyBundle

Let's assume that Alice (who has the `SignalAddress` aliceAddress) wants to establish a session with Bob (`SignalAddress` bobAddress)

```swift
import LibSignalProtocolSwift

// Download Bob's identity, current signedPreKey and one of the preKeys from the server

// Create PreKeyBundle
let preKeyBundle = try SessionPreKeyBundle(
    preKey: preKey,
    signedPreKey: signedPreKey,
    identityKey: identity)

// Create a new session by processing the PreKeyBundle
let session = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
try session.process(preKeyBundle: preKeyBundle)

// The message to encrypt
let message = "Hello Bob, it's Alice".data(using: .utf8)!

// Here Alice can send messages to Bob
let encryptedMessage = try session.encrypt(message)

// Upload the message to the server
```

### Creating a session from a received PreKeySignalMessage
Let's continue the above example and assume Bob receives the message from Alice. Bob can then establish the session:

```swift
import LibSignalProtocolSwift

// Get the message from the server

// Create the session
let session = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

// Process the message
let decryptedMessage = try session.decrypt(preKeyMessage)
```

### Using an already established session
Now Alice and Bob can both send and receive messages at will.

#### Sending

```swift
import LibSignalProtocolSwift

// Compose a message
let message =  "Hello there".data(using: .utf8)!

// Send message to Bob
let session = SessionCipher(store: aliceStore, remoteAddress: bobAddress)

// Encrypt
let encryptedMessage = try session.encrypt(message)
```

#### Receiving

```swift
import LibSignalProtocolSwift

// Get message from the server

// Receive message from Alice
let session = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

// Decrypt
let decryptedMessage = try session.decrypt(message)
```

#### Verifying identity Keys

To prevent man-in-the-middle attacks it can be beneficial to compare the identity keys either
by manually comparing the fingerprints or through scanning some sort of code (e.g. a QR-Code).
The library provides a convenient way for this:

```swift
import LibSignalProtocolSwift

// Create the fingerprint
let aliceFP = try aliceStore.fingerprint(for: bobAddress, localAddress: aliceAddress)

// Display the string...
let display = fingerprint.displayText

// ... or transmit the scannable data to the other client...
let scanData = try fingerprint.scannable.protoData()

// ... or compare to a received fingerprint
fingerprint.matches(scannedFingerprint)
```

### Miscellaneous

#### Client identifiers
The library is designed to allow different identifiers to distinguish between the different users.
The test implementation uses the `SignalAddress` struct for this, which consists of a `String` (e.g. a phone number)
and an `Int`, the `deviceId`. However it is possible to use different structs, classes, or types, as long as they
conform to the `Hashable`, `Equatable` and `CustomStringConvertible` protocols. For example, simple strings can be used:

```swift
import LibSignalProtocolSwift

class MyCustomKeyStore: KeyStore {

    typealias Address = String

    ...
}
```

Now, SessionCipher can be instantiated, using `MyCustomKeyStore` :

```swift
let aliceStore = MyCustomKeyStore()
let session = SessionCipher(store: aliceStore, remoteAddress: "Bob")
```

#### Providing a custom crypto implementation

It is possible for any custom implementation of the `SignalCryptoProvider` protocol
to serve as the cryptographic backbone of the protocol. This can be done by
setting the static `provider` variable of the `SignalCrypto` class:

```swift
import LibSignalProtocolSwift

SignalCrypto.provider = MyCustomCryptoProvider()
```

The elliptic curve functions are handled by the same C code that is deployed in
[libsignal-protocol-c](https://github.com/signalapp/libsignal-protocol-c)
and which is packaged in the [Curve25519](https://github.com/christophhagen/Curve25519)
framework to make the functions available in Swift.

## Technical Details

### Swift Package Manager Support

This library now includes full Swift Package Manager support with a custom CommonCrypto bridge that enables:
- Native SPM compatibility without CocoaPods dependencies
- Cross-platform support (iOS, macOS, tvOS, watchOS)
- Modern Swift toolchain compatibility (Swift 5.7+)
- Proper module isolation and dependency management

### Dependencies

- **SwiftProtobuf**: For Protocol Buffer serialization
- **Curve25519**: For elliptic curve cryptographic operations
- **CommonCrypto Bridge**: Custom C bridge for CommonCrypto functions (SPM compatible)

### Platform Support

- iOS 12.0+
- macOS 10.15+
- tvOS 12.0+
- watchOS 6.0+

#### Documentation

The project is documented heavily because it helps other people understand the code. The [documentation](https://github.com/christophhagen/SignalProtocolSwift/tree/master/Documentation)
is created with [jazzy](https://github.com/realm/jazzy), which creates awesome, apple-like
docs.

The docs can be (re-)generated by running the following in the project directory:
```
jazzy --min-acl private -a 'Christoph Hagen' -u 'https://github.com/christophhagen' -g 'https://github.com/daley28/LibSignalProtocolSwift' -e 'Sources/ProtocolBuffers/*' -o 'Documentation'
```

#### Disclaimer

This code is NOT intended for production use! The code is neither reviewed for errors
nor written by an expert. Please do not implement your own cryptographic software,
if you don't know EXACTLY what you are doing.
