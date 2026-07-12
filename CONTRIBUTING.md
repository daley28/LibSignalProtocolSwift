# Contributing

## Requirements

- Xcode 16.2 or newer for the current CI baseline
- Swift 5.7-compatible package manifest support
- `protoc` only when regenerating protocol buffer sources

## Local Verification

Run these before opening a pull request:

```sh
swift package resolve
swift build
swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warn-concurrency
swift test
```

The strict-concurrency build is intentionally a warning-free check. Do not silence it with unsafe annotations unless the code has a documented synchronization boundary.

The repository also contains a legacy CocoaPods-backed Xcode project. To verify the Swift package with `xcodebuild`, temporarily move `SignalProtocol.xcodeproj` and `SignalProtocol.xcworkspace` out of the checkout so Xcode opens `Package.swift` as the package root:

```sh
mv SignalProtocol.xcodeproj SignalProtocol.xcodeproj.legacy
mv SignalProtocol.xcworkspace SignalProtocol.xcworkspace.legacy
xcodebuild build -scheme LibSignalProtocolSwift -destination 'generic/platform=iOS'
xcodebuild build -scheme LibSignalProtocolSwift -destination 'generic/platform=watchOS'
mv SignalProtocol.xcodeproj.legacy SignalProtocol.xcodeproj
mv SignalProtocol.xcworkspace.legacy SignalProtocol.xcworkspace
```

## Formatting

This project includes a `.swift-format` configuration for new and modified Swift code:

```sh
swift format lint --configuration .swift-format --recursive Package.swift Sources Tests
```

The existing codebase has historical formatting, so prefer focused formatting in the files you touch rather than a repository-wide formatting-only diff.

## Protocol Buffers

Generated `.pb.swift` files are committed so consumers do not need `protoc` installed. Regenerate them only with a `protoc-gen-swift` version that is compatible with the SwiftProtobuf runtime supported by `Package.swift`.

Current maintainer command:

```sh
swift build -c release --package-path .build/checkouts/swift-protobuf --product protoc-gen-swift
PLUGIN="$PWD/.build/checkouts/swift-protobuf/.build/release/protoc-gen-swift"
cd Sources/LibSignalProtocolSwift/ProtocolBuffers
protoc --plugin="protoc-gen-swift=$PLUGIN" --swift_opt=FileNaming=DropPath --swift_out=. Fingerprint.proto LocalStorage.proto Messages.proto
```

Do not switch to the SwiftProtobuf build plugin for this package without a separate design review. The plugin is convenient for leaf packages, but this library is intended to be consumed transitively.
