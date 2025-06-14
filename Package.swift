// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "LibSignalProtocolSwift",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_15),
        .tvOS(.v9),
        .watchOS(.v4)
    ],
    products: [
        .library(
            name: "LibSignalProtocolSwift",
            targets: ["LibSignalProtocolSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.5.0"),
        .package(url: "https://github.com/christophhagen/Curve25519.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "CommonCryptoModule",
            path: "Sources/CommonCryptoModule",
            publicHeadersPath: "CommonCryptoBridge"
        ),
        .target(
            name: "LibSignalProtocolSwift",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Curve25519", package: "Curve25519"),
                "CommonCryptoModule"
            ],
            path: "Sources/LibSignalProtocolSwift"
        ),
        .testTarget(
            name: "SignalProtocolTests",
            dependencies: ["LibSignalProtocolSwift"],
            path: "Tests",
            exclude: ["Info.plist"]
        ),
    ]
)
