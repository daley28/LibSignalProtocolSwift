// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "LibSignalProtocolSwift",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_15),
        .tvOS(.v12),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "LibSignalProtocolSwift",
            type: .static,
            targets: ["LibSignalProtocolSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.20.0"),
        .package(url: "https://github.com/christophhagen/Curve25519.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "CommonCryptoBridge",
            path: "Sources/CommonCryptoModule",
            sources: ["CommonCryptoBridge.c"],
            publicHeadersPath: "CommonCryptoBridge"
        ),
        .target(
            name: "LibSignalProtocolSwift",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Curve25519", package: "Curve25519"),
                "CommonCryptoBridge"
            ],
            path: "Sources/LibSignalProtocolSwift",
            exclude: ["Info"]
        ),
        .testTarget(
            name: "SignalProtocolTests",
            dependencies: ["LibSignalProtocolSwift"],
            path: "Tests/Test Implementation"
        ),
    ]
)
