// swift-tools-version:5.3
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
            name: "SignalProtocol",
            targets: ["SignalProtocol"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.5.0"),
        .package(url: "https://github.com/christophhagen/Curve25519.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "CommonCryptoModule",
            path: "Sources/CommonCryptoModule",
            publicHeadersPath: "."
        ),
        .target(
            name: "SignalProtocol",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Curve25519", package: "Curve25519"),
                "CommonCryptoModule"
            ],
            path: "Sources",
            exclude: ["Info", "CommonCryptoModule"],
            resources: [
                .process("Info")
            ]
        ),
        .testTarget(
            name: "SignalProtocolTests",
            dependencies: ["SignalProtocol"],
            path: "Tests",
            exclude: ["Info.plist"]
        ),
    ]
)
