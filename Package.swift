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
            targets: ["LibSignalProtocolSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.20.0"),
        .package(url: "https://github.com/christophhagen/Curve25519.git", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "CommonCryptoBridge",
            path: "Sources/CommonCryptoBridge",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedLibrary("CommonCrypto", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS]))
            ]
        ),
        .target(
            name: "LibSignalProtocolSwift",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Curve25519", package: "Curve25519"),
                "CommonCryptoBridge"
            ],
            path: "Sources/LibSignalProtocolSwift",
            exclude: [
                "Info",
                "SignalProtocol.h",
                "ProtocolBuffers/Fingerprint.proto",
                "ProtocolBuffers/LocalStorage.proto",
                "ProtocolBuffers/Messages.proto"
            ],
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS]))
            ]
        ),
        .testTarget(
            name: "SignalProtocolTests",
            dependencies: ["LibSignalProtocolSwift"],
            path: "Tests/SignalProtocolTests"
        ),
    ]
)
