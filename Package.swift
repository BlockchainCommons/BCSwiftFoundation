// swift-tools-version:6.0

import PackageDescription

let package = Package(
    name: "BCFoundation",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .macCatalyst(.v16)
    ],
    products: [
        .library(
            name: "BCFoundation",
            targets: ["BCFoundation"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "7.0.0"),
        .package(url: "https://github.com/ChimeHQ/Flexer", from: "0.1.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents", from: "9.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftEnvelope", from: "5.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "6.0.0"),
    ],
    targets: [
        .target(
            name: "BCFoundation",
            dependencies: [
                "WolfBase",
                "Flexer",
                .product(name: "SecureComponents", package: "BCSwiftSecureComponents"),
                .product(name: "Envelope", package: "BCSwiftEnvelope"),
                .product(name: "BCCrypto", package: "BCSwiftCrypto"),
            ]
        ),
        .testTarget(
            name: "BCFoundationTests",
            dependencies: ["BCFoundation", "WolfBase"]
        ),
    ]
)
