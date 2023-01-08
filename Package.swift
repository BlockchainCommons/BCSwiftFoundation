// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "BCFoundation",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "BCFoundation",
            targets: ["BCFoundation"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "5.0.0"),
        .package(url: "https://github.com/ChimeHQ/Flexer.git", from: "0.1.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", from: "0.1.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftEnvelope.git", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "BCFoundation",
            dependencies: [
                "WolfBase",
                "Flexer",
                .product(name: "SecureComponents", package: "BCSwiftSecureComponents"),
                .product(name: "Envelope", package: "BCSwiftEnvelope"),
            ]
        ),
        .testTarget(
            name: "BCFoundationTests",
            dependencies: ["BCFoundation", "WolfBase"]
        ),
    ]
)
