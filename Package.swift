// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "BCFoundation",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "BCFoundation",
            targets: ["BCFoundation"]),
    ],
    dependencies: [
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "4.0.0"),
        .package(url: "https://github.com/ChimeHQ/Flexer.git", from: "0.1.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", branch: "master")
    ],
    targets: [
        .target(
            name: "BCFoundation",
            dependencies: [
                "WolfBase",
                "Flexer",
                .product(name: "BCSecureComponents", package: "BCSwiftSecureComponents"),
            ]
        ),
        .testTarget(
            name: "BCFoundationTests",
            dependencies: ["BCFoundation", "WolfBase"]
        ),
    ]
)
