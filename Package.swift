// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "BCFoundation",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "BCFoundation",
            targets: ["BCFoundation", "BCWally", "SSKR"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "3.24.0"),
        .package(url: "https://github.com/ChimeHQ/Flexer.git", from: "0.1.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(url: "https://github.com/BlockchainCommons/URKit.git", from: "5.0.0"),
        .package(url: "https://github.com/tesseract-one/Blake2.swift.git", from: "0.1.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMajor(from: "0.5.0"))
//        .package(url: "https://github.com/BlockchainCommons/URKit.git", .branch("master"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "BCFoundation",
            dependencies: [
                "WolfBase",
                "Flexer",
                "CryptoSwift",
                "URKit",
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "Blake2", package: "Blake2.swift")
            ]
        ),
        .binaryTarget(
            name: "BCWally",
            path: "Frameworks/BCWally.xcframework"
        ),
        .binaryTarget(
            name: "SSKR",
            path: "Frameworks/SSKR.xcframework"
        ),
        .testTarget(
            name: "BCFoundationTests",
            dependencies: ["BCFoundation"]
        ),
    ]
)
