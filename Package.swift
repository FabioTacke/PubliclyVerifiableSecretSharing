// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "PVSS",
    products: [
      .library(
      name: "PVSS",
    targets: ["PVSS"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", .branch("master")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .branch("master")),
        .package(url: "https://github.com/mdaxter/BignumGMP.git", .branch("master")),
    ],
    targets: [
      .target(
        name: "PVSS",
        dependencies: ["BigInt", "Bignum", "CryptoSwift"]),
      .testTarget(
        name: "PVSSTests",
        dependencies: ["PVSS"]),
    ]
)
