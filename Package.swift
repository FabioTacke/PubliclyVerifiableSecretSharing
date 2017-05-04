// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "PVSS",
    dependencies: [
        .Package(url: "https://github.com/lorentey/BigInt.git", majorVersion: 2, minor: 1),
        .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0)
    ]
)
