// swift-tools-version: 6.2
import PackageDescription

// Keep the package graph stable across hosts. Only Linux links Swift Crypto;
// macOS keeps the platform CryptoKit implementation and the same wire format.
let cryptoTargets: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
]

let package = Package(
    name: "RemozioProtocol",
    platforms: [.macOS(.v26)],
    products: [.library(name: "RemozioProtocol", targets: ["RemozioProtocol"])],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1")],
    targets: [
        .target(name: "RemozioProtocol", dependencies: cryptoTargets),
        .testTarget(name: "RemozioProtocolTests", dependencies: ["RemozioProtocol"] + cryptoTargets),
    ]
)
