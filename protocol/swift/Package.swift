// swift-tools-version: 6.2
import PackageDescription

// Keep the platform CryptoKit implementation on macOS. Linux uses the official
// Swift Crypto implementation of the same API; it does not change the wire format.
#if os(Linux)
let cryptoPackages: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
]
let cryptoTargets: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
]
#else
let cryptoPackages: [Package.Dependency] = []
let cryptoTargets: [Target.Dependency] = []
#endif

let package = Package(
    name: "RemozioProtocol",
    platforms: [.macOS(.v26)],
    products: [.library(name: "RemozioProtocol", targets: ["RemozioProtocol"])],
    dependencies: cryptoPackages,
    targets: [
        .target(name: "RemozioProtocol", dependencies: cryptoTargets),
        .testTarget(name: "RemozioProtocolTests", dependencies: ["RemozioProtocol"] + cryptoTargets),
    ]
)
