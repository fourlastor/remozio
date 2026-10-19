// swift-tools-version: 6.2
import PackageDescription

// Keep the dependency graph stable across hosts. Only Linux tests link Crypto;
// macOS tests use CryptoKit, and verification uses the shared protocol package.
let cryptoTargets: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
]

// macOS uses its SDK module; Linux exposes the system SQLite headers through CSQLite.
let sqliteTargets: [Target.Dependency] = [
    .target(name: "CSQLite", condition: .when(platforms: [.linux])),
]

let package = Package(
    name: "RemozioHostCore",
    platforms: [.macOS(.v26)],
    products: [.library(name: "RemozioHostCore", targets: ["RemozioHostCore"])],
    dependencies: [
        .package(path: "../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [
        .systemLibrary(name: "CSQLite", pkgConfig: "sqlite3", providers: [.apt(["libsqlite3-dev"])]),
        .target(name: "RemozioHostCore", dependencies: [.product(name: "RemozioProtocol", package: "swift")] + sqliteTargets),
        .testTarget(name: "RemozioHostCoreTests", dependencies: ["RemozioHostCore",
            .product(name: "RemozioProtocol", package: "swift")] + cryptoTargets + sqliteTargets),
    ]
)
