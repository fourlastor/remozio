// swift-tools-version: 6.2
import PackageDescription

// Disposable, unprivileged component integration fixture; not a host authority.
let package = Package(
    name: "LinuxApprovalCommandFixture",
    products: [
        .executable(name: "LinuxApprovalCommandFixture", targets: ["LinuxApprovalCommandFixture"]),
        .library(name: "LinuxApprovalFixtureCore", targets: ["LinuxApprovalFixtureCore"]),
    ],
    dependencies: [
        .package(path: "../../host/shared-core"),
        .package(path: "../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [
        .systemLibrary(name: "FixtureSQLite", pkgConfig: "sqlite3", providers: [.apt(["libsqlite3-dev"])]),
        .target(name: "LinuxApprovalFixtureCore", dependencies: [
            "FixtureSQLite", .product(name: "RemozioHostCore", package: "shared-core"),
            .product(name: "RemozioProtocol", package: "swift"), .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .executableTarget(name: "LinuxApprovalCommandFixture", dependencies: [
            "LinuxApprovalFixtureCore", .product(name: "RemozioHostCore", package: "shared-core"),
            .product(name: "RemozioProtocol", package: "swift"), .product(name: "Crypto", package: "swift-crypto"),
        ]),
    ]
)
