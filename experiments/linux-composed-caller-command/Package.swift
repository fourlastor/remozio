// swift-tools-version: 6.2
import PackageDescription

// Disposable composed fixture owner; never a protected Linux host authority.
let package = Package(
    name: "LinuxComposedCallerCommand",
    products: [.executable(name: "LinuxComposedCallerCommand", targets: ["LinuxComposedCallerCommand"])],
    dependencies: [
        .package(path: "../linux-approval-command"),
        .package(path: "../linux-os-capture"),
        .package(path: "../../host/shared-core"),
        .package(path: "../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [
        .target(name: "CComposedSupport"),
        .executableTarget(name: "LinuxComposedCallerCommand", dependencies: [
            "CComposedSupport",
            .product(name: "LinuxApprovalFixtureCore", package: "linux-approval-command"),
            .product(name: "LinuxOSObservation", package: "linux-os-capture"),
            .product(name: "RemozioHostCore", package: "shared-core"),
            .product(name: "RemozioProtocol", package: "swift"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
    ]
)
