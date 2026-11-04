// swift-tools-version: 6.2
import PackageDescription

// Software-key mode only: the TLS identity is a software P-256 key, not a TPM key. This is an operator-confirmed
// experiment peer, not the protected host service.
let package = Package(
    name: "LinuxPairingPeer",
    products: [
        .library(name: "CPairingTLS", targets: ["CPairingTLS"]),
        .library(name: "PairingCommitState", targets: ["PairingCommitState"]),
        .executable(name: "remozio-linux-pair", targets: ["remozio-linux-pair"]),
        .executable(name: "remozio-tls-suspend-probe", targets: ["remozio-tls-suspend-probe"]),
    ],
    dependencies: [
        .package(path: "../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [
        .systemLibrary(name: "COpenSSL", pkgConfig: "openssl", providers: [.apt(["libssl-dev"])]),
        .target(name: "CPairingTLS", dependencies: ["COpenSSL"]),
        // Test-only OpenSSL peers (ticket server, saved-session client, extra chain certificates); not a product.
        .target(name: "CPairingTLSTestSupport", dependencies: ["COpenSSL"]),
        // Durable commit state machine. No network and no TLS: it takes a decoded transcript and a proof.
        .target(name: "CPairingFiles"),
        .target(name: "PairingCommitState", dependencies: ["CPairingFiles", .product(name: "RemozioProtocol", package: "swift")]),
        // The foreground pairing tool's authority role. It stores software keys beside the commit state.
        .target(name: "LinuxPairAuthority", dependencies: [
            "CPairingTLS", "PairingCommitState",
            .product(name: "RemozioProtocol", package: "swift"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .executableTarget(name: "remozio-linux-pair", dependencies: [
            "CPairingTLS", "LinuxPairAuthority", "PairingCommitState",
            .product(name: "RemozioProtocol", package: "swift"),
        ], swiftSettings: [.swiftLanguageMode(.v5)]),
        // Attended evidence only: a read deadline across a real host suspend. CI builds it and never runs it.
        .executableTarget(name: "remozio-tls-suspend-probe", dependencies: ["CPairingTLS"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "LinuxPairAuthorityTests", dependencies: [
            "LinuxPairAuthority", "PairingCommitState", "CPairingTLS",
            .product(name: "RemozioProtocol", package: "swift"),
            .product(name: "Crypto", package: "swift-crypto"),
        ], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "PairingCommitStateTests", dependencies: [
            "PairingCommitState", "CPairingFiles",
            .product(name: "RemozioProtocol", package: "swift"),
            .product(name: "Crypto", package: "swift-crypto"),
        ], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "LinuxPairingTLSTests", dependencies: ["CPairingTLS", "CPairingTLSTestSupport"],
                    swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
