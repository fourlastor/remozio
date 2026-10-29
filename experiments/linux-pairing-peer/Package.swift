// swift-tools-version: 6.2
import PackageDescription

// Software-key mode only: the TLS identity is a file-backed P-256 key, not a TPM key. This is an operator-confirmed
// experiment peer, not the protected host service.
let package = Package(
    name: "LinuxPairingPeer",
    products: [.library(name: "CPairingTLS", targets: ["CPairingTLS"])],
    targets: [
        .systemLibrary(name: "COpenSSL", pkgConfig: "openssl", providers: [.apt(["libssl-dev"])]),
        .target(name: "CPairingTLS", dependencies: ["COpenSSL"]),
        // Test-only OpenSSL peers (ticket server, saved-session client, extra chain certificates); not a product.
        .target(name: "CPairingTLSTestSupport", dependencies: ["COpenSSL"]),
        .testTarget(name: "LinuxPairingTLSTests", dependencies: ["CPairingTLS", "CPairingTLSTestSupport"],
                    swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
