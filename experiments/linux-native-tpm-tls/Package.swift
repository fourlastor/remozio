// swift-tools-version: 6.2
import PackageDescription

// Disposable simulator experiment only; this is not a production signer or TLS-stack API.
let package = Package(
    name: "LinuxNativeTPMProbe",
    products: [.executable(name: "NativeTPMProbe", targets: ["NativeTPMProbe"])],
    targets: [
        .systemLibrary(name: "COpenSSL", pkgConfig: "openssl", providers: [.apt(["libssl-dev"])]),
        .target(name: "CNativeTPMProbe", dependencies: ["COpenSSL"]),
        .executableTarget(name: "NativeTPMProbe", dependencies: ["CNativeTPMProbe"]),
    ]
)
