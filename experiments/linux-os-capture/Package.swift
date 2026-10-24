// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "LinuxOSCaptureExperiment",
    dependencies: [
        .package(path: "../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [.executableTarget(name: "LinuxOSCaptureExperiment", dependencies: [
        .product(name: "RemozioProtocol", package: "swift"),
        .product(name: "Crypto", package: "swift-crypto"),
    ])]
)
