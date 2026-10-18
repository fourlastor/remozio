// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioCore",
    platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioCore", targets: ["RemozioCore"])],
    dependencies: [.package(path: "../../host/shared-core"), .package(path: "../../protocol/swift"), .package(url: "https://github.com/airsidemobile/JOSESwift.git", exact: "3.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.0")],
    targets: [.target(name: "RemozioMach"), .target(name: "RemozioCore", dependencies: ["RemozioMach", .product(name: "RemozioHostCore", package: "shared-core"), .product(name: "RemozioProtocol", package: "swift"), .product(name: "JOSESwift", package: "JOSESwift"),
        .product(name: "X509", package: "swift-certificates")], linkerSettings: [.linkedLibrary("bsm")]), .testTarget(name: "RemozioCoreTests", dependencies: ["RemozioCore", "RemozioMach"], resources: [.copy("Fixtures")])]
)
