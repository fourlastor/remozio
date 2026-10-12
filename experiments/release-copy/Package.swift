// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "ReleaseCopyExperiment", platforms: [.macOS("26.0")],
    dependencies: [.package(path: "../../macos/core")],
    targets: [.executableTarget(name: "ReleaseCopyProbe", dependencies: [.product(name: "RemozioCore", package: "core")])])
