// swift-tools-version: 6.2
import PackageDescription

let package = Package(name: "SparkleBoundaryProbe", platforms: [.macOS("26.0")],
    dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0")],
    targets: [.executableTarget(name: "SparkleBoundaryProbe", dependencies: [.product(name: "Sparkle", package: "Sparkle")],
        linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])])])
