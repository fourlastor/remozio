// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "RemozioSystemKeychainProbe", platforms: [.macOS("26.0")],
    targets: [.executableTarget(name: "SystemKeychainProbe"),
              .testTarget(name: "SystemKeychainProbeTests", dependencies: ["SystemKeychainProbe"])])
