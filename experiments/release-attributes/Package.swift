// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "ReleaseAttributesExperiment", platforms: [.macOS("26.0")],
 targets: [.target(name: "AttributeInspection"), .executableTarget(name: "AttributeProbe", dependencies: ["AttributeInspection"]), .testTarget(name: "AttributeInspectionTests", dependencies: ["AttributeInspection"])])
