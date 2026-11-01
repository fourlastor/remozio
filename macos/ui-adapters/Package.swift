// swift-tools-version: 6.2
import PackageDescription

let package = Package(name: "RemozioUIAdapters", platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioUIAdapters", targets: ["RemozioUIAdapters"]),
               .executable(name: "remozio-ax-structure", targets: ["RemozioAXStructureProbe"])],
    targets: [.target(name: "RemozioUIAdapters"),
              .executableTarget(name: "RemozioAXStructureProbe", dependencies: ["RemozioUIAdapters"]),
              .testTarget(name: "RemozioUIAdaptersTests", dependencies: ["RemozioUIAdapters"])])
