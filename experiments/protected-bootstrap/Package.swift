// swift-tools-version: 6.2
import PackageDescription

let package = Package(name: "RemozioBootstrapExperiment", platforms: [.macOS("26.0")],
    products: [.executable(name: "remozio-bootstrap-probe", targets: ["BootstrapProbe"])],
    targets: [.executableTarget(name: "BootstrapProbe")])
