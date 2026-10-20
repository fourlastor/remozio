// swift-tools-version: 6.2
import PackageDescription

// Synthetic offscreen previews. This is not the application product or an installer.
let package = Package(name: "SetupPreviewSnapshots", platforms: [.macOS("26.0")],
    dependencies: [.package(path: "../core")],
    targets: [.executableTarget(name: "SetupPreviewSnapshots", dependencies: [.product(name: "RemozioCore", package: "core")],
        path: ".", exclude: ["Authority", "Setup", "App/PresenceControls.swift", "Gateway", "Transport", "CommandChild", "CommandMonitor", "CommandFrontend", "Remozio.xcodeproj", "README.md", "App/RemozioApp.swift", "App/en.lproj"],
        sources: ["App/SetupFilePreview.swift", "App/PairingSheet.swift", "App/GatewaySetupSheet.swift", "Snapshots/Render.swift"])])
