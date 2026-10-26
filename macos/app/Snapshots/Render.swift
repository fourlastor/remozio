import AppKit
import CryptoKit
import RemozioProtocol
import RemozioCore
import SwiftUI

#if DEBUG
@main
struct RenderSetupPreview {
    @MainActor static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Supply a snapshot output directory") }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let defaults = try SharedSetupDefaults(
            presence: PresenceConfiguration(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000),
            wake: GatewayWakePolicy(maximumEntries: 8, maximumAttempts: 2, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60),
            delivery: GatewayDeliveryPolicy(maximumFlights: 2, minimumSendIntervalMillis: 100))
        let scope = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                                                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-not-used")
        let preview = PortableSetup(defaults: defaults, cloudflare: scope).preview
        for (name, view) in [
            ("empty-light", SetupFilePreview()),
            ("scope-light", SetupFilePreview(snapshotPreview: preview)),
            ("scope-dark", SetupFilePreview(snapshotPreview: preview)),
            ("error-light", SetupFilePreview(snapshotPreview: nil, snapshotError: "Could not open this setup file. Check the password and use a supported Remozio export.")),
        ] {
            let dark = name.hasSuffix("dark")
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            host.frame = NSRect(x: 0, y: 0, width: 540, height: name.hasPrefix("scope") ? 590 : 340)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png"))
            window.contentView = nil
            print(name + ": rendered synthetic preview")
        }
        let portableGateway = try GatewayRuntimeSettingsSelection(service: .init(delivery: defaults.delivery,
            probe: .init(maximumAttempts: 2, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 30), wake: defaults.wake),
            activation: .init(wakePollMilliseconds: 2500, wakeTimeoutMilliseconds: 5000))
        let portableDefaults = SharedSetupDefaults(presence: defaults.presence, gateway: portableGateway)
        let portablePreferences = try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: false,
            CommandFrontendCallerSettings.modeKey: "pipes", CommandFrontendCallerSettings.controlRetryKey: "17"])
        let portableKeyProcess = Process(), portableKeyPipe = Pipe()
        portableKeyProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        portableKeyProcess.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        portableKeyProcess.standardOutput = portableKeyPipe; portableKeyProcess.standardError = FileHandle.nullDevice
        try portableKeyProcess.run()
        let portableKey = portableKeyPipe.fileHandleForReading.readDataToEndOfFile(); portableKeyProcess.waitUntilExit()
        guard portableKeyProcess.terminationStatus == 0 else { fatalError("Could not generate the disposable preview key") }
        let portableProvider = try SetupFCMConfiguration(project: "remozio-preview", clientEmail: "preview@fixture.iam.gserviceaccount.com",
            privateKeyID: "synthetic-preview-key", privateKeyPEM: String(decoding: portableKey, as: UTF8.self))
        let portableClient = try SetupPushClientConfiguration(projectID: "remozio-preview", senderID: "123456789012", packageName: "dev.remozio.android")
        let portableFull = PortableSetup(defaults: portableDefaults, fcm: portableProvider,
            pushClient: portableClient, appPreferences: portablePreferences).preview
        let portableSettingsOnly = PortableSetup(defaults: portableDefaults).preview
        let portableSparse = PortableSetup(defaults: defaults, appPreferences: portablePreferences).preview
        let portableEmpty = PortableSetup(defaults: defaults, appPreferences: try PortableAppPreferences(preferences: [:])).preview
        for (name, portableScope, bottom) in [
            ("portable-preview-full-light", portableFull, false),
            ("portable-preview-full-dark", portableFull, false),
            ("portable-preview-full-bottom-light", portableFull, true),
            ("portable-preview-full-bottom-dark", portableFull, true),
            ("portable-preview-settings-only-light", portableSettingsOnly, false),
            ("portable-preview-settings-only-dark", portableSettingsOnly, false),
            ("portable-preview-sparse-light", portableSparse, false),
            ("portable-preview-sparse-dark", portableSparse, false),
            ("portable-preview-empty-preferences-light", portableEmpty, false),
            ("portable-preview-empty-preferences-dark", portableEmpty, false),
        ] {
            let dark = name.hasSuffix("dark"), view = SetupFilePreview(snapshotPreview: portableScope)
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = app.appearance; host.frame = NSRect(x: 0, y: 0, width: 540, height: 590)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host; host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.5))
            if bottom {
                func portableScroll(_ view: NSView) -> NSScrollView? {
                    if let scroll = view as? NSScrollView { return scroll }
                    for child in view.subviews { if let scroll = portableScroll(child) { return scroll } }
                    return nil
                }
                guard let scroll = portableScroll(host), let document = scroll.documentView else {
                    fatalError("No portable preview scroll view")
                }
                let edge = document.isFlipped ? max(0, document.bounds.height - scroll.contentView.bounds.height) : 0
                scroll.contentView.scroll(to: NSPoint(x: 0, y: edge)); scroll.reflectScrolledClipView(scroll.contentView)
                RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            }
            host.displayIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png")); window.contentView = nil
            print(name + ": rendered synthetic portable scope; frame=\(host.frame); fitting=\(host.fittingSize)")
        }
        let combinedScope = PortableSetup(defaults: portableDefaults, fcm: portableProvider, cloudflare: scope,
            pushClient: portableClient, appPreferences: portablePreferences).preview
        for (label, state, bottom) in [
            ("ready", SetupFileImportSnapshot.ready, false),
            ("ready-bottom", .ready, true),
            ("running", .importing, true),
            ("cleanup", .cleanup, true),
            ("unresolved", .reconciliation, true),
            ("completed", .completed, true),
            ("unavailable", .unavailable, true),
            ("refused-tunnel", .rejectedTunnel, false),
            ("refused-access", .rejectedAccess, false),
            ("refused-dns", .rejectedDNS, false),
            ("refused-dns-storage", .rejectedDNS, true),
            ("refused-details-unavailable", .refusalDetailsUnavailable, false),
        ] {
            for dark in [false, true] {
                let name = "setup-import-" + label + (dark ? "-dark" : "-light")
                let view = SetupFilePreview(snapshotPreview: combinedScope, importState: state, acceptedCustody: label != "refused-dns-storage")
                app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
                host.appearance = app.appearance; host.frame = NSRect(x: 0, y: 0, width: 540, height: 640)
                let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
                window.contentView = host; host.layoutSubtreeIfNeeded()
                RunLoop.current.run(until: Date().addingTimeInterval(0.2))
                if bottom {
                    func importScroll(_ view: NSView) -> NSScrollView? {
                        if let scroll = view as? NSScrollView { return scroll }
                        for child in view.subviews { if let scroll = importScroll(child) { return scroll } }
                        return nil
                    }
                    if let scroll = importScroll(host), let document = scroll.documentView {
                        let edge = document.isFlipped ? max(0, document.bounds.height - scroll.contentView.bounds.height) : 0
                        scroll.contentView.scroll(to: NSPoint(x: 0, y: edge)); scroll.reflectScrolledClipView(scroll.contentView)
                    }
                }
                host.displayIfNeeded()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
                try png.write(to: output.appendingPathComponent(name + ".png")); window.contentView = nil
                print(name + ": rendered inert import state")
            }
        }
        func gatewayProgress(stage: Int) throws -> SetupGatewayActivationProgress {
            let id = Data(repeating: 1, count: 16), digest = Data(repeating: 2, count: 32)
            let setup = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-setup-progress"),
                2: .bytes(id), 3: .bytes(id), 4: .bytes(id), 5: .bytes(id), 6: .unsigned(501), 7: .bytes(id),
                8: .bytes(digest), 9: stage > 0 ? .bytes(id) : .null,
                10: stage > 0 ? .bytes(digest) : .null, 11: .boolean(stage > 1)]), limits: .init(maxBytes: 640, maxDepth: 1, maxItems: 25))
            let settings = try GatewayRuntimeActivationSettings()
            let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-activation-progress"),
                2: .bytes(setup), 3: stage > 2 ? .bytes(digest) : .null,
                4: stage > 2 ? .bytes(settings.bytes) : .null, 5: .boolean(stage > 2), 6: .boolean(stage > 2)]), limits: .init(maxBytes: 1280, maxDepth: 1, maxItems: 15))
            return try .decode(bytes)
        }
        for (name, stage, loaded, notice) in [
            ("push-empty-light", -1, true, Optional<MacGatewaySetupNotice>.none),
            ("push-provider-light", 0, true, nil),
            ("push-advanced-light", 0, true, nil),
            ("push-journal-light", 1, true, nil),
            ("push-activate-light", 2, true, nil),
            ("push-registered-light", 3, true, nil),
            ("push-registered-dark", 3, true, nil),
            ("push-uncertain-light", 1, false, .operationFailed),
        ] {
            let dark = name.hasSuffix("dark"), progress = stage < 0 ? nil : try gatewayProgress(stage: stage)
            let view = GatewaySetupContent(progress: progress, loaded: loaded, operation: nil, notice: notice,
                cleanupComplete: nil, form: .constant(GatewaySetupForm()), project: nil, importFailed: false, canPrepare: false,
                onImport: {}, onRefresh: {}, onPrepare: {}, onJournal: {}, onActivate: {}, onClose: {}, advanced: name == "push-advanced-light")
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = app.appearance; host.frame = NSRect(x: 0, y: 0, width: 560, height: stage == 0 ? 640 : 520)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host; host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.5))
            host.displayIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png")); window.contentView = nil
            print(name + ": rendered synthetic push setup state; frame=\(host.frame); fitting=\(host.fittingSize); layout=\(window.contentLayoutRect)")
        }
        let originalSelection = try GatewayRuntimeSettingsSelection(service: .init(delivery: defaults.delivery,
            probe: .init(maximumAttempts: 2, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 30), wake: defaults.wake),
            activation: .init())
        let changedSelection = try GatewayRuntimeSettingsSelection(service: originalSelection.service,
            activation: .init(wakePollMilliseconds: 2500, wakeTimeoutMilliseconds: 5000))
        let savedActivation = try gatewayProgress(stage: 3)
        func settingsProgress(pending: Bool, supported: Bool = true) throws -> SetupGatewaySettingsProgress {
            let id = Data(repeating: 1, count: 16), digest = Data(repeating: 2, count: 32)
            let revision = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-settings-revision"),
                2: .bytes(Data(repeating: 3, count: 16)), 3: .bytes(id), 4: .bytes(digest), 5: .unsigned(1),
                6: .bytes(digest), 7: .bytes(changedSelection.bytes), 8: .bytes(digest), 9: .bytes(digest)]),
                limits: .init(maxBytes: 32768, maxDepth: 1, maxItems: 21))
            return try .decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-settings-progress"),
                2: .bytes(savedActivation.bytes), 3: .null, 4: pending ? .bytes(revision) : .null,
                5: pending ? .unsigned(0) : .null, 6: .bytes(originalSelection.bytes), 7: .boolean(supported)]),
                limits: .init(maxBytes: SetupGatewaySettingsProgress.maximumByteCount, maxDepth: 1, maxItems: 17)))
        }
        for (name, pending, changed, width, height) in [
            ("push-settings-saved-light", false, false, 560.0, 680.0),
            ("push-settings-saved-dark", false, false, 560.0, 680.0),
            ("push-settings-changed-light", false, true, 560.0, 680.0),
            ("push-settings-pending-light", true, true, 560.0, 680.0),
            ("push-settings-limits-light", false, false, 560.0, 760.0),
            ("push-settings-narrow-light", true, true, 500.0, 680.0),
            ("push-settings-legacy-light", false, false, 560.0, 740.0),
            ("push-settings-legacy-limits-light", false, false, 560.0, 760.0),
        ] {
            var form = GatewaySetupForm(); form.selectRetained(changed ? changedSelection : originalSelection)
            let dark = name.hasSuffix("dark"), progress = try settingsProgress(pending: pending, supported: !name.contains("legacy"))
            let view = GatewaySetupContent(progress: savedActivation, loaded: true, operation: nil, notice: nil,
                cleanupComplete: nil, form: .constant(form), project: nil, importFailed: false, canPrepare: false,
                onImport: {}, onRefresh: {}, onPrepare: {}, onJournal: {}, onActivate: {}, onClose: {},
                settingsProgress: progress, advanced: name.contains("limits"), wakeLimitsExpanded: name.contains("limits"))
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = app.appearance; host.frame = NSRect(x: 0, y: 0, width: width, height: height)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host; host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.5))
            if name.contains("limits") {
                func findScroll(_ view: NSView) -> NSScrollView? {
                    if let scroll = view as? NSScrollView { return scroll }
                    for child in view.subviews { if let scroll = findScroll(child) { return scroll } }
                    return nil
                }
                if let scroll = findScroll(host), let document = scroll.documentView {
                    let bottom = max(0, document.bounds.height - scroll.contentView.bounds.height)
                    scroll.contentView.scroll(to: NSPoint(x: 0, y: bottom)); scroll.reflectScrolledClipView(scroll.contentView)
                    RunLoop.current.run(until: Date().addingTimeInterval(0.2))
                    print(name + ": scrolled actual native content to the wake limits")
                }
            }
            host.displayIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png")); window.contentView = nil
            print(name + ": rendered synthetic settings state; frame=\(host.frame); fitting=\(host.fittingSize)")
        }
        for (name, phase, dark) in [
            ("pairing-waiting-light", MacPairingSessionPhase.waitingForPhone, false),
            ("pairing-code-light", MacPairingSessionPhase.comparing, false),
            ("pairing-code-dark", MacPairingSessionPhase.comparing, true),
            ("pairing-expired-light", MacPairingSessionPhase.expired, false),
            ("pairing-lost-receipt-light", MacPairingSessionPhase.registeredOnMac, false),
        ] {
            var state = PairingPresentation()
            state.phase = phase
            state.invitationText = try PairingInvitation(macID: Data(repeating: 1, count: 16),
                accountID: Data(repeating: 2, count: 16), label: "Synthetic Mac",
                authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                minimumEnvelopeVersion: 1).exportText()
            state.comparisonCode = "37MRQ S9XSE 3EMYL 7QA8F"
            state.remainingSeconds = 42
            state.phones = [.init(id: Data(repeating: 1, count: 16), suffix: "C4D8E012")]
            let view = PairingSheetContent(state: state, working: false, onSelect: { _ in }, onConfirm: {}, onClose: {})
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = app.appearance
            host.frame = NSRect(x: 0, y: 0, width: 540, height: 620)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png"))
            window.contentView = nil
            print(name + ": rendered synthetic pairing state")
        }
    }
}

#else
@main
struct RenderSetupPreviewUnavailable {
    static func main() { fatalError("Synthetic snapshots require a Debug build") }
}
#endif
