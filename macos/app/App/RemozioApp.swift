import AppKit
import RemozioCore
import SwiftUI

@main
struct RemozioApp: App {
    @State private var presence = PresenceControls()
    @State private var login = MacLoginItemControls()
    @State private var setup = MacSetupServiceControls()
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true

    var body: some Scene {
        Window("Remozio", id: "main") {
            SetupOverview(presence: presence, setup: setup)
                .task { presence.start() }
        }
        .defaultSize(width: 600, height: 440)
        .windowResizability(.contentMinSize)

        MenuBarExtra("Remozio", systemImage: "hand.raised", isInserted: $showMenuBarExtra) {
            RemozioMenu(presence: presence)
                .task { presence.start() }
        }

        Settings {
            Form {
                Section {
                    Toggle("Show Remozio in the menu bar", isOn: $showMenuBarExtra)
                    Text("You can always open Remozio from the Dock or Applications.")
                        .foregroundStyle(.secondary)
                }
                LoginItemSettingsSection(controls: login)
                PresenceSettingsSection(controls: presence)
                CommandCallerSettingsForm()
            }
            .formStyle(.grouped)
            .frame(minWidth: 440, idealWidth: 500, minHeight: 240)
        }
    }
}

private struct CommandCallerSettingsForm: View {
    @AppStorage(CommandFrontendCallerSettings.modeKey) private var mode = "pty"
    @AppStorage(CommandFrontendCallerSettings.disconnectKey) private var disconnect = "terminate"
    @AppStorage(CommandFrontendCallerSettings.timeoutKey) private var timeout = "30000"
    @AppStorage(CommandFrontendCallerSettings.initialBackoffKey) private var initial = "250"
    @AppStorage(CommandFrontendCallerSettings.maximumBackoffKey) private var maximum = "2000"
    @AppStorage(CommandFrontendCallerSettings.controlTimeoutKey) private var control = "5000"
    @AppStorage(CommandFrontendCallerSettings.controlRetryKey) private var retry = "50"
    @AppStorage(CommandFrontendCallerSettings.foregroundRetryKey) private var foreground = "250"

    private var valid: Bool {
        do {
            _ = try CommandFrontendCallerSettings(preferences: [
                CommandFrontendCallerSettings.modeKey: mode, CommandFrontendCallerSettings.disconnectKey: disconnect,
                CommandFrontendCallerSettings.timeoutKey: timeout, CommandFrontendCallerSettings.initialBackoffKey: initial,
                CommandFrontendCallerSettings.maximumBackoffKey: maximum, CommandFrontendCallerSettings.controlTimeoutKey: control,
                CommandFrontendCallerSettings.controlRetryKey: retry, CommandFrontendCallerSettings.foregroundRetryKey: foreground],
                defaultIOMode: .pty, defaultDisconnectBehavior: .terminate,
                defaultReadiness: .init(timeoutMilliseconds: 30000))
            return true
        } catch { return false }
    }
    var body: some View {
        Section("Command caller") {
            Picker("Default command I/O", selection: $mode) {
                Text("Terminal (PTY)").tag("pty")
                Text("Pipes").tag("pipes")
            }
            Picker("If the caller disconnects", selection: $disconnect) {
                Text("Terminate the command").tag("terminate")
                Text("Let the command continue").tag("continue")
            }
            TextField("Readiness wait (ms)", text: $timeout)
            TextField("Initial connection backoff (ms)", text: $initial)
            TextField("Maximum connection backoff (ms)", text: $maximum)
            TextField("Control validation timeout (ms)", text: $control)
            TextField("Control retry interval (ms)", text: $retry)
            TextField("Foreground retry interval (ms)", text: $foreground)
            Text("These settings apply to new CLI invocations. They do not limit command runtime or change approval expiry.")
                .foregroundStyle(.secondary)
            if !valid {
                Label("Use positive whole milliseconds. Intervals must not exceed 60000, and maximum backoff must be at least initial backoff.",
                      systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
        }
    }
}

private struct SetupOverview: View {
    let presence: PresenceControls
    let setup: MacSetupServiceControls
    @State private var showingSetupPreview = false
    @State private var showingPairing = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Remozio").font(.largeTitle).accessibilityAddTraits(.isHeader)
                    Text("Approvals from your Macs, on your Android devices.")
                        .font(.title3).foregroundStyle(.secondary)
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label(presence.status != nil ? "This Mac’s authority is connected" : presence.configured ? "This Mac’s authority is unavailable" : "This Mac is not configured", systemImage: "macbook.and.iphone")
                            .font(.headline)
                        Divider()
                        SetupServiceSection(controls: setup)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                }
                HStack(spacing: 12) {
                    Button("Pair a phone…") { showingPairing = true }
                    Button("Preview setup file…") { showingSetupPreview = true }
                }
                HStack {
                    SettingsLink()
                    Spacer()
                    Text("Development build").font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(28)
            .frame(maxWidth: 720)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(minWidth: 440, minHeight: 340)
        .sheet(isPresented: $showingPairing) { PairingSheet() }
        .sheet(isPresented: $showingSetupPreview) { SetupFilePreview() }
    }
}

private struct RemozioMenu: View {
    @Environment(\.openWindow) private var openWindow
    let presence: PresenceControls

    var body: some View {
        Text(presence.headline)
        if presence.status != nil {
            Button("Automatic") { Task { await presence.setMode(.automatic) } }
                .disabled(presence.changing)
            Button("Present") { Task { await presence.setMode(.present) } }
                .disabled(presence.changing)
            Button("Away") { Task { await presence.setMode(.away) } }
                .disabled(presence.changing)
        }
        if let notice = presence.notice { Text(notice) }
        Divider()
        Button("Open Remozio") {
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
        SettingsLink()
        Divider()
        Button("Quit Remozio") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
    }
}

private struct LoginItemSettingsSection: View {
    @Environment(\.scenePhase) private var scenePhase
    let controls: MacLoginItemControls
    var body: some View {
        Section("Start at login") {
            Toggle("Open Remozio at login", isOn: Binding(
                get: { controls.state.registered },
                set: { enabled in Task { await controls.setEnabled(enabled) } }))
                .disabled(controls.changing)
            statusText.foregroundStyle(.secondary)
            if controls.changing { ProgressView("Updating login setting…") }
            if controls.state == .requiresApproval {
                Button("Open Login Items settings") { controls.openSettings() }
                    .disabled(controls.changing)
            }
            if controls.notice != nil {
                Label("Could not change the login setting. Review its current status and try again.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
            Button("Refresh login status") { controls.refresh() }
                .disabled(controls.changing)
        }
        .task { controls.refresh() }
        .onChange(of: scenePhase) { _, next in
            if next == .active { controls.refresh() }
        }
    }
    private var statusText: Text {
        switch controls.state {
        case .notRegistered: Text("Remozio will not open automatically at login.")
        case .enabled: Text("macOS allows Remozio to open at login.")
        case .requiresApproval: Text("Waiting for your approval in Login Items settings.")
        case .notFound: Text("macOS could not find the login item.")
        case .unknown: Text("Login status is unavailable. Refresh to try again.")
        }
    }
}

private struct SetupServiceSection: View {
    @Environment(\.scenePhase) private var scenePhase
    let controls: MacSetupServiceControls

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Mac setup service").font(.headline)
            statusText.foregroundStyle(.secondary)
            if let operation = controls.operation {
                switch operation {
                case .inspecting: ProgressView("Checking setup service…")
                case .registering: ProgressView("Enabling setup service…")
                }
            }
            HStack {
                if controls.state == .notRegistered {
                    Button("Enable setup service") { Task { await controls.enable() } }
                        .buttonStyle(.borderedProminent)
                }
                if controls.state == .requiresApproval {
                    Button("Approve in System Settings…") { controls.openSettings() }
                        .buttonStyle(.borderedProminent)
                }
                Button("Refresh setup status") { Task { await controls.refresh() } }
            }
            .disabled(controls.operation != nil)
            if let notice = controls.notice {
                switch notice {
                case .inspectionFailed:
                    Label("Could not check the setup service. Refresh to try again.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                case .registrationFailed:
                    Label("Could not finish enabling the setup service. Review its current status before trying again.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }
        }
        .task { await controls.refresh() }
        .onChange(of: scenePhase) { _, next in
            if next == .active { Task { await controls.refresh() } }
        }
    }
    private var statusText: Text {
        switch controls.state {
        case .requiresInstallation:
            Text("Install Remozio with its package, then open the installed app.")
        case .notRegistered:
            Text("Enable the setup service to continue setting up this Mac. macOS requires administrator approval.")
        case .requiresApproval:
            Text("Approve Remozio in Login Items & Extensions, then return here.")
        case .enabled:
            Text("macOS allows the setup service to run. Account setup is still being connected.")
        case .notFound:
            Text("macOS could not find the setup service. Reinstall Remozio with its package.")
        case .unavailable:
            Text("The setup service status is unavailable. Refresh to try again.")
        }
    }
}
