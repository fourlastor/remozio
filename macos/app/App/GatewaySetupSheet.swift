import AppKit
import RemozioCore
import SwiftUI
import UniformTypeIdentifiers

struct GatewaySetupSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var controls = MacGatewaySetupControls()
    @State private var form = GatewaySetupForm()
    @State private var provider: SetupFCMConfiguration?
    @State private var importing = false
    @State private var importFailed = false
    @State private var selection = GatewaySetupFormSelection()
    @State private var work: Task<Void, Never>?

    var body: some View {
        GatewaySetupContent(progress: controls.progress, loaded: controls.loaded, operation: controls.operation,
            notice: controls.notice, cleanupComplete: controls.lastJournalCleanupComplete, form: $form,
            project: provider?.project, importFailed: importFailed, canPrepare: provider.flatMap { try? form.choices(provider: $0) } != nil,
            onImport: { importing = true }, onRefresh: { run { await controls.refresh() } },
            onPrepare: {
                guard let provider, let choices = try? form.choices(provider: provider) else { return }
                run { await controls.prepare(choices) }
            }, onJournal: { run { await controls.initializeJournal() } },
            onActivate: {
                let settings = controls.settingsProgress == nil ? try? form.activationSettings() : controls.progress?.settings
                guard let settings else { return }
                run { await controls.activate(settings: settings) }
            }, onClose: { work?.cancel(); provider = nil; dismiss() }, settingsProgress: controls.settingsProgress,
            onApplySettings: {
                guard let selection = try? form.settingsSelection() else { return }
                run { await controls.applySettings(selection) }
            })
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            do {
                let url = try result.get(), scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let input = try FileHandle(forReadingFrom: url); defer { try? input.close() }
                let data = try input.read(upToCount: 65537) ?? Data()
                provider = try SetupFCMConfiguration(serviceAccountJSON: data); importFailed = false
            } catch CocoaError.userCancelled { }
            catch { importFailed = true }
        }
        .task { await controls.refresh(); selectRetainedOnce() }
        .onChange(of: controls.progress?.settings) { _, _ in selectRetainedOnce() }
        .onChange(of: try? controls.settingsProgress?.bytes) { _, _ in selectRetainedOnce() }
        .onChange(of: try? controls.initialSelection?.bytes) { _, _ in selectRetainedOnce() }
        .onDisappear { work?.cancel(); provider = nil }
    }
    private func selectRetainedOnce() {
        selection.update(form: &form, activation: controls.progress, settings: controls.settingsProgress, initial: controls.initialSelection)
    }
    private func run(_ operation: @escaping @MainActor () async -> Void) {
        guard work == nil else { return }
        work = Task { await operation(); work = nil }
    }
}

struct GatewaySetupContent: View {
    let progress: SetupGatewayActivationProgress?
    let loaded: Bool
    let operation: MacGatewaySetupOperation?
    let notice: MacGatewaySetupNotice?
    let cleanupComplete: Bool?
    @Binding var form: GatewaySetupForm
    let project: String?
    let importFailed: Bool
    let canPrepare: Bool
    let onImport: () -> Void
    let onRefresh: () -> Void
    let onPrepare: () -> Void
    let onJournal: () -> Void
    let onActivate: () -> Void
    let onClose: () -> Void
    var settingsProgress: SetupGatewaySettingsProgress? = nil
    var onApplySettings: () -> Void = {}
    @State var advanced = false
    @State var wakeLimitsExpanded = false
    private var working: Bool { operation != nil }
    private var editingLocked: Bool {
        working || settingsProgress.map { $0.stage != nil || !$0.supportsSettingsChanges } == true
    }
    private var validService: Bool { (try? form.serviceSettings()) != nil }
    private var activation: GatewayRuntimeActivationSettings? { try? form.activationSettings() }
    private var savedTimings: GatewayRuntimeActivationSettings? {
        if let settingsProgress { return try? settingsProgress.currentSelection.activation }
        return progress?.settings
    }
    private var retainedChanged: Bool { savedTimings != nil && savedTimings != activation }
    private var settingsChanged: Bool {
        guard let settingsProgress else { return false }
        return (try? form.settingsSelection().bytes) != (try? settingsProgress.currentSelection.bytes)
    }
    private var validSettings: Bool { (try? form.settingsSelection()) != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("Push notifications").font(.title2).accessibilityAddTraits(.isHeader)
                    Text("Let this Mac wake paired phones when an approval needs your attention.")
                        .foregroundStyle(.secondary)
                    if !loaded {
                        if working { ProgressView("Reading saved setup…") }
                        else { Text("Refresh to read this account’s saved setup before making changes.") }
                    } else if let progress {
                        savedProgress(progress)
                        if progress.setup.journalIntentDigest == nil {
                            providerFields
                            serviceFields
                        } else if let settingsProgress {
                            settingsFields(settingsProgress)
                        } else if progress.setup.journalInitialized {
                            activationFields
                        }
                    } else {
                        Label("Set up command approvals first", systemImage: "info.circle")
                        Text("Prepare the account and start its authority and transport services, then return here.")
                            .foregroundStyle(.secondary)
                    }
                    operationStatus
                    noticeStatus
                }
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 620)
            Divider()
            footer
        }
        .padding(24).frame(minWidth: 500, idealWidth: 560, maxWidth: 640)
    }
    private var footer: some View {
        ViewThatFits(in: .horizontal) {
            HStack {
                Button("Refresh", action: onRefresh).disabled(working)
                Spacer()
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                actionButton
            }
            VStack(alignment: .trailing, spacing: 12) {
                HStack {
                    Button("Refresh", action: onRefresh).disabled(working)
                    Spacer()
                    Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                }
                HStack { Spacer(); actionButton }
            }
        }
    }
    private func savedProgress(_ progress: SetupGatewayActivationProgress) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Saved setup").font(.headline)
            marker("Provider configuration prepared", complete: progress.setup.journalIntentDigest != nil)
            marker("Push storage prepared", complete: progress.setup.journalInitialized)
            marker("Service registration saved", complete: progress.jobRegistered)
            Text("These records show completed setup steps. They do not confirm that a service is running or a phone is reachable.")
                .font(.callout).foregroundStyle(.secondary)
            if cleanupComplete == false {
                Label("Push storage is ready, but temporary setup service cleanup needs another attempt.", systemImage: "exclamationmark.triangle")
                Button("Retry temporary service cleanup…", action: onJournal).disabled(working || !loaded)
            }
        }
    }
    private func marker(_ title: LocalizedStringKey, complete: Bool) -> some View {
        Label(title, systemImage: complete ? "checkmark.circle" : "circle")
    }
    private var providerFields: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Firebase project").font(.headline)
            VStack(alignment: .leading, spacing: 8) {
                Button(project == nil ? "Choose service account JSON…" : "Replace service account JSON…", action: onImport)
                if let project { LabeledContent("Project") { Text(verbatim: project).textSelection(.enabled) } }
            }
            if importFailed {
                Label(project == nil ? "Could not read the service account. Choose a valid Firebase JSON file." :
                    "Could not read that file. The previously selected project is still selected.", systemImage: "exclamationmark.triangle")
            }
            entry("Firebase sender ID", text: $form.senderID)
            entry("Android package name", text: $form.packageName)
            if project != nil, !form.senderID.isEmpty, form.fileWakeCustodyAccepted, validService, !canPrepare {
                Label("Check the sender ID and package name against the Android Firebase configuration.", systemImage: "exclamationmark.triangle")
            }
            Text("Use the sender ID and package name from your Android Firebase configuration. Import does not save the key or contact Firebase.")
                .font(.callout).foregroundStyle(.secondary)
            Text("Remozio stores the push provider key in a private service file. Access to that file can expose the key.")
                .foregroundStyle(.secondary)
            Toggle("I accept private file storage for the push provider key", isOn: $form.fileWakeCustodyAccepted)
        }.disabled(working)
    }
    private var serviceFields: some View {
        DisclosureGroup("Delivery limits and timings", isExpanded: $advanced) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Times use milliseconds unless the label says seconds. These limits never extend approval expiry.")
                    .font(.callout).foregroundStyle(.secondary)
                ForEach(GatewaySetupField.allCases.filter { ![.wakePoll, .wakeTimeout, .wakeConnections, .wakeOperations, .wakeChallenge].contains($0) }, id: \.self) { field in
                    entry(label(field), text: Binding(get: { form[field] }, set: { form[field] = $0 }))
                }
                if !validService {
                    Label("Use whole numbers within the supported limits. Pending entries must fit stored controls, and maximum backoff must cover base backoff.", systemImage: "exclamationmark.triangle")
                }
            }.padding(.top, 8)
        }.disabled(working)
    }
    private func settingsFields(_ progress: SetupGatewaySettingsProgress) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Saved service settings").font(.headline)
            if !progress.supportsSettingsChanges {
                Label("Live settings changes are unavailable for this account’s saved setup.", systemImage: "info.circle")
                Text("You can still restore the saved push service. Its identity and paired phones stay the same.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            if progress.stage != nil {
                Label("A settings change is pending. Resume it before starting another change.", systemImage: "arrow.clockwise")
            }
            activationFields
            serviceFields
            DisclosureGroup("Wake limits", isExpanded: $wakeLimitsExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach([GatewaySetupField.wakeConnections, .wakeOperations, .wakeChallenge], id: \.self) { field in
                        entry(label(field), text: Binding(get: { form[field] }, set: { form[field] = $0 }))
                    }
                }.padding(.top, 8)
            }
            if !validSettings { Text("Check the wake limits and service settings before applying this change.") }
            if settingsChanged, progress.stage == nil {
                Button("Use saved settings") { if let saved = try? progress.currentSelection { form.selectRetained(saved) } }.disabled(editingLocked)
            }
            Text("Applying settings pauses push delivery while the services switch. Refresh does not apply or resume a change.")
                .font(.callout).foregroundStyle(.secondary)
        }.disabled(working)
    }
    private var activationFields: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Wake timings").font(.headline)
            entry("Wake poll interval (ms)", text: Binding(get: { form[.wakePoll] }, set: { form[.wakePoll] = $0 }))
            entry("Wake request timeout (ms)", text: Binding(get: { form[.wakeTimeout] }, set: { form[.wakeTimeout] = $0 }))
            if activation == nil {
                Label("Use a poll interval from 100 to 60000 ms and a timeout from 1 to 60000 ms.", systemImage: "exclamationmark.triangle")
            }
            if retainedChanged && settingsProgress?.stage == nil {
                Text("These timings differ from the saved settings. Apply the change explicitly.")
                    .foregroundStyle(.secondary)
                if let settings = savedTimings {
                    Button("Use saved timings") { form.selectRetained(settings) }.disabled(editingLocked)
                }
            }
        }.disabled(working)
    }
    @ViewBuilder private var operationStatus: some View {
        if let operation {
            switch operation {
            case .refreshing: EmptyView()
            case .preparing: ProgressView("Preparing push configuration…")
            case .initializingJournal: ProgressView("Preparing push storage…")
            case .activating: ProgressView("Registering the push service…")
            case .applyingSettings: ProgressView("Applying saved service settings…")
            }
        }
    }
    @ViewBuilder private var noticeStatus: some View {
        if let notice {
            switch notice {
            case .refreshFailed: Label("Could not read setup. Refresh to try again.", systemImage: "exclamationmark.triangle")
            case .operationFailed: Label("Could not confirm the result. Refresh before trying another setup action.", systemImage: "exclamationmark.triangle")
            case .settingsTransitionRequired: Text("Use the saved timings or finish the pending settings change before restoring the service.")
            case .settingsUnavailable: Text("This account’s saved setup does not support live settings changes. You can restore the saved push service.")
            }
        }
    }
    @ViewBuilder private var actionButton: some View {
        if loaded, let progress {
            if progress.setup.journalIntentDigest == nil {
                Button("Prepare configuration…", action: onPrepare)
                    .disabled(working || !canPrepare)
            } else if !progress.setup.journalInitialized {
                Button("Prepare push storage…", action: onJournal).disabled(working)
            } else if let settingsProgress {
                Button("Restore push service…", action: onActivate).disabled(working || settingsProgress.stage != nil)
                Button(settingsProgress.stage == nil ? "Apply settings…" : "Resume settings change…", action: onApplySettings)
                    .disabled(working || !settingsProgress.supportsSettingsChanges || !validSettings || (settingsProgress.stage == nil && !settingsChanged))
            } else {
                Button(progress.jobRegistered ? "Restore push service…" : "Start push service…", action: onActivate)
                    .disabled(working || activation == nil || retainedChanged)
            }
        }
    }
    private func entry(_ title: LocalizedStringKey, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.callout)
            TextField(title, text: text).labelsHidden().disabled(editingLocked)
        }
    }
    private func label(_ field: GatewaySetupField) -> LocalizedStringKey {
        switch field {
        case .wakeConnections: "Concurrent wake connections"
        case .wakeOperations: "Concurrent wake operations"
        case .wakeChallenge: "Wake challenge lifetime (ms)"
        case .operations: "Concurrent control operations"
        case .handshake: "Handshake timeout (ms)"
        case .authorityLease: "Authority lease (ms)"
        case .providerTimeout: "Provider timeout (seconds)"
        case .schedulerRetry: "Scheduler retry interval (ms)"
        case .storedControls: "Stored control limit"
        case .pendingPerEnrollment: "Pending controls per phone"
        case .candidateLifetime: "Token candidate lifetime (ms)"
        case .databaseBusy: "Database busy timeout (ms)"
        case .deliveryFlights: "Concurrent provider requests"
        case .sendInterval: "Minimum send interval (ms)"
        case .retryBase: "Base retry backoff (ms)"
        case .retryMaximum: "Maximum retry backoff (ms)"
        case .probeAttempts: "Token probe attempt limit"
        case .probeDelay: "Token probe retry delay (ms)"
        case .probeTTL: "Token probe TTL (seconds)"
        case .wakeEntries: "Queued approval wake limit"
        case .wakeAttempts: "Approval wake attempt limit"
        case .enrollmentInterval: "Minimum wake interval per phone (ms)"
        case .wakeLifetime: "Approval wake lifetime (ms)"
        case .wakeTTL: "Approval wake TTL (seconds)"
        case .wakePoll: "Wake poll interval (ms)"
        case .wakeTimeout: "Wake request timeout (ms)"
        }
    }
}

struct GatewaySettingsSection: View {
    @State private var showingSetup = false
    var body: some View {
        Section("Push notifications") {
            Text("Each Mac uses your Firebase project to wake paired Android devices. Push delivery is optional and requires explicit setup.")
                .foregroundStyle(.secondary)
            Button("Set up push notifications…") { showingSetup = true }
        }.sheet(isPresented: $showingSetup) { GatewaySetupSheet() }
    }
}
