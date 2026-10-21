import RemozioCore
import SwiftUI
import UniformTypeIdentifiers

#if DEBUG
enum SetupFileImportSnapshot { case ready, importing, cleanup, reconciliation, completed, unavailable, rejectedTunnel, rejectedAccess, rejectedDNS, refusalDetailsUnavailable }
#endif

struct SetupFilePreview: View {
    @Environment(\.dismiss) private var dismiss
    @State private var choosingFile = false
    @State private var showingAccountPreparation = false
    @State private var file: URL?
    @State private var password = ""
    @State private var preview: SetupPreview?
    @State private var reviewed: ReviewedSetupFile?
    @State private var controls: MacPortableSetupImportControls?
    @State private var setup: MacSetupServiceControls
    @State private var runtimeCustody = false
    @State private var pushCustody = false
    @State private var relayCustody = false
    @State private var failure: LocalizedStringKey?
    @State private var paused: SetupPortableImportOperationResult.Status?
    @State private var completed = false
    @State private var verifiedCompletion: SetupPortableImportProgress?
    @State private var work: Task<Void, Never>?
    @FocusState private var passwordFocused: Bool
    private let accountPreparation: (@MainActor () -> AnyView)?
    #if DEBUG
    private var snapshot: SetupFileImportSnapshot?
    #endif

    init(setup: MacSetupServiceControls? = nil, accountPreparation: (@MainActor () -> AnyView)? = nil) {
        _setup = State(initialValue: setup ?? MacSetupServiceControls())
        self.accountPreparation = accountPreparation
    }
    #if DEBUG
    init(snapshotPreview: SetupPreview?, snapshotError: LocalizedStringKey? = nil,
         importState: SetupFileImportSnapshot = .ready, acceptedCustody: Bool = false) {
        _preview = State(initialValue: snapshotPreview); _failure = State(initialValue: snapshotError)
        _setup = State(initialValue: MacSetupServiceControls()); accountPreparation = nil
        snapshot = snapshotPreview == nil ? nil : importState
        _runtimeCustody = State(initialValue: acceptedCustody)
        _pushCustody = State(initialValue: acceptedCustody); _relayCustody = State(initialValue: acceptedCustody)
    }
    #endif
    private var isSnapshot: Bool {
        #if DEBUG
        snapshot != nil
        #else
        false
        #endif
    }
    private var busy: Bool {
        #if DEBUG
        if snapshot == .importing { return true }
        #endif
        return work != nil || controls?.working == true || setup.operation != nil
    }
    private var isComplete: Bool {
        #if DEBUG
        if snapshot == .completed { return true }
        #endif
        return completed
    }
    private var pausedStatus: SetupPortableImportOperationResult.Status? {
        #if DEBUG
        if snapshot == .cleanup { return .waitingForCleanup }
        if snapshot == .reconciliation { return .requiresReconciliation }
        if snapshot == .rejectedTunnel || snapshot == .rejectedAccess || snapshot == .rejectedDNS || snapshot == .refusalDetailsUnavailable { return .providerRejected }
        #endif
        if let records = controls?.recovery?.records {
            if records.contains(where: { $0.phase == .unknown || $0.phase == .dispatched }) { return .requiresReconciliation }
            if records.contains(where: { $0.phase == .rejected }) { return .providerRejected }
        }
        return paused
    }
    private var rejectedResource: SetupPortableImportRecovery.Resource? {
        #if DEBUG
        switch snapshot {
        case .rejectedTunnel: return .tunnel
        case .rejectedAccess: return .accessApplication
        case .rejectedDNS: return .dnsRecord
        default: break
        }
        #endif
        return controls?.recovery?.records.first(where: { $0.phase == .rejected })?.resource
    }
    private var refusal: SetupPortableImportRecovery.Refusal? {
        #if DEBUG
        switch snapshot {
        case .rejectedTunnel: return .rateLimited
        case .rejectedAccess: return .providerRejected
        case .rejectedDNS: return .unauthorized
        default: break
        }
        #endif
        guard let resource = rejectedResource else { return nil }
        return controls?.recovery?.rejectedRecord(for: resource)?.refusal
    }
    private var recoveryHostname: String? {
        #if DEBUG
        if snapshot == .rejectedTunnel || snapshot == .rejectedAccess || snapshot == .rejectedDNS {
            return "m-0123456789abcdef0123456789abcdef.a-long-test-label.for-synthetic-recovery.remozio.example.invalid"
        }
        #endif
        return controls?.recovery?.relayScope?.hostname
    }
    private var canRetry: Bool {
        guard !busy, !isComplete, rejectedResource != nil, choices.satisfies(required) else { return false }
        return isSnapshot || (setup.state == .enabled && controls?.loaded == true && controls?.recovery != nil)
    }
    private var retryTitle: LocalizedStringKey {
        switch rejectedResource {
        case .tunnel: "Retry tunnel setup…"
        case .accessApplication: "Retry access setup…"
        case .dnsRecord: "Retry DNS setup…"
        case nil: "Retry setup…"
        }
    }
    private var required: Set<SetupPortableImportCustodyRequirement> {
        #if DEBUG
        if snapshot != nil {
            guard !isComplete, snapshot != .unavailable else { return [] }
            if snapshot == .cleanup || snapshot == .reconciliation || snapshot == .rejectedTunnel || snapshot == .rejectedAccess || snapshot == .rejectedDNS || snapshot == .refusalDetailsUnavailable {
                return preview?.cloudflareAccount == nil ? [] : [.relayCredential]
            }
            var result: Set<SetupPortableImportCustodyRequirement> = [.runtimeFiles]
            if preview?.firebaseProject != nil { result.insert(.pushCredentials) }
            if preview?.cloudflareAccount != nil { result.insert(.relayCredential) }
            return result
        }
        #endif
        return controls?.requiredCustody ?? []
    }
    private var choices: SetupPortableImportCustodyChoices {
        .init(runtimeFiles: runtimeCustody, pushCredentials: pushCustody, relayCredential: relayCustody)
    }
    private var rootCompleted: Bool {
        verifiedCompletion != nil
    }
    private var canImport: Bool {
        guard !busy, !isComplete, pausedStatus != .requiresReconciliation, pausedStatus != .providerRejected else { return false }
        if isSnapshot {
            #if DEBUG
            if snapshot == .unavailable { return false }
            #endif
            return choices.satisfies(required)
        }
        if rootCompleted { return true }
        return setup.state == .enabled && controls?.loaded == true && controls?.progress != nil && choices.satisfies(required)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Import setup file").font(.title2).accessibilityAddTraits(.isHeader)
                Text("Review shared configuration exported from another Mac.")
                    .foregroundStyle(Color.primary.opacity(0.8))
            }
            if let preview {
                VStack(alignment: .leading, spacing: 12) {
                    importStatus
                    if let failure { errorLabel(failure) }
                    if !busy && !isComplete { Button("Refresh Mac status") { refreshMacStatus() } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        SetupScopePreview(preview: preview)
                        if !required.isEmpty && !isComplete { Divider(); custodyChoices }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 520)
            } else { fileForm }
            actions
        }
        .padding(24).frame(width: 540)
        .frame(minHeight: preview == nil ? 280 : 480, idealHeight: preview == nil ? 330 : 640, maxHeight: 760)
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            switch result {
            case let .success(url):
                releaseReview(); file = url; password = ""; failure = nil; passwordFocused = true
            case .failure: failure = "Could not open the file picker. Try choosing the file again."
            }
        }
        .sheet(isPresented: $showingAccountPreparation, onDismiss: refreshMacStatus) {
            if let accountPreparation { accountPreparation() }
        }
        .onDisappear { work?.cancel(); reviewed?.close(); controls?.close(); password = "" }
    }
    private var fileForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button("Choose file…") { choosingFile = true }.disabled(busy)
                if let file {
                    Text(verbatim: file.lastPathComponent).lineLimit(1).truncationMode(.middle).help(file.lastPathComponent)
                }
            }
            SecureField("Export password", text: $password).focused($passwordFocused)
                .disabled(file == nil || busy).onSubmit { startPreview() }
            if busy { ProgressView("Opening encrypted file…").controlSize(.small) }
            if let failure { errorLabel(failure) }
            Text("Reviewing the file does not apply settings or create resources.")
                .font(.callout).foregroundStyle(Color.primary.opacity(0.8))
        }
    }
    private var custodyChoices: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Storage on this Mac").font(.headline).accessibilityAddTraits(.isHeader)
            Text("These choices apply locally. The setup file cannot accept them for you.")
                .foregroundStyle(Color.primary.opacity(0.8))
            if required.contains(.runtimeFiles) {
                Toggle("Store this Mac’s transport key in a private file", isOn: $runtimeCustody)
                Text("The authority key stays in hardware.").font(.callout).foregroundStyle(Color.primary.opacity(0.8))
            }
            if required.contains(.pushCredentials) {
                Toggle("Store push credentials in protected files", isOn: $pushCustody)
            }
            if required.contains(.relayCredential) {
                Toggle("Store this Mac’s relay credential in a private file", isOn: $relayCustody)
            }
        }
        .fixedSize(horizontal: false, vertical: true).disabled(busy)
    }
    @ViewBuilder private var importStatus: some View {
        if isComplete {
            Label("Setup saved on this Mac", systemImage: "checkmark.circle").font(.headline)
            Text("Only the listed app preferences were applied. Phone pairing and live connection checks are separate.")
                .foregroundStyle(Color.primary.opacity(0.8))
        } else if busy {
            ProgressView(activityTitle).controlSize(.small)
            Text("Closing this sheet stops further steps. Completed changes stay saved for recovery.")
                .font(.callout).foregroundStyle(Color.primary.opacity(0.8))
        } else if let status = pausedStatus {
            switch status {
            case .waitingForCleanup:
                Label("Setup cleanup is pending", systemImage: "exclamationmark.triangle").font(.headline)
                Text("Continue import to check cleanup before another setup step.")
            case .requiresReconciliation:
                Label("A provider change needs review", systemImage: "exclamationmark.triangle").font(.headline)
                Text("The provider did not confirm a change. Remozio stopped without repeating it. Keep this file for recovery.")
                Text("Refreshing reads this Mac’s saved state. It does not resolve the provider change.")
                    .font(.callout).foregroundStyle(Color.primary.opacity(0.8))
            case .providerRejected:
                Label("The provider rejected a change", systemImage: "exclamationmark.triangle").font(.headline)
                if rejectedResource != nil {
                    switch refusal {
                    case .unauthorized: Text("Check the provisioning credential’s permissions before retrying.")
                    case .rateLimited: Text("The provider rate limit was reached. Wait before retrying.")
                    default: Text("Check the provider configuration before retrying.")
                    }
                    if let hostname = recoveryHostname {
                        Text(verbatim: hostname).textSelection(.enabled)
                    }
                    Text("Retry checks the provider state before preparing another attempt. Administrator approval is required.")
                        .font(.callout).foregroundStyle(Color.primary.opacity(0.8))
                    if !choices.satisfies(required) {
                        Text("Accept the storage choices below before retrying.")
                            .font(.callout).foregroundStyle(Color.primary.opacity(0.8))
                    }
                } else {
                    Text("Refresh this Mac’s status to read recovery details. Saved changes have not been removed.")
                }
            case .applied: EmptyView()
            }
        } else if isSnapshot {
            #if DEBUG
            if snapshot == .unavailable {
                Text("Prepare this account and its service accounts before importing the file.")
                Button("Prepare this account…") {}
            } else { Text("Review the storage choices, then import on this Mac.") }
            #endif
        } else if rootCompleted {
            Label("Mac setup is saved", systemImage: "checkmark.circle").font(.headline)
            Text("App preferences still need to be applied. Review the current settings, then try applying them again.")
            SettingsLink()
        } else if setup.state != .enabled {
            setupServiceStatus
        } else if let notice = controls?.notice {
            switch notice {
            case .refreshFailed:
                errorLabel("Could not read this Mac’s saved setup. Refresh its status to try again.")
            case .operationOutcomeUnknown:
                errorLabel("The last setup result could not be confirmed. Refresh this Mac’s status before continuing.")
            case .custodyRequired:
                Text("Accept the required storage choices before importing.")
            case .authorizationExpired:
                Text("Administrator approval expired. Refresh this Mac’s status before continuing.")
            case .differentSetupFile:
                errorLabel("This file does not match this Mac’s retained import. Reopen the matching setup file.")
            }
        } else if controls?.progress == nil {
            Text("Prepare this account and its service accounts before importing the file.")
            if accountPreparation != nil { Button("Prepare this account…") { showingAccountPreparation = true } }
        } else if controls?.loaded != true {
            Text("Refresh this Mac’s saved setup before continuing.")
        } else { Text("Review the storage choices, then import on this Mac.") }
    }
    @ViewBuilder private var setupServiceStatus: some View {
        switch setup.state {
        case .requiresInstallation, .notFound:
            Text("Install Remozio with its package, then open the installed app.")
        case .notRegistered:
            Text("Enable this Mac’s setup service before importing. macOS asks for administrator approval.")
            Button("Enable setup service") {
                run { await setup.enable(); await loadMacStatus() }
            }
        case .requiresApproval:
            Text("Approve Remozio in Login Items & Extensions, then refresh this Mac’s status.")
            Button("Approve in System Settings…") { setup.openSettings() }
        case .unavailable:
            Text("This Mac’s setup service status is unavailable. Refresh its status to try again.")
        case .enabled: EmptyView()
        }
    }
    private var activityTitle: LocalizedStringKey {
        #if DEBUG
        if snapshot == .importing { return "Preparing local services…" }
        #endif
        guard let activity = controls?.activity else { return "Checking this Mac…" }
        switch activity {
        case .refreshing: return "Reading saved setup…"
        case .applying(let action):
            switch action {
            case .retain: return "Saving reviewed configuration…"
            case .prepareRuntime, .prepareRelayPlan: return "Preparing local services…"
            case .activateRuntime: return "Starting local services…"
            case .prepareGateway, .activateGateway: return "Preparing push notifications…"
            case .createTunnel, .applyIngress, .prepareRunCredential, .createAccess, .createDNS, .publishConnector: return "Preparing this Mac’s relay…"
            case .prepareRefusedTunnelRetry, .prepareRefusedAccessRetry, .prepareRefusedDNSRetry: return "Checking provider state…"
            case .complete: return "Checking saved setup…"
            }
        }
    }
    private var importTitle: LocalizedStringKey {
        if rootCompleted { return "Apply app preferences" }
        if controls?.progress?.operationID != nil || pausedStatus == .waitingForCleanup { return "Continue import…" }
        return "Import…"
    }
    private var actions: some View {
        HStack {
            if preview != nil && !isComplete {
                Button("Choose another file…") { choosingFile = true }.disabled(busy)
            }
            Spacer()
            Button(isComplete ? LocalizedStringKey("Done") : LocalizedStringKey("Close")) { close() }
                .keyboardShortcut(isComplete ? .defaultAction : .cancelAction)
            if preview == nil {
                Button("Review") { startPreview() }.keyboardShortcut(.defaultAction)
                    .disabled(file == nil || password.isEmpty || busy)
            } else if !isComplete, let resource = rejectedResource {
                Button(retryTitle) { startImport(retrying: resource) }.keyboardShortcut(.defaultAction).disabled(!canRetry)
            } else if !isComplete {
                Button(importTitle) { startImport() }.keyboardShortcut(.defaultAction).disabled(!canImport)
            }
        }
    }
    private func errorLabel(_ message: LocalizedStringKey) -> some View {
        Label { Text(message).foregroundStyle(.primary) } icon: {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.red)
        }.fixedSize(horizontal: false, vertical: true)
    }
    private func run(_ operation: @escaping @MainActor () async -> Void) {
        guard work == nil, !isSnapshot else { return }
        work = Task { defer { work = nil }; await operation() }
    }
    private func startPreview() {
        guard let file, !password.isEmpty, !busy, !isSnapshot else { return }
        let enteredPassword = password; password = ""; failure = nil
        run {
            do {
                let value = try await SetupFilePreviewReader.shared.review(file: file, password: enteredPassword)
                guard !Task.isCancelled else { value.close(); return }
                reviewed = value; preview = value.preview
                controls = MacPortableSetupImportControls(reviewed: value)
                await loadMacStatus()
            } catch is CancellationError { return }
            catch {
                guard !Task.isCancelled else { return }
                if case SetupPreviewReadError.unreadable = error {
                    failure = "Could not read this file. Choose a local setup file and try again."
                } else { failure = "Could not open this setup file. Check the password and use a supported Remozio export." }
                passwordFocused = true
            }
        }
    }
    private func loadMacStatus() async {
        await setup.refresh()
        guard !Task.isCancelled, setup.state == .enabled else { return }
        await controls?.refresh()
        if controls?.loaded == true && controls?.recovery != nil { paused = nil }
    }
    private func refreshMacStatus() { run { await loadMacStatus() } }
    private func startImport(retrying resource: SetupPortableImportRecovery.Resource? = nil) {
        guard (resource == nil ? canImport : canRetry), !isSnapshot, let reviewed, let controls else { return }
        failure = nil; paused = nil
        if rootCompleted { applyPreferences(reviewed, controls: controls); return }
        do { _ = try preview?.appPreferences?.applicationValues(readExisting: { UserDefaults.standard.object(forKey: $0) }) }
        catch { failure = "The imported command caller settings conflict with this Mac’s settings. Review Settings, then try again."; return }
        run {
            if let resource { await controls.retryImport(resource: resource, custody: choices) }
            else { await controls.importFile(custody: choices) }
            guard !Task.isCancelled else { return }
            if controls.lastResult?.action == .complete && controls.lastResult?.status == .applied {
                verifiedCompletion = controls.progress
                applyPreferences(reviewed, controls: controls)
            } else if let result = controls.lastResult { paused = result.status }
        }
    }
    private func applyPreferences(_ reviewed: ReviewedSetupFile, controls: MacPortableSetupImportControls) {
        guard let progress = verifiedCompletion else { return }
        do {
            let defaults = UserDefaults.standard
            let values = try reviewed.appPreferenceValues(completed: progress, readExisting: { defaults.object(forKey: $0) })
            for key in values.keys.sorted() { defaults.set(values[key], forKey: key) }
            completed = true; paused = nil; failure = nil; reviewed.close()
        } catch { failure = "Mac setup is saved, but app preferences could not be applied. Review Settings, then try again." }
    }
    private func releaseReview() {
        reviewed?.close(); controls?.close(); reviewed = nil; controls = nil; preview = nil
        paused = nil; completed = false; verifiedCompletion = nil; runtimeCustody = false; pushCustody = false; relayCustody = false
    }
    private func close() { work?.cancel(); reviewed?.close(); controls?.close(); password = ""; dismiss() }
}

struct SetupScopePreview: View {
    let preview: SetupPreview
    var body: some View {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Included configuration").font(.headline).accessibilityAddTraits(.isHeader)
                    Label("Presence and push defaults", systemImage: "slider.horizontal.3")
                    if preview.categories.contains(.gatewayOperationalDefaults) {
                        Label("Push service and wake settings", systemImage: "bell.badge")
                        Text("Includes saved push timings and limits.")
                            .foregroundStyle(Color.primary.opacity(0.8))
                    }
                    if preview.categories.contains(.appPreferences) {
                        Label("App and command caller preferences", systemImage: "gearshape")
                    }
                    if preview.categories.contains(.fcmCredentials) {
                        Label("Firebase push credentials", systemImage: "bell")
                    }
                    if preview.categories.contains(.cloudflareProvisioning) {
                        Label("Cloudflare provisioning credentials", systemImage: "network")
                    }
                }
                if let project = preview.firebaseProject {
                    scope("Firebase project", value: project)
                    if let client = preview.pushClient {
                        scope("Firebase sender ID", value: client.senderID)
                        scope("Android package name", value: client.packageName)
                    }
                }
                if let preferences = preview.appPreferences { appPreferences(preferences) }
                if let account = preview.cloudflareAccount {
                    VStack(alignment: .leading, spacing: 12) {
                        scope("Cloudflare account", value: account)
                        if let zone = preview.cloudflareZone { scope("DNS zone", value: zone) }
                        if let suffix = preview.dnsSuffix { scope("DNS suffix", value: suffix) }
                    }
                }
                if preview.firebaseProject != nil || preview.cloudflareAccount != nil {
                    Text("This file does not prove provider access. Credential values stay hidden.")
                        .foregroundStyle(Color.primary.opacity(0.8))
                }
                Text("Pairings, approval keys, audit history, and ADB grants are not included.")
                    .foregroundStyle(Color.primary.opacity(0.8))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
    }
    private func appPreferences(_ preferences: PortableAppPreferences) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("App preferences").font(.headline).accessibilityAddTraits(.isHeader)
            if let shown = preferences.menuBarVisible {
                LabeledContent("Menu bar") { Text(shown ? LocalizedStringKey("Shown") : LocalizedStringKey("Hidden")) }
            }
            if preferences.menuBarVisible == nil && preferences.commandOverrides.isEmpty {
                Text("No app preference overrides are included.").foregroundStyle(Color.primary.opacity(0.8))
            }
            ForEach(PortableAppPreferences.commandKeys.filter { preferences.commandOverrides[$0] != nil }, id: \.self) { key in
                if let value = preferences.commandOverrides[key] {
                    LabeledContent(appPreferenceTitle(key)) {
                        if key == CommandFrontendCallerSettings.modeKey {
                            Text(value == "pty" ? LocalizedStringKey("Terminal (PTY)") : LocalizedStringKey("Pipes"))
                        } else if key == CommandFrontendCallerSettings.disconnectKey {
                            Text(value == "terminate" ? LocalizedStringKey("Terminate the command") : LocalizedStringKey("Let the command continue"))
                        } else { Text(verbatim: value) }
                    }
                }
            }
            Text("Only listed app preferences are included. Unset values are absent.")
                .foregroundStyle(Color.primary.opacity(0.8)).fixedSize(horizontal: false, vertical: true)
            Text("Login registration and the current presence mode stay local.")
                .foregroundStyle(Color.primary.opacity(0.8)).fixedSize(horizontal: false, vertical: true)
        }
    }
    private func appPreferenceTitle(_ key: String) -> LocalizedStringKey {
        switch key {
        case CommandFrontendCallerSettings.modeKey: "Default command I/O"
        case CommandFrontendCallerSettings.disconnectKey: "If the caller disconnects"
        case CommandFrontendCallerSettings.timeoutKey: "Readiness wait (ms)"
        case CommandFrontendCallerSettings.initialBackoffKey: "Initial connection backoff (ms)"
        case CommandFrontendCallerSettings.maximumBackoffKey: "Maximum connection backoff (ms)"
        case CommandFrontendCallerSettings.controlTimeoutKey: "Control validation timeout (ms)"
        case CommandFrontendCallerSettings.controlRetryKey: "Control retry interval (ms)"
        case CommandFrontendCallerSettings.foregroundRetryKey: "Foreground retry interval (ms)"
        default: "Command caller setting"
        }
    }
    private func scope(_ title: LocalizedStringKey, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            Text(verbatim: value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
}
