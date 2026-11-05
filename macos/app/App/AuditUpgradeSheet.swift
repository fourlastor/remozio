import Foundation
import RemozioCore
import SwiftUI

struct AuditUpgradeSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var controls = MacAuditUpgradeControls()
    @State private var work: Task<Void, Never>?
    var body: some View {
        AuditUpgradeContent(progress: controls.progress, loaded: controls.loaded, activity: controls.activity,
            notice: controls.notice, canUpgrade: controls.canUpgrade,
            onRefresh: { run { await controls.refresh() } }, onUpgrade: { run { await controls.upgrade() } },
            onClose: { work?.cancel(); controls.close(); dismiss() })
        .task { await controls.refresh() }
        .onDisappear { work?.cancel(); controls.close() }
    }
    private func run(_ operation: @escaping @MainActor () async -> Void) {
        guard work == nil else { return }
        work = Task { await operation(); work = nil }
    }
}

/// Inert presentation also used by synthetic previews. Registration observations are not service health checks.
struct AuditUpgradeContent: View {
    let progress: SetupAuditUpgradeProgress?
    let loaded: Bool
    let activity: MacAuditUpgradeActivity?
    let notice: MacAuditUpgradeNotice?
    let canUpgrade: Bool
    let onRefresh: () -> Void
    let onUpgrade: () -> Void
    let onClose: () -> Void
    @State var detailsExpanded = false
    private var working: Bool { activity != nil }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Audit history setup").font(.title2).accessibilityAddTraits(.isHeader)
                    Text("Let paired phones read this account’s existing audit history.")
                        .foregroundStyle(.secondary)
                    GroupBox {
                        VStack(alignment: .leading, spacing: 10) {
                            if activity == .upgrading {
                                Label("Applying the audit upgrade…", systemImage: "arrow.triangle.2.circlepath").font(.headline)
                                Text("Closing this panel stops waiting. The upgrade may already have changed files. Refresh before trying again.")
                            } else if activity == .refreshing {
                                Text("Reading saved setup…").font(.headline)
                            } else if let progress {
                                Label(stageTitle(progress.stage), systemImage: stageIcon(progress.stage)).font(.headline)
                                Text(stageDetail(progress.stage))
                                if progress.stage == .registrationObserved {
                                    Text(progress.registrationObserved.isEmpty ?
                                        "No previously registered jobs required a restart." :
                                        "The selected service registrations were observed. This does not prove service or phone connectivity.")
                                }
                            } else if notice == .progressUnavailable {
                                Text("Audit upgrade status is unavailable.").font(.headline)
                                Text("Another audit upgrade may still be running. Refresh to check its saved progress.")
                            } else if loaded {
                                Text("Command approval setup is incomplete for this account.").font(.headline)
                                Text("Prepare command approvals first, then refresh here.")
                            } else {
                                Text("Saved setup is unavailable.").font(.headline)
                                Text("Refresh to read this account’s setup before making changes.")
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    }
                    if let notice { noticeText(notice).foregroundStyle(.secondary) }
                    if canUpgrade || activity == .upgrading {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("What changes").font(.headline)
                            Text("The upgrade updates the existing audit files and can briefly pause Remozio services. It preserves this account’s identity and settings.")
                            Text("Only services that were previously registered can restart. macOS asks for administrator approval before the attempt.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let progress {
                        DisclosureGroup("Account details", isExpanded: $detailsExpanded) {
                            VStack(alignment: .leading, spacing: 8) {
                                LabeledContent("Mac ID") { identifier(progress.runtime.macID) }
                                LabeledContent("Account ID") { identifier(progress.runtime.accountID) }
                                LabeledContent("Account UID", value: String(progress.runtime.ownerUID))
                            }.padding(.top, 8)
                        }
                    }
                }
            }
            Divider()
            HStack {
                Button("Refresh", action: onRefresh).disabled(working)
                Spacer()
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                Button(progress?.stage == .ready ? "Upgrade audit history…" : "Resume audit upgrade…", action: onUpgrade)
                    .disabled(!canUpgrade || working).keyboardShortcut(.defaultAction)
            }
        }.padding(24).frame(minWidth: 480, idealWidth: 560, maxWidth: 640, minHeight: 440, idealHeight: 560)
    }
    private func identifier(_ bytes: Data) -> some View {
        Text(bytes.map { String(format: "%02x", $0) }.joined())
            .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
    }
    private func noticeText(_ notice: MacAuditUpgradeNotice) -> Text {
        switch notice {
        case .invalidSettings: Text("Correct the setup waits in Settings, then refresh this panel.")
        case .refreshFailed: Text("Could not read saved setup. Check that this Remozio release and its setup service are available, then refresh.")
        case .progressUnavailable: Text("New changes stay disabled until a fresh read succeeds.")
        case .notSubmitted: Text("This attempt did not submit an upgrade. Refresh before trying again.")
        case .progressChanged: Text("Saved setup changed after your review. Refresh and review it before trying again.")
        case .outcomeUnknown: Text("The upgrade outcome is unknown. It may already have changed files. Refresh before deciding whether to resume.")
        }
    }
    private func stageTitle(_ stage: SetupAuditUpgradeProgress.Stage) -> LocalizedStringKey {
        switch stage {
        case .ready: "Ready for the audit upgrade"
        case .waitingForActivity: "Another Remozio operation is active"
        case .waitingForMachine: "Machine setup is busy"
        case .graphPrepared: "The audit upgrade is prepared"
        case .waitingForQuiescence: "Waiting for services to stop"
        case .filesChanging: "Audit files need recovery"
        case .filesVerified: "Audit files are verified"
        case .metadataCommitted, .readyToRestart: "The audit upgrade is saved"
        case .registrationObserved: "Registration checks finished"
        case .alreadyCurrent: "Audit history is already configured"
        }
    }
    private func stageDetail(_ stage: SetupAuditUpgradeProgress.Stage) -> LocalizedStringKey {
        switch stage {
        case .ready: "Command approvals are prepared for this account. Review the account details before upgrading."
        case .waitingForActivity, .waitingForMachine: "Nothing is queued. Resume when the other operation finishes."
        case .graphPrepared: "The saved upgrade can resume with the same account and settings."
        case .waitingForQuiescence: "The attempt could not obtain every required stop confirmation. Resume explicitly when the services can stop."
        case .filesChanging: "Some upgrade files may already have changed. Resume the saved upgrade instead of starting another setup."
        case .filesVerified: "The upgraded audit files have been checked. Resume to save the remaining setup."
        case .metadataCommitted, .readyToRestart: "The saved setup does not confirm that services restarted. Resume to check the services selected for restart."
        case .registrationObserved: "This is the result of the last explicit attempt. Refresh reads saved metadata and clears these observations."
        case .alreadyCurrent: "No audit upgrade is needed. Service and phone connectivity are checked separately."
        }
    }
    private func stageIcon(_ stage: SetupAuditUpgradeProgress.Stage) -> String {
        switch stage {
        case .registrationObserved, .alreadyCurrent: "checkmark.circle"
        case .waitingForActivity, .waitingForMachine, .waitingForQuiescence: "pause.circle"
        case .filesChanging: "exclamationmark.triangle"
        default: "list.bullet.rectangle"
        }
    }
}

struct AuditUpgradeSettingsSection: View {
    @AppStorage(MacAuditUpgradeSettings.readTimeoutKey) private var readTimeout = "60000"
    @AppStorage(MacAuditUpgradeSettings.operationTimeoutKey) private var operationTimeout = "60000"
    private var valid: Bool {
        (try? MacAuditUpgradeSettings(preferences: [MacAuditUpgradeSettings.readTimeoutKey: readTimeout,
            MacAuditUpgradeSettings.operationTimeoutKey: operationTimeout])) != nil
    }
    var body: some View {
        Section("Setup waits") {
            TextField("Setup read timeout (ms)", text: $readTimeout)
            TextField("Setup result timeout (ms)", text: $operationTimeout)
            Text("These waits apply to new audit maintenance requests. A timeout does not undo completed work. Refresh after an unknown result.")
                .foregroundStyle(.secondary)
            if !valid {
                Label("Use whole milliseconds: 1–60000 for reads and 1–300000 for setup results.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
            Button("Reset setup waits") { readTimeout = "60000"; operationTimeout = "60000" }
        }
    }
}
