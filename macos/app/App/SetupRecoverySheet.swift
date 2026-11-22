import RemozioCore
import SwiftUI

struct SetupRecoverySheet: View {
    @Environment(\.dismiss) private var dismiss
    let controls: MacSetupRecoveryControls
    @State private var confirming = false
    @State private var selected: MacSetupRecoveryControls.Selection?

    var body: some View {
        SetupRecoveryContent(status: controls.statusSummary, attempt: controls.attemptSummary,
            canRestore: controls.selection != nil, canCheckProgress: controls.canCheckProgress,
            canStopTracking: controls.canStopTracking,
            onRefresh: { Task { await controls.refresh() } }, onRestore: confirmRestore,
            onProgress: { Task { await controls.readProgress() } },
            onStopTracking: { Task { await controls.endTracking() } }, onClose: { dismiss() })
        .task { if controls.statusSummary == .unread { await controls.refresh() } }
        .onChange(of: controls.selection) { _, current in
            if confirming, current != selected { confirming = false }
        }
        .alert("Restore saved setup?", isPresented: $confirming, presenting: selected) { target in
            Button("Cancel", role: .cancel) {}.keyboardShortcut(.defaultAction)
            Button("Restore saved setup", role: .destructive) { Task { await controls.begin(target) } }
        } message: { _ in
            Text("Restore uses this Mac’s saved setup. macOS asks for administrator approval before the request is sent.")
        }
    }

    private func confirmRestore() {
        guard let selection = controls.selection else { return }
        selected = selection
        confirming = true
    }
}

/// Redacted presentation shared with the synthetic snapshot renderer.
struct SetupRecoveryContent: View {
    let status: MacSetupRecoveryControls.StatusSummary
    let attempt: MacSetupRecoveryControls.AttemptSummary
    let canRestore: Bool
    let canCheckProgress: Bool
    let canStopTracking: Bool
    let onRefresh: () -> Void
    let onRestore: () -> Void
    let onProgress: () -> Void
    let onStopTracking: () -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Setup recovery").font(.title2).accessibilityAddTraits(.isHeader)
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    if status == .reading { ProgressView("Reading saved setup…") }
                    else { Text(statusText) }
                    if let result = attemptText {
                        Divider()
                        Text(result)
                    }
                    if canStopTracking {
                        Text("Stopping tracking closes this connection. It cannot undo the request.")
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Button("Refresh status", action: onRefresh).disabled(status == .reading || attempt == .submitting)
                if canCheckProgress { Button("Check recovery progress", action: onProgress) }
                if canStopTracking { Button("Stop tracking", action: onStopTracking) }
            }
            HStack {
                Spacer()
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                if canRestore { Button("Restore…", action: onRestore) }
            }
        }
        .padding(24)
        .frame(minWidth: 440, idealWidth: 500)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var statusText: LocalizedStringKey {
        switch status {
        case .unread, .reading: "Read the saved setup to check for recovery."
        case .unavailable: "Could not read saved setup. Refresh to try again."
        case .noSavedWork: "There is no saved setup that needs recovery."
        case .busy: "Setup is busy. Refresh after the current operation finishes."
        case .applicabilityUnavailable: "Remozio cannot confirm that Restore is available for this setup."
        case .noAction: "The saved setup currently offers no recovery action."
        case .restoreAvailable: "The saved setup is available for Restore."
        }
    }

    private var attemptText: LocalizedStringKey? {
        switch attempt {
        case .idle: nil
        case .authorizing: "Waiting for administrator approval…"
        case .submitting: "Sending the Restore request…"
        case .pending: "Setup recorded the request. Check recovery progress for the result."
        case .notSubmitted: "Remozio did not send the Restore request. Refresh before trying again."
        case .unconfirmed: "Remozio could not confirm the result. The request may still be running."
        case .restored: "Setup reported that the saved setup was restored. Service health is still unconfirmed."
        case .refused: "Setup refused the Restore request. Refresh for the current status."
        case .repairRequired: "Setup reported that repair is required. Refresh for the current status."
        case .failed: "Setup reported that Restore did not finish. Refresh for the current status."
        }
    }
}
