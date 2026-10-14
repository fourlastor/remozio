import AppKit
import CoreImage.CIFilterBuiltins
import Darwin
import Foundation
import Observation
import RemozioCore
import SwiftUI

struct PairingPhoneRow: Identifiable {
    let id: Data
    let suffix: String
}
struct PairingPresentation {
    var phase: MacPairingSessionPhase = .idle
    var invitationText: String?
    var phones: [PairingPhoneRow] = []
    var comparisonCode: String?
    var remainingSeconds: UInt64?
    var notice: String?
    init() {}
    init(_ snapshot: MacPairingSessionSnapshot) {
        phase = snapshot.phase; invitationText = try? snapshot.invitation?.exportText()
        phones = snapshot.candidates.filter { $0.phase == .proposed }.map {
            .init(id: $0.id, suffix: $0.proposal.phone.scope.phoneID.suffix(4).map { String(format: "%02X", $0) }.joined())
        }
        comparisonCode = snapshot.comparisonCode
        remainingSeconds = snapshot.remainingMilliseconds.map { ($0 + 999) / 1000 }
    }
}

@MainActor @Observable
final class MacPairingControls {
    private(set) var presentation = PairingPresentation()
    private(set) var working = false
    private(set) var closing = false
    @ObservationIgnored private var session: MacPairingSession?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var cleanup: Task<Void, Never>?
    @ObservationIgnored private var polling: Task<MacPairingSessionSnapshot, Error>?
    deinit { polling?.cancel(); for job in jobs.values { job.cancel() }; session?.abort() }

    func start() {
        guard session == nil, !closing else { return }
        presentation = PairingPresentation(); presentation.phase = .connecting
        let id = UUID(); generation = id
        do {
            let base = "/Library/Application Support/Remozio/"
            let root = try AuthorityPresenceClientConfiguration.load(path: base + "presence-client-\(getuid()).cbor")
            let transport = try TransportPairingControlConfiguration.load(path: base + "pairing-client-\(getuid()).cbor")
            let next = try MacPairingSession(rootConfiguration: root, transportConfiguration: transport)
            session = next
            launch { [weak self] in
                do {
                    let value = try await next.start(label: String(localized: "This Mac"))
                    self?.accept(value, id: id)
                    while !Task.isCancelled {
                        if self?.working == true {
                            try await Task.sleep(for: .milliseconds(500))
                            continue
                        }
                        let refresh = Task { try await next.current() }
                        self?.polling = refresh
                        let current: MacPairingSessionSnapshot
                        do {
                            current = try await withTaskCancellationHandler(operation: { try await refresh.value },
                                onCancel: { refresh.cancel() })
                        } catch {
                            self?.polling = nil
                            throw error
                        }
                        self?.polling = nil
                        self?.accept(current, id: id)
                        if current.phase == .waitingForBiometric, current.phoneProofAvailable, self?.working == false {
                            self?.working = true
                            do { self?.accept(try await next.commit(), id: id) }
                            catch { self?.accept(await next.snapshot(), id: id) }
                            self?.working = false
                            return
                        }
                        if [.receiptSent, .registeredOnMac, .expired, .unavailable, .outcomeUnknown, .closed].contains(current.phase) { return }
                        try await Task.sleep(for: .milliseconds(500))
                    }
                } catch {
                    self?.accept(await next.snapshot(), id: id)
                }
            }
        } catch {
            presentation.phase = .unavailable
            presentation.notice = String(localized: "Set up this Mac’s protected services before pairing a phone.")
        }
    }
    func select(_ candidate: Data) {
        guard let session, let id = generation, !working else { return }; working = true
        let refresh = polling
        launch { [weak self] in
            _ = try? await refresh?.value
            guard !Task.isCancelled, self?.generation == id else { return }
            self?.presentation.phase = .authorizing
            do { self?.accept(try await session.select(candidateID: candidate), id: id) }
            catch {
                self?.accept(await session.snapshot(), id: id)
                if case SetupAdministratorAuthorizationError.cancelled = error {
                    self?.presentation.notice = String(localized: "Authorization was cancelled. You can choose the phone again.")
                }
            }
            self?.working = false
        }
    }
    func confirm() {
        guard let session, let id = generation, !working else { return }; working = true
        let refresh = polling
        launch { [weak self] in
            _ = try? await refresh?.value
            guard !Task.isCancelled, self?.generation == id else { return }
            do { self?.accept(try await session.confirmComparison(), id: id) }
            catch { self?.accept(await session.snapshot(), id: id) }
            self?.working = false
        }
    }
    func stop() {
        guard !closing else { return }
        generation = nil; session?.abort(); closing = true
        let owned = Array(jobs.values), session = session, refresh = polling
        refresh?.cancel()
        for job in owned { job.cancel() }
        cleanup = Task { [weak self] in
            await session?.close()
            _ = try? await refresh?.value
            for job in owned { await job.value }
            guard let self else { return }
            self.session = nil; self.polling = nil; self.jobs.removeAll(); self.working = false; self.closing = false; self.cleanup = nil
        }
    }
    private func accept(_ snapshot: MacPairingSessionSnapshot, id: UUID) {
        guard generation == id else { return }; presentation = PairingPresentation(snapshot)
    }
    private func launch(_ operation: @escaping @MainActor @Sendable () async -> Void) {
        let id = UUID(), job = Task { await operation() }; jobs[id] = job
        Task { [weak self] in await job.value; self?.jobs[id] = nil }
    }
}

struct PairingSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var controls = MacPairingControls()
    var body: some View {
        PairingSheetContent(state: controls.presentation, working: controls.working,
            onSelect: controls.select, onConfirm: controls.confirm, onClose: { controls.stop(); dismiss() })
            .task { controls.start() }
            .onDisappear { controls.stop() }
    }
}
struct PairingSheetContent: View {
    let state: PairingPresentation
    let working: Bool
    let onSelect: (Data) -> Void
    let onConfirm: () -> Void
    let onClose: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Pair a phone").font(.title2).accessibilityAddTraits(.isHeader)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    content
                    if let notice = state.notice {
                        Text(notice).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Spacer()
                Button(isFinished ? String(localized: "Close") : String(localized: "Cancel"), action: onClose).keyboardShortcut(.cancelAction)
                if state.phase == .comparing {
                    Button("The codes match", action: onConfirm).buttonStyle(.borderedProminent).disabled(working)
                }
            }
        }
        .padding(24).frame(minWidth: 440, idealWidth: 520, maxWidth: 600, minHeight: 460, idealHeight: 620)
    }
    private var isFinished: Bool { [.receiptSent, .registeredOnMac, .outcomeUnknown, .expired, .unavailable, .closed].contains(state.phase) }
    @ViewBuilder private var content: some View {
        switch state.phase {
        case .idle, .connecting:
            ProgressView("Connecting to this Mac’s services…")
        case .waitingForPhone:
            Text("Open Remozio on your phone and choose Pair a Mac.").font(.headline)
            Text("Keep the phone and Mac on the same network for this setup.").foregroundStyle(.primary)
            if let text = state.invitationText {
                if let image = qr(text) {
                    HStack { Spacer(); Image(nsImage: image).interpolation(.none).resizable().scaledToFit().frame(width: 220, height: 220).padding(16).background(.white, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel(Text("Pairing invitation for this Mac")); Spacer() }
                }
                Button("Copy pairing text") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
                Text("Use the copied text if you cannot scan this screen.").font(.callout).foregroundStyle(.primary)
            }
            ForEach(state.phones) { phone in
                Button { onSelect(phone.id) } label: { HStack { Image(systemName: "iphone"); Text("Pair phone \(phone.suffix)"); Spacer(); Image(systemName: "chevron.right") } }
                    .disabled(working)
            }
            if state.phones.isEmpty { Text("Waiting for your phone…").foregroundStyle(.primary) }
        case .authorizing:
            ProgressView("Waiting for macOS authorization…")
            Text("macOS verifies administrator access before this Mac can enroll the phone.").foregroundStyle(.primary)
        case .comparing, .waitingForBiometric:
            Text("Compare the code on both devices.").font(.headline)
            if let code = state.comparisonCode { Text(verbatim: code).font(.title.monospaced()).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
            Text("Confirm only if the code matches the Remozio setup screen you opened on your phone.")
            if let seconds = state.remainingSeconds { Text("Expires in \(seconds) seconds").font(.callout).foregroundStyle(.primary) }
            if state.phase == .waitingForBiometric { ProgressView("Confirm with biometrics on your phone…") }
        case .committing:
            ProgressView("Saving the enrollment on this Mac…")
        case .receiptSent:
            Label("Enrollment saved on this Mac", systemImage: "checkmark.circle").font(.headline)
            Text("The confirmation was sent to your phone. Check that the phone finishes setup before using approvals.")
        case .registeredOnMac:
            Label("Enrollment saved on this Mac", systemImage: "checkmark.circle").font(.headline)
            Text("The reply to your phone was lost. Keep its incomplete setup record. Receipt recovery is still being connected.")
        case .outcomeUnknown:
            Label("Check the phone before trying again", systemImage: "exclamationmark.triangle").font(.headline)
            Text("The Mac’s reply was lost. Enrollment may have been saved. Keep the phone’s incomplete setup record. Receipt recovery is still being connected.")
        case .expired:
            Text("This setup expired.").font(.headline)
            Text("Close this sheet and start pairing again. No new enrollment was confirmed here.")
        case .unavailable, .closed:
            Text("Pairing is unavailable.").font(.headline)
            Text("Check this Mac’s service setup, then close this sheet and try again.")
        }
    }
    private func qr(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(text.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 6, y: 6)),
              let image = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: image.width, height: image.height))
    }
}
