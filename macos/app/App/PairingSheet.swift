import Accessibility
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
        phase = snapshot.phase
        invitationText = try? (snapshot.rePairInvitation?.exportText() ?? snapshot.invitation?.exportText())
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
    @ObservationIgnored private var rePairSheet: UUID?
    @ObservationIgnored private var predecessor: DeliveryRecipient?
    @ObservationIgnored private var unresolved = Set<DeliveryRecipient>()
    deinit { polling?.cancel(); for job in jobs.values { job.cancel() }; session?.abort() }

    func startRePair(_ selection: PairedPhoneSelection, sheet: UUID) async {
        if session != nil { stop() }
        rePairSheet = sheet
        await cleanup?.value
        guard !Task.isCancelled, rePairSheet == sheet else { return }
        start(predecessor: selection)
    }

    func stopRePair(sheet: UUID) {
        guard rePairSheet == sheet else { return }
        stop()
    }

    func start(predecessor selection: PairedPhoneSelection? = nil) {
        guard session == nil, !closing else { return }
        if let selection, unresolved.contains(selection.phone) {
            presentation = PairingPresentation()
            presentation.phase = .outcomeUnknown
            return
        }
        predecessor = selection?.phone
        presentation = PairingPresentation(); presentation.phase = .connecting
        let id = UUID(); generation = id
        do {
            let base = "/Library/Application Support/Remozio/"
            let root = try AuthorityPresenceClientConfiguration.load(path: base + "presence-client-\(getuid()).cbor")
            let transport = try TransportPairingControlConfiguration.load(path: base + "pairing-client-\(getuid()).cbor")
            let next = try MacPairingSession(rootConfiguration: root, transportConfiguration: transport,
                predecessor: selection)
            session = next
            launch { [weak self] in
                do {
                    let value = try await next.start(label: String(localized: "This Mac"))
                    self?.accept(value, id: id)
                    while !Task.isCancelled, self?.generation == id {
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
                        if current.phase == .waitingForBiometric, current.phoneProofAvailable,
                           self?.generation == id, self?.working == false {
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
        rePairSheet = nil
        guard !closing else { return }
        generation = nil; closing = true
        presentation = PairingPresentation()
        let owned = Array(jobs.values), session = session, refresh = polling, predecessor = predecessor
        if predecessor == nil {
            session?.abort()
            refresh?.cancel()
            for job in owned { job.cancel() }
        }
        cleanup = Task { [weak self] in
            if let predecessor, let session {
                if !(await session.closeForRePair()) { self?.unresolved.insert(predecessor) }
            } else {
                await session?.close()
            }
            _ = try? await refresh?.value
            for job in owned { await job.value }
            guard let self else { return }
            self.session = nil; self.predecessor = nil; self.polling = nil; self.jobs.removeAll()
            self.working = false; self.closing = false; self.cleanup = nil
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
struct RePairSheet: View {
    @Environment(\.dismiss) private var dismiss
    let controls: MacPairingControls
    let requestID: UUID
    let selection: PairedPhoneSelection
    let identifier: String

    var body: some View {
        PairingSheetContent(state: controls.presentation, working: controls.working,
            onSelect: controls.select, onConfirm: controls.confirm,
            onClose: { controls.stopRePair(sheet: requestID); dismiss() }, rePairIdentifier: identifier)
            .task { await controls.startRePair(selection, sheet: requestID) }
            .onDisappear { controls.stopRePair(sheet: requestID) }
    }
}

struct PairingSheetContent: View {
    let state: PairingPresentation
    let working: Bool
    let onSelect: (Data) -> Void
    let onConfirm: () -> Void
    let onClose: () -> Void
    var rePairIdentifier: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Group {
                if let rePairIdentifier { Text("Re-pair phone \(rePairIdentifier)") }
                else { Text("Pair a phone") }
            }.font(.title2).accessibilityAddTraits(.isHeader)
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
            Group {
                if rePairIdentifier != nil { Text("Open the retained Mac in Remozio on your phone and choose Re-pair.") }
                else { Text("Open Remozio on your phone and choose Pair a Mac.") }
            }.font(.headline)
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
                Button { onSelect(phone.id) } label: {
                    HStack {
                        Image(systemName: "iphone")
                        if let rePairIdentifier { Text("Re-pair phone \(rePairIdentifier)") }
                        else { Text("Pair phone \(phone.suffix)") }
                        Spacer()
                        Image(systemName: "chevron.right")
                    }
                }
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

extension AuthorityPairingChannel {
    static func forCurrentAccount() throws -> AuthorityPairingChannel {
        let path = "/Library/Application Support/Remozio/presence-client-\(getuid()).cbor"
        return try AuthorityPairingChannel(configuration: .load(path: path))
    }
}

struct GatewayRevocationWarning: View {
    let status: GatewayRevocationStatus

    var body: some View {
        if status.health != .clear {
            Label {
                message.fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            }
        }
    }

    private var message: Text {
        switch status.health {
        case .clear: return Text("")
        case .pending: return Text("Gateway changes are pending. Push delivery may pause.")
        case .blocked: return Text("Revocation delivery blocked. Push delivery may pause.")
        case .gatewayUpdateNeeded: return Text("Gateway update needed to finish the pending changes.")
        case .grantAbandonmentInconclusive:
            if let since = status.inconclusiveSinceUnixMillis {
                let started = min(Date(), Date(timeIntervalSince1970: Double(since) / 1000))
                return Text("Revocation delivery inconclusive for \(started, style: .timer).")
            } else {
                return Text("Revocation delivery inconclusive. The gateway has not confirmed the retired phone registration.")
            }
        case .pushDisabled: return Text("Push is disabled. The gateway revocation is pending.")
        case .registrationChanged: return Text("The gateway registration changed before it confirmed revocation.")
        case .waitingForGrantExpiry: return Text("The gateway is waiting for an earlier phone registration to expire.")
        }
    }
}

struct PairedPhonesSheet: View {
    private struct Confirmation {
        let selection: PairedPhoneSelection
        let identifier: String
    }

    private struct RePairRequest: Identifiable {
        let id = UUID()
        let selection: PairedPhoneSelection
        let identifier: String
    }

    private struct DiscardConfirmation {
        let record: ExpiredRePairRecord
        let identifier: String
    }

    let rePairControls: MacPairingControls
    @Environment(\.dismiss) private var dismiss
    @State private var rePairRequest: RePairRequest?
    @State private var channel: AuthorityPairingChannel?
    @State private var snapshot: PairedPhoneSnapshot?
    @State private var confirmation: Confirmation?
    @State private var expiredRePairs = MacExpiredRePairControls(openChannel: AuthorityPairingChannel.forCurrentAccount)
    @State private var discardConfirmation: DiscardConfirmation?
    @State private var showingDiscardConfirmation = false
    @State private var unconfirmed: PairedPhoneSelection?
    @State private var showingConfirmation = false
    @State private var busy = false
    @State private var notice: String?
    @State private var refreshError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Paired phones").font(.title2).accessibilityAddTraits(.isHeader)
            if let snapshot {
                switch snapshot.revocationAvailability {
                case .available: EmptyView()
                case .gatewayUnsupported: Text("You can revoke a phone on this Mac. The gateway may need an update to receive the revocation.")
                case .gatewayUnavailable: Text("You can revoke a phone on this Mac. Gateway delivery may be delayed.")
                }
                GatewayRevocationWarning(status: snapshot.gatewayRevocationStatus)
                if snapshot.phones.isEmpty && snapshot.rePairablePhones.isEmpty { Text("No phones are paired with this Mac.") }
                else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(snapshot.phones, id: \.self) { phone in
                                let id = displayID(phone, among: snapshot.phones)
                                HStack {
                                    Text("Phone \(id)")
                                    Spacer()
                                    Button("Revoke…") {
                                        guard let selection = snapshot.selection(for: phone) else { return }
                                        confirmation = Confirmation(selection: selection, identifier: id)
                                        showingConfirmation = true
                                    }
                                    .accessibilityLabel(Text("Revoke phone \(id)"))
                                    .disabled(busy)
                                }
                            }
                            if !snapshot.rePairablePhones.isEmpty { Text("Revoked phones").font(.headline) }
                            ForEach(snapshot.rePairablePhones, id: \.self) { phone in
                                let identifier = displayID(phone, among: snapshot.rePairablePhones)
                                let epoch = phone.enrollmentEpoch.suffix(4).map { String(format: "%02X", $0) }.joined()
                                HStack {
                                    VStack(alignment: .leading) {
                                        Text("Phone \(identifier)")
                                        Text("Enrollment \(epoch)").font(.caption)
                                    }
                                    Spacer()
                                    Button("Re-pair…") {
                                        guard let selection = snapshot.rePairSelection(for: phone) else { return }
                                        rePairRequest = RePairRequest(selection: selection, identifier: identifier)
                                    }
                                    .accessibilityLabel(Text("Re-pair phone \(identifier)"))
                                    .disabled(busy)
                                }
                            }
                        }
                    }
                    .frame(maxHeight: 260)
                }
            }
            expiredRePairSection
            if busy { ProgressView().controlSize(.small).accessibilityLabel("Checking paired phones") }
            if let notice { Text(notice).fixedSize(horizontal: false, vertical: true) }
            if let refreshError { Text(refreshError).fixedSize(horizontal: false, vertical: true) }
            HStack {
                if let unconfirmed {
                    Button("Check revocation status") { run { await reconcile(unconfirmed) } }
                        .disabled(busy)
                }
                Button("Refresh") { run { await refresh() } }
                    .disabled(busy)
                Spacer()
                Button("Done") { dismiss() }.disabled(busy)
            }
        }
        .frame(width: 420, alignment: .leading)
        .padding(24)
        .task {
            guard !busy else { return }
            busy = true
            await refresh()
            busy = false
        }
        .onDisappear {
            channel?.abort()
            expiredRePairs.cancel()
        }
        .sheet(item: $rePairRequest, onDismiss: { run { await refresh() } }) { request in
            RePairSheet(controls: rePairControls, requestID: request.id, selection: request.selection,
                identifier: request.identifier)
        }
        .alert("Revoke this phone?", isPresented: $showingConfirmation, presenting: confirmation) { item in
            Button("Cancel", role: .cancel) {}
            Button("Revoke", role: .destructive) { run { await revoke(item.selection) } }
        } message: { item in
            Text("Phone \(item.identifier) will lose access to this Mac. Pair it again to restore access.")
        }
        .confirmationDialog("Discard this expired re-pair attempt?", isPresented: $showingDiscardConfirmation,
                            titleVisibility: .visible, presenting: discardConfirmation) { item in
            Button("Discard", role: .destructive) {
                run { await expiredRePairs.discardConfirmed(item.record) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { item in
            Text("This Mac will no longer tell phone \(item.identifier) that the attempt expired. The phone keeps its setup until you pair it again or remove the setup on the phone.")
        }
        .onChange(of: showingDiscardConfirmation) { _, showing in
            if !showing { discardConfirmation = nil }
        }
        .onChange(of: expiredRePairs.notice) { _, notice in
            if let notice { AccessibilityNotification.Announcement(discardMessage(notice)).post() }
        }
    }

    @ViewBuilder
    private var expiredRePairSection: some View {
        if let records = expiredRePairs.records, !records.isEmpty {
            Text("Expired re-pair attempts").font(.headline).accessibilityAddTraits(.isHeader)
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(records, id: \.phoneID) { record in
                        let identifier = displayID(record.phoneID, among: records.map(\.phoneID))
                        let expiry = Date(timeIntervalSince1970: Double(record.originalExpiryUnixMilliseconds) / 1000)
                        HStack {
                            VStack(alignment: .leading) {
                                Text("Phone \(identifier)")
                                switch record.reason {
                                case .deadlineElapsed:
                                    Text("Pairing time expired").font(.caption)
                                    Text("Original expiry \(expiry, format: .dateTime.year().month().day().hour().minute())")
                                        .font(.caption)
                                case .retiredIncarnation:
                                    Text("Remozio restarted before the attempt finished.").font(.caption)
                                }
                            }
                            Spacer()
                            Button("Discard…") {
                                discardConfirmation = DiscardConfirmation(record: record, identifier: identifier)
                                showingDiscardConfirmation = true
                            }
                            .accessibilityLabel(Text("Discard expired re-pair attempt for phone \(identifier)"))
                            .disabled(busy)
                        }
                    }
                }
            }
            .frame(maxHeight: 200)
        } else {
            switch expiredRePairs.availability {
            case .unread, .available: EmptyView()
            case .supportUnconfirmed:
                Text("This version of Remozio may need an update to show expired re-pair attempts.")
                    .fixedSize(horizontal: false, vertical: true)
            case .unavailable:
                Text("Expired re-pair attempts are unavailable.").fixedSize(horizontal: false, vertical: true)
            }
        }
        if let notice = expiredRePairs.notice {
            Text(discardMessage(notice)).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func discardMessage(_ notice: MacExpiredRePairControls.Notice) -> String {
        switch notice {
        case .discarded: String(localized: "Expired re-pair attempt discarded.")
        case .authorizationCancelled: String(localized: "Authorization was cancelled.")
        case .notSubmitted: String(localized: "The discard request was not sent. No change was made.")
        case .noLongerListed: String(localized: "The expired re-pair attempt is no longer listed.")
        case .unconfirmed: String(localized: "Could not confirm that the expired re-pair attempt was discarded.")
        }
    }

    private func displayID(_ phone: DeliveryRecipient, among rows: [DeliveryRecipient]) -> String {
        displayID(phone.phoneID, among: rows.map(\.phoneID))
    }

    private func displayID(_ phoneID: Data, among rows: [Data]) -> String {
        let suffix = phoneID.suffix(4)
        let matching = rows.filter { $0.suffix(4) == suffix }
        let shortID = suffix.map { String(format: "%02X", $0) }.joined()
        guard matching.count > 1, let position = matching.firstIndex(of: phoneID) else { return shortID }
        return String(localized: "\(shortID), \(position + 1) of \(matching.count)")
    }

    private func run(_ work: @escaping @MainActor () async -> Void) {
        guard !busy else { return }
        busy = true
        Task {
            await work()
            busy = false
        }
    }

    private func connect() async throws -> AuthorityPairingChannel {
        channel?.abort()
        let next = try AuthorityPairingChannel.forCurrentAccount()
        channel = next
        _ = try await next.start()
        return next
    }

    private func refresh() async {
        do {
            let active = try await connect()
            snapshot = try await active.pairedPhonesForRePair()
            refreshError = nil
        } catch is CancellationError {
            return
        } catch {
            snapshot = nil
            let message = String(localized: "Paired phones are unavailable.")
            refreshError = message
            AccessibilityNotification.Announcement(message).post()
        }
        await expiredRePairs.refresh()
    }

    private func revoke(_ selection: PairedPhoneSelection) async {
        guard let channel else { return }
        do { await apply(try await channel.revokePhone(selection), selection: selection) }
        catch SetupAdministratorAuthorizationError.cancelled {
            announce(String(localized: "Authorization was cancelled."))
        } catch {
            snapshot = nil
            await reconcile(selection)
        }
    }

    private func reconcile(_ selection: PairedPhoneSelection) async {
        do {
            let active = try await connect()
            await apply(try await active.revocationStatus(selection), selection: selection)
        } catch {
            await apply(.unknown, selection: selection)
        }
    }

    private func apply(_ result: PhoneRevocationStatus, selection: PairedPhoneSelection) async {
        unconfirmed = nil
        switch result {
        case .revokedOnMac:
            announce(String(localized: "Phone revoked on this Mac."))
        case .gatewayPending:
            unconfirmed = selection
            announce(String(localized: "Phone revoked on this Mac. Push delivery to other phones may pause until the gateway receives the revocation."))
        case .gatewayApplied:
            announce(String(localized: "Phone revoked on this Mac and at the gateway."))
        case .gatewayBlocked:
            unconfirmed = selection
            announce(String(localized: "Phone revoked on this Mac. The gateway could not apply the revocation."))
        case .gatewayUnsupported:
            unconfirmed = selection
            announce(String(localized: "Phone revoked on this Mac. The gateway may need an update to receive the revocation."))
        case .gatewayUnavailable:
            unconfirmed = selection
            announce(String(localized: "Phone revoked on this Mac. Gateway delivery is unavailable."))
        case .gatewayNotRequired:
            announce(String(localized: "Phone revoked on this Mac. Gateway delivery is unnecessary."))
        case .gatewayInconclusive:
            unconfirmed = selection
            announce(String(localized: "Phone revoked on this Mac. The gateway has not confirmed delivery."))
        case .staleSelection:
            announce(String(localized: "The list changed. Select the phone again."))
        case .active:
            announce(String(localized: "This phone is still paired. Select it again to revoke it."))
        case .unknown:
            snapshot = nil
            unconfirmed = selection
            announce(String(localized: "Could not confirm whether the phone was revoked. Check its status before trying again."))
            await expiredRePairs.refresh()
            return
        }
        await refresh()
    }

    private func announce(_ value: String) {
        notice = value
        AccessibilityNotification.Announcement(value).post()
    }
}
