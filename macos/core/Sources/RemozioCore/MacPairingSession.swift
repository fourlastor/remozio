import Foundation
import RemozioProtocol

public enum MacPairingSessionError: Error { case invalidConfiguration, invalidState, closed, expired, changedCandidate }
public enum MacPairingSessionPhase: Sendable {
    case idle, connecting, waitingForPhone, authorizing, comparing, waitingForBiometric, committing
    case registeredOnMac, receiptSent, expired, unavailable, outcomeUnknown, closed
}

/// Display data only. A receipt write never claims that the phone activated its enrollment.
public struct MacPairingSessionSnapshot: Sendable {
    public let phase: MacPairingSessionPhase
    public let invitation: PairingInvitation?
    public let candidates: [TransportPairingCandidate]
    public let selectedPhoneID: Data?
    public let comparisonCode: String?
    public let remainingMilliseconds: UInt64?
    public let phoneProofAvailable: Bool
}

protocol MacPairingRootControl: Sendable {
    func start() async throws -> AuthorityPairingContext
    func stage(_ proposal: PairingPhoneProposal, authorization: Data) async throws -> PairingTranscript
    func commit(confirmedDigest: Data, biometricProof: Data, authorization: Data) async throws -> Data
    nonisolated func abort()
    func close() async
}
protocol MacPairingTransportControl: Sendable {
    func start(invitation: PairingInvitation) async throws -> UInt16
    func current() async throws -> TransportPairingSnapshot
    func stage(candidateID: Data, transcript: PairingTranscript) async throws
    func deliverReceipt(candidateID: Data, signature: Data) async throws
    nonisolated func abort()
    func close() async
}
protocol MacPairingAdministrator: Sendable {
    func authorization() async throws -> Data
    func close() async
}
extension AuthorityPairingChannel: MacPairingRootControl {}
extension TransportPairingChannel: MacPairingTransportControl {}

private actor NativePairingAdministrator: MacPairingAdministrator {
    private var session: SetupAdministratorSession?
    private var closed = false
    func authorization() throws -> Data {
        try Task.checkCancellation()
        guard !closed else { throw MacPairingSessionError.closed }
        if session == nil { session = try SetupAdministratorSession() }
        let session = session!
        try session.authorize()
        try Task.checkCancellation()
        return try session.externalForm()
    }
    func close() { closed = true; session?.close(); session = nil }
}

/// One explicit app-owned enrollment. Only the authenticated Root transcript is confirmable; commits never retry.
public actor MacPairingSession {
    private let root: any MacPairingRootControl
    private let transport: any MacPairingTransportControl
    private let administrator: any MacPairingAdministrator
    private let cancellation = ChannelCancellation()
    private let unixMilliseconds: @Sendable () -> UInt64
    private let elapsedMilliseconds: @Sendable () -> UInt64
    private var phase = MacPairingSessionPhase.idle
    private var context: AuthorityPairingContext?
    private var invitation: PairingInvitation?
    private var candidates: [TransportPairingCandidate] = []
    private var selected: TransportPairingCandidate?
    private var transcript: PairingTranscript?
    private var deadline: UInt64?
    private var proof: Data?
    private var busy = false
    private var commitAttempted = false
    private var humanConfirmed = false

    /// Both inputs must come from protected installation metadata. This opens no channel until start is called.
    public init(rootConfiguration: AuthorityPresenceClientConfiguration, transportConfiguration: TransportPairingControlConfiguration) throws {
        guard rootConfiguration.macID == transportConfiguration.macID,
              rootConfiguration.accountID == transportConfiguration.accountID,
              rootConfiguration.ownerUID == transportConfiguration.ownerUID,
              rootConfiguration.serviceName != transportConfiguration.serviceName else { throw MacPairingSessionError.invalidConfiguration }
        root = try AuthorityPairingChannel(configuration: rootConfiguration)
        transport = try TransportPairingChannel(configuration: transportConfiguration)
        administrator = NativePairingAdministrator()
        unixMilliseconds = { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) }
        elapsedMilliseconds = { UInt64(ProcessInfo.processInfo.systemUptime * 1000) }
    }
    // Logical drivers cannot establish installed identity, native administrator consent or hardware custody.
    init(root: any MacPairingRootControl, transport: any MacPairingTransportControl, administrator: any MacPairingAdministrator,
         unixMilliseconds: @escaping @Sendable () -> UInt64, elapsedMilliseconds: @escaping @Sendable () -> UInt64) {
        self.root = root; self.transport = transport; self.administrator = administrator
        self.unixMilliseconds = unixMilliseconds; self.elapsedMilliseconds = elapsedMilliseconds
    }
    deinit { root.abort(); transport.abort() }

    public func start(label: String) async throws -> MacPairingSessionSnapshot {
        try active(); guard phase == .idle, !busy else { throw MacPairingSessionError.invalidState }
        busy = true; phase = .connecting; defer { busy = false }
        do {
            let context = try await root.start(); try active()
            let invitation = try context.invitation(label: label)
            _ = try await transport.start(invitation: invitation); try active()
            self.context = context; self.invitation = invitation; phase = .waitingForPhone
            return snapshot()
        } catch { await fail(); throw error }
    }
    public func current() async throws -> MacPairingSessionSnapshot {
        try active()
        guard !busy, phase == .waitingForPhone || phase == .comparing || phase == .waitingForBiometric else { return snapshot() }
        busy = true; defer { busy = false }
        do {
            try checkDeadline()
            let current = try await transport.current(); try active()
            candidates = current.candidates
            if let selected {
                guard let candidate = candidates.first(where: { $0.id == selected.id }),
                      try candidate.proposal.encode() == selected.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
                if let signature = candidate.biometricProof, let transcript {
                    guard try transcript.verify(signature: signature, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
                        throw MacPairingSessionError.changedCandidate
                    }
                    proof = signature
                }
            }
            return snapshot()
        } catch { await fail(); throw error }
    }
    /// The user selects this current phone. Administrator rights are requested only after the Root handshake.
    public func select(candidateID: Data) async throws -> MacPairingSessionSnapshot {
        try active(); guard !busy, phase == .waitingForPhone, let context, let invitation,
              let candidate = candidates.first(where: { $0.id == candidateID && $0.phase == .proposed }) else {
            throw MacPairingSessionError.invalidState
        }
        busy = true; phase = .authorizing; defer { busy = false }
        do {
            let authorization = try await administrator.authorization(); try active()
            let current = try await transport.current(); try active()
            guard let actual = current.candidates.first(where: { $0.id == candidateID && $0.phase == .proposed }),
                  try actual.proposal.encode() == candidate.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
            let staged = try await root.stage(actual.proposal, authorization: authorization); try active()
            try actual.proposal.validate(staged); try invitation.validateMacClaims(in: staged)
            let wall = unixMilliseconds(), elapsed = elapsedMilliseconds()
            guard wall >= staged.issuedAtUnixMillis, wall < staged.expiresAtUnixMillis else { throw MacPairingSessionError.expired }
            let remaining = min(context.lifetimeMilliseconds, staged.expiresAtUnixMillis - wall)
            let (end, overflow) = elapsed.addingReportingOverflow(remaining)
            guard !overflow else { throw MacPairingSessionError.expired }
            selected = actual; transcript = staged; deadline = end; proof = nil; humanConfirmed = false
            try await transport.stage(candidateID: candidateID, transcript: staged); try active(); try checkDeadline()
            phase = .comparing
            return snapshot()
        } catch SetupAdministratorAuthorizationError.cancelled { phase = .waitingForPhone; throw SetupAdministratorAuthorizationError.cancelled }
        catch { await fail(); throw error }
    }
    /// Invoke only for an explicit comparison of the complete transcript on both setup surfaces.
    public func confirmComparison() throws -> MacPairingSessionSnapshot {
        try active(); try checkDeadline()
        guard !busy, phase == .comparing, transcript != nil else { throw MacPairingSessionError.invalidState }
        humanConfirmed = true; phase = .waitingForBiometric; return snapshot()
    }
    /// Requires the explicit human confirmation and the current phone proof. A lost Root reply is never retried.
    public func commit() async throws -> MacPairingSessionSnapshot {
        try active(); try checkDeadline()
        guard !busy, phase == .waitingForBiometric, humanConfirmed, !commitAttempted,
              let transcript, let selected, let proof else { throw MacPairingSessionError.invalidState }
        busy = true; defer { busy = false }
        do {
            let authorization = try await administrator.authorization(); try active(); try checkDeadline()
            let current = try await transport.current(); try active(); try checkDeadline()
            guard let candidate = current.candidates.first(where: { $0.id == selected.id }),
                  candidate.phase == .proofReady, candidate.biometricProof == proof,
                  try candidate.proposal.encode() == selected.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
            guard try transcript.verify(signature: proof, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
                throw MacPairingSessionError.changedCandidate
            }
            phase = .committing; commitAttempted = true
            let receipt = try await root.commit(confirmedDigest: transcript.digest(), biometricProof: proof, authorization: authorization)
            guard try transcript.verify(signature: receipt, publicKey: transcript.macAuthorityKey, purpose: .macCommit) else {
                throw MacPairingSessionError.invalidState
            }
            phase = .registeredOnMac
            try active()
            do {
                try await transport.deliverReceipt(candidateID: selected.id, signature: receipt)
                try active(); phase = .receiptSent
            } catch { /* Root returned a verified durable receipt; phone delivery remains uncertain. */ }
            await releaseChannels()
            return snapshot()
        } catch { await fail(); throw error }
    }
    public nonisolated func abort() { cancellation.cancel(); root.abort(); transport.abort() }
    /// Cancels admission immediately. Native authorization cleanup may wait for its actual OS call to return.
    public func close() async {
        abort()
        if phase != .registeredOnMac && phase != .receiptSent && phase != .outcomeUnknown { phase = commitAttempted ? .outcomeUnknown : .closed }
        await releaseChannels()
    }
    private func active() throws {
        try Task.checkCancellation()
        guard cancellation.ifActive({}) else { throw MacPairingSessionError.closed }
    }
    private func checkDeadline() throws {
        if let deadline, elapsedMilliseconds() >= deadline { throw MacPairingSessionError.expired }
    }
    private func fail() async {
        if phase != .registeredOnMac && phase != .receiptSent {
            if commitAttempted { phase = .outcomeUnknown }
            else if !cancellation.ifActive({}) { phase = .closed }
            else if let deadline, elapsedMilliseconds() >= deadline { phase = .expired }
            else { phase = .unavailable }
        }
        await releaseChannels()
    }
    private func releaseChannels() async { root.abort(); transport.abort(); await root.close(); await transport.close(); await administrator.close() }
    public func snapshot() -> MacPairingSessionSnapshot {
        let elapsed = elapsedMilliseconds()
        let remaining = deadline.map { $0 > elapsed ? $0 - elapsed : 0 }
        return .init(phase: phase, invitation: invitation, candidates: candidates, selectedPhoneID: selected?.proposal.phone.scope.phoneID,
            comparisonCode: try? transcript?.verificationCode(), remainingMilliseconds: remaining, phoneProofAvailable: proof != nil)
    }
}
