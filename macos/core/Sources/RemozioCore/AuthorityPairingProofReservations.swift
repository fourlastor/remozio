import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization

/// One authenticated Transport connection. The native owner retires this binding with its link.
final class AuthorityPairingProofLink: Sendable {
    private enum State { case available, bound, retired }
    private let state = Mutex(State.available)
    private let verifyPolicy: @Sendable () throws -> Void
    private let validatePolicy: @Sendable (JournalTransaction) throws -> Void

    init(verifyPolicy: @escaping @Sendable () throws -> Void,
         validatePolicy: @escaping @Sendable (JournalTransaction) throws -> Void) {
        self.verifyPolicy = verifyPolicy
        self.validatePolicy = validatePolicy
    }

    func claim() throws {
        try state.withLock {
            guard case .available = $0 else { throw AuthorityPairingSetupError.unavailable }
            $0 = .bound
        }
    }

    func requireActive() throws {
        try state.withLock {
            if case .retired = $0 { throw AuthorityPairingSetupError.unavailable }
        }
    }

    func verifyCurrent() throws {
        try requireActive()
        try verifyPolicy()
        try requireActive()
    }

    func validateCurrent(_ transaction: JournalTransaction) throws {
        try requireActive()
        try validatePolicy(transaction)
        try requireActive()
    }

    func retire() { state.withLock { $0 = .retired } }
}

/// Short-lived proof state for an exact Authority window and an authenticated Transport link.
final class AuthorityPairingProofReservations: Sendable {
    struct Candidate: Sendable, CustomStringConvertible, CustomReflectable {
        let id: UUID
        let challenge: Data
        var description: String { "AuthorityPairingProofCandidate(redacted)" }
        var customMirror: Mirror { Mirror(self, children: [Mirror.Child]()) }
    }

    fileprivate struct Pending {
        let deadline: AuthorityMoment
        let peerPoint: Data
        let exporter: Data
        let challenge: Data
    }

    /// A window can clear raw proof inputs without taking the reservation owner's lock.
    final class PendingCandidates: Sendable {
        private struct State {
            var closed = false
            var entries: [UUID: Pending] = [:]
        }

        private let state = Mutex(State())

        fileprivate var count: Int { state.withLock { $0.entries.count } }

        fileprivate func insert(_ entry: Pending, for id: UUID) throws {
            try state.withLock {
                guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }
                $0.entries[id] = entry
            }
        }

        @discardableResult
        fileprivate func remove(_ id: UUID) -> Pending? {
            state.withLock { $0.entries.removeValue(forKey: id) }
        }

        fileprivate func prune(at current: AuthorityMoment) {
            state.withLock { $0.entries = $0.entries.filter { AuthorityPairingProofReservations.isBefore(current, $0.value.deadline) } }
        }

        fileprivate func removeAll() { state.withLock { $0.entries.removeAll() } }

        func close() {
            state.withLock {
                $0.closed = true
                $0.entries.removeAll()
            }
        }
    }

    private struct State {
        var connectionIDs: Set<UUID> = []
        // Keep an exporter fingerprint for replay rejection after its raw bytes leave pending.
        var exporterDigests: Set<SHA256.Digest> = []
        var retired = false
    }

    static let maximumPending = 4
    // Keep the replay checks for the link's lifetime. Refuse further registrations at this bound.
    static let maximumRegistrations = 256
    private let window: AuthorityPairingV2Window
    private let link: AuthorityPairingProofLink
    private let now: @Sendable () throws -> AuthorityMoment
    private let makeChallenge: @Sendable () throws -> Data
    private let verifyWindow: @Sendable () throws -> Void
    private let pending: PendingCandidates
    private let state = Mutex(State())

    var pendingCount: Int { pending.count }

    init(window: AuthorityPairingV2Window, authorityOwner: UUID, link: AuthorityPairingProofLink,
         now: @escaping @Sendable () throws -> AuthorityMoment, makeChallenge: @escaping @Sendable () throws -> Data,
         verifyWindow: @escaping @Sendable () throws -> Void) throws {
        guard window.authorityOwner == authorityOwner else { throw AuthorityPairingSetupError.wrongScope }
        try verifyWindow()
        try link.verifyCurrent()
        let pending = PendingCandidates()
        try window.bindProofLink(link, pending: pending, at: now())
        self.pending = pending
        self.window = window
        self.link = link
        self.now = now
        self.makeChallenge = makeChallenge
        self.verifyWindow = verifyWindow
    }

    deinit { retire() }

    /// Charge native proof work to the window before decoding or checking a proof.
    func withXPCWork<Value>(_ operation: () throws -> Value) throws -> Value {
        guard window.proofXPCBudget.acquire() else { throw AuthorityXPCEndpointError.unavailable }
        defer { window.proofXPCBudget.release() }
        return try operation()
    }

    func register(connection: UUID, acceptedAt: UInt64, peerPoint: Data, exporter: Data) throws -> Candidate {
        try checkCurrentAndPrune()
        return try state.withLock {
            let received = try now()
            guard !$0.retired, pendingCount < Self.maximumPending,
                  $0.connectionIDs.count < Self.maximumRegistrations, !$0.connectionIDs.contains(connection),
                  peerPoint.count == 65, peerPoint.first == 4, exporter.count == 32 else {
                throw AuthorityPairingSetupError.unavailable
            }
            let exporterDigest = SHA256.hash(data: exporter)
            guard !$0.exporterDigests.contains(exporterDigest) else { throw AuthorityPairingSetupError.unavailable }
            let deadline = try window.proofDeadline(for: link, acceptedAt: acceptedAt, at: received)
            let challenge = try makeChallenge()
            guard challenge.count == 32 else { throw AuthorityPairingSetupError.invalidConfiguration }
            let completed = try now()
            guard completed.milliseconds >= received.milliseconds, Self.isBefore(completed, deadline) else {
                throw PairingEnrollmentError.expired
            }
            try link.requireActive()
            let id = UUID()
            try pending.insert(.init(deadline: deadline, peerPoint: peerPoint, exporter: exporter, challenge: challenge), for: id)
            $0.connectionIDs.insert(connection)
            $0.exporterDigests.insert(exporterDigest)
            return Candidate(id: id, challenge: challenge)
        }
    }

    func verify(candidate: UUID, proposalBytes: Data, tag: Data) throws {
        try checkCurrentAndPrune()
        try state.withLock {
            guard !$0.retired, let pending = pending.remove(candidate) else {
                throw AuthorityPairingSetupError.unavailable
            }
            let received = try now()
            guard Self.isBefore(received, pending.deadline) else { throw PairingEnrollmentError.expired }
            guard tag.count == 32, proposalBytes.count <= PairingSetupPreludeV2.maximumBytes else {
                throw AuthorityPairingSetupError.invalidConfirmation
            }
            let proposal = try PairingPhoneProposal.decode(proposalBytes)
            let proof = PairingSetupV2Proof(windowID: window.id, connection: candidate, peerPoint: pending.peerPoint,
                challenge: pending.challenge, exporter: pending.exporter, proposal: proposal, tag: tag)
            try window.verifyProof(proof, link: link, deadline: pending.deadline, at: received)
            do {
                let completed = try now()
                guard completed.milliseconds >= received.milliseconds, Self.isBefore(completed, pending.deadline) else {
                    throw PairingEnrollmentError.expired
                }
                try link.requireActive()
            } catch {
                window.disconnected(candidate)
                throw error
            }
        }
    }

    func confirm(candidate: UUID) throws {
        try checkCurrentAndPrune()
        try state.withLock {
            guard !$0.retired else { throw AuthorityPairingSetupError.unavailable }
            try window.confirmProof(candidate: candidate, link: link, at: now())
        }
    }

    func retire(candidate: UUID) {
        state.withLock { _ in
            pending.remove(candidate)
            window.disconnected(candidate)
        }
        prunePending()
    }

    func retire() {
        link.retire()
        state.withLock {
            $0.retired = true
            pending.close()
            $0.connectionIDs.removeAll()
            $0.exporterDigests.removeAll()
            window.retireProofLink(link)
        }
    }

    private func checkCurrentAndPrune() throws {
        prunePending()
        try verifyWindow()
        try link.verifyCurrent()
    }

    private func prunePending() {
        state.withLock { _ in
            guard let current = try? now(), window.acceptsProofRegistrations(for: link, at: current) else {
                pending.removeAll()
                return
            }
            pending.prune(at: current)
        }
    }

    private static func isBefore(_ current: AuthorityMoment, _ deadline: AuthorityMoment) -> Bool {
        current.epoch == deadline.epoch && current.milliseconds < deadline.milliseconds
    }
}
