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

    private struct Pending {
        let deadline: AuthorityMoment
        let peerPoint: Data
        let exporter: Data
        let challenge: Data
    }

    private struct Confirmation {
        let id: UUID
        let deadline: AuthorityMoment
    }

    private struct State {
        var pending: [UUID: Pending] = [:]
        var connectionIDs: Set<UUID> = []
        var exporterDigests: Set<SHA256.Digest> = []
        var confirmation: Confirmation?
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
    private let state = Mutex(State())

    init(window: AuthorityPairingV2Window, link: AuthorityPairingProofLink, now: @escaping @Sendable () throws -> AuthorityMoment,
         makeChallenge: @escaping @Sendable () throws -> Data, verifyWindow: @escaping @Sendable () throws -> Void) throws {
        try verifyWindow()
        try link.verifyCurrent()
        try window.bindProofLink(link, at: now())
        self.window = window
        self.link = link
        self.now = now
        self.makeChallenge = makeChallenge
        self.verifyWindow = verifyWindow
    }

    deinit { retire() }

    func register(connection: UUID, acceptedAt: UInt64, peerPoint: Data, exporter: Data) throws -> Candidate {
        try verifyWindow()
        try link.verifyCurrent()
        return try state.withLock {
            let received = try now()
            $0.pending = $0.pending.filter { Self.isBefore(received, $0.value.deadline) }
            guard !$0.retired, $0.pending.count < Self.maximumPending,
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
            $0.connectionIDs.insert(connection)
            $0.exporterDigests.insert(exporterDigest)
            $0.pending[id] = .init(deadline: deadline, peerPoint: peerPoint, exporter: exporter, challenge: challenge)
            return Candidate(id: id, challenge: challenge)
        }
    }

    func verify(candidate: UUID, proposalBytes: Data, tag: Data) throws {
        try verifyWindow()
        try link.verifyCurrent()
        try state.withLock {
            guard !$0.retired, $0.confirmation == nil, let pending = $0.pending.removeValue(forKey: candidate) else {
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
            try window.verifyProof(proof, link: link, at: received)
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
            $0.pending.removeAll()
            $0.confirmation = .init(id: candidate, deadline: pending.deadline)
        }
    }

    func confirm(candidate: UUID) throws {
        try verifyWindow()
        try link.verifyCurrent()
        try state.withLock {
            guard !$0.retired, let confirmation = $0.confirmation, confirmation.id == candidate else {
                throw AuthorityPairingSetupError.unavailable
            }
            $0.confirmation = nil
            do {
                let current = try now()
                guard Self.isBefore(current, confirmation.deadline) else { throw PairingEnrollmentError.expired }
                try window.confirmProof(candidate: candidate, link: link, at: current)
            } catch {
                window.disconnected(candidate)
                throw error
            }
        }
    }

    func retire(candidate: UUID) {
        state.withLock {
            $0.pending.removeValue(forKey: candidate)
            if $0.confirmation?.id == candidate { $0.confirmation = nil }
            window.disconnected(candidate)
        }
    }

    func retire() {
        link.retire()
        state.withLock {
            $0.retired = true
            $0.pending.removeAll()
            $0.connectionIDs.removeAll()
            $0.exporterDigests.removeAll()
            $0.confirmation = nil
            window.retireProofLink(link)
        }
    }

    private static func isBefore(_ current: AuthorityMoment, _ deadline: AuthorityMoment) -> Bool {
        current.epoch == deadline.epoch && current.milliseconds < deadline.milliseconds
    }
}
