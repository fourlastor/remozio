import Foundation
import RemozioProtocol
import Synchronization

/// An Authority-owned window. Only the signed app receives the export payload.
final class AuthorityPairingV2Window: Sendable {
    private enum Phase {
        case open(PairingInvitationV2)
        case awaitingConfirmation(UUID, Data, AuthorityMoment)
        case proved(UUID, Data)
        case staging(UUID)
        case closed
    }

    private struct State {
        var phase: Phase
        var proofLink: AuthorityPairingProofLink?
    }

    private let state: Mutex<State>
    private let started: AuthorityMoment
    private let deadline: UInt64
    let publicInvitation: PairingInvitation
    let id: Data
    let predecessor: PairedPhoneSelection?
    let authorityOwner: UUID?

    init(invitation: PairingInvitationV2, predecessor: PairedPhoneSelection?, started: AuthorityMoment,
         authorityOwner: UUID? = nil) throws {
        let end = started.milliseconds.addingReportingOverflow(invitation.lifetimeMilliseconds)
        guard !end.overflow, invitation.replacement == (try predecessor?.predecessor) else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        self.started = started
        deadline = end.partialValue
        publicInvitation = invitation.invitation
        id = invitation.windowID
        self.predecessor = predecessor
        self.authorityOwner = authorityOwner
        state = Mutex(.init(phase: .open(invitation)))
    }

    func export(at now: AuthorityMoment) throws -> PairingInvitationV2 {
        try state.withLock {
            try requireCurrent(now)
            guard case .open(let invitation) = $0.phase else { throw AuthorityPairingSetupError.unavailable }
            return invitation
        }
    }

    func bindProofLink(_ link: AuthorityPairingProofLink, at now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            try link.requireActive()
            guard $0.proofLink == nil, case .open = $0.phase else { throw AuthorityPairingSetupError.unavailable }
            try link.claim()
            $0.proofLink = link
        }
    }

    func acceptsProofRegistrations(for link: AuthorityPairingProofLink, at now: AuthorityMoment) -> Bool {
        state.withLock {
            guard $0.proofLink === link, case .open = $0.phase else { return false }
            do { try requireCurrent(now); try link.requireActive(); return true }
            catch { return false }
        }
    }

    func proofDeadline(for link: AuthorityPairingProofLink, acceptedAt: UInt64, at now: AuthorityMoment) throws -> AuthorityMoment {
        try state.withLock {
            try requireCurrent(now)
            try link.requireActive()
            guard $0.proofLink === link, case .open = $0.phase,
                  started.milliseconds <= acceptedAt, acceptedAt <= now.milliseconds else {
                throw AuthorityPairingSetupError.unavailable
            }
            let acceptDeadline = acceptedAt.addingReportingOverflow(3_000)
            guard !acceptDeadline.overflow else { throw PairingEnrollmentError.expired }
            let end = min(acceptDeadline.partialValue, deadline)
            guard now.milliseconds < end else { throw PairingEnrollmentError.expired }
            return .init(epoch: started.epoch, milliseconds: end)
        }
    }

    /// This in-process path serves the existing logical setup and loopback fixtures.
    func reserve(_ proof: PairingSetupV2Proof, at now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            guard $0.proofLink == nil, case .open(let invitation) = $0.phase else {
                throw AuthorityPairingSetupError.invalidConfirmation
            }
            $0.phase = .proved(proof.connection, try verifiedProposal(proof, invitation: invitation))
        }
    }

    /// A verified proof spends the one-use invitation. Staging waits for Transport to confirm the candidate.
    func verifyProof(_ proof: PairingSetupV2Proof, link: AuthorityPairingProofLink,
                     deadline: AuthorityMoment, at now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            try link.requireActive()
            guard $0.proofLink === link, case .open(let invitation) = $0.phase else {
                throw AuthorityPairingSetupError.invalidConfirmation
            }
            try requireConfirmationDeadline(deadline, at: now)
            $0.phase = .awaitingConfirmation(proof.connection, try verifiedProposal(proof, invitation: invitation), deadline)
        }
    }

    func confirmProof(candidate: UUID, link: AuthorityPairingProofLink, at now: AuthorityMoment) throws {
        try state.withLock {
            guard $0.proofLink === link, case .awaitingConfirmation(let id, let proposal, let deadline) = $0.phase,
                  id == candidate else { throw AuthorityPairingSetupError.invalidConfirmation }
            do {
                try requireCurrent(now)
                try link.requireActive()
                try requireConfirmationDeadline(deadline, at: now)
            } catch {
                $0.phase = .closed
                throw error
            }
            $0.phase = .proved(id, proposal)
        }
    }

    func takeProposal(connection: UUID, matching bytes: Data, at now: AuthorityMoment) throws -> PairingPhoneProposal {
        try state.withLock {
            try requireCurrent(now)
            try $0.proofLink?.requireActive()
            guard case .proved(let selected, let retained) = $0.phase, selected == connection, retained == bytes else {
                throw AuthorityPairingSetupError.invalidConfirmation
            }
            let proposal = try PairingPhoneProposal.decode(retained)
            $0.phase = .staging(connection)
            return proposal
        }
    }

    func requireStaging(_ now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            try $0.proofLink?.requireActive()
            guard case .staging = $0.phase else { throw AuthorityPairingSetupError.unavailable }
        }
    }

    func validateTransport(_ transaction: JournalTransaction) throws {
        let link = state.withLock { $0.proofLink }
        try link?.validateCurrent(transaction)
    }

    /// Return true when this connection closes the window.
    @discardableResult
    func disconnected(_ connection: UUID) -> Bool {
        state.withLock {
            switch $0.phase {
            case .awaitingConfirmation(let owner, _, _) where owner == connection,
                 .proved(let owner, _) where owner == connection, .staging(let owner) where owner == connection:
                $0.phase = .closed
                return true
            default:
                return false
            }
        }
    }

    func retireProofLink(_ link: AuthorityPairingProofLink) {
        state.withLock { if $0.proofLink === link { $0.phase = .closed } }
    }

    func expireIfDue(_ now: AuthorityMoment) throws {
        try state.withLock {
            do {
                if case .closed = $0.phase { throw AuthorityPairingSetupError.unavailable }
                try requireCurrent(now)
                try $0.proofLink?.requireActive()
                if case .awaitingConfirmation(_, _, let deadline) = $0.phase {
                    try requireConfirmationDeadline(deadline, at: now)
                }
            } catch {
                $0.phase = .closed
                throw error
            }
        }
    }

    func close() { state.withLock { $0.phase = .closed } }

    private func requireCurrent(_ now: AuthorityMoment) throws {
        guard now.epoch == started.epoch, now.milliseconds >= started.milliseconds, now.milliseconds < deadline else {
            throw PairingEnrollmentError.expired
        }
    }

    private func requireConfirmationDeadline(_ proofDeadline: AuthorityMoment, at now: AuthorityMoment) throws {
        guard proofDeadline.epoch == started.epoch, proofDeadline.milliseconds <= deadline,
              now.milliseconds < proofDeadline.milliseconds else { throw PairingEnrollmentError.expired }
    }

    private func verifiedProposal(_ proof: PairingSetupV2Proof, invitation: PairingInvitationV2) throws -> Data {
        guard proof.windowID == id, proof.proposal.transportKey.publicKey == proof.peerPoint,
              try invitation.verifiesProof(proof.tag, proposal: proof.proposal, challenge: proof.challenge,
                exporter: proof.exporter) else { throw AuthorityPairingSetupError.invalidConfirmation }
        return try proof.proposal.encode()
    }
}

/// Transport produces the connection binding. The phone supplies the proposal and tag only.
struct PairingSetupV2Proof: Sendable, CustomStringConvertible, CustomReflectable {
    let windowID: Data
    let connection: UUID
    let peerPoint: Data
    let challenge: Data
    let exporter: Data
    let proposal: PairingPhoneProposal
    let tag: Data
    var description: String { "PairingSetupV2Proof(redacted)" }
    var customMirror: Mirror { Mirror(self, children: [Mirror.Child]()) }
}
