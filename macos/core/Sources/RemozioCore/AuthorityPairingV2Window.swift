import Foundation
import RemozioProtocol
import Synchronization

/// An Authority-owned window. Only the signed app receives the export payload.
final class AuthorityPairingV2Window: Sendable {
    private enum State {
        case open(PairingInvitationV2)
        case proved(UUID, Data)
        case staging(UUID)
        case closed
    }
    private let state: Mutex<State>
    private let started: AuthorityMoment
    private let deadline: UInt64
    let publicInvitation: PairingInvitation
    let id: Data
    let predecessor: PairedPhoneSelection?

    init(invitation: PairingInvitationV2, predecessor: PairedPhoneSelection?, started: AuthorityMoment) throws {
        let end = started.milliseconds.addingReportingOverflow(invitation.lifetimeMilliseconds)
        guard !end.overflow, invitation.replacement == (try predecessor?.predecessor) else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        self.started = started
        deadline = end.partialValue
        publicInvitation = invitation.invitation
        id = invitation.windowID
        self.predecessor = predecessor
        state = Mutex(.open(invitation))
    }

    func export(at now: AuthorityMoment) throws -> PairingInvitationV2 {
        try state.withLock {
            try requireCurrent(now)
            guard case .open(let invitation) = $0 else { throw AuthorityPairingSetupError.unavailable }
            return invitation
        }
    }

    /// After proof, discard the secret and hold only the exact proposal and connection.
    func reserve(_ proof: PairingSetupV2Proof, at now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            guard case .open(let invitation) = $0, proof.windowID == id,
                  proof.proposal.transportKey.publicKey == proof.peerPoint,
                  try invitation.verifiesProof(proof.tag, proposal: proof.proposal, challenge: proof.challenge,
                    exporter: proof.exporter) else { throw AuthorityPairingSetupError.invalidConfirmation }
            $0 = .proved(proof.connection, try proof.proposal.encode())
        }
    }

    func takeProposal(connection: UUID, matching bytes: Data, at now: AuthorityMoment) throws -> PairingPhoneProposal {
        try state.withLock {
            try requireCurrent(now)
            guard case .proved(let selected, let retained) = $0, selected == connection, retained == bytes else {
                throw AuthorityPairingSetupError.invalidConfirmation
            }
            let proposal = try PairingPhoneProposal.decode(retained)
            $0 = .staging(connection)
            return proposal
        }
    }

    func requireStaging(_ now: AuthorityMoment) throws {
        try state.withLock {
            try requireCurrent(now)
            guard case .staging = $0 else { throw AuthorityPairingSetupError.unavailable }
        }
    }

    func disconnected(_ connection: UUID) {
        state.withLock {
            switch $0 {
            case .proved(let owner, _) where owner == connection, .staging(let owner) where owner == connection:
                $0 = .closed
            default: break
            }
        }
    }

    func expireIfDue(_ now: AuthorityMoment) throws {
        try state.withLock {
            do { try requireCurrent(now) }
            catch { $0 = .closed; throw error }
        }
    }

    func close() { state.withLock { $0 = .closed } }

    private func requireCurrent(_ now: AuthorityMoment) throws {
        guard now.epoch == started.epoch, now.milliseconds >= started.milliseconds, now.milliseconds < deadline else {
            throw PairingEnrollmentError.expired
        }
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
