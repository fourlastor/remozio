import Foundation
import Synchronization

/// One verified app connection owns this rendezvous. Its ID alone grants no pairing admission.
final class AuthorityPairingRendezvous: Sendable {
    private struct VerifiedLink {
        let link: AuthorityPairingProofLink
        let offerDeadline: ContinuousClock.Instant
    }

    private enum State {
        case waiting
        case offered(UUID)
        case ready(VerifiedLink)
        case opening(VerifiedLink)
        case opened(VerifiedLink)
        case retired
    }

    let id = AuthorityPairingProofWire.bytes(UUID())
    let revision: AuthorityPairingSetupAccess.V2ActivationRevision
    let lanScope: PairingLANScope?
    private let deadline: ContinuousClock.Instant
    private let now: @Sendable () -> ContinuousClock.Instant
    private let state = Mutex(State.waiting)

    init(revision: AuthorityPairingSetupAccess.V2ActivationRevision, lanScope: PairingLANScope? = nil,
         deadline: ContinuousClock.Instant = .now.advanced(by: AuthorityPairingProofWire.bootstrapTimeout),
         now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) {
        self.revision = revision
        self.lanScope = lanScope
        self.deadline = deadline
        self.now = now
    }

    func claim(offer: UUID) -> Bool {
        state.withLock {
            guard case .waiting = $0, now() < deadline else { return false }
            $0 = .offered(offer)
            return true
        }
    }

    func acceptHello(offer: UUID, link: AuthorityPairingProofLink, offerDeadline: ContinuousClock.Instant) -> Bool {
        state.withLock {
            guard case .offered(let claimed) = $0, claimed == offer,
                  now() < min(deadline, offerDeadline) else { return false }
            $0 = .ready(VerifiedLink(link: link, offerDeadline: offerDeadline))
            return true
        }
    }

    /// A token cannot cross access incarnations. On a live endpoint this compares the immutable startup revision.
    /// Role validation and protected publication govern changes to the installed policy.
    func admitOpening(revision: AuthorityPairingSetupAccess.V2ActivationRevision, _ promote: () throws -> Bool) throws -> Bool {
        try state.withLock {
            guard case .ready(let verified) = $0, self.revision == revision, now() < verified.offerDeadline else {
                return false
            }
            $0 = .retired
            try verified.link.verifyCurrent()
            guard try promote() else { return false }
            $0 = .opening(verified)
            return true
        }
    }

    func publishWindow() -> Bool {
        state.withLock {
            guard case .opening(let verified) = $0, now() < verified.offerDeadline else { return false }
            $0 = .opened(verified)
            return true
        }
    }

    func permitsBinding(link: AuthorityPairingProofLink) -> Bool {
        state.withLock {
            guard case .opened(let verified) = $0 else { return false }
            return verified.link === link && now() < verified.offerDeadline
        }
    }

    var isRetired: Bool {
        state.withLock { if case .retired = $0 { return true }; return false }
    }

    func retire() { state.withLock { $0 = .retired } }
}
