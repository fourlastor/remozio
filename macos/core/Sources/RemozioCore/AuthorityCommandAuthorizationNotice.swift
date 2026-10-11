import Foundation
import RemozioProtocol
import Synchronization

/// A trusted scheduling hint after durable consumption. It never grants execution permission.
public struct AuthorityCommandAuthorizationNotice: Equatable, Sendable {
    public let requestID: Data
    public let requestDigest: Data
    public let challenge: Data
    init(state: ApprovalRequestState) {
        requestID = state.requestID; requestDigest = state.requestDigest; challenge = state.challenge
    }
}

extension AuthorityJournal {
    /// Authentication and transition inspection share one lock. Notifications run after that lock is released.
    /// The callback must enqueue promptly; the executor must recheck all durable, policy and capture gates.
    func withValidatedCommandExchange<Value: Sendable>(requestID: Data, decisionSupplied: Bool,
        validate: @Sendable (JournalTransaction) throws -> Void,
        body: @Sendable (ApprovalRequestCoordinator) throws -> Value,
        onCommandAuthorized: @Sendable (AuthorityCommandAuthorizationNotice) -> Void) throws -> Value {
        let notice = Mutex<AuthorityCommandAuthorizationNotice?>(nil)
        defer { if let value = notice.withLock({ $0 }) { onCommandAuthorized(value) } }
        return try withValidatedRequests(validate: validate, body: { owner in
            let before = decisionSupplied ? try? owner.state(requestID: requestID) : nil
            defer {
                if let before, before.requestKind == .command,
                   before.phase == .queued || before.phase == .presented,
                   let after = try? owner.state(requestID: requestID), after.phase == .authorized,
                   after.requestDigest == before.requestDigest, after.challenge == before.challenge,
                   let outcome = try? owner.historicalOutcome(requestID: requestID),
                   outcome.phase == .authorized, outcome.receipt.event.category == .command,
                   outcome.receipt.event.outcome == .accepted,
                   outcome.receipt.decision.action == CapturedAction(choice: .execute, scope: .currentRequest),
                   outcome.receipt.decision.requestDigest == after.requestDigest,
                   outcome.receipt.decision.challenge == after.challenge {
                    notice.withLock { $0 = AuthorityCommandAuthorizationNotice(state: after) }
                }
            }
            return try body(owner)
        })
    }
}
