import Foundation

/// The GUI app has a separate retained code role. Transport and phone interfaces cannot call these controls.
final class AuthorityPresenceAccess: Sendable {
    private let journal: AuthorityJournal
    private let presence: AuthorityPresenceRuntime
    private let entry: AuthorityCodeEntry
    private let roleRevision: UUID
    private let epoch: UUID
    private let now: @Sendable () throws -> AuthorityMoment
    private let validateSelf: @Sendable (JournalTransaction) throws -> Void
    init(journal: AuthorityJournal, presence: AuthorityPresenceRuntime, appPolicy: XPCPeerPolicy,
         now: @escaping @Sendable () throws -> AuthorityMoment,
         validateSelf: @escaping @Sendable (JournalTransaction) throws -> Void = AuthoritySelfValidation.validate) throws {
        guard appPolicy.expectedUserID == presence.configuration.ownerUID else { throw AuthorityPresenceError.wrongScope }
        let retained = try journal.read { tx in
            try validateSelf(tx)
            let trust = try tx.approvalTrustSnapshot()
            guard trust.macID == presence.configuration.macID, trust.accountID == presence.configuration.accountID,
                  let policy = try tx.codePolicy(), let entry = policy.policy.entries.first(where: { $0.role == .app }),
                  entry.active, let revision = policy.roleRevisions[.app] else { throw AuthorityPresenceIPCError.policyMismatch }
            let installed = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: appPolicy.expectedUserID,
                expectedAuditSessionID: appPolicy.expectedAuditSessionID)
            guard installed.requirement == appPolicy.requirement else { throw AuthorityPresenceIPCError.policyMismatch }
            return (entry, revision)
        }
        self.journal = journal; self.presence = presence; entry = retained.0; roleRevision = retained.1
        epoch = try now().epoch
        self.now = now; self.validateSelf = validateSelf
    }
    func acquireReleaseActivity() throws -> ReleaseActivityToken? { try journal.acquireReleaseActivity() }
    func verifyCurrent() throws { try journal.read { try self.requireCurrent($0) } }
    func status(binding: AuthorityPresenceBinding) throws -> AuthorityPresenceStatus {
        try requireBinding(binding)
        return try withOwner { try self.status(owner: $0, binding: binding, conflict: false) }
    }
    func publish(_ publication: AuthorityPresencePublication) throws -> AuthorityPresenceStatus {
        try requireBinding(publication.binding)
        return try withOwner { owner in
            guard try self.presence.publish(publication.snapshot, observer: publication.binding.connectionID,
                sampledAt: publication.sampledAt, now: self.now()) else { throw AuthorityPresenceError.invalidObservation }
            return try self.status(owner: owner, binding: publication.binding, conflict: false)
        }
    }
    func setMode(_ change: AuthorityPresenceModeChange) throws -> AuthorityPresenceStatus {
        try requireBinding(change.binding)
        return try withOwner { owner in
            var conflict = false
            do { _ = try owner.setLocalRoutingMode(change.mode, expectedRevision: change.expectedRevision, now: self.now(), receiptTimeMs: nil) }
            catch RoutingJournalError.conflict { conflict = true }
            return try self.status(owner: owner, binding: change.binding, conflict: conflict)
        }
    }
    func withdraw(observer: UUID) { presence.withdraw(observer: observer) }
    private func status(owner: ApprovalRequestCoordinator, binding: AuthorityPresenceBinding, conflict: Bool) throws -> AuthorityPresenceStatus {
        let moment = try now()
        return try .init(binding: binding, sampledAt: moment, state: owner.localRoutingState(),
            routing: presence.routing(owner: owner, now: moment), conflict: conflict)
    }
    private func withOwner<T: Sendable>(_ body: @Sendable (ApprovalRequestCoordinator) throws -> T) throws -> T {
        try journal.withValidatedRequests(validate: { try self.requireCurrent($0) }, body: body)
    }
    private func requireBinding(_ binding: AuthorityPresenceBinding) throws {
        guard binding.macID == presence.configuration.macID, binding.accountID == presence.configuration.accountID,
              binding.clockEpoch == epoch else { throw AuthorityPresenceIPCError.invalidMessage }
    }
    private func requireCurrent(_ tx: JournalTransaction) throws {
        try validateSelf(tx)
        guard let policy = try tx.codePolicy(), policy.roleRevisions[.app] == roleRevision,
              policy.policy.entries.first(where: { $0.role == .app }) == entry else { throw AuthorityPresenceIPCError.policyMismatch }
    }
}
