import Foundation
import RemozioProtocol

public enum AuthorityTransportAccessError: Error, Equatable { case unconfigured, policyMismatch }

/// Binds one listener incarnation to retained transport code. OS identity checks remain mandatory on each invocation.
final class AuthorityTransportAccess: Sendable {
    private let journal: AuthorityJournal
    private let entry: AuthorityCodeEntry
    private let roleRevision: UUID
    private let maximumPayloadBytes: Int
    private let minimumEnvelopeVersion: UInt64
    private let auditVersions: Set<UInt64>

    init(journal: AuthorityJournal, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
         maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64, auditVersions: Set<UInt64>) throws {
        let binding = try journal.read { transaction in
            let trust = try transaction.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes,
                minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions)
            guard trust.macID == macID, trust.accountID == accountID else { throw AuthorityXPCEndpointError.invalidConfiguration }
            guard let snapshot = try transaction.codePolicy(),
                  let entry = snapshot.policy.entries.first(where: { $0.role == .transport }),
                  let revision = snapshot.roleRevisions[.transport] else {
                throw AuthorityTransportAccessError.unconfigured
            }
            guard entry.active else { throw AuthorityTransportAccessError.policyMismatch }
            let retained = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: peerPolicy.expectedUserID,
                expectedAuditSessionID: peerPolicy.expectedAuditSessionID)
            guard retained.requirement == peerPolicy.requirement else { throw AuthorityTransportAccessError.policyMismatch }
            return (entry, revision)
        }
        entry = binding.0; roleRevision = binding.1
        self.journal = journal; self.maximumPayloadBytes = maximumPayloadBytes
        self.minimumEnvelopeVersion = minimumEnvelopeVersion; self.auditVersions = auditVersions
    }

    /// Checks hello. Operation handlers check inside the transaction that reads the protected data.
    func verifyCurrent() throws {
        try journal.read { try self.requireCurrent($0) }
    }

    func snapshot() throws -> DirectApprovalTrust {
        try journal.read { transaction in
            try self.requireCurrent(transaction)
            return try transaction.directApprovalTrust(maximumPayloadBytes: self.maximumPayloadBytes,
                minimumEnvelopeVersion: self.minimumEnvelopeVersion, auditVersions: self.auditVersions)
        }
    }

    func validate(_ binding: AuthorityPeerBinding) throws -> Bool {
        do {
            try journal.read { transaction in
                try self.requireCurrent(transaction)
                try transaction.requireDirectApprovalBinding(binding)
            }
            return true
        } catch EnrollmentJournalError.staleRevision { return false }
          catch EnrollmentJournalError.unavailableEnrollment { return false }
    }

    func requestFrame(binding: AuthorityPeerBinding, requestID: Data,
                      handler: @Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data) throws -> Data?) throws -> Data? {
        try journal.withValidatedRequests(validate: { transaction in
            try self.requireCurrent(transaction)
            try transaction.requireDirectApprovalBinding(binding)
        }, body: { try handler($0, binding, requestID) })
    }

    func pendingRequestIDs(binding: AuthorityPeerBinding,
                           handler: @Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding) throws -> [Data]) throws -> [Data] {
        try journal.withValidatedRequests(validate: { transaction in
            try self.requireCurrent(transaction)
            try transaction.requireDirectApprovalBinding(binding)
        }, body: { try handler($0, binding) })
    }

    func exchangeRequest(binding: AuthorityPeerBinding, requestID: Data, decisionFrame: Data?,
                         handler: @Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data, Data?) throws -> Data?,
                         onCommandAuthorized: @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> Data? {
        try journal.withValidatedCommandExchange(requestID: requestID, decisionSupplied: decisionFrame != nil,
            validate: { transaction in
                try self.requireCurrent(transaction)
                try transaction.requireDirectApprovalBinding(binding)
            }, body: { try handler($0, binding, requestID, decisionFrame) }, onCommandAuthorized: onCommandAuthorized)
    }

    func pairingReceipt(binding: AuthorityPeerBinding, setupID: Data,
                        handler: AuthorityPairingReceiptProvider) throws -> Data? {
        guard setupID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        return try journal.withValidatedRequests(validate: { transaction in
            try self.requireCurrent(transaction)
            try transaction.requireDirectApprovalBinding(binding)
        }, body: { owner in
            try handler(owner, binding, setupID, { transaction in
                try self.requireCurrent(transaction)
                try transaction.requireDirectApprovalBinding(binding)
            })
        })
    }

    func phonePushRegistration(binding: AuthorityPeerBinding, frame: PhonePushRegistrationFrame,
                               handler: AuthorityPhonePushRegistrationProvider) throws -> PhonePushRegistrationFrame {
        try journal.withValidatedRequests(validate: { transaction in
            try self.requireCurrent(transaction)
            try transaction.requireDirectApprovalBinding(binding)
        }, body: { owner in
            try handler(owner, binding, frame, { transaction in
                try self.requireCurrent(transaction)
                try transaction.requireDirectApprovalBinding(binding)
            })
        })
    }

    private func requireCurrent(_ transaction: JournalTransaction) throws {
        guard let snapshot = try transaction.codePolicy(), snapshot.roleRevisions[.transport] == roleRevision,
              snapshot.policy.entries.first(where: { $0.role == .transport }) == entry else {
            throw AuthorityTransportAccessError.policyMismatch
        }
    }
}
