import Darwin
import Foundation

/// Owns a paired journal for a registered Gateway without selecting an unregistered Authority health role.
final class MachineUpdateGatewayPairedHealthReader: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let configuration: AuthorityServiceConfiguration
    private let expected: MachineUpdateRestartHealthPlan.Requirement
    private let registration: GatewayRegistrationIdentity
    private let policy: AuthorityCodePolicySnapshot
    private let requests: [ReleaseRequestContract]
    private let verifyCurrent: @Sendable () throws -> Void
    private let release: @Sendable () -> Void
    private var closed = false, closing = false, retired = false, consumed = false
    private var retainedProof: MachineUpdateConsumerHealthProof?

    /// Gateway-only selection deliberately excludes any account whose foreground owner already holds the paired journal.
    struct RestartSelection {
        let account: MachineUpdateRestartHealthPlan.Account
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let backend: RuntimeReleaseBackendPlan
        let policy: AuthorityCodePolicySnapshot
        let requests: [ReleaseRequestContract]

        init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence, accountID: Data) throws {
            let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)
            let (account, requirement) = try plan.select(accountID: accountID, role: .notificationGateway)
            guard !account.requirements.contains(where: { $0.role == .authority }),
                  let backend = account.backend,
                  let policy = try snapshot.configuration.policy(accountID: accountID),
                  let authority = candidate.manifest.components.first(where: { $0.role == .authority }),
                  backend.gateway.registration.rootPublicKey == account.configuration.host.command.presence.wake.request.authorityPublicKey else {
                throw RuntimePreparationError.changedScope
            }
            self.account = account; self.requirement = requirement; self.backend = backend
            self.policy = policy; requests = authority.requests
        }
    }

    /// Borrows closed admission and opens only the paired read-only journal. No Authority signing key is loaded.
    static func openForRestart(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence, accountID: Data,
        activity: MachineUpdateRestartSharedActivity, sourceAccess: MachineUpdateHealthSourceAccess,
        readCurrent: @escaping @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let selected = try RestartSelection(snapshot: snapshot, candidate: candidate, accountID: accountID)
        let host = selected.account.configuration.host
        let request = host.command.presence.wake.request
        let service = request.service, expected = selected.requirement, policy = selected.policy, requests = selected.requests
        let verifier = MachineUpdateNativeRestartVerifier(snapshot: snapshot, host: host, sourceAccess: sourceAccess,
            readCurrent: readCurrent)
        let loan = try activity.acquireShared()
        let verify: @Sendable () throws -> Void
        let journal: AuthorityJournal
        do {
            verify = try verifier.authorityCheck(binding: expected.binding, loan: loan)
            try verify()
            let gatewayPolicy = try selected.backend.source.pair.authority.material.phonePush.journalPolicy(clockEpoch: UUID())
            journal = try AuthorityJournal(updateHealthStorage: AuthorityStorage.openForUpdateHealth(configuration: service,
                gatewayPolicy: gatewayPolicy), validateSelf: {
                    try MachineUpdateAuthorityHealthJournalValidation.requireCurrent($0, configuration: service,
                        binding: expected.binding, policy: policy, requests: requests)
                })
        } catch { loan.close(); throw error }
        return try Self(journal: journal, configuration: service, expected: expected,
            gateway: selected.backend.gateway, rootPublicKey: request.authorityPublicKey,
            policy: policy, requests: requests, verifyCurrent: verify, release: { loan.close() })
    }

    /// The native bootstrap supplies an authenticated context. Owned tests supply a paired fixture and injected checks.
    init(journal: AuthorityJournal, configuration: AuthorityServiceConfiguration,
        expected: MachineUpdateRestartHealthPlan.Requirement, gateway: GatewayServiceConfiguration,
        rootPublicKey: Data, policy: AuthorityCodePolicySnapshot, requests: [ReleaseRequestContract],
        verifyCurrent: @escaping @Sendable () throws -> Void, release: @escaping @Sendable () -> Void = {}) throws {
        self.journal = journal; self.configuration = configuration; self.expected = expected
        registration = gateway.registration; self.policy = policy; self.requests = requests
        self.verifyCurrent = verifyCurrent; self.release = release
        do {
            guard journal.updateHealthOnly else { throw JournalDatabaseError.readOnly }
            guard expected.role == .notificationGateway, expected.code.role == .notificationGateway, expected.code.active,
                  expected.executionUID == gateway.serviceUID, expected.publicKey == gateway.receiptPublicKey,
                  expected.binding.macID == configuration.macID, expected.binding.accountID == configuration.accountID,
                  registration.macID == configuration.macID, registration.accountID == configuration.accountID,
                  registration.rootPublicKey == rootPublicKey,
                  expected.binding.sourcePolicyRevision == policy.revision,
                  try expected.binding.sourcePolicyDigest == MachineUpdateActivationRecord.digest(policy.storedBytes) else {
                throw RuntimePreparationError.changedScope
            }
            try validate()
        } catch { try? close(); throw error }
    }
    /// The fresh authenticated report must match the exact local head and retained history in the paired read.
    func accept(_ proof: MachineUpdateConsumerHealthProof) throws {
        try lock.withLock {
            guard !closed, !closing, !retired, !consumed else { throw MachineUpdateRoleChallengeError.unavailable }
            consumed = true
            do {
                try validate()
                let configuration = configuration, expected = expected, registration = registration
                let policy = policy, requests = requests
                try journal.readForUpdateHealth { transaction in
                    try MachineUpdateAuthorityHealthJournalValidation.requireCurrent(transaction, configuration: configuration,
                        binding: expected.binding, policy: policy, requests: requests)
                    try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: expected,
                        registration: registration, transaction: transaction)
                }
                try validate(); retainedProof = proof
            } catch { retired = true; throw error }
        }
    }
    func validateHealthScope() throws {
        try lock.withLock {
            guard !closed, !closing, !retired, let proof = retainedProof else { throw MachineUpdateRoleChallengeError.unavailable }
            do {
                try validate()
                let configuration = configuration, expected = expected, registration = registration, policy = policy, requests = requests
                try journal.readForUpdateHealth { transaction in
                    try MachineUpdateAuthorityHealthJournalValidation.requireCurrent(transaction, configuration: configuration,
                        binding: expected.binding, policy: policy, requests: requests)
                    try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: expected,
                        registration: registration, transaction: transaction)
                }
                try validate()
            } catch MachineUpdateHealthSourceError.busy { throw MachineUpdateHealthSourceError.busy }
            catch { retired = true; throw error }
        }
    }
    private func validate() throws {
        try lock.withLock {
            guard !closed, !closing, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
            try verifyCurrent()
            guard !closed, !closing, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
            let configuration = configuration, expected = expected, policy = policy, requests = requests
            try journal.readForUpdateHealth {
                try MachineUpdateAuthorityHealthJournalValidation.requireCurrent($0, configuration: configuration,
                    binding: expected.binding, policy: policy, requests: requests)
            }
            try verifyCurrent()
            guard !closed, !closing, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
        }
    }
    func close() throws {
        try lock.withLock {
            guard !closed else { return }; closing = true
            try journal.close()
            closed = true; retainedProof = nil; release()
        }
    }
    deinit { try? close() }
}
