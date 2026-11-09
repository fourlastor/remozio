import Darwin
import Foundation

/// Owns the paired read-only journal and signer for the Authority restart challenge.
final class MachineUpdateAuthorityHealthOwner: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let configuration: AuthorityServiceConfiguration
    private let requirement: Requirement
    private let policy: AuthorityCodePolicySnapshot
    private let requests: [ReleaseRequestContract]
    private let restartGateway: MachineUpdateAuthorityReadinessGateway?
    private let verifyCurrent: @Sendable () throws -> Void
    private let release: @Sendable () -> Void
    private var sign: (@Sendable (Data) throws -> Data)?
    private var closed = false, closing = false, answering = false

    /// Selects startup inputs from the retained restart snapshot without opening the journal or key.
    struct RestartSelection: Sendable {
        let host: InstalledAuthorityCommandConfiguration
        let requirement: Requirement
        let policy: AuthorityCodePolicySnapshot
        let requests: [ReleaseRequestContract]
        let gateway: MachineUpdateAuthorityReadinessGateway?
        let gatewayPolicy: GatewayAuthorityPolicy?

        init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence, accountID: Data) throws {
            let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)
            let (account, authority) = try plan.select(accountID: accountID, role: .authority)
            let host = account.configuration.host, request = host.command.presence.wake.request
            guard let policy = try snapshot.configuration.policy(accountID: accountID),
                  let component = candidate.manifest.components.first(where: { $0.role == .authority }),
                  authority.code == host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
                  authority.binding.macID == request.service.macID, authority.binding.accountID == request.service.accountID,
                  authority.binding.installationID == host.installationID, request.authorityPublicKey == authority.publicKey,
                  authority.binding.sourcePolicyRevision == policy.revision,
                  try authority.binding.sourcePolicyDigest == MachineUpdateActivationRecord.digest(policy.storedBytes) else {
                throw RuntimePreparationError.changedScope
            }
            if let selected = account.requirements.first(where: { $0.role == .notificationGateway }) {
                guard let backend = account.backend, backend.gateway.registration.rootPublicKey == authority.publicKey else {
                    throw RuntimePreparationError.changedScope
                }
                gateway = try .init(requirement: selected, registration: backend.gateway.registration)
                gatewayPolicy = try backend.source.pair.authority.material.phonePush.journalPolicy(clockEpoch: UUID())
            } else {
                gateway = nil; gatewayPolicy = nil
            }
            self.host = host; requirement = authority; self.policy = policy; requests = component.requests
        }
    }

    /// The restart owner must revalidate the exact snapshot, signed release, and observed placement in `verifyRestart`.
    static func openForRestart(_ selection: RestartSelection, activity: MachineUpdateRestartSharedActivity,
        verifyRestart: @escaping @Sendable () throws -> Void) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let host = selection.host, requirement = selection.requirement
        guard host.machineDirectory == MachineBootstrap.machineDirectory else { throw InstalledAuthorityCommandError.wrongInstallation }
        let paths = try RuntimePreparationPaths(accountID: requirement.binding.accountID)
        let path = paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name
        let codeRequirement = try AuthoritySelfValidation.requirement(for: requirement.code)
        let loan = try activity.acquireShared()
        let verify: @Sendable () throws -> Void = {
            try loan.requireScope(macID: requirement.binding.macID, installationID: requirement.binding.installationID,
                activationAttempt: requirement.binding.activationAttempt)
            try verifyRestart()
            guard try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + InstalledAuthorityCommandConfiguration.executablePath,
                  try InstalledAuthorityCommandConfiguration.load(path: path).canonicalBytes == host.canonicalBytes else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try DynamicCodeValidation.validateSelf(requirement: codeRequirement)
            try loan.validate()
        }
        let request = host.command.presence.wake.request, service = request.service
        let journal: AuthorityJournal
        do {
            try verify()
            journal = try AuthorityJournal(updateHealthStorage: AuthorityStorage.openForUpdateHealth(configuration: service,
                gatewayPolicy: selection.gatewayPolicy), validateSelf: {
                    try MachineUpdateAuthorityHealthJournalValidation.requireCurrent($0, configuration: service,
                        binding: requirement.binding, policy: selection.policy, requests: selection.requests)
                })
        } catch { loan.close(); throw error }
        let signer: EnclaveAuthorityRequestSigner
        do {
            try verify()
            signer = try EnclaveAuthorityRequestSigner.restore(ProtectedServiceConfiguration.read(path: request.keyRecordPath),
                configuration: service, expectedPublicKey: requirement.publicKey)
            try verify()
        } catch { try? journal.close(); loan.close(); throw error }
        return try .init(journal: journal, configuration: service, requirement: requirement,
            policy: selection.policy, requests: selection.requests, keyPublicKey: signer.publicKey,
            restartGateway: selection.gateway,
            verifyCurrent: verify, sign: signer.sign, release: { loan.close() })
    }

    /// The caller must authenticate the native scope and retain the existing Authority key.
    init(journal: AuthorityJournal, configuration: AuthorityServiceConfiguration, requirement: Requirement,
        policy: AuthorityCodePolicySnapshot, requests: [ReleaseRequestContract], keyPublicKey: Data,
        restartGateway: MachineUpdateAuthorityReadinessGateway? = nil,
        verifyCurrent: @escaping @Sendable () throws -> Void, sign: @escaping @Sendable (Data) throws -> Data,
        release: @escaping @Sendable () -> Void = {}) throws {
        self.journal = journal; self.configuration = configuration; self.requirement = requirement
        self.policy = policy; self.requests = requests; self.verifyCurrent = verifyCurrent
        self.restartGateway = restartGateway
        self.sign = sign; self.release = release
        do {
            guard journal.updateHealthOnly else { throw JournalDatabaseError.readOnly }
            guard requirement.role == .authority, requirement.code.role == .authority, requirement.code.active,
                  requirement.executionUID == 0, requirement.publicKey == keyPublicKey,
                  requirement.binding.macID == configuration.macID, requirement.binding.accountID == configuration.accountID,
                  requirement.binding.sourcePolicyRevision == policy.revision,
                  try requirement.binding.sourcePolicyDigest == MachineUpdateActivationRecord.digest(policy.storedBytes) else {
                throw RuntimePreparationError.changedScope
            }
            try validate()
        } catch { try? close(); throw error }
    }

    func validateHealthScope() throws {
        try lock.withLock {
            do { try validate() }
            catch { sign = nil; throw error }
        }
    }

    func answer(_ request: Data) throws -> Data {
        try answer(request, gateway: nil, makeProof: { nil })
    }

    /// Installed readiness supplies the protected Gateway selection, if registered, and the current clock.
    func answerReadiness(_ request: MachineUpdateAuthorityReadinessRequest,
        gateway: MachineUpdateAuthorityReadinessGateway?, now: AuthorityMoment) throws -> Data {
        try answer(request.challenge, gateway: gateway, makeProof: { try request.gatewayProof(expected: gateway, now: now) })
    }

    private func answer(_ request: Data, gateway: MachineUpdateAuthorityReadinessGateway?,
        makeProof: () throws -> MachineUpdateConsumerHealthProof?) throws -> Data {
        try lock.withLock {
            guard !answering else { throw MachineUpdateRoleChallengeError.unavailable }
            answering = true; defer { answering = false }
            do {
                try requireAvailable()
                guard gateway == restartGateway else { throw MachineUpdateRoleChallengeError.changedScope }
                if let gateway {
                    let selected = gateway.requirement
                    guard selected.binding == requirement.binding, selected.configurationEpoch == requirement.configurationEpoch,
                          selected.configurationRevision == requirement.configurationRevision,
                          selected.backendEpoch == requirement.backendEpoch, selected.backendRevision == requirement.backendRevision,
                          selected.code.role == .notificationGateway, selected.code.active, selected.executionUID > 0,
                          selected.executionUID < UInt32.max, gateway.registration.rootPublicKey == requirement.publicKey else {
                        throw MachineUpdateRoleChallengeError.changedScope
                    }
                }
                let proof = try makeProof()
                return try MachineUpdateRoleChallengeSession.answer(request, expected: requirement,
                    verifyCurrent: { try self.validate(gateway: gateway, proof: proof) }, sign: { bytes in
                        guard let sign = self.sign else { throw MachineUpdateRoleChallengeError.unavailable }
                        return try sign(bytes)
                    })
            } catch { sign = nil; throw error }
        }
    }

    private func validate(gateway: MachineUpdateAuthorityReadinessGateway? = nil,
        proof: MachineUpdateConsumerHealthProof? = nil) throws {
        try requireAvailable()
        try verifyCurrent()
        try requireAvailable()
        let configuration = configuration, binding = requirement.binding, policy = policy, requests = requests
        try journal.readForUpdateHealth {
            try MachineUpdateAuthorityHealthJournalValidation.requireCurrent($0, configuration: configuration,
                binding: binding, policy: policy, requests: requests)
            if let gateway, let proof {
                try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: gateway.requirement,
                    registration: gateway.registration, transaction: $0)
            }
        }
        try verifyCurrent()
        try requireAvailable()
    }

    private func requireAvailable() throws {
        guard !closed, !closing, sign != nil else { throw MachineUpdateRoleChallengeError.unavailable }
    }

    func close() throws {
        try lock.withLock {
            guard !closed else { return }
            closing = true; sign = nil
            try journal.close()
            closed = true; release()
        }
    }
    deinit { try? close() }
}
