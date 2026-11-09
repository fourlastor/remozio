import Foundation

/// Retained policy operands only. This record grants no writer, native health, request admission or machine completion authority.
struct MachineUpdatePolicyIntentRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Codable, Sendable { case prepared = 1, writing = 2, recorded = 3 }
    enum Reconciliation: Equatable, Sendable {
        case sourceUnchanged
        case recorded(MachineUpdatePolicyIntentRecord)
    }
    struct EpochScope: Codable, Equatable, Sendable {
        let configurationID: UUID
        let configurationRevision: UUID
        let configurationDigest: Data
        let backendID: UUID
        let backendRevision: UUID
        let backendDigest: Data

        init(configuration: MachineUpdateConfigurationEpochRecord, backend: MachineUpdateBackendEpochRecord) throws {
            configurationID = configuration.id; configurationRevision = configuration.revision
            configurationDigest = try MachineUpdateActivationRecord.digest(configuration.encoded)
            backendID = backend.id; backendRevision = backend.revision
            backendDigest = try MachineUpdateActivationRecord.digest(backend.encoded)
        }
        init(configurationID: UUID, configurationRevision: UUID, configurationDigest: Data,
             backendID: UUID, backendRevision: UUID, backendDigest: Data) {
            self.configurationID = configurationID; self.configurationRevision = configurationRevision
            self.configurationDigest = configurationDigest; self.backendID = backendID
            self.backendRevision = backendRevision; self.backendDigest = backendDigest
        }
    }
    struct StoredPolicy: Codable, Equatable, Sendable {
        let revision: UUID
        let bytes: Data
        init(_ value: AuthorityCodePolicySnapshot) throws { revision = value.revision; bytes = try value.storedBytes }
        func snapshot() throws -> AuthorityCodePolicySnapshot { try .decodeStored(bytes, revision: revision) }
    }
    static let formatName = "authority.machine-update-policy-intent"
    static let maximumBytes = 262144
    let formatVersion: UInt64
    let id: UUID
    private(set) var revision: UUID
    let binding: RuntimeReleaseBinding
    let epochs: EpochScope
    let sourcePolicy: StoredPolicy
    let sourceCheckpoint: Data
    let completionPolicy: Data
    private(set) var phase: Phase
    private(set) var committedPolicy: StoredPolicy?
    private(set) var committedCheckpoint: Data?
    var policyRecorded: Bool { phase == .recorded }
    var description: String { "MachineUpdatePolicyIntentRecord(redacted)" }
    var debugDescription: String { description }

    init(binding: RuntimeReleaseBinding, epochs: EpochScope,
         source: AuthorityJournal.MachineUpdatePolicyBoundary, plan: MachineUpdatePolicyPlan,
         id: UUID = UUID(), revision: UUID = UUID()) throws {
        guard source.macID == binding.macID, source.accountID == binding.accountID,
              source.policy == plan.source, plan.releaseDigest == binding.installedReleaseDigest else {
            throw PreparationStoreError.staleRevision
        }
        try binding.requireStartupPolicy(plan.startupPolicy)
        try binding.requireCompletionPolicy(plan.completionPolicy)
        formatVersion = 1; self.id = id; self.revision = revision; self.binding = binding; self.epochs = epochs
        sourcePolicy = try .init(source.policy); sourceCheckpoint = try source.checkpoint.bytes
        completionPolicy = try plan.completionPolicy.bytes; phase = .prepared
        committedPolicy = nil; committedCheckpoint = nil
        try validate()
    }

    /// Checks the archived scope only. Live owners must separately validate their current stores and native boundary.
    func requireSnapshot(_ snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence) throws {
        try validate()
        _ = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)
        guard snapshot.source.replacement.activation.phase == .restartChecking,
              try EpochScope(configuration: snapshot.configuration.record, backend: snapshot.backend.record) == epochs,
              try snapshot.configuration.policy(accountID: binding.accountID) == sourcePolicy.snapshot(),
              let plans = try snapshot.configuration.configuration(accountID: binding.accountID),
              plans.completion.binding == binding,
              try plans.completion.host.codePolicy.bytes == completionPolicy else {
            throw PreparationStoreError.staleRevision
        }
        try binding.requireSourceForPublication(snapshot.source, currentPolicy: sourcePolicy.snapshot(), candidate: candidate)
    }

    func requireSource(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate()
        guard current.macID == binding.macID, current.accountID == binding.accountID,
              try current.policy == sourcePolicy.snapshot(), try current.checkpoint.bytes == sourceCheckpoint else {
            throw PreparationStoreError.staleRevision
        }
    }

    /// Proposes the write marker. The machine owner must persist it before the account write starts.
    func preparingWrite(expected: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Self {
        guard phase == .prepared else { throw PreparationStoreError.invalidTransition }
        try requireSource(expected)
        var next = self; next.revision = UUID(); next.phase = .writing
        try next.validate(); return next
    }

    /// Proposes retained receipt facts only. The machine owner must independently persist this transition.
    func recording(_ receipt: AuthorityJournal.MachineUpdatePolicyCommitReceipt) throws -> Self {
        guard phase == .writing else { throw PreparationStoreError.invalidTransition }
        try requireSource(receipt.source)
        var next = self; next.revision = UUID(); next.phase = .recorded
        next.committedPolicy = try StoredPolicy(receipt.policy); next.committedCheckpoint = try receipt.checkpoint.bytes
        try next.validate(); return next
    }

    /// Classifies a fresh paired read. An unchanged source grants no retry or writer authority.
    func reconciling(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Reconciliation {
        try validate()
        guard phase == .writing else { throw PreparationStoreError.invalidTransition }
        guard current.macID == binding.macID, current.accountID == binding.accountID else { throw PreparationStoreError.staleRevision }
        let source = try sourcePolicy.snapshot(), target = try AuthorityCodePolicy.decode(completionPolicy)
        if target != source.policy, current.policy == source, try current.checkpoint.bytes == sourceCheckpoint {
            return .sourceUnchanged
        }
        try requireReceipt(policy: current.policy, checkpoint: current.checkpoint, source: source, target: target)
        var next = self; next.revision = UUID(); next.phase = .recorded
        next.committedPolicy = try StoredPolicy(current.policy); next.committedCheckpoint = try current.checkpoint.bytes
        try next.validate()
        return .recorded(next)
    }

    private func validate() throws {
        _ = try binding.encoded
        guard formatVersion == 1, binding.formatVersion == 2,
              epochs.configurationDigest.count == 32, epochs.backendDigest.count == 32,
              !sourcePolicy.bytes.isEmpty, sourcePolicy.bytes.count <= AuthorityCodePolicy.maximumBytes,
              !completionPolicy.isEmpty, completionPolicy.count <= AuthorityCodePolicy.maximumBytes else {
            throw PreparationStoreError.corruptRecord
        }
        let source = try sourcePolicy.snapshot(), target = try AuthorityCodePolicy.decode(completionPolicy)
        _ = try ContinuityCheckpoint.decode(sourceCheckpoint)
        guard source.revision == binding.sourcePolicyRevision,
              try source.storedBytes == sourcePolicy.bytes,
              MachineUpdateActivationRecord.digest(sourcePolicy.bytes) == binding.sourcePolicyDigest,
              target.formatVersion == source.policy.formatVersion,
              target.entries.map(\.role) == source.policy.entries.map(\.role),
              zip(target.entries, source.policy.entries).allSatisfy({ pair in pair.0.active == pair.1.active }) else {
            throw PreparationStoreError.corruptRecord
        }
        try target.requireSuccessor(of: source.policy)
        try binding.requireCompletionPolicy(target)
        switch phase {
        case .prepared, .writing:
            guard committedPolicy == nil, committedCheckpoint == nil else { throw PreparationStoreError.corruptRecord }
        case .recorded:
            guard let committedPolicy, let committedCheckpoint,
                  !committedPolicy.bytes.isEmpty, committedPolicy.bytes.count <= AuthorityCodePolicy.maximumBytes else {
                throw PreparationStoreError.corruptRecord
            }
            try requireReceipt(policy: committedPolicy.snapshot(), checkpoint: ContinuityCheckpoint.decode(committedCheckpoint),
                source: source, target: target)
        }
    }

    private func requireReceipt(policy: AuthorityCodePolicySnapshot, checkpoint: ContinuityCheckpoint,
                                source: AuthorityCodePolicySnapshot, target: AuthorityCodePolicy) throws {
        let previous = try ContinuityCheckpoint.decode(sourceCheckpoint)
        guard policy.policy == target else { throw PreparationStoreError.corruptRecord }
        if target == source.policy {
            guard policy == source, checkpoint == previous else { throw PreparationStoreError.corruptRecord }
            return
        }
        guard previous.generation < UInt64.max, previous.currentAuthorityGeneration < UInt64.max,
              checkpoint.generation == previous.generation + 1,
              checkpoint.authorityGeneration == previous.currentAuthorityGeneration + 1,
              checkpoint.authorityDigest != previous.authorityDigest,
              checkpoint.ledgerDigest == previous.ledgerDigest, checkpoint.journalEpoch == previous.journalEpoch,
              checkpoint.journalHead == previous.journalHead, policy.revision != source.revision else {
            throw PreparationStoreError.corruptRecord
        }
        for (old, updated) in zip(source.policy.entries, target.entries) {
            if old == updated {
                guard policy.roleRevisions[old.role] == source.roleRevisions[old.role] else { throw PreparationStoreError.corruptRecord }
            } else {
                guard policy.roleRevisions[old.role] != source.roleRevisions[old.role] else { throw PreparationStoreError.corruptRecord }
            }
        }
    }

    var encoded: Data { get throws {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
}
