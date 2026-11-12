import Foundation

/// Retains completion operands and receipts. It grants no writer, health proof, or ordinary startup authority.
struct MachineUpdateRetainedSetupCompletionIntentRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Codable, Sendable { case prepared = 1, writing = 2, recorded = 3 }
    enum Reconciliation: Equatable, Sendable {
        case sourceUnchanged
        case recorded(MachineUpdateRetainedSetupCompletionIntentRecord)
    }
    typealias StoredPolicy = MachineUpdatePolicyIntentRecord.StoredPolicy
    static let formatName = "authority.retained-setup-completion-intent"
    static let currentFormatVersion: UInt64 = 1
    static let maximumBytes = 262144
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let startupIntent: MachineUpdateRetainedSetupPolicyIntentRecord
    let binding: RuntimeRetainedSetupReleaseBinding
    let activationPlanDigest: Data
    let inventoryDigest: Data
    let phase: Phase
    let committedPolicy: StoredPolicy?
    let committedCheckpoint: Data?
    var description: String { "MachineUpdateRetainedSetupCompletionIntentRecord(redacted)" }
    var debugDescription: String { description }

    private init(id: UUID, revision: UUID, startupIntent: MachineUpdateRetainedSetupPolicyIntentRecord,
        binding: RuntimeRetainedSetupReleaseBinding, activationPlanDigest: Data, inventoryDigest: Data,
        phase: Phase, committedPolicy: StoredPolicy?, committedCheckpoint: Data?) throws {
        formatVersion = Self.currentFormatVersion; self.id = id; self.revision = revision
        self.startupIntent = startupIntent; self.binding = binding
        self.activationPlanDigest = activationPlanDigest; self.inventoryDigest = inventoryDigest
        self.phase = phase; self.committedPolicy = committedPolicy; self.committedCheckpoint = committedCheckpoint
        _ = try encoded
    }
    private func advanced(to phase: Phase, policy: StoredPolicy? = nil, checkpoint: Data? = nil) throws -> Self {
        try .init(id: id, revision: UUID(), startupIntent: startupIntent, binding: binding,
            activationPlanDigest: activationPlanDigest, inventoryDigest: inventoryDigest, phase: phase,
            committedPolicy: policy, committedCheckpoint: checkpoint)
    }
    /// Proposes metadata values only. The owner must separately retain the proposal and prove live health.
    init(snapshot: MachineUpdateRetainedSetupActivationSnapshot,
        source: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        id: UUID = UUID(), revision: UUID = UUID()) throws {
        guard snapshot.state.jobsRegistered, let plan = snapshot.state.plan,
              snapshot.runtime.setup.account?.inInventory == true else { throw RuntimeActivationError.incomplete }
        try snapshot.requirePair(source); try snapshot.requirePlan(plan, candidate: candidate)
        try self.init(id: id, revision: revision, startupIntent: snapshot.intent, binding: plan.retainedSetupBinding,
            activationPlanDigest: MachineUpdateActivationRecord.digest(plan.encoded),
            inventoryDigest: MachineUpdateActivationRecord.digest(snapshot.runtime.setup.source.actual.inventory.canonicalBytes),
            phase: .prepared, committedPolicy: nil, committedCheckpoint: nil)
        try requireSource(source); try requireSnapshot(snapshot, candidate: candidate)
    }
    /// Checks the registered frame. The owner must separately observe the paired stores and current health.
    func requireSnapshot(_ snapshot: MachineUpdateRetainedSetupActivationSnapshot, candidate: SignedReleaseEvidence) throws {
        try validate()
        guard snapshot.state.jobsRegistered, snapshot.runtime.setup.account?.inInventory == true,
              snapshot.intent == startupIntent, let plan = snapshot.state.plan,
              plan.retainedSetupBinding == binding,
              try MachineUpdateActivationRecord.digest(plan.encoded) == activationPlanDigest,
              MachineUpdateActivationRecord.digest(snapshot.runtime.setup.source.actual.inventory.canonicalBytes) == inventoryDigest else {
            throw PreparationStoreError.staleRevision
        }
        try snapshot.requirePlan(plan, candidate: candidate); _ = try completionPlan(candidate: candidate)
    }
    /// Derives policy values from the startup receipt. This does not write a policy or metadata row.
    func completionPlan(candidate: SignedReleaseEvidence) throws -> MachineUpdatePolicyPlan {
        try validate(); try startupIntent.requireCandidate(candidate)
        let plan = try MachineUpdatePolicyPlan(source: startupPolicy(), candidate: candidate)
        try requirePlan(plan); return plan
    }
    func requirePlan(_ plan: MachineUpdatePolicyPlan) throws {
        try validate()
        let source = try startupPolicy()
        guard plan.source == source, plan.startupPolicy == source.policy,
              plan.releaseDigest == startupIntent.installedReleaseDigest,
              try plan.completionPolicy.bytes == startupIntent.completionPolicy else { throw PreparationStoreError.staleRevision }
    }
    func requireSource(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate(); try startupIntent.requireRecorded(current)
    }
    /// The machine owner must persist this proposal before the separate account write.
    func preparingWrite(expected: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Self {
        try validate(); guard phase == .prepared else { throw PreparationStoreError.invalidTransition }
        try requireSource(expected); return try advanced(to: .writing)
    }
    /// Proposes a separate completion receipt. The immutable startup receipt remains exact.
    func recording(_ receipt: AuthorityJournal.MachineUpdatePolicyCommitReceipt) throws -> Self {
        try validate(); guard phase == .writing else { throw PreparationStoreError.invalidTransition }
        try requireSource(receipt.source)
        return try advanced(to: .recorded, policy: .init(receipt.policy), checkpoint: receipt.checkpoint.bytes)
    }
    /// An unchanged pair grants no retry authority. A recovered receipt is a proposal for its separate owner.
    func reconciling(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Reconciliation {
        try validate(); guard phase == .writing else { throw PreparationStoreError.invalidTransition }
        guard current.macID == startupIntent.macID, current.accountID == startupIntent.accountID else {
            throw PreparationStoreError.staleRevision
        }
        let source = try startupPolicy(), target = try AuthorityCodePolicy.decode(startupIntent.completionPolicy)
        if source.policy != target, current.policy == source, try current.checkpoint.bytes == startupIntent.committedCheckpoint {
            return .sourceUnchanged
        }
        try requireReceipt(policy: current.policy, checkpoint: current.checkpoint)
        return try .recorded(advanced(to: .recorded, policy: .init(current.policy), checkpoint: current.checkpoint.bytes))
    }
    func requireRecorded(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate(); guard phase == .recorded else { throw PreparationStoreError.invalidTransition }
        guard current.macID == startupIntent.macID, current.accountID == startupIntent.accountID,
              try committedPolicy?.snapshot() == current.policy,
              try current.checkpoint.bytes == committedCheckpoint else { throw PreparationStoreError.staleRevision }
    }
    func requireTransition(from previous: Self) throws {
        try validate(); try previous.validate()
        guard id == previous.id, revision != previous.revision, formatVersion == previous.formatVersion,
              startupIntent == previous.startupIntent, binding == previous.binding,
              activationPlanDigest == previous.activationPlanDigest, inventoryDigest == previous.inventoryDigest,
              previous.phase == .prepared && phase == .writing || previous.phase == .writing && phase == .recorded else {
            throw PreparationStoreError.invalidTransition
        }
    }

    private func startupPolicy() throws -> AuthorityCodePolicySnapshot {
        guard let policy = startupIntent.committedPolicy else { throw PreparationStoreError.corruptRecord }
        return try policy.snapshot()
    }
    private func validate() throws {
        _ = try startupIntent.encoded; _ = try binding.encoded
        guard formatVersion == Self.currentFormatVersion, startupIntent.phase == .recorded,
              activationPlanDigest.count == 32, inventoryDigest.count == 32,
              binding.macID == startupIntent.macID, binding.installationID == startupIntent.installationID,
              binding.accountID == startupIntent.accountID, binding.ownerUID == startupIntent.ownerUID,
              binding.installedReleaseDigest == startupIntent.installedReleaseDigest,
              binding.initializationDigest == startupIntent.initializationDigest,
              binding.retainedSourceDigest == startupIntent.sourceDigest,
              try binding.policyIntentDigest == MachineUpdateActivationRecord.digest(startupIntent.encoded),
              binding.sourceCheckpointDigest == MachineUpdateActivationRecord.digest(startupIntent.sourceCheckpoint),
              binding.startupPolicyDigest == MachineUpdateActivationRecord.digest(startupIntent.startupPolicy),
              binding.completionPolicyDigest == MachineUpdateActivationRecord.digest(startupIntent.completionPolicy),
              let checkpoint = startupIntent.committedCheckpoint else { throw PreparationStoreError.corruptRecord }
        let source = try startupPolicy()
        guard try binding.sourcePolicyDigest == MachineUpdateActivationRecord.digest(startupIntent.sourcePolicy.snapshot().storedBytes),
              try binding.startupPolicySnapshotDigest == MachineUpdateActivationRecord.digest(source.storedBytes),
              binding.startupCheckpointDigest == MachineUpdateActivationRecord.digest(checkpoint) else { throw PreparationStoreError.corruptRecord }
        try binding.requireStartupPolicy(source.policy)
        switch phase {
        case .prepared, .writing:
            guard committedPolicy == nil, committedCheckpoint == nil else { throw PreparationStoreError.corruptRecord }
        case .recorded:
            guard let committedPolicy, let committedCheckpoint else { throw PreparationStoreError.corruptRecord }
            let policy = try committedPolicy.snapshot()
            guard try policy.storedBytes == committedPolicy.bytes else { throw PreparationStoreError.corruptRecord }
            try requireReceipt(policy: policy, checkpoint: .decode(committedCheckpoint))
        }
    }
    private func requireReceipt(policy: AuthorityCodePolicySnapshot, checkpoint: ContinuityCheckpoint) throws {
        let source = try startupPolicy(), target = try AuthorityCodePolicy.decode(startupIntent.completionPolicy)
        guard let bytes = startupIntent.committedCheckpoint else { throw PreparationStoreError.corruptRecord }
        let previous = try ContinuityCheckpoint.decode(bytes)
        guard policy.policy == target else { throw PreparationStoreError.corruptRecord }
        if source.policy == target {
            guard policy == source, checkpoint == previous else { throw PreparationStoreError.corruptRecord }; return
        }
        guard previous.generation < UInt64.max, previous.currentAuthorityGeneration < UInt64.max,
              checkpoint.generation == previous.generation + 1,
              checkpoint.authorityGeneration == previous.currentAuthorityGeneration + 1,
              checkpoint.authorityDigest != previous.authorityDigest, policy.revision != source.revision,
              checkpoint.ledgerDigest == previous.ledgerDigest, checkpoint.journalEpoch == previous.journalEpoch,
              checkpoint.journalHead == previous.journalHead else { throw PreparationStoreError.corruptRecord }
        for (old, updated) in zip(source.policy.entries, target.entries) {
            guard (old == updated) == (source.roleRevisions[old.role] == policy.roleRevisions[old.role]) else {
                throw PreparationStoreError.corruptRecord
            }
        }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }; return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
}
