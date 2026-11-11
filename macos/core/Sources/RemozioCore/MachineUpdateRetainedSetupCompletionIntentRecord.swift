import Foundation

/// Retains completion operands and receipts. It grants no writer, health proof, or ordinary startup authority.
struct MachineUpdateRetainedSetupCompletionIntentRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Codable, Sendable { case prepared = 1, writing = 2, recorded = 3 }
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
