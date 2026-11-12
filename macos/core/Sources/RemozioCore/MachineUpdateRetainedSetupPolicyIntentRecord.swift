import Foundation

/// Proposed startup-policy progress. This record grants no writer, native health, completion floor, or request authority.
struct MachineUpdateRetainedSetupPolicyIntentRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Codable, Sendable { case prepared = 1, writing = 2, recorded = 3 }
    enum Observation: Equatable, Sendable { case sourceUnchanged, startupBoundary }
    typealias StoredPolicy = MachineUpdatePolicyIntentRecord.StoredPolicy
    static let formatName = "authority.retained-setup-policy-intent"
    static let currentFormatVersion: UInt64 = 2
    static let maximumBytes = 131072
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let macID: Data
    let installationID: Data
    let accountID: Data
    let ownerUID: UInt32
    let sourceDigest: Data
    let initializationDigest: Data
    let installedReleaseDigest: Data
    let sourcePolicy: StoredPolicy
    let sourceCheckpoint: Data
    let startupPolicy: Data
    let completionPolicy: Data
    let phase: Phase
    let committedPolicy: StoredPolicy?
    let committedCheckpoint: Data?
    var description: String { "MachineUpdateRetainedSetupPolicyIntentRecord(redacted)" }
    var debugDescription: String { description }

    init(source: MachineUpdateRetainedSetupActivationSource, id: UUID = UUID(), revision: UUID = UUID()) throws {
        let preparation = source.runtime.preparation
        guard let initialization = source.runtime.setup.account?.initialization else {
            throw RuntimeActivationError.incomplete
        }
        formatVersion = Self.currentFormatVersion; self.id = id; self.revision = revision
        macID = preparation.macID; installationID = preparation.installationID
        accountID = preparation.accountID; ownerUID = preparation.ownerUID; sourceDigest = source.digest
        initializationDigest = try MachineUpdateActivationRecord.digest(initialization.bytes)
        installedReleaseDigest = source.policy.releaseDigest
        sourcePolicy = try .init(source.policy.source); sourceCheckpoint = try source.accountPolicy.checkpoint.bytes
        startupPolicy = try source.policy.startupPolicy.bytes; completionPolicy = try source.policy.completionPolicy.bytes
        phase = .prepared; committedPolicy = nil; committedCheckpoint = nil
        try validate()
    }
    /// Checks the machine facts and archived operands without using the live account policy as the source.
    func requireMaterial(_ material: MachineUpdateRetainedSetupPolicyMaterial, candidate: SignedReleaseEvidence) throws {
        let plan = try MachineUpdatePolicyPlan(source: sourcePolicy.snapshot(), candidate: candidate)
        try requirePlan(plan)
        let preparation = material.runtime.preparation
        guard macID == preparation.macID, installationID == preparation.installationID,
              accountID == preparation.accountID, ownerUID == preparation.ownerUID,
              try MachineUpdateActivationRecord.digest(material.initialization.bytes) == initializationDigest,
              try material.scopeDigest(policy: plan, checkpoint: .decode(sourceCheckpoint)) == sourceDigest else {
            throw PreparationStoreError.staleRevision
        }
    }

    /// Checks recorded operands against current metadata. The caller separately observes the paired journal.
    func requireSnapshot(_ snapshot: MachineUpdateStableRuntimeActivationSnapshot, candidate: SignedReleaseEvidence) throws {
        try requireCandidate(candidate)
        let preparation = snapshot.runtime.preparation
        guard macID == preparation.macID, installationID == preparation.installationID,
              accountID == preparation.accountID, ownerUID == preparation.ownerUID,
              let initial = snapshot.runtime.setup.account?.initialization,
              try MachineUpdateActivationRecord.digest(initial.bytes) == initializationDigest,
              try MachineUpdateRetainedSetupActivationSource.retainedScopeDigest(snapshot: snapshot,
                sourcePolicy: sourcePolicy.snapshot(), sourceCheckpoint: .decode(sourceCheckpoint), candidate: candidate) == sourceDigest else {
            throw PreparationStoreError.staleRevision
        }
    }
    func requireCandidate(_ candidate: SignedReleaseEvidence) throws {
        try requirePlan(MachineUpdatePolicyPlan(source: sourcePolicy.snapshot(), candidate: candidate))
    }

    /// Compares a decoded record with the actual machine and the original paired stores.
    func observe(owner: LocalAccountIdentity, machine: PreparationIntentStore, journal: AuthorityJournal,
        candidate: SignedReleaseEvidence) throws -> Observation {
        let material = try machine.retainedSetupPolicyMaterial(owner: owner, candidate: candidate)
        try requireMaterial(material, candidate: candidate)
        let initialization = material.initialization
        let current = try readBoundary(journal: journal, initialization: initialization)
        try machine.retainedSetupPolicyMaterial(owner: owner, candidate: candidate).requireSame(as: material)
        guard try readBoundary(journal: journal, initialization: initialization) == current else {
            throw PreparationStoreError.staleRevision
        }
        switch phase {
        case .prepared:
            guard try current.policy == sourcePolicy.snapshot(), try current.checkpoint.bytes == sourceCheckpoint else {
                throw PreparationStoreError.staleRevision
            }
            return .sourceUnchanged
        case .writing:
            return try observeWriting(current)
        case .recorded:
            try requireRecorded(current)
            return .startupBoundary
        }
    }

    private func readBoundary(journal: AuthorityJournal, initialization: AuthorityInitializationIntent)
        throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        if phase == .prepared {
            return try journal.captureUnactivatedSetupPolicySource(expected: initialization)
        }
        return try journal.captureRetainedSetupPolicyBoundary(expected: initialization)
    }

    private func requirePlan(_ plan: MachineUpdatePolicyPlan) throws {
        try validate()
        guard try plan.source == sourcePolicy.snapshot(), plan.releaseDigest == installedReleaseDigest,
              try plan.startupPolicy.bytes == startupPolicy, try plan.completionPolicy.bytes == completionPolicy else {
            throw PreparationStoreError.staleRevision
        }
    }
    /// Classifies the actual paired read while a write outcome is unresolved.
    /// A boundary outside the source and expected successor propagates corruptRecord from receipt validation.
    private func observeWriting(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Observation {
        try validate()
        guard phase == .writing else { throw PreparationStoreError.invalidTransition }
        guard current.macID == macID, current.accountID == accountID else { throw PreparationStoreError.staleRevision }
        let source = try sourcePolicy.snapshot(), target = try AuthorityCodePolicy.decode(startupPolicy)
        if target != source.policy, current.policy == source, try current.checkpoint.bytes == sourceCheckpoint {
            return .sourceUnchanged
        }
        try requireReceipt(policy: current.policy, checkpoint: current.checkpoint)
        return .startupBoundary
    }

    /// Checks a retained acknowledgement against the actual pair. The recorded marker alone proves no current health.
    func requireRecorded(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate(); guard phase == .recorded else { throw PreparationStoreError.invalidTransition }
        guard current.macID == macID, current.accountID == accountID,
              try committedPolicy?.snapshot() == current.policy,
              try current.checkpoint.bytes == committedCheckpoint else { throw PreparationStoreError.staleRevision }
    }
    private func validate() throws {
        guard formatVersion == Self.currentFormatVersion, [macID, installationID, accountID].allSatisfy({ $0.count == 16 }),
              ownerUID > 0, ownerUID < UInt32.max,
              [sourceDigest, initializationDigest, installedReleaseDigest].allSatisfy({ $0.count == 32 }),
              [sourcePolicy.bytes, startupPolicy, completionPolicy].allSatisfy({ !$0.isEmpty && $0.count <= AuthorityCodePolicy.maximumBytes }) else {
            throw PreparationStoreError.corruptRecord
        }
        let source = try sourcePolicy.snapshot(), startup = try AuthorityCodePolicy.decode(startupPolicy)
        let completion = try AuthorityCodePolicy.decode(completionPolicy)
        _ = try ContinuityCheckpoint.decode(sourceCheckpoint)
        guard try source.storedBytes == sourcePolicy.bytes,
              startup.formatVersion == source.policy.formatVersion, completion.formatVersion == startup.formatVersion,
              startup.entries.map(\.role) == source.policy.entries.map(\.role),
              completion.entries.map(\.role) == startup.entries.map(\.role) else { throw PreparationStoreError.corruptRecord }
        try startup.requireSuccessor(of: source.policy); try completion.requireSuccessor(of: startup)
        for ((old, first), final) in zip(zip(source.policy.entries, startup.entries), completion.entries) {
            guard old.active == first.active, first.active == final.active,
                  first.minimumGeneration == old.minimumGeneration,
                  first.installedGeneration == final.installedGeneration,
                  first.codeDirectoryHash == final.codeDirectoryHash,
                  (old == first && first == final) || final.minimumGeneration == final.installedGeneration else {
                throw PreparationStoreError.corruptRecord
            }
        }
        switch phase {
        case .prepared, .writing:
            guard committedPolicy == nil, committedCheckpoint == nil else { throw PreparationStoreError.corruptRecord }
        case .recorded:
            guard let committedPolicy, let committedCheckpoint else { throw PreparationStoreError.corruptRecord }
            let committed = try committedPolicy.snapshot()
            guard try committed.storedBytes == committedPolicy.bytes else { throw PreparationStoreError.corruptRecord }
            try requireReceipt(policy: committed, checkpoint: .decode(committedCheckpoint))
        }
    }
    private func requireReceipt(policy: AuthorityCodePolicySnapshot, checkpoint: ContinuityCheckpoint) throws {
        let source = try sourcePolicy.snapshot(), previous = try ContinuityCheckpoint.decode(sourceCheckpoint)
        let target = try AuthorityCodePolicy.decode(startupPolicy)
        guard policy.policy == target else { throw PreparationStoreError.corruptRecord }
        if target == source.policy {
            guard policy == source, checkpoint == previous else { throw PreparationStoreError.corruptRecord }; return
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
            guard (old == updated) == (policy.roleRevisions[old.role] == source.roleRevisions[old.role]) else {
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
