import Foundation

/// Retained runtime provenance and recorded startup facts only. This value grants no publication, startup, health or completion authority.
struct RuntimeRetainedSetupReleaseBinding: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.retained-setup-release"
    static let maximumBytes = 8192
    let formatVersion: UInt64
    let macID: Data
    let installationID: Data
    let accountID: Data
    let ownerUID: UInt32
    let activationAttempt: UUID
    let candidateDigest: Data
    let admissionDigest: Data
    let updateID: Data
    let stableSealDigest: Data
    let installedEpochDigest: Data
    let sealedInventoryDigest: Data
    let sourceAccountDigest: Data
    let preparationDigest: Data
    let initializationDigest: Data
    let provisioningInventoryDigest: Data
    let provisioningReleaseDigest: Data
    let previousInstalledReleaseDigest: Data
    let installedReleaseDigest: Data
    let runtimeReferenceDigest: Data
    let retainedSourceDigest: Data
    let policyIntentDigest: Data
    let sourcePolicyDigest: Data
    let sourceCheckpointDigest: Data
    let startupPolicyDigest: Data
    let startupPolicySnapshotDigest: Data
    let startupCheckpointDigest: Data
    let completionPolicyDigest: Data
    var description: String { "RuntimeRetainedSetupReleaseBinding(redacted)" }
    var debugDescription: String { description }

    init(snapshot: MachineUpdateRetainedSetupPolicySnapshot, current: AuthorityJournal.MachineUpdatePolicyBoundary,
        candidate: SignedReleaseEvidence) throws {
        try Self.requireFormats(candidate)
        guard let intent = snapshot.intent, intent.phase == .recorded,
              let reference = snapshot.activation.runtime.state.reference else { throw RuntimeActivationError.incomplete }
        try intent.requireSnapshot(snapshot.activation, candidate: candidate); try intent.requireRecorded(current)
        let runtime = snapshot.activation.runtime, preparation = runtime.preparation, source = runtime.setup.source
        let actual = source.actual, seal = actual.seal
        let original = try source.unconfiguredRetainedAccount(accountID: preparation.accountID, ownerUID: preparation.ownerUID)
        let provisioning = try source.provisioningInventory(accountID: preparation.accountID,
            ownerUID: preparation.ownerUID, releaseDigest: preparation.releaseDigest)
        try reference.validate(account: preparation, services: runtime.plan)
        guard reference.services.releaseDigest == provisioning.releaseDigest,
              provisioning.releaseDigest != actual.inventory.releaseDigest,
              intent.installedReleaseDigest == actual.inventory.releaseDigest else { throw RuntimeActivationError.changedScope }
        formatVersion = 1; macID = preparation.macID; installationID = preparation.installationID
        accountID = preparation.accountID; ownerUID = preparation.ownerUID; activationAttempt = seal.finishing.attemptID
        candidateDigest = seal.finishing.candidateDigest; admissionDigest = seal.finishing.admissionDigest
        updateID = seal.finishing.updateID; stableSealDigest = try Self.digest(seal.encoded)
        installedEpochDigest = try Self.digest(actual.installed.record.encoded); sealedInventoryDigest = seal.initialInventoryDigest
        sourceAccountDigest = original.sourceDigest; preparationDigest = try Self.digest(preparation.bytes)
        initializationDigest = intent.initializationDigest; provisioningInventoryDigest = Self.digest(provisioning.canonicalBytes)
        provisioningReleaseDigest = provisioning.releaseDigest; previousInstalledReleaseDigest = source.historicalInventory.releaseDigest
        installedReleaseDigest = actual.inventory.releaseDigest; runtimeReferenceDigest = try Self.digest(reference.encoded)
        retainedSourceDigest = intent.sourceDigest; policyIntentDigest = try Self.digest(intent.encoded)
        sourcePolicyDigest = try Self.digest(intent.sourcePolicy.snapshot().storedBytes)
        sourceCheckpointDigest = Self.digest(intent.sourceCheckpoint)
        startupPolicyDigest = Self.digest(intent.startupPolicy); startupPolicySnapshotDigest = try Self.digest(current.policy.storedBytes)
        startupCheckpointDigest = try Self.digest(current.checkpoint.bytes); completionPolicyDigest = Self.digest(intent.completionPolicy)
        try validate(); try requireHistoricalRuntime(reference); try requireStartupPolicy(current.policy.policy)
    }
    /// The publication owner supplies fresh actual reads. Other account rows and native ownership require its enclosing scope.
    func requireSourceForPublication(_ snapshot: MachineUpdateRetainedSetupPolicySnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence) throws {
        guard try Self(snapshot: snapshot, current: current, candidate: candidate) == self else { throw RuntimeActivationError.changedScope }
    }
    /// Compares archived provenance with an exact historical runtime. It grants no current startup authority.
    func requireHistoricalRuntime(_ reference: RuntimeMaterialReference) throws {
        try validate()
        let services = reference.services
        guard macID == services.macID, installationID == services.installationID, accountID == services.accountID,
              ownerUID == services.ownerUID, provisioningReleaseDigest == services.releaseDigest,
              try runtimeReferenceDigest == Self.digest(reference.encoded) else { throw RuntimeActivationError.changedScope }
    }

    func requirePreparation(_ account: AccountPreparationIntent) throws {
        try validate()
        guard account.macID == macID, account.installationID == installationID, account.accountID == accountID,
              account.ownerUID == ownerUID, account.releaseDigest == provisioningReleaseDigest,
              try Self.digest(account.bytes) == preparationDigest else { throw RuntimeActivationError.changedScope }
    }
    func requireStartupPolicy(_ policy: AuthorityCodePolicy) throws {
        try validate()
        guard try Self.digest(policy.bytes) == startupPolicyDigest else { throw RuntimeActivationError.changedScope }
    }

    /// Compares stored policy bytes and the checkpoint. It does not compare the global policy revision.
    /// Publication must also use requireSourceForPublication with the current snapshot and boundary.
    func requireRecordedBoundary(_ boundary: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate(); try requireStartupPolicy(boundary.policy.policy)
        guard boundary.macID == macID, boundary.accountID == accountID,
              try Self.digest(boundary.policy.storedBytes) == startupPolicySnapshotDigest,
              try Self.digest(boundary.checkpoint.bytes) == startupCheckpointDigest else { throw RuntimeActivationError.changedScope }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try MachineUpdatePreflightCompatibility.retainedSetupRequirements
    } }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    private static func digest(_ bytes: Data) -> Data { MachineUpdateActivationRecord.digest(bytes) }
    private func validate() throws {
        guard formatVersion == 1, [macID, installationID, accountID].allSatisfy({ $0.count == 16 }),
              ownerUID > 0, ownerUID < UInt32.max, provisioningReleaseDigest != installedReleaseDigest,
              [candidateDigest, admissionDigest, updateID, stableSealDigest, installedEpochDigest, sealedInventoryDigest,
               sourceAccountDigest, preparationDigest, initializationDigest, provisioningInventoryDigest, provisioningReleaseDigest,
               previousInstalledReleaseDigest, installedReleaseDigest, runtimeReferenceDigest, retainedSourceDigest, policyIntentDigest,
               sourcePolicyDigest, sourceCheckpointDigest, startupPolicyDigest, startupPolicySnapshotDigest,
               startupCheckpointDigest, completionPolicyDigest].allSatisfy({ $0.count == 32 }) else {
            throw RuntimeActivationError.invalidPlan
        }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw RuntimeActivationError.invalidPlan }; return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw RuntimeActivationError.invalidPlan }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return value
        } catch { throw RuntimeActivationError.invalidPlan }
    }
}
