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

    /// Compares archived provenance with an exact historical runtime. It grants no current startup authority.
    func requireHistoricalRuntime(_ reference: RuntimeMaterialReference) throws {
        try validate()
        let services = reference.services
        guard macID == services.macID, installationID == services.installationID, accountID == services.accountID,
              ownerUID == services.ownerUID, provisioningReleaseDigest == services.releaseDigest,
              try runtimeReferenceDigest == Self.digest(reference.encoded) else { throw RuntimeActivationError.changedScope }
    }

    func requireStartupPolicy(_ policy: AuthorityCodePolicy) throws {
        try validate()
        guard try Self.digest(policy.bytes) == startupPolicyDigest else { throw RuntimeActivationError.changedScope }
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
