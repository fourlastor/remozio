import Foundation

/// Decodes archived completion facts. The value grants no publication, health, admission, or startup authority.
struct RuntimeRetainedSetupCompletionBinding: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.retained-setup-completion"
    static let maximumBytes = 16384
    let formatVersion: UInt64
    let startupBinding: RuntimeRetainedSetupReleaseBinding
    let recordedCompletionDigest: Data
    let activationPlanDigest: Data
    let recordedInventoryDigest: Data
    let completionPolicyRevision: UUID
    let completionPolicySnapshotDigest: Data
    let completionCheckpointDigest: Data
    var description: String { "RuntimeRetainedSetupCompletionBinding(redacted)" }
    var debugDescription: String { description }

    func requireCompletionPolicy(_ policy: AuthorityCodePolicy) throws {
        try validate()
        guard try Self.digest(policy.bytes) == startupBinding.completionPolicyDigest else {
            throw RuntimeActivationError.changedScope
        }
    }

    /// Checks the exact recorded completion pair. The policy digest and the global revision have separate checks.
    func requireRecordedBoundary(_ boundary: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try validate(); try requireCompletionPolicy(boundary.policy.policy)
        guard boundary.macID == startupBinding.macID, boundary.accountID == startupBinding.accountID,
              boundary.policy.revision == completionPolicyRevision,
              try Self.digest(boundary.policy.storedBytes) == completionPolicySnapshotDigest,
              try Self.digest(boundary.checkpoint.bytes) == completionCheckpointDigest else {
            throw RuntimeActivationError.changedScope
        }
    }

    private static func digest(_ bytes: Data) -> Data { MachineUpdateActivationRecord.digest(bytes) }
    private func validate() throws {
        _ = try startupBinding.encoded
        guard formatVersion == 1,
              [recordedCompletionDigest, activationPlanDigest, recordedInventoryDigest,
               completionPolicySnapshotDigest, completionCheckpointDigest].allSatisfy({ $0.count == 32 }) else {
            throw RuntimeActivationError.invalidPlan
        }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw RuntimeActivationError.invalidPlan }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw RuntimeActivationError.invalidPlan }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }
            return value
        } catch { throw RuntimeActivationError.invalidPlan }
    }
}
