import Foundation
import RemozioProtocol

/// Preserves recorded completion facts. Decoding grants no publication, startup, health, or mutation authority.
struct RuntimeRetainedSetupCompletionArchive: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.retained-setup-completion-archive"
    static let maximumBytes = 1_048_576
    private static let purpose = "retained-setup-completion-archive"
    let binding: RuntimeRetainedSetupCompletionBinding
    let originalActivationBytes: Data
    let completionIntentBytes: Data
    let recordedInventoryBytes: Data
    var description: String { "RuntimeRetainedSetupCompletionArchive(redacted)" }
    var debugDescription: String { description }

    private init(binding: RuntimeRetainedSetupCompletionBinding, originalActivationBytes: Data,
        completionIntentBytes: Data, recordedInventoryBytes: Data) throws {
        self.binding = binding; self.originalActivationBytes = originalActivationBytes
        self.completionIntentBytes = completionIntentBytes; self.recordedInventoryBytes = recordedInventoryBytes
        try validate()
    }

    func originalActivation() throws -> RuntimeRetainedSetupActivationArchive {
        try .decode(originalActivationBytes)
    }
    func completionIntent() throws -> MachineUpdateRetainedSetupCompletionIntentRecord {
        try .decode(completionIntentBytes)
    }
    func recordedInventory() throws -> InstallationInventory {
        try .decode(recordedInventoryBytes, expectedMacID: binding.startupBinding.macID)
    }

    private func validate() throws {
        _ = try binding.encoded
        guard !originalActivationBytes.isEmpty, originalActivationBytes.count <= RuntimeRetainedSetupActivationArchive.maximumBytes,
              !completionIntentBytes.isEmpty, completionIntentBytes.count <= MachineUpdateRetainedSetupCompletionIntentRecord.maximumBytes,
              !recordedInventoryBytes.isEmpty, recordedInventoryBytes.count <= (try InstallationInventory.limits.maxBytes),
              MachineUpdateActivationRecord.digest(originalActivationBytes) == binding.activationPlanDigest,
              MachineUpdateActivationRecord.digest(completionIntentBytes) == binding.recordedCompletionDigest,
              MachineUpdateActivationRecord.digest(recordedInventoryBytes) == binding.recordedInventoryDigest else {
            throw RuntimeActivationError.invalidPlan
        }
        let activation = try originalActivation(), record = try completionIntent(), inventory = try recordedInventory()
        let startup = binding.startupBinding
        guard activation.binding == startup, record.phase == .recorded, record.binding == startup,
              record.activationPlanDigest == binding.activationPlanDigest, record.inventoryDigest == binding.recordedInventoryDigest,
              let policy = try record.committedPolicy?.snapshot(), let checkpoint = record.committedCheckpoint,
              policy.revision == binding.completionPolicyRevision,
              try MachineUpdateActivationRecord.digest(policy.storedBytes) == binding.completionPolicySnapshotDigest,
              MachineUpdateActivationRecord.digest(checkpoint) == binding.completionCheckpointDigest,
              inventory.macID == startup.macID, inventory.installationID == startup.installationID,
              inventory.releaseDigest == startup.installedReleaseDigest, inventory.bundlePath == activation.bundlePath,
              inventory.accounts.contains(where: { $0.accountID == startup.accountID && $0.ownerUID == startup.ownerUID }) else {
            throw RuntimeActivationError.changedScope
        }
        try startup.requireHistoricalRuntime(activation.reference)
        try binding.requireCompletionPolicy(policy.policy)
    }

    var encoded: Data { get throws {
        try validate()
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose),
            2: .bytes(binding.encoded), 3: .bytes(originalActivationBytes),
            4: .bytes(completionIntentBytes), 5: .bytes(recordedInventoryBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes,
                  case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1), fields[1] == .text(purpose),
                  case .bytes(let binding) = fields[2], case .bytes(let activation) = fields[3],
                  case .bytes(let completion) = fields[4], case .bytes(let inventory) = fields[5] else {
                throw RuntimeActivationError.invalidPlan
            }
            let value = try Self(binding: .decode(binding), originalActivationBytes: activation,
                completionIntentBytes: completion, recordedInventoryBytes: inventory)
            guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }
            return value
        } catch { throw RuntimeActivationError.invalidPlan }
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 13)
}
