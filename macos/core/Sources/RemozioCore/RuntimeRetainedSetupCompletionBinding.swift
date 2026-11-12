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

    init(snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence) throws {
        try snapshot.requireSame(as: .init(activation: snapshot.activation, intent: snapshot.intent, candidate: candidate))
        guard case .completionRecorded(let record) = try snapshot.classifyPair(current),
              let plan = snapshot.activation.state.plan, record.binding == plan.retainedSetupBinding else {
            throw RuntimeActivationError.incomplete
        }
        let binding = plan.retainedSetupBinding
        try record.requireSnapshot(snapshot.activation, candidate: candidate)
        formatVersion = 1; startupBinding = binding
        recordedCompletionDigest = try Self.digest(record.encoded)
        activationPlanDigest = record.activationPlanDigest
        recordedInventoryDigest = record.inventoryDigest
        completionPolicyRevision = current.policy.revision
        completionPolicySnapshotDigest = try Self.digest(current.policy.storedBytes)
        completionCheckpointDigest = try Self.digest(current.checkpoint.bytes)
        try validate(); try requireRecordedBoundary(current)
    }
    func requireSourceForPublication(_ snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence) throws {
        guard try Self(snapshot: snapshot, current: current, candidate: candidate) == self else {
            throw RuntimeActivationError.changedScope
        }
    }
    /// Compares archived provenance only. Current preparation and native admission need a separate owner.
    func requireHistoricalRuntime(_ reference: RuntimeMaterialReference) throws {
        try validate(); try startupBinding.requireHistoricalRuntime(reference)
    }

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

    static var completedHostRequirements: [RetainedReleaseFormat] { get throws {
        var values: [RetainedReleaseFormat] = []
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            values.append(try .init(role: role, name: formatName, readVersions: [1], writeVersions: role == .setupController ? [1] : []))
            values.append(try .init(role: role, name: GatewaySettingsConsumerHostConfiguration.formatName,
                readVersions: [GatewaySettingsConsumerHostConfiguration.retainedSetupCompletionVersion],
                writeVersions: role == .setupController ? [GatewaySettingsConsumerHostConfiguration.retainedSetupCompletionVersion] : []))
        }
        for role in [AuthorityCodeRole.authority, .setupController] {
            for name in [RuntimeRetainedSetupCompletionArchive.formatName, RuntimeRetainedSetupCompletionConfiguration.formatName,
                         RuntimeRetainedSetupCompletionPublication.formatName] {
                values.append(try .init(role: role, name: name, readVersions: [1], writeVersions: role == .setupController ? [1] : []))
            }
        }
        return values
    } }
    static func requireCompletedHostFormats(_ candidate: SignedReleaseEvidence) throws {
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        for requirement in try completedHostRequirements {
            guard let declaration = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
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
