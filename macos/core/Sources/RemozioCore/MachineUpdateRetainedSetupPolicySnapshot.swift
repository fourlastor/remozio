import Foundation

/// Reads retained policy metadata. The caller must separately read the paired journal and retain native custody.
struct MachineUpdateRetainedSetupPolicySnapshot {
    let activation: MachineUpdateStableRuntimeActivationSnapshot
    let intent: MachineUpdateRetainedSetupPolicyIntentRecord?

    init(activation: MachineUpdateStableRuntimeActivationSnapshot,
        intent: MachineUpdateRetainedSetupPolicyIntentRecord?, candidate: SignedReleaseEvidence) throws {
        guard activation.origin == .retained, activation.installed == nil,
              activation.state.plan == nil, !activation.state.jobsRegistered,
              activation.runtime.setup.account?.inInventory == false else { throw RuntimeActivationError.changedScope }
        _ = try activation.runtime.setup.source.unconfiguredRetainedAccount(
            accountID: activation.runtime.preparation.accountID, ownerUID: activation.runtime.preparation.ownerUID)
        try intent?.requireSnapshot(activation, candidate: candidate)
        self.activation = activation; self.intent = intent
    }
    func requireSame(as other: Self) throws {
        try activation.requireSame(as: other.activation)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }
    /// Compares retention values only. The private writer must protect every other row and the exact catalog change.
    func requireRetention(_ record: MachineUpdateRetainedSetupPolicyIntentRecord, from before: Self) throws {
        guard intent == record, before.intent == nil, record.phase == .prepared,
              MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        try requireUnchangedRuntime(from: before, allowMigration: true)
    }
    func requireTransition(_ record: MachineUpdateRetainedSetupPolicyIntentRecord, from before: Self) throws {
        guard intent == record, let previous = before.intent,
              MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        try record.requireTransition(from: previous)
        try requireUnchangedRuntime(from: before, allowMigration: false)
    }
    private func requireUnchangedRuntime(from before: Self, allowMigration: Bool) throws {
        let actual = activation.runtime.setup.source, previous = before.activation.runtime.setup.source
        let frame = actual.actual, prior = previous.actual
        try activation.runtime.setup.requireOwner(before.activation.runtime.setup.owner)
        guard !before.activation.runtime.state.configurationPublished,
              MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(prior.schemaVersion),
              frame.schemaVersion == prior.schemaVersion || (allowMigration && prior.schemaVersion == 24 && frame.schemaVersion == 25),
              frame.inventory == prior.inventory, frame.activation == prior.activation, frame.admission == prior.admission,
              frame.candidate == prior.candidate, frame.installed.record == prior.installed.record,
              frame.installed.artifacts == prior.installed.artifacts, try frame.seal.encoded == prior.seal.encoded,
              actual.historicalInventory == previous.historicalInventory, actual.provisioningHistory == previous.provisioningHistory,
              actual.preparations == previous.preparations, actual.initializations == previous.initializations,
              actual.accounts == previous.accounts,
              activation.runtime.preparation == before.activation.runtime.preparation,
              activation.runtime.plan == before.activation.runtime.plan,
              activation.runtime.reservedNumbers == before.activation.runtime.reservedNumbers,
              activation.runtime.state == before.activation.runtime.state, activation.origin == before.activation.origin,
              try activation.installed?.encoded == before.activation.installed?.encoded else {
            throw PreparationStoreError.staleRevision
        }
        try activation.requireState(before.activation.state)
    }
}
