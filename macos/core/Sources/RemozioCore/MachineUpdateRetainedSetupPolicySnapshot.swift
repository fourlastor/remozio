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
}
