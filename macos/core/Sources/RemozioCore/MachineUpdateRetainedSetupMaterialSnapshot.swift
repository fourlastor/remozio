import Foundation

/// Checked retained material metadata. The private writer must separately pin every other row and the catalog.
struct MachineUpdateRetainedSetupMaterialSnapshot {
    let runtime: MachineUpdateStableRuntimePreparationSnapshot
    let activation: RuntimeActivationState

    init(runtime: MachineUpdateStableRuntimePreparationSnapshot, activation: RuntimeActivationState) throws {
        let setup = runtime.setup
        guard setup.account?.origin == .retained, setup.account?.inInventory == false,
              setup.account?.initialization?.complete == true, runtime.preparation.storagePrepared,
              !runtime.state.configurationPublished, activation.plan == nil, !activation.jobsRegistered else {
            throw RuntimePreparationError.changedScope
        }
        _ = try setup.source.unconfiguredRetainedAccount(accountID: runtime.preparation.accountID,
            ownerUID: runtime.preparation.ownerUID)
        self.runtime = runtime; self.activation = activation
    }

    func requireReference(_ reference: RuntimeMaterialReference) throws {
        try reference.validate(account: runtime.preparation, services: runtime.plan)
        if let previous = runtime.state.reference {
            guard previous == reference else { throw RuntimePreparationError.conflictingMaterial }
        }
    }

    func requireSame(as other: Self) throws {
        try runtime.requireSame(as: other.runtime)
        try requireActivation(other.activation)
    }

    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try runtime.requireCurrent(machine: machine, candidate: candidate)
        try requireActivation(machine.runtimeActivation(accountID: runtime.preparation.accountID))
        try runtime.requireCurrent(machine: machine, candidate: candidate)
    }

    /// Allows only an unpublished reference. This comparison grants no storage or native authority.
    func requireRetained(_ reference: RuntimeMaterialReference, from before: Self) throws {
        try before.requireReference(reference)
        try runtime.setup.requireAccountStorageState(preparation: before.runtime.preparation,
            initialization: before.runtime.setup.account?.initialization, from: before.runtime.setup)
        guard runtime.preparation == before.runtime.preparation, runtime.plan == before.runtime.plan,
              runtime.reservedNumbers == before.runtime.reservedNumbers,
              runtime.state == .init(reference: reference, configurationPublished: false) else {
            throw PreparationStoreError.staleRevision
        }
        try requireActivation(before.activation)
    }

    private func requireActivation(_ other: RuntimeActivationState) throws {
        guard activation.jobsRegistered == other.jobsRegistered,
              try activation.plan?.encoded == other.plan?.encoded else { throw PreparationStoreError.staleRevision }
    }
}
