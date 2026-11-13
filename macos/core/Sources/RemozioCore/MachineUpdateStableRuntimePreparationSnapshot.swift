import Foundation

/// Reads stable service claims and runtime material. It grants no authority to create accounts or publish files.
struct MachineUpdateStableRuntimePreparationSnapshot {
    let setup: MachineUpdateStableAccountSetupSnapshot
    let preparation: AccountPreparationIntent
    let plan: ServiceAccountPlan
    let state: RuntimePreparationState
    let reservedNumbers: Set<UInt32>

    init(setup: MachineUpdateStableAccountSetupSnapshot, services: ServiceAccountPlanStorage.State,
        state: RuntimePreparationState, reservedNumbers: Set<UInt32>) throws {
        guard let preparation = setup.preparation, preparation.storagePrepared,
              setup.account?.initialization?.complete == true, services.complete, let plan = services.plan,
              state.reference != nil || !state.configurationPublished else { throw RuntimePreparationError.incomplete }
        try plan.validate(account: preparation)
        guard reservedNumbers.count <= 128,
              Set(plan.claims.map(\.number)).isSubset(of: reservedNumbers) else { throw RuntimePreparationError.changedScope }
        try state.reference?.validate(account: preparation, services: plan)
        self.setup = setup; self.preparation = preparation; self.plan = plan
        self.state = state; self.reservedNumbers = reservedNumbers
    }

    func requireSame(as other: Self) throws {
        try setup.requireSame(as: other.setup)
        guard preparation == other.preparation, plan == other.plan,
              state == other.state, reservedNumbers == other.reservedNumbers else { throw PreparationStoreError.staleRevision }
    }

    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableRuntimePreparationSnapshot(owner: setup.owner, candidate: candidate).requireSame(as: self)
    }
    /// Compares publication values only. The private writer must also pin every other row and the catalog.
    func requirePublished(from before: Self) throws {
        try requireRuntimeInputs(from: before)
        guard let reference = state.reference, state.configurationPublished else { throw RuntimePreparationError.incomplete }
        try reference.validate(account: before.preparation, services: before.plan)
        if let retained = before.state.reference {
            guard reference == retained else { throw RuntimePreparationError.conflictingMaterial }
        }
    }

    func requireChange(reference: RuntimeMaterialReference, published: Bool, from before: Self) throws {
        try requireRuntimeInputs(from: before)
        guard state == .init(reference: reference, configurationPublished: published) else { throw PreparationStoreError.staleRevision }
        try reference.validate(account: before.preparation, services: before.plan)
        if let retained = before.state.reference {
            guard retained == reference, !before.state.configurationPublished || published else {
                throw RuntimePreparationError.conflictingMaterial
            }
        } else {
            guard !published else { throw RuntimePreparationError.incomplete }
        }
    }

    private func requireRuntimeInputs(from before: Self) throws {
        guard setup.account?.origin == .currentRelease, before.setup.account?.origin == .currentRelease else {
            throw RuntimePreparationError.changedScope
        }
        try setup.requireAccountStorageState(preparation: before.preparation,
            initialization: before.setup.account?.initialization, from: before.setup)
        guard preparation == before.preparation, plan == before.plan, reservedNumbers == before.reservedNumbers else {
            throw PreparationStoreError.staleRevision
        }
    }
}
