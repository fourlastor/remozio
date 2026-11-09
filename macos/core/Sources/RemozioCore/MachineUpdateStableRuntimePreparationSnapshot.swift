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
}
