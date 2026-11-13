import Foundation

/// Actual service reservations and frozen account inputs. This value grants no directory creation or runtime authority.
struct MachineUpdateStableServiceAccountSnapshot {
    let setup: MachineUpdateStableAccountSetupSnapshot
    let state: ServiceAccountPlanStorage.State
    let reservedNumbers: Set<UInt32>
    let preparation: AccountPreparationIntent

    init(setup: MachineUpdateStableAccountSetupSnapshot, state: ServiceAccountPlanStorage.State, reservedNumbers: Set<UInt32>) throws {
        guard setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
        guard let preparation = setup.preparation, preparation.storagePrepared,
              setup.account?.initialization?.complete == true, reservedNumbers.count <= 128,
              state.plan != nil || !state.complete else { throw ServiceAccountProvisioningError.incomplete }
        try state.plan?.validate(account: preparation)
        if let plan = state.plan {
            guard Set(plan.claims.map(\.number)).isSubset(of: reservedNumbers) else { throw ServiceAccountProvisioningError.changedScope }
        }
        self.setup = setup; self.preparation = preparation; self.state = state; self.reservedNumbers = reservedNumbers
    }
    func requireSame(as other: Self) throws {
        try setup.requireSame(as: other.setup)
        guard state == other.state, reservedNumbers == other.reservedNumbers else { throw PreparationStoreError.staleRevision }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableServiceAccountSnapshot(owner: setup.owner, candidate: candidate).requireSame(as: self)
    }
    /// Checks the actual final state after plan retention and directory preparation return to the authenticated owner.
    func requirePrepared(from before: Self) throws {
        try setup.requireAccountStorageState(preparation: before.preparation, initialization: before.setup.account?.initialization, from: before.setup)
        guard let plan = state.plan, state.complete else { throw ServiceAccountProvisioningError.incomplete }
        try plan.validate(account: before.preparation)
        if let retained = before.state.plan {
            guard plan == retained, reservedNumbers == before.reservedNumbers else { throw ServiceAccountProvisioningError.conflictingRecord }
        } else {
            let numbers = Set(plan.claims.map(\.number))
            guard numbers.isDisjoint(with: before.reservedNumbers), reservedNumbers == before.reservedNumbers.union(numbers) else {
                throw ServiceAccountProvisioningError.conflictingRecord
            }
        }
    }
    func requireChange(plan: ServiceAccountPlan, complete: Bool, from before: Self) throws {
        try setup.requireAccountStorageState(preparation: before.preparation, initialization: before.setup.account?.initialization, from: before.setup)
        try plan.validate(account: before.preparation)
        guard state == .init(plan: plan, complete: complete) else { throw PreparationStoreError.staleRevision }
        if let retained = before.state.plan {
            guard retained == plan, !before.state.complete || complete, reservedNumbers == before.reservedNumbers else {
                throw ServiceAccountProvisioningError.conflictingRecord
            }
        } else {
            let numbers = Set(plan.claims.map(\.number))
            guard !complete, numbers.isDisjoint(with: before.reservedNumbers),
                  reservedNumbers == before.reservedNumbers.union(numbers) else { throw ServiceAccountProvisioningError.conflictingRecord }
        }
    }
}
