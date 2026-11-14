import Foundation

/// Checked read values only. Native identity, files, settings recovery, and admission require their separate owners.
struct MachineUpdateStableRuntimeViewInputs {
    let source: MachineUpdateStableRuntimeSource
    let retained: [MachineUpdateRetainedSetupActivationSnapshot]
    let runtime: RuntimeReleaseCompatibilitySnapshot
    let currentJournals: [Data: GatewayJournalPreparationState]

    init(source: MachineUpdateStableRuntimeSource, retained: [MachineUpdateRetainedSetupActivationSnapshot],
        runtime: RuntimeReleaseCompatibilitySnapshot, currentJournals: [Data: GatewayJournalPreparationState]) throws {
        let actual = source.actual, inputs = runtime.inputs
        guard (24...RuntimeMaintenanceWindowStorage.schemaVersion).contains(inputs.schemaVersion),
              inputs.schemaVersion == actual.schemaVersion, inputs.macID == actual.inventory.macID,
              inputs.inventory == actual.inventory.canonicalBytes,
              try inputs.machineUpdateActivation == actual.activation.encoded,
              try inputs.updateAdmissionRegistration == actual.admission.encoded,
              try inputs.installedRelease == actual.installed.record.encoded else { throw PreparationStoreError.staleRevision }
        let ids = retained.map { $0.runtime.preparation.accountID }
        guard Set(ids).count == ids.count else { throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot }
        for snapshot in retained {
            guard snapshot.state.plan != nil else { throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot }
            try snapshot.runtime.setup.source.requireSame(as: source)
        }
        let expected = Set(source.accounts.filter { account in account.origin == .currentRelease &&
            inputs.gateways.contains(where: { $0.accountID == account.accountID }) }.map(\.accountID))
        guard Set(currentJournals.keys) == expected,
              currentJournals.allSatisfy({ id, state in state.intent.map({ $0.accountID == id }) ?? !state.initialized }) else {
            throw RuntimePreparationError.changedScope
        }
        self.source = source; self.retained = retained.sorted { $0.runtime.preparation.accountID.lexicographicallyPrecedes($1.runtime.preparation.accountID) }
        self.runtime = runtime; self.currentJournals = currentJournals
    }
    func requireSame(as other: Self) throws {
        try source.requireSame(as: other.source)
        guard runtime.inputs == other.runtime.inputs, currentJournals == other.currentJournals,
              retained.count == other.retained.count else { throw PreparationStoreError.staleRevision }
        for (actual, expected) in zip(retained, other.retained) { try actual.requireSame(as: expected) }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableRuntimeViewInputs(expected: source, retained: retained, candidate: candidate).requireSame(as: self)
    }
    func validate(_ candidate: SignedReleaseEvidence, policy: AuthorityCodePolicy, machine: PreparationIntentStore) throws {
        guard try InstallationInventory.digest(candidate) == source.actual.inventory.releaseDigest else {
            throw PreparationStoreError.staleRevision
        }
        try runtime.validate(candidate, policy: policy, verifyCurrent: { try requireCurrent(machine: machine, candidate: candidate) })
    }
}
