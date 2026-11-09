import Foundation

/// Advances only completion files. Inventory publication, metadata retirement and admission remain separate protected operations.
enum MachineUpdateCompletionFileCoordinator {
    typealias Plan = MachineUpdateCompletionPublicationPlan
    typealias Record = MachineUpdateCompletionPublicationRecord
    typealias Scope = PreparationIntentStore.CompletionPublicationScope
    enum Stage {
        case intentRecorded(Data, Plan.File)
        case staged(Data, Plan.File)
        case published(Data, Plan.File)
        case acknowledged(Data, Plan.File)
        case filesPublished
    }

    /// The installed owner supplies current code, placement and paired policy checks for each scope.
    static func publishNative(_ publication: Record, plan: Plan, expected: MachineUpdateCompletionIntentArchive,
        restart: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence, machine: PreparationIntentStore,
        directory: ReleaseDestinationLease, admission: UpdateRestartAdmissionLease,
        verifyCurrent: (Scope) throws -> Void) throws -> Record {
        try publish(publication, plan: plan, expected: expected, restart: restart, candidate: candidate,
            machine: machine, directory: directory, admission: admission, validate: { scope in
                let current = try scope.read()
                guard let record = current.publication else { throw PreparationStoreError.invalidTransition }
                try MachineUpdateCompletionPublicationFiles.requireBackendMetadataNative(current.completion.restart,
                    verifyCurrent: { try verifyCurrent(scope) })
                try MachineUpdateCompletionPublicationFiles.requireNative(plan, publication: record,
                    verifyCurrent: { try verifyCurrent(scope) })
            }, publishFile: { record, entry, scope, didStage in
                try MachineUpdateCompletionPublicationFiles.publishNative(plan, publication: record, accountID: entry.accountID,
                    file: entry.file, verifyCurrent: { try verifyCurrent(scope) }, didStage: didStage)
            })
    }

    static func publish(_ publication: Record, plan: Plan, expected: MachineUpdateCompletionIntentArchive,
        restart: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        machine: PreparationIntentStore, directory: ReleaseDestinationLease, admission: UpdateRestartAdmissionLease,
        validate: (Scope) throws -> Void,
        publishFile: (Record, Plan.Entry, Scope, (AdministrativeSetupPublication.Stage) throws -> Void) throws -> Void,
        didStore: (PreparationIntentStore.CompletionIntentStorageStage, Scope) throws -> Void = { _, _ in },
        didStage: (Stage) throws -> Void = { _ in }) throws -> Record {
        try publication.requirePlan(plan)
        guard publication.inventoryState == .pending else { throw PreparationStoreError.invalidTransition }
        func check(_ record: Record) throws {
            try machine.withCurrentMachineUpdateCompletionPublication(expected: expected, publication: record, plan: plan,
                restartSnapshot: restart, candidate: candidate, directory: directory, restart: admission, validate)
        }
        func store(_ stage: PreparationIntentStore.CompletionIntentStorageStage, _ scope: Scope) throws {
            try validate(scope); try didStore(stage, scope); try validate(scope)
        }
        var current = publication
        try check(current)
        for entry in plan.entries {
            switch try current.state(accountID: entry.accountID, file: entry.file) {
            case .published: continue
            case .pending:
                current = try machine.advanceMachineUpdateCompletionPublication(current, operation: .prepare(entry.accountID, entry.file),
                    plan: plan, expected: expected, restartSnapshot: restart, candidate: candidate, directory: directory, restart: admission, verifyScoped: store)
                try didStage(.intentRecorded(entry.accountID, entry.file))
            case .writing: break
            }
            try machine.withCurrentMachineUpdateCompletionPublication(expected: expected, publication: current, plan: plan,
                restartSnapshot: restart, candidate: candidate, directory: directory, restart: admission) { scope in
                try validate(scope)
                try withoutActuallyEscaping(validate) { scopedValidate in
                    try withoutActuallyEscaping(didStage) { notify in
                        try publishFile(current, entry, scope, { stage in
                            try scopedValidate(scope)
                            switch stage {
                            case .staged: try notify(.staged(entry.accountID, entry.file))
                            case .published: try notify(.published(entry.accountID, entry.file))
                            }
                            try scopedValidate(scope)
                        })
                    }
                }
                try validate(scope)
            }
            current = try machine.advanceMachineUpdateCompletionPublication(current, operation: .complete(entry.accountID, entry.file),
                plan: plan, expected: expected, restartSnapshot: restart, candidate: candidate, directory: directory, restart: admission, verifyScoped: store)
            try didStage(.acknowledged(entry.accountID, entry.file))
        }
        guard current.filesPublished, current.inventoryState == .pending else { throw PreparationStoreError.invalidTransition }
        try check(current)
        try didStage(.filesPublished)
        try check(current)
        return current
    }
}
