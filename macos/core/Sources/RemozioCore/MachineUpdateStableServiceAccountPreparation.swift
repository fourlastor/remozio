import Darwin
import Foundation

/// The caller holds machine admission and verifies current administrator rights throughout directory work.
enum MachineUpdateStableServiceAccountPreparation {
    /// currentCodePolicy must come from the current authority journal.
    static func resumeNative(machine: PreparationIntentStore, expected: MachineUpdateStableServiceAccountSnapshot,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyCurrent: @escaping (MachineUpdateStableServiceAccountSnapshot) throws -> Void) throws -> ServiceAccountPlanStorage.State {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard expected.setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
        let inventory = expected.setup.source.actual.inventory
        guard inventory.bundlePath == MachineBootstrap.bundlePath,
              let app = currentCodePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = currentCodePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw AccountPreparationError.conflict
        }
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let identity = try placement.preparationCopyIdentity(name: bundle.lastPathComponent)
        func verifyNative(_ actual: MachineUpdateStableServiceAccountSnapshot) throws {
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try actual.setup.source.actual.inventory.compareRelease(release)
            guard try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else { throw AccountPreparationError.conflict }
            try MachineUpdateStableReleaseRecord.requireFormats(release)
            try ReleaseGenerationPreflight.validate(release, against: currentCodePolicy)
            for entry in [app, setup] {
                guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                      entry.installedGeneration == component.generation,
                      entry.codeDirectoryHash == release.codeDirectoryHashes[entry.role] else { throw AccountPreparationError.conflict }
            }
            let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            guard try DynamicCodeValidation.selfPath() == inventory.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw AccountPreparationError.conflict
            }
            let owner = try LocalAccountDirectory.lookup(uid: actual.setup.owner.uid)
            try actual.setup.requireOwner(owner); try verifyCurrent(actual)
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
        }
        try expected.requireCurrent(machine: machine, candidate: candidate)
        try verifyNative(expected)
        let service = try NativeServiceAccountDirectory(accountID: expected.preparation.accountID, ownerUID: expected.preparation.ownerUID)
        return try resume(machine: machine, expected: expected, candidate: candidate, directory: directory, admission: admission,
            serviceDirectory: service, makePlan: { account, reserved in
                try ServiceAccountAllocator.plan(account: account, reserved: reserved, available: service.available)
            }, verifyCurrent: verifyNative)
    }

    static func resume(machine: PreparationIntentStore, expected: MachineUpdateStableServiceAccountSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        serviceDirectory: any ServiceAccountDirectoryAccess,
        makePlan: (AccountPreparationIntent, Set<UInt32>) throws -> ServiceAccountPlan,
        verifyCurrent: @escaping (MachineUpdateStableServiceAccountSnapshot) throws -> Void,
        didStage: (ServiceAccountPreparation.Stage) throws -> Void = { _ in },
        didStorageStage: (PreparationIntentStore.CompletionIntentStorageStage) throws -> Void = { _ in },
        inspectStorage: (ServiceAccountPlanStorage) throws -> Void = { _ in }) throws -> ServiceAccountPlanStorage.State {
        guard expected.setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
        return try withoutActuallyEscaping(didStorageStage) { borrowedHook in
        let processID = getpid(), thread = pthread_self()
        var active = true, current = expected
        var storageStageHook: ((PreparationIntentStore.CompletionIntentStorageStage) throws -> Void)? = borrowedHook
        var currentVerification: ((MachineUpdateStableServiceAccountSnapshot) throws -> Void)? = verifyCurrent
        var borrowed: MachineUpdateStableServiceAccountSnapshot?
        weak var writer = machine
        defer { active = false; writer = nil; borrowed = nil; storageStageHook = nil; currentVerification = nil }
        func requireLifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard active, writer != nil else { throw JournalLeaseError.invalidated }
        }
        func verifyBoundary(_ actual: MachineUpdateStableServiceAccountSnapshot) throws {
            try requireLifetime()
            guard actual.setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
            try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
            try actual.setup.requireOwner(expected.setup.owner)
            guard let currentVerification else { throw JournalLeaseError.invalidated }
            try currentVerification(actual)
            try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
        }
        func snapshot() throws -> MachineUpdateStableServiceAccountSnapshot {
            try requireLifetime()
            // The private writer supplied this frame inside its current transaction. Do not reopen the machine reader.
            if let borrowed { try verifyBoundary(borrowed); return borrowed }
            guard let writer else { throw JournalLeaseError.invalidated }
            try current.requireCurrent(machine: writer, candidate: candidate)
            try verifyBoundary(current)
            try current.requireCurrent(machine: writer, candidate: candidate)
            return current
        }
        func verify() throws { _ = try snapshot() }
        func withFrame(_ actual: MachineUpdateStableServiceAccountSnapshot, _ body: () throws -> Void) throws {
            try requireLifetime()
            guard borrowed == nil else { throw PreparationStoreError.transactionActive }
            if actual.state == current.state { try actual.requireSame(as: current) }
            else if let plan = actual.state.plan {
                try actual.requireChange(plan: plan, complete: actual.state.complete, from: current)
            } else { throw ServiceAccountProvisioningError.changedScope }
            borrowed = actual; defer { borrowed = nil }
            try verifyBoundary(actual); try body(); try verifyBoundary(actual)
        }
        func change(_ plan: ServiceAccountPlan, complete: Bool, verification: () throws -> Void) throws {
            try requireLifetime()
            guard borrowed == nil else { throw PreparationStoreError.transactionActive }
            try verify(); try verification()
            guard let writer else { throw JournalLeaseError.invalidated }
            let state: ServiceAccountPlanStorage.State
            func check(_ stage: PreparationIntentStore.CompletionIntentStorageStage,
                _ actual: MachineUpdateStableServiceAccountSnapshot) throws {
                try withFrame(actual) {
                    guard let storageStageHook else { throw JournalLeaseError.invalidated }
                    try verification(); try storageStageHook(stage); try verification()
                }
            }
            if complete {
                state = try writer.completeStableServiceAccountPlan(plan, expected: current, candidate: candidate,
                    directory: directory, admission: admission, verifyScoped: check)
            } else {
                state = try writer.retainStableServiceAccountPlan(plan, expected: current, candidate: candidate,
                    directory: directory, admission: admission, verifyScoped: check)
            }
            let actual = try writer.stableServiceAccountSnapshot(owner: expected.setup.owner, candidate: candidate)
            try actual.requireChange(plan: plan, complete: state.complete, from: current)
            guard actual.state == state else { throw ServiceAccountProvisioningError.changedScope }
            current = actual; try verify(); try verification()
        }
        try verify()
        let storage = try ServiceAccountPlanStorage(account: expected.preparation, operations: .init(
            load: { try snapshot().state },
            retain: { plan, verify in try change(plan, complete: false, verification: verify) },
            complete: { plan, verify in try change(plan, complete: true, verification: verify) }))
        try inspectStorage(storage); try verify()
        _ = try ServiceAccountPreparation.resume(account: expected.preparation, storage: storage, directory: serviceDirectory,
            makePlan: {
                let actual = try snapshot()
                let plan = try makePlan(actual.preparation, actual.reservedNumbers)
                try verify(); return plan
            }, verifyCurrent: verify, didStage: { stage in try didStage(stage); try verify() })
        let final = try snapshot()
        guard final.state.complete else { throw ServiceAccountProvisioningError.incomplete }
        return final.state
        }
    }
}
