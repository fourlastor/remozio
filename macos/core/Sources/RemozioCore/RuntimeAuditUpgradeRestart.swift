import Darwin
import Foundation

struct RuntimeAuditUpgradeRestartOperations {
    let validateJob: (InstalledAccountJobManifest, InstallationInventory, SignedReleaseEvidence, () throws -> Void) throws -> Void
    let ensure: (InstalledAccountJobManifest, () throws -> Void) throws -> Void
    let inspect: (InstalledAccountJobManifest, () throws -> Void) throws -> RuntimeJobRegistration.Observation
    static var native: Self {
        .init(validateJob: { job, inventory, release, verify in
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try verify(); try job.validate(job.bytes, inventory: inventory, release: release)
            let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()),
                owner: 0, visibility: .sharedMetadata, createIfMissing: false)
            defer { directory.close() }
            guard let account = job.declaration.accountID else { throw RuntimeActivationError.invalidPlan }
            try AdministrativeSetupPublication.validateRetained(job.bytes,
                file: .accountJob(accountID: account, role: job.declaration.role), directory: directory, owner: 0, verify: verify)
            try verify()
        }, ensure: { try RuntimeJobRegistration.ensure($0, verifyCurrent: $1) }, inspect: { job, verify in
            try verify(); let result = try RuntimeJobRegistration.inspect(job); try verify(); return result
        })
    }
}

/// Resumes registration only. Neither retained setup flags nor matching launchd output report a healthy service.
enum RuntimeAuditUpgradeRestart {
    struct Result: Equatable {
        let selectedRoles: Set<AuthorityCodeRole>
        let registrationConfirmed: Set<AuthorityCodeRole>
    }
    /// The cutover owner must close its coordinator and machine writer first. No live barrier can come from a saved phase.
    static func resume(graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                       installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                       verifyOwner: @escaping () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try graph.requireOwner(0)
        let activity = try ReleaseActivityBarrier.open(machineDirectory: MachineBootstrap.machineDirectory)
        let token = try activity.acquireShared(); defer { token.close() }
        let account = graph.snapshot.plan.sourceAccount
        return try run(graph: graph, record: record, installedRelease: installedRelease, currentPolicy: currentPolicy,
            openMachine: { try PreparationIntentStore.open(directoryPath: MachineBootstrap.machineDirectory, macID: account.macID) },
            verifyOwnerAndActivity: {
                try token.validate(); try verifyOwner()
                try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: account.ownerUID),
                    uid: account.ownerUID, directoryID: account.directoryID)
            },
            requireFenceAbsent: { try RuntimeAuditUpgradeStartupFence.requireOpen(macID: account.macID, accountID: account.accountID) },
            operations: .native)
    }
    static func resumeOwned(graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                            installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                            openMachine: @escaping () throws -> PreparationIntentStore,
                            verifyOwnerAndActivity: @escaping () throws -> Void,
                            requireFenceAbsent: @escaping () throws -> Void,
                            operations: RuntimeAuditUpgradeRestartOperations,
                            didRegister: (AuthorityCodeRole) throws -> Void = { _ in }) throws -> Result {
        guard getuid() > 0, getuid() == geteuid(), graph.snapshot.ownership == .ordinaryOwnerFixture else {
            throw JournalLeaseError.unsafeMetadata
        }
        return try run(graph: graph, record: record, installedRelease: installedRelease, currentPolicy: currentPolicy,
            openMachine: openMachine, verifyOwnerAndActivity: verifyOwnerAndActivity, requireFenceAbsent: requireFenceAbsent,
            operations: operations, didRegister: didRegister)
    }
    private static func run(graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                            installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                            openMachine: @escaping () throws -> PreparationIntentStore,
                            verifyOwnerAndActivity: @escaping () throws -> Void,
                            requireFenceAbsent: @escaping () throws -> Void,
                            operations: RuntimeAuditUpgradeRestartOperations,
                            didRegister: (AuthorityCodeRole) throws -> Void = { _ in }) throws -> Result {
        try graph.requireOwner(getuid()); try record.validate(graph)
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        let plan = graph.snapshot.plan, account = plan.sourceAccount, processID = getpid()
        var jobs: [InstalledAccountJobManifest] = []
        if plan.sourceJobsRegistered { jobs += [plan.preparation.target.authorityJob, plan.preparation.target.transportJob] }
        if plan.gateway.activation.jobRegistered {
            guard plan.sourceJobsRegistered, plan.gateway.activation.filesPublished, let gateway = plan.gateway.activation.plan else {
                throw RuntimeActivationError.incomplete
            }
            jobs.append(try gateway.gatewayJob)
        }
        func verify() throws {
            guard getpid() == processID else { throw RuntimeActivationError.unavailable }
            try verifyOwnerAndActivity(); try requireFenceAbsent(); try Task.checkCancellation()
        }
        // Every verification ends its machine borrow before launchctl runs or a callback can inspect a live service.
        func inventory(verifyGraphBytes: Bool = false) throws -> InstallationInventory {
            try verify()
            let machine = try openMachine()
            do {
                try machine.validateStorageLease()
                guard let current = try machine.runtimeAuditCutover(accountID: account.accountID),
                      current.phase == .metadataCommitted, current.graph == record,
                      try machine.accountPreparation(ownerUID: account.ownerUID) == account,
                      try machine.initialization(accountID: account.accountID) == plan.sourceInitialization,
                      let inventory = try machine.inventory() else { throw RuntimePreparationError.changedScope }
                if verifyGraphBytes {
                    guard try machine.runtimeAuditGraphBytes(record) == graph.bytes else { throw RuntimePreparationError.changedScope }
                }
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let foreground = try machine.runtimeActivation(accountID: account.accountID)
                let gateway = try machine.gatewayRuntimeActivation(accountID: account.accountID)
                guard runtime.configurationPublished, runtime.reference == plan.preparation.intent.target,
                      try foreground.plan?.encoded == plan.preparation.target.encoded,
                      foreground.jobsRegistered == plan.sourceJobsRegistered,
                      try gateway.plan?.encoded == plan.gateway.activation.plan?.encoded,
                      gateway.filesPublished == plan.gateway.activation.filesPublished,
                      gateway.jobRegistered == plan.gateway.activation.jobRegistered,
                      inventory.macID == plan.sourceInventory.macID,
                      inventory.installationID == plan.sourceInventory.installationID,
                      inventory.bundlePath == plan.sourceInventory.bundlePath,
                      inventory.releaseDigest == plan.sourceInventory.releaseDigest else { throw RuntimePreparationError.changedScope }
                try inventory.compareRelease(installedRelease)
                for job in jobs { try job.validate(job.bytes, inventory: inventory, release: installedRelease) }
                try verify(); try machine.close(); return inventory
            } catch { try? machine.close(); throw error }
        }
        _ = try inventory(verifyGraphBytes: true)
        func verifyCurrent() throws { _ = try inventory() }
        // Validate every selected declaration before the first registration. Dynamic settings remain owned by startup recovery.
        for job in jobs { try operations.validateJob(job, inventory(), installedRelease, verifyCurrent) }
        var confirmed = Set<AuthorityCodeRole>()
        for job in jobs {
            func verifyJob() throws { try operations.validateJob(job, inventory(), installedRelease, verifyCurrent) }
            try verifyJob(); try operations.ensure(job, verifyJob); try didRegister(job.declaration.role); try verifyJob()
            switch try operations.inspect(job, verifyJob) {
            case .matching: confirmed.insert(job.declaration.role)
            case .conflicting: throw RuntimeActivationError.conflictingPlan
            case .absent: throw RuntimeActivationError.unavailable
            }
        }
        try verifyCurrent()
        return .init(selectedRoles: Set(jobs.map { $0.declaration.role }), registrationConfirmed: confirmed)
    }
}
