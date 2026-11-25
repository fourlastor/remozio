import Darwin
import Foundation

/// Root Setup owns the complete stop, publication and exact job registration sequence.
public enum PairingColdDisableSetup {
    public enum RecoveryError: Error {
        case originalJobsRestored, originalJobsRestorationFailed
    }

    public static func run(accountIdentifier: String) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let identifier = accountIdentifier.lowercased()
        guard identifier.utf8.count == 32, identifier.utf8.allSatisfy({
            (48...57).contains($0) || (97...102).contains($0)
        }) else { throw PairingColdDisableError.changedConfiguration }
        let startup = AdministrativeSetupConfiguration.startupPath
        let setup = try AdministrativeSetupConfiguration.load(path: startup)
        let activity = try ReleaseActivityBarrier.open(machineDirectory: setup.machineDirectory)
        let exclusive = try activity.acquireExclusive()
        defer { exclusive.close() }

        func useMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let store = try PreparationIntentStore.open(directoryPath: setup.machineDirectory, macID: setup.macID)
            do {
                let value = try body(store)
                try store.close()
                return value
            } catch { try? store.close(); throw error }
        }
        guard let inventory = try useMachine({ try $0.loadInventory() }),
              let account = inventory.accounts.first(where: { LowercaseHexadecimal.encode($0.accountID) == identifier }),
              let app = setup.codePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let component = setup.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw PairingColdDisableError.unavailable
        }
        let accountID = account.accountID
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        try setup.validate(inventory: inventory, release: release)
        let requirement = try XPCPeerPolicy(teamID: component.teamID, componentIdentifier: component.identifier,
            approvedCodeDirectoryHashes: [component.codeDirectoryHash], expectedUserID: 0).requirement
        let executable = bundle.appendingPathComponent(AdministrativeSetupConfiguration.executablePath).path
        let pinnedSetup = setup.canonicalBytes
        let macID = setup.macID
        @Sendable func verifyConfiguration() throws {
            guard try AdministrativeSetupConfiguration.load(path: startup).canonicalBytes == pinnedSetup,
                  try DynamicCodeValidation.selfPath() == executable else { throw PairingColdDisableError.changedConfiguration }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            try RuntimeAuditUpgradeStartupFence.requireOpen(macID: macID, accountID: accountID)
        }
        func verifyOwner() throws {
            try verifyConfiguration()
            try placement.validate()
        }
        try verifyOwner()
        let (plan, initial) = try useMachine { store in
            guard try store.loadInventory() == inventory,
                  let initial = try store.initialization(accountID: accountID), initial.complete else {
                throw PairingColdDisableError.unavailable
            }
            let state = try store.runtimeActivation(accountID: accountID)
            guard let plan = state.plan, state.jobsRegistered,
                  try plan.enrolledInventory(inventory) == inventory else { throw PairingColdDisableError.unavailable }
            try plan.host.validateRelease(release, bundlePath: inventory.bundlePath)
            return (plan, initial)
        }
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, visibility: .privateState, createIfMissing: false)
        defer { directory.close() }
        let jobs = [plan.authorityJob, plan.transportJob]
        let jobDirectory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { jobDirectory.close() }
        func verifyJobs() throws {
            try verifyOwner()
            for job in jobs {
                try AdministrativeSetupPublication.validateRetained(job.bytes,
                    file: .accountJob(accountID: accountID, role: job.declaration.role),
                    directory: jobDirectory, owner: 0, verify: verifyOwner)
            }
        }
        try verifyJobs()
        try RuntimeMaintenanceBootstrapGuard.requireNativeOpen(plan.authorityJob)
        func withRegistrationActivity(_ body: (ReleaseActivityToken) throws -> Void) throws {
            exclusive.close()
            let shared = try activity.acquireShared()
            defer { shared.close() }
            try body(shared)
        }

        func loadActivation() throws -> RuntimeActivationState {
            try useMachine { store in
                guard try store.loadInventory() == inventory else { throw PairingColdDisableError.changedConfiguration }
                return try store.runtimeActivation(accountID: accountID)
            }
        }

        func currentPlan() throws -> RuntimeActivationPlan {
            let state = try loadActivation()
            guard let current = state.plan, state.jobsRegistered,
                  current.authorityJob.bytes == plan.authorityJob.bytes,
                  current.transportJob.bytes == plan.transportJob.bytes else {
                throw PairingColdDisableError.changedConfiguration
            }
            try current.host.validateRelease(release, bundlePath: inventory.bundlePath)
            return current
        }

        func verifyPlan(_ expected: RuntimeActivationPlan) throws {
            try verifyJobs()
            guard try currentPlan().encoded == expected.encoded else { throw PairingColdDisableError.changedConfiguration }
            try PairingColdDisablePublication.requireConfiguration(expected.host, directory: directory, owner: 0, verify: verifyOwner)
        }

        let prior = try PairingColdDisablePublication.readIntent(directory: directory, owner: 0)
        if let prior {
            if prior.completed { try prior.requirePairingTarget(plan.host) }
            else { try prior.requireScope(plan.host) }
        } else if plan.host.command.presence.pairing?.v2ActivationEnabled == false {
            // A previous invocation may have retired the record before its success reply reached the operator.
            func verifyRetired() throws {
                guard try PairingColdDisablePublication.readIntent(directory: directory, owner: 0) == nil else {
                    throw PairingColdDisableError.changedConfiguration
                }
                try verifyPlan(plan)
            }
            try verifyRetired()
            try withRegistrationActivity { shared in
                for job in jobs {
                    try RuntimeJobRegistration.ensure(job, verifyCurrent: {
                        try shared.validate()
                        try verifyRetired()
                    })
                }
            }
            return
        } else {
            _ = try PairingColdDisableConfiguration(source: plan.host)
        }

        func canRestoreOriginal() throws -> Bool {
            try PairingColdDisablePublication.canRestoreOriginal(plan, directory: directory, owner: 0,
                loadActivation: loadActivation, verify: verifyJobs)
        }
        func restoreIfUnpublished() throws -> Bool {
            guard try canRestoreOriginal() else { return false }
            func verifyOriginal() throws {
                guard try canRestoreOriginal() else { throw PairingColdDisableError.changedConfiguration }
            }
            try withRegistrationActivity { shared in
                var restorationError: (any Error)?
                for job in jobs {
                    do {
                        try RuntimeJobRegistration.ensure(job, verifyCurrent: {
                            try shared.validate()
                            try verifyOriginal()
                        })
                    } catch {
                        restorationError = error
                    }
                }
                if let restorationError { throw restorationError }
                try verifyOriginal()
            }
            return true
        }

        let record: PairingColdDisableIntent
        if let prior, prior.completed {
            record = prior
        } else {
            let sessions = try jobs.map {
                try RuntimeJobStopSession.open(job: $0, policy: plan.host.codePolicy, rootActivity: exclusive,
                    verifyOwnerAndFence: verifyOwner)
            }
            // Keep the one-shot owner alive from the first bootout through publication or original job restoration.
            let interrupt = signal(SIGINT, SIG_IGN)
            let termination = signal(SIGTERM, SIG_IGN)
            defer {
                signal(SIGINT, interrupt)
                signal(SIGTERM, termination)
            }
            let deadline = ContinuousClock.now.advanced(by: .seconds(30))
            // Pending replay may start with both jobs absent. The intent already closes pairing. Exact launchd
            // absence, the role barrier and Authority journal custody establish the replay boundary.
            record = try stopAndPublish(sessions, requireLiveJobs: prior == nil, wait: {
                guard ContinuousClock.now < deadline else { return false }
                Thread.sleep(forTimeInterval: 0.1)
                return true
            }, restoreIfUnpublished: restoreIfUnpublished) {
                func verifyExit() throws {
                    try exclusive.validateExclusive()
                    try verifyOwner()
                    for session in sessions { try session.requireRemoved() }
                }
                try verifyExit()
                let roles = try plan.reference.serviceActivity.map { reference in
                    try ServiceReleaseActivityBarrier.openForUpdate(services: plan.reference.services, role: .transport,
                        expected: reference.identity(for: .transport), verifyCurrent: {
                            try exclusive.validateExclusive()
                            try verifyConfiguration()
                        }).acquireExclusive()
                }
                defer { roles?.close() }
                let journal = try AuthorityJournalCutoverInspection.openInitialized(initialization: initial,
                    policy: plan.host.codePolicy, rootActivity: exclusive, verifyOwnerAndFence: verifyExit)
                defer { try? journal.close() }
                func verifyStopped() throws {
                    try verifyExit()
                    try roles?.validateExclusive()
                    try journal.validateLifetime()
                }
                let result = try PairingColdDisablePublication.apply(expectedHost: plan.host, directory: directory, owner: 0,
                    verifyStopped: verifyStopped, retainTarget: { target in
                        let next = try plan.replacingPairingHost(target)
                        try useMachine { store in
                            guard try store.loadInventory() == inventory else { throw PairingColdDisableError.changedConfiguration }
                            try store.retainColdDisabledPairing(expected: plan, target: next)
                        }
                    })
                try journal.close()
                return result
            }
        }

        let target = try currentPlan()
        try record.requirePairingTarget(target.host)
        func verifyTarget() throws { try verifyPlan(target) }
        func verifyRestart() throws {
            guard try PairingColdDisablePublication.readIntent(directory: directory, owner: 0) == record,
                  record.completed else { throw PairingColdDisableError.changedConfiguration }
            try verifyTarget()
        }
        try verifyRestart()
        try withRegistrationActivity { shared in
            for job in jobs {
                try RuntimeJobRegistration.ensure(job, verifyCurrent: {
                    try shared.validate()
                    try verifyRestart()
                })
            }
            try verifyRestart()
            try PairingColdDisablePublication.retire(record, retainedHost: target.host, directory: directory, owner: 0, verify: {
                try shared.validate()
                try verifyTarget()
            })
        }
    }

    static func stopAndPublish<Value>(_ sessions: [RuntimeJobStopSession], requireLiveJobs: Bool,
        wait: () -> Bool, restoreIfUnpublished: () throws -> Bool, publish: () throws -> Value) throws -> Value {
        if requireLiveJobs {
            // Capture both witnesses before either session may issue bootout.
            for session in sessions { try session.requireRunning() }
        }
        do {
            repeat {
                let observations = try sessions.map { try $0.poll() }
                if observations.allSatisfy({ $0 == .registrationRemoved }) { return try publish() }
            } while wait()
            throw PairingColdDisableError.unavailable
        } catch {
            if requireLiveJobs {
                let restored: Bool
                do { restored = try restoreIfUnpublished() }
                catch { throw RecoveryError.originalJobsRestorationFailed }
                if restored { throw RecoveryError.originalJobsRestored }
            }
            throw error
        }
    }
}
