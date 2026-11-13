import Darwin
import Foundation
import RemozioProtocol

/// Composes native custody and policy storage. No command, RPC, service or automatic activation calls this entry.
enum MachineUpdateRetainedSetupPolicyNativeEntry {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Access = MachineUpdateRetainedSetupPolicyOwner.JournalAccess
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    typealias Verify = () throws -> Void
    typealias Support = MachineUpdateRetainedSetupPromotionNativeSupport

    /// The policy argument is deliberately absent. Only the held current authority pair supplies it.
    static func resumeNative(machineDirectory: String, expected: Snapshot, candidate: SignedReleaseEvidence,
        currentAuthorityAccountID: Data) throws -> Snapshot {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard machineDirectory == MachineBootstrap.machineDirectory else { throw MachineUpdateActivationError.wrongBoundary }
        let (initial, host) = try publishedAuthority(expected: expected, accountID: currentAuthorityAccountID)
        let paths = try Support.Paths(accountID: initial.accountID, journalPath: initial.journalPath, continuityPath: initial.continuityPath)
        let hostPath = try RuntimePreparationPaths(accountID: initial.accountID).privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name
        func published() throws {
            guard try ProtectedServiceConfiguration.read(path: hostPath) == host.canonicalBytes else { throw RuntimeActivationError.changedScope }
        }
        try published()
        let currentJournal = try openJournal(access: .readOnly, initial: initial,
            openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
            openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory, excludingDirectory: $0) },
            verifySelf: { transaction in
                guard try transaction.codePolicy() != nil else { throw AuthoritySelfValidationError.unconfigured }
            })
        defer { try? currentJournal.close() }
        let result = try withCurrentPolicy(initial: initial, read: {
            try published(); let boundary = try currentJournal.captureRetainedSetupPolicyBoundary(expected: initial)
            try published(); return boundary
        }) { policy, current in
            try current()
            return try MachineUpdateRetainedSetupPolicyNativeContext.withNativeScope(machineDirectory: machineDirectory,
                expected: expected, candidate: candidate, currentCodePolicy: policy) { native in
                try current()
                return try native.withResources { directory, admission in
                    let target = try targetInitialization(expected)
                    let targetPaths = try Support.Paths(accountID: target.accountID,
                        journalPath: target.journalPath, continuityPath: target.continuityPath)
                    let value = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: expected, candidate: candidate,
                        directory: directory, admission: admission,
                        useMachine: closedMachine(open: {
                            try PreparationIntentStore.open(directoryPath: machineDirectory, macID: target.macID)
                        }, validate: { try $0.validateStorageLease(nativeDirectory: machineDirectory) }),
                        openJournal: { access in
                            try openJournal(access: access, initial: target,
                                openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: targetPaths.journalDirectory) },
                                openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: targetPaths.continuityDirectory, excludingDirectory: $0) },
                                verifySelf: { _ in try native.withResources { _, _ in try current() } })
                        }, verifySnapshot: { frame in try current(); try native.verify(frame); try current() })
                    try current(); return value
                }
            }
        }
        try published(); try currentJournal.close(); return result
    }

    /// Selects a published authority host, not an arbitrary inventory member or the historical target.
    static func publishedAuthority(expected: Snapshot, accountID: Data) throws -> (AuthorityInitializationIntent, InstalledAuthorityCommandConfiguration) {
        let runtime = expected.activation.runtime, source = runtime.setup.source
        guard accountID != runtime.preparation.accountID,
              let member = source.actual.inventory.accounts.first(where: { $0.accountID == accountID }),
              let configuration = try source.actual.installed.configuration().configuration(accountID: accountID),
              configuration.completion.host.command.accountID == accountID,
              configuration.completion.host.command.callerUID == member.ownerUID,
              let initial = source.accounts.first(where: { $0.accountID == accountID && $0.ownerUID == member.ownerUID && $0.inInventory })?.initialization,
              initial.complete, initial.macID == source.actual.inventory.macID,
              initial.installationID == source.actual.inventory.installationID else { throw RuntimeActivationError.changedScope }
        return (initial, configuration.completion.host)
    }
    private static func targetInitialization(_ expected: Snapshot) throws -> AuthorityInitializationIntent {
        guard let initial = expected.activation.runtime.setup.account?.initialization, initial.complete else { throw RuntimeActivationError.incomplete }
        return initial
    }
    /// Owned readers test comparison and expiry only. Native callers supply the actual held read-only pair.
    static func withCurrentPolicy<Value>(initial: AuthorityInitializationIntent, read: () throws -> Boundary,
        perform: (AuthorityCodePolicy, @escaping Verify) throws -> Value) throws -> Value {
        let first = try read()
        guard initial.complete, first.macID == initial.macID, first.accountID == initial.accountID else { throw AuthorityInitializationError.invalidBoundary }
        func verify() throws {
            guard try read() == first else { throw AuthorityCodePolicyError.staleRevision }
        }
        return try Support.withScopedVerification(verify) { current in
            try current(); let value = try perform(first.policy.policy, current); try current(); return value
        }
    }
    /// The provider closes the same connection before returning the frame. It closes on every failure too.
    static func closedMachine(open: @escaping () throws -> PreparationIntentStore,
        validate: @escaping (PreparationIntentStore) throws -> Void) -> MachineUpdateRetainedSetupPolicyFrame.UseMachine {
        { body in
            let machine = try open()
            do {
                try validate(machine); let value = try body(machine); try validate(machine)
                try machine.close(); return value
            } catch { try? machine.close(); throw error }
        }
    }
    /// Access is typed. The read-only branch uses the fixed existing reader; startup never initializes or repairs.
    static func openJournal(access: Access, initial: AuthorityInitializationIntent,
        openJournalLease: @Sendable () throws -> sending ProtectedJournalLease,
        openContinuityLease: @Sendable (ProtectedStorageLease.DirectoryIdentity) throws -> sending ProtectedContinuityLease,
        verifySelf: (JournalTransaction) throws -> Void) throws -> AuthorityJournal {
        guard initial.complete else { throw RuntimeActivationError.incomplete }
        switch access {
        case .readOnly:
            return try AuthorityJournal(updateHealthStorage: Support.openExistingStorage(initial: initial,
                openJournalLease: openJournalLease, openContinuityLease: openContinuityLease), validateSelf: verifySelf)
        case .startup:
            let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
            let storage = try AuthorityStorage(openJournal: {
                let lease = try openJournalLease()
                do {
                    guard lease.databasePath == initial.journalPath else { throw MachineUpdateActivationError.wrongBoundary }
                    try CutoverSQLitePreflight.validate(path: lease.databasePath, validateLease: lease.validate)
                    return try JournalDatabase(lease: lease, macID: initial.macID, accountID: initial.accountID,
                        recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                        maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: false)
                } catch { lease.close(); throw error }
            }, openContinuity: { excluded in
                let lease = try openContinuityLease(excluded)
                do {
                    guard lease.databasePath == initial.continuityPath else { throw MachineUpdateActivationError.wrongBoundary }
                    try CutoverSQLitePreflight.validate(path: lease.databasePath, validateLease: lease.validate)
                    return try ContinuityStore(lease: lease, macID: initial.macID, accountID: initial.accountID, initialize: nil)
                } catch { lease.close(); throw error }
            })
            return try AuthorityJournal(retainedSetupPolicyStorage: storage, validateSelf: verifySelf)
        }
    }
}
