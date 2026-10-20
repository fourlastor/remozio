import Darwin
import Foundation

/// The authenticated setup endpoint supplies the caller and protected host verifier.
/// Every machine borrow closes before native inspection or registration. No retry repeats an uncertain operation body.
enum GatewayRuntimeActivationRootOperation {
    static func resumeNative(machineDirectory: String, macID: Data, ownerUID: UInt32,
                             expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings,
                             expectedImport: SharedSetupImportIntent? = nil, verifyHost: @escaping (InstallationInventory) throws -> Void) throws -> SetupGatewayActivationProgress {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory), token = try activity.acquireShared()
        defer { token.close() }
        return try resume(ownerUID: ownerUID, expected: expected, settings: settings, expectedImport: expectedImport,
            openMachine: { try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID) },
            verifyHost: { inventory in
                guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                try token.validate(); try activity.validate(); try verifyHost(inventory)
            }, lookupAccount: LocalAccountDirectory.lookup, operations: .native)
    }
    // Owned stores and injected native operations prove composition, not Root admission or actual launchd behavior.
    static func resume(ownerUID: UInt32, expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings,
                       expectedImport: SharedSetupImportIntent? = nil, openMachine: () throws -> PreparationIntentStore,
                       verifyHost: (InstallationInventory) throws -> Void,
                       lookupAccount: (UInt32) throws -> LocalAccountIdentity,
                       operations: GatewayRuntimeActivationOperations) throws -> SetupGatewayActivationProgress {
        guard ownerUID > 0, ownerUID < UInt32.max, expected.setup.ownerUID == ownerUID else { throw AdministrativeSetupError.wrongAccount }
        guard expected.setup.journalInitialized else { throw GatewayPreparationError.incomplete }
        return try withoutActuallyEscaping(openMachine) { openMachine in
        try withoutActuallyEscaping(verifyHost) { verifyHost in
        try withoutActuallyEscaping(lookupAccount) { lookupAccount in
        let processID = getpid()
        func borrow<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            try Task.checkCancellation()
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
            var next: PreparationIntentStore?
            while next == nil {
                do { next = try openMachine() }
                catch JournalLeaseError.busy {
                    try Task.checkCancellation()
                    guard DispatchTime.now().uptimeNanoseconds < deadline else { throw JournalLeaseError.busy }
                    usleep(50000)
                }
            }
            guard let machine = next else { throw GatewayPreparationError.incomplete }
            do { let result = try body(machine); try machine.close(); return result }
            catch { try? machine.close(); throw error }
        }
        func setup(_ machine: PreparationIntentStore, _ account: AccountPreparationIntent) throws -> SetupGatewayProgress {
            try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                activation: machine.runtimeActivation(accountID: account.accountID), material: machine.gatewayPreparation(accountID: account.accountID),
                journal: machine.gatewayJournalPreparation(accountID: account.accountID))
        }
        let retained = try borrow { machine -> (AccountPreparationIntent, InstallationInventory, GatewayRuntimeActivationPlan) in
            guard let inventory = try machine.inventory(), let account = try machine.accountPreparation(ownerUID: ownerUID) else {
                throw GatewayPreparationError.incomplete
            }
            try verifyHost(inventory); try machine.validateAccountPreparation(account)
            try SharedSetupImportGatewayRuntimeScope.validate(machine: machine, account: account, expected: expectedImport, activationSettings: settings)
            try LocalAccountDirectory.validateOwnership(lookupAccount(ownerUID), uid: ownerUID, directoryID: account.directoryID)
            let state = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            guard try SetupGatewayActivationProgress(setup: setup(machine, account), state: state) == expected,
                  let foreground = try machine.runtimeActivation(accountID: account.accountID).plan else {
                throw AdministrativeSetupError.staleProgress
            }
            let plan = try state.plan ?? GatewayRuntimeActivationPlan(journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory, wakePollMilliseconds: settings.wakePollMilliseconds,
                wakeTimeoutMilliseconds: settings.wakeTimeoutMilliseconds)
            guard let wake = plan.extensions.transport.wake, wake.pollMilliseconds == settings.wakePollMilliseconds,
                  wake.wake.timeoutMilliseconds == settings.wakeTimeoutMilliseconds else { throw GatewayPreparationError.conflictingMaterial }
            return (account, inventory, plan)
        }
        let (account, inventory, plan) = retained
        func verify(_ machine: PreparationIntentStore) throws {
            try Task.checkCancellation()
            guard getpid() == processID, let current = try machine.inventory(),
                  current.installationID == inventory.installationID, current.releaseDigest == inventory.releaseDigest,
                  current.bundlePath == inventory.bundlePath else { throw AdministrativeSetupError.changedInstallation }
            try verifyHost(current); try machine.validateAccountPreparation(account)
            try SharedSetupImportGatewayRuntimeScope.validate(machine: machine, account: account, expected: expectedImport, activationSettings: settings)
            try LocalAccountDirectory.validateOwnership(lookupAccount(ownerUID), uid: ownerUID, directoryID: account.directoryID)
            guard try setup(machine, account) == expected.setup else { throw AdministrativeSetupError.staleProgress }
        }
        _ = try GatewayRuntimeActivationOperation.resume(plan: plan, withMachine: { body in try borrow(body) },
            verifyScope: verify, operations: operations)
        return try borrow { machine in
            try verify(machine)
            let result = try SetupGatewayActivationProgress(setup: setup(machine, account), state: machine.gatewayRuntimeActivation(accountID: account.accountID))
            try result.validateActivation(of: expected, selectedSettings: settings); return result
        }
        }
        }
        }
    }
}
