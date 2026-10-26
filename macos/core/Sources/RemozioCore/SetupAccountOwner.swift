import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupError: Error, Equatable {
    case invalidConfiguration, unavailable, wrongAccount, changedInstallation, staleProgress
}

/// Serializes setup operations. Production opens a fresh machine writer for each operation.
/// The host retains protected placement and verifies its current signed release on each use.
public final class SetupAccountOwner: @unchecked Sendable {
    private enum Machines {
        // Logical endpoint fixtures can borrow an existing connection. Production uses scoped access.
        case retained(PreparationIntentStore)
        case scoped(() throws -> PreparationIntentStore)
        func use<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            switch self {
            case .retained(let machine): return try body(machine)
            case .scoped(let open):
                let machine = try open()
                do {
                    let value = try body(machine)
                    try machine.close()
                    return value
                } catch { try? machine.close(); throw error }
            }
        }
        // Retry only lease acquisition, never an operation body or an unknown commit.
        func useActivation<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard case .scoped(let open) = self else { throw AdministrativeSetupError.unavailable }
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
            var next: PreparationIntentStore?
            while next == nil {
                do { next = try open() }
                catch JournalLeaseError.busy {
                    guard DispatchTime.now().uptimeNanoseconds < deadline else { throw JournalLeaseError.busy }
                    usleep(50_000)
                }
            }
            let machine = next!
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
        func close() throws { if case .retained(let machine) = self { try machine.close() } }
    }
    private let lock = NSRecursiveLock()
    private let machines: Machines
    private let releaseActivity: ReleaseActivityBarrier?
    private let processID = getpid()
    private let installationID: Data
    private let expectedReleaseDigest: Data
    private let resume: (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent
    private let verifyHost: (InstallationInventory) throws -> Void
    private let accountCodePolicy: AuthorityCodePolicy?
    private let lookupAccount: (uid_t) throws -> LocalAccountIdentity
    private let prepareAccount: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent
    private let prepareServices: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State
    private let prepareRuntime: (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState
    private let activationOperations: RuntimeActivationOperations
    private let asynchronousWork = SetupOwnerAsyncWork()
    private let setupReplyWork = SetupOwnerAsyncWork()
    private let gatewayJournalOperation: GatewaySetupJournalOperations?
    private let gatewayActivationOperation: GatewaySetupActivationOperations?
    private let gatewaySettingsOperation: GatewaySetupSettingsOperations?
    private let importedGatewayOperation: GatewaySetupImportedRuntimeOperations?
    private var closing = false
    private var closed = false

    public static func open(machineDirectory: String, macID: Data, expectedReleaseDigest: Data) throws -> SetupAccountOwner {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory)
        return try .init(openMachine: { try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID) },
            expectedReleaseDigest: expectedReleaseDigest,
            resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) }, releaseActivity: activity,
            gatewayJournalOperation: .native(machineDirectory: machineDirectory, macID: macID),
            gatewayActivationOperation: .native(machineDirectory: machineDirectory, macID: macID),
            gatewaySettingsOperation: .native(machineDirectory: machineDirectory, macID: macID),
            importedGatewayOperation: .native(machineDirectory: machineDirectory, macID: macID))
    }
    // Same-owner lifecycle fixtures use the same scoped factory as production.
    convenience init(openMachine: @escaping () throws -> PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in },
         accountCodePolicy: AuthorityCodePolicy? = nil,
         lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent = {
             try AccountPreparationController.resume(machine: $0, expected: $1, verifyCurrent: $2)
         }, prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State = {
             try ServiceAccountPreparation.prepare(machine: $0, account: $1, verifyCurrent: $2)
         }, prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState = {
             try RuntimePublicationController.prepare(machine: $0, account: $1, expected: $2, fileCustodyAccepted: $3, verifyCurrent: $4)
         }, activationOperations: RuntimeActivationOperations = .native, releaseActivity: ReleaseActivityBarrier? = nil,
         gatewayJournalOperation: GatewaySetupJournalOperations? = nil, gatewayActivationOperation: GatewaySetupActivationOperations? = nil,
         gatewaySettingsOperation: GatewaySetupSettingsOperations? = nil,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations? = nil) throws {
        try self.init(machines: .scoped(openMachine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations, releaseActivity: releaseActivity, gatewayJournalOperation: gatewayJournalOperation, gatewayActivationOperation: gatewayActivationOperation, gatewaySettingsOperation: gatewaySettingsOperation, importedGatewayOperation: importedGatewayOperation)
    }
    // Logical endpoint fixtures retain actual protected storage. They do not prove production lease lifetime.
    convenience init(machine: PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in },
         accountCodePolicy: AuthorityCodePolicy? = nil,
         lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent = {
             try AccountPreparationController.resume(machine: $0, expected: $1, verifyCurrent: $2)
         }, prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State = {
             try ServiceAccountPreparation.prepare(machine: $0, account: $1, verifyCurrent: $2)
         }, prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState = {
             try RuntimePublicationController.prepare(machine: $0, account: $1, expected: $2, fileCustodyAccepted: $3, verifyCurrent: $4)
         }, activationOperations: RuntimeActivationOperations = .native, releaseActivity: ReleaseActivityBarrier? = nil,
         gatewayJournalOperation: GatewaySetupJournalOperations? = nil, gatewayActivationOperation: GatewaySetupActivationOperations? = nil,
         gatewaySettingsOperation: GatewaySetupSettingsOperations? = nil,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations? = nil) throws {
        try self.init(machines: .retained(machine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations, releaseActivity: releaseActivity, gatewayJournalOperation: gatewayJournalOperation, gatewayActivationOperation: gatewayActivationOperation, gatewaySettingsOperation: gatewaySettingsOperation, importedGatewayOperation: importedGatewayOperation)
    }
    private init(machines: Machines, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void,
         accountCodePolicy: AuthorityCodePolicy?, lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent,
         prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State,
         prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState,
         activationOperations: RuntimeActivationOperations, releaseActivity: ReleaseActivityBarrier?,
         gatewayJournalOperation: GatewaySetupJournalOperations?, gatewayActivationOperation: GatewaySetupActivationOperations?, gatewaySettingsOperation: GatewaySetupSettingsOperations?,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations?) throws {
        self.releaseActivity = releaseActivity; self.gatewayJournalOperation = gatewayJournalOperation
        self.gatewayActivationOperation = gatewayActivationOperation; self.gatewaySettingsOperation = gatewaySettingsOperation
        self.importedGatewayOperation = importedGatewayOperation
        self.machines = machines; self.expectedReleaseDigest = expectedReleaseDigest; self.resume = resume; self.verifyHost = verifyHost
        self.accountCodePolicy = accountCodePolicy; self.lookupAccount = lookupAccount; self.prepareAccount = prepareAccount; self.prepareServices = prepareServices; self.prepareRuntime = prepareRuntime; self.activationOperations = activationOperations
        do {
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            installationID = try machines.use { machine in
                guard expectedReleaseDigest.count == 32, let inventory = try machine.inventory(),
                      inventory.releaseDigest == expectedReleaseDigest else { throw AdministrativeSetupError.invalidConfiguration }
                return inventory.installationID
            }
        } catch { try? machines.close(); throw error }
    }
    deinit { try? close() }
    public func close() throws {
        try lock.withLock {
            guard !closed else { return }
            closing = true; asynchronousWork.closeAdmission(); setupReplyWork.closeAdmission()
            guard asynchronousWork.isIdle, setupReplyWork.isIdle else { throw AdministrativeSetupError.unavailable }
            try machines.close(); closed = true
        }
    }
    func closeWhenIdle() async throws {
        lock.withLock { closing = true; asynchronousWork.closeAdmission(); setupReplyWork.closeAdmission() }
        await setupReplyWork.waitUntilIdle()
        await asynchronousWork.waitUntilIdle()
        try close()
    }
    func acquireSetupReplyAdmission() throws -> SetupOwnerAsyncWork.Token {
        try lock.withLock {
            guard !closed, !closing, getpid() == processID else { throw AdministrativeSetupError.unavailable }
            return try setupReplyWork.admit()
        }
    }
    /// The native endpoint retains this reference through response encoding and the reply callback.
    func acquireReleaseActivity() throws -> ReleaseActivityToken? {
        try lock.withLock {
            guard !closed, !closing else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            return try releaseActivity?.acquireShared()
        }
    }

    private func withMachine<Value>(admission: SetupOwnerAsyncWork.Token? = nil,
                                    _ body: (PreparationIntentStore) throws -> Value) throws -> Value {
        try lock.withLock {
            guard !closed, !closing, asynchronousWork.permits(admission) else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            let result = try machines.use(body)
            try activity?.validate()
            return result
        }
    }
    func verifyCurrent() throws {
        try withMachine { _ = try currentInventory($0) }
    }
    func progress(accountID: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent? {
        try withMachine { machine in
            try requireAccount(accountID, callerUID: callerUID, machine: machine)
            let value = try machine.initialization(accountID: accountID)
            _ = try currentInventory(machine)
            return value
        }
    }
    func resumeAccount(accountID: Data, setupID: Data, expectedRevision: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent {
        try withMachine { machine in
            guard setupID.count == 16, expectedRevision.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
            try requireAccount(accountID, callerUID: callerUID, machine: machine)
            guard let expected = try machine.initialization(accountID: accountID), expected.setupID == setupID,
                  expected.revision == expectedRevision else { throw AdministrativeSetupError.staleProgress }
            let result = try resume(machine, expected)
            _ = try currentInventory(machine)
            return result
        }
    }
    func enrollment(callerUID: uid_t) throws -> AccountPreparationIntent? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            let owner = try lookupAccount(callerUID)
            guard owner.uid == callerUID else { throw AdministrativeSetupError.wrongAccount }
            let retained = try machine.accountPreparation(ownerUID: callerUID)
            if let retained { try verifyEnrollment(retained, callerUID: callerUID, machine: machine) }
            _ = try currentInventory(machine)
            return retained
        }
    }
    // The endpoint supplies the kernel-authenticated UID and validates current administrator rights first.
    func beginEnrollment(callerUID: uid_t, allowedTargetUIDs: Set<UInt32>, disclosureAccepted: Bool) throws -> AccountPreparationIntent {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let policy = accountCodePolicy else { throw AdministrativeSetupError.unavailable }
            let owner = try lookupAccount(callerUID)
            guard owner.uid == callerUID else { throw AdministrativeSetupError.wrongAccount }
            let intent = try machine.beginAccountPreparation(owner: owner, allowedTargetUIDs: allowedTargetUIDs,
                disclosureAccepted: disclosureAccepted, expectedInventoryRevision: inventory.revision,
                makeInitial: { mac, account in try Self.initialAuthority(macID: mac, accountID: account, codePolicy: policy) })
            try verifyEnrollment(intent, callerUID: callerUID, machine: machine)
            return intent
        }
    }
    func resumeEnrollment(callerUID: uid_t, setupID: Data, expectedRevision: Data) throws -> AccountPreparationIntent {
        try withMachine { machine in
            guard setupID.count == 16, expectedRevision.count == 16,
                  let expected = try machine.accountPreparation(ownerUID: callerUID), expected.setupID == setupID,
                  expected.revision == expectedRevision else { throw AdministrativeSetupError.staleProgress }
            try verifyEnrollment(expected, callerUID: callerUID, machine: machine)
            let result = try prepareAccount(machine, expected, { try self.verifyEnrollment(expected, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(result, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func serviceAccountsProgress(callerUID: uid_t) throws -> SetupServiceAccountProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard account.storagePrepared else { return nil }
            let result = try SetupServiceAccountProgress(account: account, state: machine.serviceAccountPlan(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func resumeServiceAccounts(callerUID: uid_t, expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress {
        try withMachine { machine in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try SetupServiceAccountProgress(account: account, state: machine.serviceAccountPlan(accountID: account.accountID)) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            let state = try prepareServices(machine, account, { try self.verifyEnrollment(account, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let result = try SetupServiceAccountProgress(account: account, state: state)
            try result.validateCompletion(of: expected)
            return result
        }
    }
    func runtimeProgress(callerUID: uid_t) throws -> SetupRuntimeProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            guard services.complete else { return nil }
            let value = try SetupRuntimeProgress(account: account, services: services, state: machine.runtimePreparation(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return value
        }
    }
    func resumeRuntime(callerUID: uid_t, expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) throws -> SetupRuntimeProgress {
        try withMachine { machine in
            guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            let state = try machine.runtimePreparation(accountID: account.accountID)
            guard try SetupRuntimeProgress(account: account, services: services, state: state) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            let result = try prepareRuntime(machine, account, state, fileCustodyAccepted, {
                try self.verifyEnrollment(account, callerUID: callerUID, machine: machine)
            })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let progress = try SetupRuntimeProgress(account: account, services: services, state: result)
            try progress.validateCompletion(of: expected)
            return progress
        }
    }
    func gatewayProgress(callerUID: uid_t) throws -> SetupGatewayProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try machine.runtimeActivation(accountID: account.accountID).jobsRegistered else { return nil }
            let progress = try gatewayProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return progress
        }
    }
    // The endpoint must authenticate the UID and current administrator rights before this explicit operation.
    func prepareGateway(callerUID: uid_t, expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) throws -> SetupGatewayProgress {
        try prepareGateway(callerUID: callerUID, expected: expected) { machine, account, verify in
            try GatewaySetupAccountPreparation.prepare(machine: machine, account: account, choices: choices, verifyCurrent: verify)
        }
    }
    // Owned fixtures keep the real machine store and account checks. The injected preparation proves neither Root admission nor service isolation.
    func prepareGateway(callerUID: uid_t, expected: SetupGatewayProgress,
                        prepare: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> Void) throws -> SetupGatewayProgress {
        try withMachine { machine in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayProgress(machine: machine, account: account) == expected else { throw AdministrativeSetupError.staleProgress }
            if expected.journalInitialized { return expected }
            try prepare(machine, account, { try self.verifyEnrollment(account, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let progress = try gatewayProgress(machine: machine, account: account)
            try progress.validatePreparation(of: expected)
            return progress
        }
    }
    func resumeGatewayJournal(callerUID: uid_t, expected: SetupGatewayProgress) async throws -> SetupGatewayJournalResult {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = gatewayJournalOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try asynchronousWork.admit()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        let digest = try withMachine(admission: context.0) { machine -> Data in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayProgress(machine: machine, account: account) == expected,
                  let digest = expected.journalIntentDigest else { throw AdministrativeSetupError.staleProgress }
            return digest
        }
        try Task.checkCancellation()
        // The first writer is closed. The Root operation owns a separate machine lease across its exchange.
        let report = try await context.2.resume(callerUID, digest, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        guard report.intentDigest == digest else { throw AdministrativeSetupError.staleProgress }
        let progress = try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewayProgress(machine: machine, account: account)
            try value.validateJournalCompletion(of: expected)
            return value
        }
        return try .init(progress: progress, cleanupComplete: report.cleanupComplete)
    }
    private func gatewayProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewayProgress {
        try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
            activation: machine.runtimeActivation(accountID: account.accountID),
            material: machine.gatewayPreparation(accountID: account.accountID), journal: machine.gatewayJournalPreparation(accountID: account.accountID))
    }
    func gatewayActivationProgress(callerUID: uid_t) throws -> SetupGatewayActivationProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try machine.runtimeActivation(accountID: account.accountID).jobsRegistered else { return nil }
            let progress = try gatewayActivationProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine); return progress
        }
    }
    func resumeGatewayActivation(callerUID: uid_t, expected: SetupGatewayActivationProgress,
                                 settings: GatewayRuntimeActivationSettings) async throws -> SetupGatewayActivationProgress {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = gatewayActivationOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try asynchronousWork.admit()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        try withMachine(admission: context.0) { machine in
            guard expected.setup.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayActivationProgress(machine: machine, account: account) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            guard expected.setup.journalInitialized else { throw GatewayPreparationError.incomplete }
            guard expected.settings == nil || expected.settings == settings else { throw GatewayPreparationError.conflictingMaterial }
        }
        try Task.checkCancellation()
        let report = try await context.2.resume(callerUID, expected, settings, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        return try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewayActivationProgress(machine: machine, account: account)
            try value.validateActivation(of: expected, selectedSettings: settings)
            guard report.planDigest.count == 32, value.planDigest == report.planDigest else { throw AdministrativeSetupError.staleProgress }
            return value
        }
    }
    func prepareImportedGateway(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                fileWakeCustodyAccepted: Bool,
                                prepare: (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices, GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                    try GatewaySetupAccountPreparation.prepareImported(machine: $0, account: $1, choices: $2, selection: $3, verifyCurrent: $4)
                                }, validate: (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices, GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                    try SharedSetupImportGatewayPreparedValidation.validateNative(machine: $0, account: $1, choices: $2, selection: $3, verifyCurrent: $4)
                                }) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            func verifyDestination() throws {
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                guard try currentInventory(machine) == inventory,
                      try machine.serviceAccountPlan(accountID: account.accountID) == services,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                    throw AdministrativeSetupError.staleProgress
                }
            }
            return try machine.withSharedImportJournal { journal in
                guard let journal, var retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                let before = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard before == expected else { throw AdministrativeSetupError.staleProgress }
                guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                guard retained.phase == .runtimePublished || retained.phase == .gatewayPrepared else {
                    throw SharedSetupImportError.invalidTransition
                }
                func verify() throws {
                    try verifyDestination()
                    guard try journal.current(scope: scope) == retained else { throw SharedSetupImportError.staleRevision }
                }
                func validatePrepared(_ choices: GatewaySetupPreparationChoices?, _ verify: () throws -> Void) throws {
                    if let choices {
                        guard let selection = proposal.defaults.gateway else { throw PortableSetupError.rejected }
                        try withoutActuallyEscaping(verify) { current in
                            try validate(machine, account, choices, selection, current)
                        }
                    } else {
                        try SharedSetupImportGatewayPreparedValidation.validateAbsent(machine: machine, account: account, verifyCurrent: verify)
                    }
                }
                try verify()
                if retained.phase == .runtimePublished {
                    try SharedSetupImportGatewayScope.withReviewedPreparation(machine: machine, account: account,
                        journal: journal, expected: retained, proposal: proposal, fileWakeCustodyAccepted: fileWakeCustodyAccepted,
                        verifyCurrent: verify) { choices, current in
                        try withoutActuallyEscaping(current) { preparedCurrent in
                            if let choices {
                                guard let selection = proposal.defaults.gateway else { throw PortableSetupError.rejected }
                                try prepare(machine, account, choices, selection, preparedCurrent)
                            }
                            try validatePrepared(choices, preparedCurrent)
                        }
                    }
                    try verify(); retained = try journal.advance(retained, to: .gatewayPrepared)
                } else {
                    let choices = proposal.fcm == nil && proposal.pushClient == nil ? nil
                        : try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false)
                    try validatePrepared(choices, verify)
                }
                try verify()
                return try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
            }
        }
    }


    func resumeImportedGateway(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                               validatePrepared: @Sendable (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices,
                                   GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                       try SharedSetupImportGatewayPreparedValidation.validateNative(machine: $0, account: $1,
                                           choices: $2, selection: $3, verifyCurrent: $4)
                                   }) async throws -> SetupImportedGatewayRuntimeResult {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = importedGatewayOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try asynchronousWork.admit()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        func read() throws -> (SharedSetupImportIntent, SetupGatewayActivationProgress) {
            try withMachine(admission: context.0) { machine in
                guard expected.runtime.ownerUID == callerUID,
                      let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
                let retained = try machine.withSharedImportJournal { journal in
                    guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                    let current = try SetupPortableImportProgress(account: account, inventory: inventory,
                        services: services, runtime: runtime, retained: retained)
                    guard current == expected else { throw AdministrativeSetupError.staleProgress }
                    guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                    return retained
                }
                guard proposal.fcm != nil, proposal.pushClient != nil, let selection = proposal.defaults.gateway else {
                    throw GatewayPreparationError.incomplete
                }
                let choices = try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false)
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                        throw AdministrativeSetupError.staleProgress
                    }
                    try SharedSetupImportGatewayRuntimeScope.validate(machine: machine, account: account,
                        expected: retained, activationSettings: selection.activation)
                }
                try verify(); try validatePrepared(machine, account, choices, selection, verify); try verify()
                return (retained, try gatewayActivationProgress(machine: machine, account: account))
            }
        }
        let before = try read(), retained = before.0
        guard let digest = before.1.setup.journalIntentDigest, let selection = proposal.defaults.gateway else {
            throw GatewayPreparationError.incomplete
        }
        let verifyHost: @Sendable (InstallationInventory) throws -> Void = { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try self.verifyHost(inventory)
            }
        }
        try Task.checkCancellation()
        let initialized = try await context.2.initialize(callerUID, digest, retained, verifyHost)
        try Task.checkCancellation(); try context.1?.validate()
        let ready = try read()
        guard ready.0 == retained, initialized.intentDigest == digest, ready.1.setup.journalInitialized else {
            throw AdministrativeSetupError.staleProgress
        }
        if !initialized.cleanupComplete {
            return .init(progress: expected, cleanupComplete: false, activation: nil)
        }
        let report = try await context.2.activate(callerUID, ready.1, selection.activation, retained, verifyHost)
        try Task.checkCancellation(); try context.1?.validate()
        let final = try read()
        guard final.0 == retained else { throw AdministrativeSetupError.staleProgress }
        try final.1.validateActivation(of: ready.1, selectedSettings: selection.activation)
        guard final.1.planDigest == report.planDigest else { throw AdministrativeSetupError.staleProgress }
        return .init(progress: expected, cleanupComplete: true, activation: final.1)
    }


    func prepareImportedRelayPlan(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                  selectPort: (Set<UInt16>) throws -> UInt16 = { try SharedSetupRelayPortSelection.choose(reserved: $0) }) throws -> SharedSetupImportRelayPlan {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                guard try SetupPortableImportProgress(account: account, inventory: inventory, services: services,
                    runtime: runtime, retained: retained) == expected else { throw AdministrativeSetupError.staleProgress }
                guard try retained.matches(proposal), proposal.cloudflare != nil else { throw SharedSetupImportError.conflict }
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                return try machine.withSharedImportRelayDirectory { directory, owner in
                    try SharedSetupImportRelayStorage.prepare(expected: retained, records: journal.records(),
                        runtimePublished: runtime.reference != nil || runtime.configurationPublished,
                        directory: directory, owner: owner, select: selectPort, verifyCurrent: verify)
                }
            }
        }
    }


    func inspectImportedRelayScope(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                   inspect: @escaping @Sendable (SetupCloudflareConfiguration) async throws -> CloudflareProvisioningScope = {
                                       try await CloudflareProvisioningScopeClient.native().inspect($0)
                                   }) async throws -> CloudflareProvisioningScope {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: false) { configuration, _ in
            let result = try await inspect(configuration); try result.validate(configuration); return result
        }
    }

    func inspectImportedRelayTunnel(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                    inspect: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan) async throws -> CloudflareImportedRelayInspection = {
                                        try await CloudflareImportedRelayInspection.native(configuration: $0, expected: $1, plan: $2)
                                    }) async throws -> CloudflareImportedRelayInspection {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let result = try await inspect(configuration, binding.retained, plan)
            try result.validate(configuration: configuration, expected: binding.retained, plan: plan); return result
        }
    }

    private struct ImportedRelayInspectionBinding: Sendable {
        let retained: SharedSetupImportIntent
        let inventory: InstallationInventory
        let plan: SharedSetupImportRelayPlan?
        let planSnapshot: SharedSetupImportRelayStorage.Snapshot?
        let admission: SetupOwnerAsyncWork.Token
    }

    func createImportedRelayTunnel(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                    inspect: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan) async throws -> CloudflareImportedRelayInspection = {
                                        try await CloudflareImportedRelayInspection.native(configuration: $0, expected: $1, plan: $2)
                                    },
                                    create: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan, SharedSetupRelayProvisioningRecord) async throws -> CloudflareTunnelCreationOutcome = {
                                        try await CloudflareTunnelCreationClient.native().create($0, expected: $1, plan: $2, dispatched: $3)
                                    }) async throws -> SharedSetupRelayProvisioningRecord {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let prepared = try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try SharedSetupRelayProvisioningStorage.begin(expected: retained, plan: plan, directory: directory, owner: owner, verifyCurrent: verify)
            }
            if prepared.phase == .created { return prepared }
            guard prepared.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let observed = try await inspect(configuration, binding.retained, plan)
            try observed.validate(configuration: configuration, expected: binding.retained, plan: plan)
            guard observed.tunnel == nil else { throw RelayProvisioningError.wrongScope }
            try Task.checkCancellation()
            let dispatched = try prepared.transition(to: .dispatched)
            try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try Task.checkCancellation()
                try SharedSetupRelayProvisioningStorage.replace(dispatched, previous: prepared, expected: retained, plan: plan,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            let outcome: CloudflareTunnelCreationOutcome
            do { outcome = try await create(configuration, binding.retained, plan, dispatched) }
            catch { outcome = .unknown }
            let next: SharedSetupRelayProvisioningRecord
            switch outcome {
            case .created(let observation):
                if observation.accountID == configuration.accountID, observation.name == plan.tunnelName,
                   observation.tunnelID.utf8.count == 36, let uuid = UUID(uuidString: observation.tunnelID),
                   uuid.uuidString.lowercased() == observation.tunnelID {
                    next = try dispatched.transition(to: .created, tunnelID: observation.tunnelID)
                } else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            // Record an acknowledgement before reporting cancellation. If closing or scope changes prevent this, dispatch remains unresolved.
            try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try SharedSetupRelayProvisioningStorage.replace(next, previous: dispatched, expected: retained, plan: plan,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    func applyImportedRelayIngress(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                   send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareTunnelConfigurationObservation {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, created, _, scoped in
            let intent = binding.retained
            let routes = CloudflarePrivateRouteClient(send: scoped)
            _ = try await routes.inspect(configuration, expected: intent, plan: plan, created: created)
            let observed = try await CloudflareTunnelConfigurationClient(send: scoped).apply(configuration, expected: intent, plan: plan, created: created)
            _ = try await routes.inspect(configuration, expected: intent, plan: plan, created: created)
            return observed
        }
    }

    func inspectImportedRelayPrivateRoutes(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                          send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflarePrivateRouteObservation {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, created, _, scoped in
            let intent = binding.retained
            return try await CloudflarePrivateRouteClient(send: scoped).inspect(configuration, expected: intent, plan: plan, created: created)
        }
    }

    func readImportedRelayRunCredential(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                        send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareTunnelRunCredential {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, scoped in
            try await CloudflareTunnelTokenClient(send: scoped).read(configuration, expected: binding.retained, plan: plan, created: tunnel)
        }
    }

    func createImportedAccessApplication(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                         send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupAccessApplicationRecord {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, scoped in
            let initial = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                let record = try SharedSetupAccessApplicationStorage.begin(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
                let snapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
                return (record, snapshot)
            }
            if initial.0.phase == .created { return initial.0 }
            guard initial.0.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let client = CloudflareAccessApplicationClient(send: scoped)
            try await client.inspectAbsent(configuration, expected: binding.retained, plan: plan, createdTunnel: tunnel)
            try Task.checkCancellation()
            let dispatched = try initial.0.transition(to: .dispatched)
            let sentSnapshot = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == initial.1 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation()
                try SharedSetupAccessApplicationStorage.replace(dispatched, previous: initial.0, expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
                return try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
            }
            let outcome: CloudflareAccessApplicationCreationOutcome
            do { outcome = try await client.create(configuration, expected: binding.retained, plan: plan, createdTunnel: tunnel, dispatched: dispatched) }
            catch { outcome = .unknown }
            let next: SharedSetupAccessApplicationRecord
            switch outcome {
            case .created(let app):
                if app.accountID == configuration.accountID, app.name == plan.accessApplicationName, app.hostname == plan.hostname,
                   let value = try? dispatched.transition(to: .created, applicationID: app.applicationID, audience: app.audience) { next = value }
                else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == sentSnapshot else { throw RelayProvisioningError.staleRecord }
                try SharedSetupAccessApplicationStorage.replace(next, previous: dispatched, expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    func inspectImportedInitialAccessApplication(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                                send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareInitialAccessObservation {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareAccessApplicationClient(send: scoped).inspectInitial(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func inspectImportedAccessHostnameInventory(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                               send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareAccessHostnameInventory {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareAccessHostnameClient(send: scoped).inspect(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func inspectImportedRelayPublicationPreflight(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                                send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareRelayPublicationPreflight {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareRelayPublicationPreflightClient(send: scoped).inspect(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func createImportedDNSRecord(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                 send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupDNSRecord {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, application, scoped in
            let initial = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                let record = try SharedSetupDNSStorage.begin(expected: intent, plan: plan, createdTunnel: tunnel, application: application,
                    directory: directory, owner: owner, verifyCurrent: verify)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                let accessSnapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
                return (record, snapshot, accessSnapshot)
            }
            if initial.0.phase == .created { return initial.0 }
            guard initial.0.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            @Sendable func verifyDNS(_ record: SharedSetupDNSRecord, _ snapshot: SharedSetupDNSStorage.Snapshot) throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == record,
                          try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == snapshot,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                            directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let preflightSend: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyDNS(initial.0, initial.1); return try await scoped(request)
            }
            let observed: CloudflareRelayPublicationPreflight
            do {
                observed = try await CloudflareRelayPublicationPreflightClient(send: preflightSend).inspect(configuration,
                    expected: binding.retained, plan: plan, createdTunnel: tunnel, application: application)
                try verifyDNS(initial.0, initial.1)
            } catch { try Task.checkCancellation(); try verifyDNS(initial.0, initial.1); throw error }
            switch observed.hostnameAssessment {
            case .noOtherMatchObserved, .exactHostnamePrecedesBroaderWildcardRoots: break
            case .requiresPrecedenceVerification: throw RelayProvisioningError.requiresReconciliation
            }
            try Task.checkCancellation()
            let dispatched = try initial.0.transition(to: .dispatched)
            let sentSnapshot = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) == initial.1,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation()
                try SharedSetupDNSStorage.replace(dispatched, previous: initial.0, expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner, verifyCurrent: verify)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                return snapshot
            }
            let creationSend: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyDNS(dispatched, sentSnapshot); return try await scoped(request)
            }
            let outcome: CloudflareDNSCreationOutcome
            do {
                outcome = try await CloudflareDNSRecordClient(send: creationSend).create(configuration, expected: binding.retained,
                    plan: plan, createdTunnel: tunnel, application: application, dispatched: dispatched)
            } catch { outcome = .unknown }
            let next: SharedSetupDNSRecord
            switch outcome {
            case .created(let identity):
                if identity.zoneID == configuration.zoneID, identity.hostname == plan.hostname,
                   identity.target == dispatched.tunnelID + ".cfargotunnel.com",
                   let created = try? dispatched.transition(to: .created, dnsRecordID: identity.recordID) { next = created }
                else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) == sentSnapshot,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                try SharedSetupDNSStorage.replace(next, previous: dispatched, expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    func inspectImportedDNSRecord(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                  send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareDNSRecordObservation {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, application, scoped in
            let retained = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.requiresReconciliation }
                _ = try record.createdRecord(expected: intent, plan: plan, createdTunnel: tunnel, application: application)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                try verify(); return (record, snapshot)
            }
            @Sendable func verifyDNS() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == retained.0,
                          try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == retained.1 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let dnsSend: CloudflareProvisioningScopeClient.Send = { request in try Task.checkCancellation(); try verifyDNS(); return try await scoped(request) }
            do {
                let result = try await CloudflareDNSRecordClient(send: dnsSend).inspect(configuration, expected: binding.retained,
                    plan: plan, createdTunnel: tunnel, application: application, record: retained.0)
                try verifyDNS(); return result
            } catch { try Task.checkCancellation(); try verifyDNS(); throw error }
        }
    }

    private func withCreatedImportedAccessApplication<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                        send: CloudflareProvisioningScopeClient.Send?,
                        operation: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding, SharedSetupImportRelayPlan,
                            SharedSetupRelayProvisioningRecord, SharedSetupRelayProvisioningStorage.Snapshot, SharedSetupAccessApplicationRecord, @escaping CloudflareProvisioningScopeClient.Send) async throws -> Value) async throws -> Value {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, scoped in
            let retained = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) else { throw RelayProvisioningError.requiresReconciliation }
                _ = try record.createdApplication(expected: intent, plan: plan, createdTunnel: tunnel)
                let snapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner)); try verify(); return (record, snapshot)
            }
            @Sendable func verifyAccess() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == retained.0,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == retained.1 else { throw RelayProvisioningError.staleRecord }; try verify()
                }
            }
            let accessSend: CloudflareProvisioningScopeClient.Send = { request in try Task.checkCancellation(); try verifyAccess(); return try await scoped(request) }
            do {
                let result = try await operation(configuration, binding, plan, tunnel, tunnelSnapshot, retained.0, accessSend)
                try verifyAccess(); return result
            } catch { try Task.checkCancellation(); try verifyAccess(); throw error }
        }
    }

    private static func requireAccessSnapshot(_ value: SharedSetupAccessApplicationStorage.Snapshot?) throws -> SharedSetupAccessApplicationStorage.Snapshot {
        guard let value else { throw RelayProvisioningError.staleRecord }; return value
    }

    private func withImportedAccessDirectory<Value>(binding: ImportedRelayInspectionBinding, tunnel: SharedSetupRelayProvisioningRecord,
                        tunnelSnapshot: SharedSetupRelayProvisioningStorage.Snapshot, callerUID: uid_t, expected: SetupPortableImportProgress,
                        proposal: PortableSetup,
                        body: (SharedSetupImportIntent, SharedSetupImportRelayPlan, ProtectedSetupDirectory, uid_t, () throws -> Void) throws -> Value) throws -> Value {
        try withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
            return try withoutActuallyEscaping(verify) { current in
                func verifyAll() throws {
                    try current()
                    guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == tunnel,
                          try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == tunnelSnapshot else {
                        throw RelayProvisioningError.staleRecord
                    }
                }
                try verifyAll(); let result = try body(intent, plan, directory, owner, verifyAll); try verifyAll(); return result
            }
        }
    }

    private func withCreatedImportedRelay<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                            send: CloudflareProvisioningScopeClient.Send?,
                            operation: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding, SharedSetupImportRelayPlan,
                                SharedSetupRelayProvisioningRecord, SharedSetupRelayProvisioningStorage.Snapshot, @escaping CloudflareProvisioningScopeClient.Send) async throws -> Value) async throws -> Value {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let retained = try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner),
                      let snapshot = try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) else {
                    throw RelayProvisioningError.requiresReconciliation
                }
                _ = try record.createdTunnel(expected: intent, plan: plan); try verify(); return (record, snapshot)
            }
            @Sendable func verifyRetained() throws {
                try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == retained.0,
                          try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == retained.1 else {
                        throw RelayProvisioningError.staleRecord
                    }
                    try verify()
                }
            }
            let transport: CloudflareProvisioningScopeClient.Send
            if let send { transport = send }
            else { let native = try FCMHTTPTransport(timeoutSeconds: 30); transport = { try await native.send($0) } }
            let scoped: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyRetained()
                return try await transport(request)
            }
            do {
                _ = try await CloudflareCreatedTunnelClient(send: scoped).inspect(configuration, expected: binding.retained, plan: plan, created: retained.0)
                try Task.checkCancellation(); try verifyRetained()
                let observed = try await operation(configuration, binding, plan, retained.0, retained.1, scoped)
                try Task.checkCancellation(); try verifyRetained(); return observed
            } catch {
                try Task.checkCancellation(); try verifyRetained()
                throw error
            }
        }
    }

    private func withImportedRelayProvisioning<Value>(binding: ImportedRelayInspectionBinding, callerUID: uid_t,
                    expected: SetupPortableImportProgress, proposal: PortableSetup,
                    body: (SharedSetupImportIntent, SharedSetupImportRelayPlan, ProtectedSetupDirectory, uid_t, () throws -> Void) throws -> Value) throws -> Value {
        try withMachine(admission: binding.admission) { machine in
            guard expected.runtime.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            guard inventory == binding.inventory else { throw AdministrativeSetupError.staleProgress }
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope), retained == binding.retained,
                      try retained.matches(proposal),
                      try SetupPortableImportProgress(account: account, inventory: inventory, services: services,
                        runtime: runtime, retained: retained) == expected else { throw AdministrativeSetupError.staleProgress }
                return try machine.withSharedImportRelayDirectory { directory, owner in
                    try SharedSetupImportRelayStorage.validateTrackedFiles(records: journal.records(), directory: directory)
                    guard let plan = try SharedSetupImportRelayStorage.read(expected: retained, directory: directory, owner: owner),
                          plan == binding.plan,
                          try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) == binding.planSnapshot else {
                        throw AdministrativeSetupError.staleProgress
                    }
                    func verify() throws {
                        try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                        guard try currentInventory(machine) == binding.inventory,
                              try machine.serviceAccountPlan(accountID: account.accountID) == services,
                              try machine.runtimePreparation(accountID: account.accountID) == runtime,
                              try journal.current(scope: scope) == retained,
                              try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) == binding.planSnapshot else {
                            throw AdministrativeSetupError.staleProgress
                        }
                    }
                    try verify(); let result = try body(retained, plan, directory, owner, verify); try verify(); return result
                }
            }
        }
    }

    private func withImportedRelayInspection<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                requiresPlan: Bool,
                                inspect: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding) async throws -> Value) async throws -> Value {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID else { throw AdministrativeSetupError.unavailable }
            let admission = try asynchronousWork.admit()
            do { return (admission, try releaseActivity?.acquireShared()) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        func read() throws -> (SharedSetupImportIntent, InstallationInventory, SharedSetupImportRelayPlan?, SharedSetupImportRelayStorage.Snapshot?) {
            try withMachine(admission: context.0) { machine in
                guard expected.runtime.ownerUID == callerUID,
                      let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
                return try machine.withSharedImportJournal { journal in
                    guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                    let progress = try SetupPortableImportProgress(account: account, inventory: inventory,
                        services: services, runtime: runtime, retained: retained)
                    guard progress == expected else { throw AdministrativeSetupError.staleProgress }
                    guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                    var plan: SharedSetupImportRelayPlan?, snapshot: SharedSetupImportRelayStorage.Snapshot?
                    if requiresPlan {
                        try machine.withSharedImportRelayDirectory { directory, owner in
                            try SharedSetupImportRelayStorage.validateTrackedFiles(records: journal.records(), directory: directory)
                            guard let value = try SharedSetupImportRelayStorage.read(expected: retained, directory: directory, owner: owner),
                                  let identity = try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) else {
                                throw SharedSetupImportCompletionValidation.Failure.incomplete
                            }
                            plan = value; snapshot = identity
                        }
                    }
                    return (retained, inventory, plan, snapshot)
                }
            }
        }
        try Task.checkCancellation()
        let before = try read()
        guard let configuration = proposal.cloudflare else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
        try Task.checkCancellation()
        let result = try await inspect(configuration, .init(retained: before.0, inventory: before.1, plan: before.2,
            planSnapshot: before.3, admission: context.0))
        try Task.checkCancellation(); try context.1?.validate()
        let after = try read()
        guard after.0 == before.0, after.1 == before.1, after.2 == before.2, after.3 == before.3 else {
            throw AdministrativeSetupError.staleProgress
        }
        try Task.checkCancellation()
        return result
    }

    func verifiedPortableImportCompletion(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                           operations: SharedSetupImportCompletionValidation.Operations = .native) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope), retained.phase == .rootComplete else {
                    throw SharedSetupImportCompletionValidation.Failure.incomplete
                }
                let current = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard current == expected else { throw AdministrativeSetupError.staleProgress }
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                try SharedSetupImportCompletionValidation.validate(machine: machine, account: account, retained: retained,
                    proposal: proposal, operations: operations, verifyCurrent: verify)
                try verify(); return current
            }
        }
    }

    func portableImportProgress(callerUID: uid_t) throws -> SetupPortableImportProgress? {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            guard services.complete else { return nil }
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                let retained = try journal?.current(scope: scope)
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal?.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                let result = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                try verify(); return result
            }
        }
    }
    // A future native endpoint must supply the authenticated UID and fresh administrator authorization.
    // Retention grants no credential custody, runtime publication or service activation.
    func retainPortableImport(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                              didStage: (SharedSetupImportPublication.Stage) throws -> Void = { _ in }) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            let inventory = try currentInventory(machine)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            func verifyDestination() throws {
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                guard try currentInventory(machine) == inventory,
                      try machine.serviceAccountPlan(accountID: account.accountID) == services,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                    throw AdministrativeSetupError.staleProgress
                }
            }
            let existing: SharedSetupImportIntent? = try machine.withSharedImportJournal { journal in
                let retained = try journal?.current(scope: scope)
                let progress = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard progress == expected else { throw AdministrativeSetupError.staleProgress }
                try verifyDestination()
                guard let journal else { return nil }
                // Atomic first publication never exposes an empty journal. Do not repair an unexplained final directory.
                guard try !journal.records().isEmpty else { throw SharedSetupImportError.corruptRecord }
                return try SharedSetupImportRetention.retain(machine: machine, account: account, expectedRuntime: expected.runtime,
                    expectedImport: retained, proposal: proposal, journal: journal, verifyCurrent: verifyDestination)
            }
            let retained: SharedSetupImportIntent
            if let existing { retained = existing }
            else {
                guard expected.operationID == nil else { throw AdministrativeSetupError.staleProgress }
                func verifyUnconfigured() throws {
                    try verifyDestination()
                    try SharedSetupImportRetention.requireUnconfiguredDestination(machine: machine, account: account, runtime: runtime)
                }
                try verifyUnconfigured()
                let intent = try SharedSetupImportIntent(scope: scope, proposal: proposal)
                retained = try machine.publishSharedImport(intent, verifyCurrent: verifyUnconfigured, didStage: didStage)
            }
            try verifyDestination()
            let result = try SetupPortableImportProgress(account: account, inventory: inventory,
                services: services, runtime: runtime, retained: retained)
            try result.validateRetention(of: expected, proposalDigest: Data(SHA256.hash(data: try proposal.canonicalBytes())))
            return result
        }
    }

    func gatewaySettingsProgress(callerUID: uid_t) throws -> SetupGatewaySettingsProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let activation = try gatewayActivationProgress(machine: machine, account: account)
            guard activation.jobRegistered else { return nil }
            let value = try gatewaySettingsProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine); return value
        }
    }

    func retainGatewaySettings(callerUID: uid_t, expected: SetupGatewaySettingsProgress,
                               selection: GatewayRuntimeSettingsSelection) throws -> SetupGatewaySettingsProgress {
        try withMachine { machine in
            guard expected.activation.setup.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard expected.supportsSettingsChanges else { throw GatewayPreparationError.incomplete }
            guard try gatewaySettingsProgress(machine: machine, account: account) == expected,
                  try expected.pending == nil else { throw AdministrativeSetupError.staleProgress }
            let inventory = try currentInventory(machine)
            guard let activation = try machine.gatewayRuntimeActivation(accountID: account.accountID).plan,
                  let foreground = try machine.runtimeActivation(accountID: account.accountID).plan,
                  foreground.consumerHosts != nil else { throw GatewayPreparationError.incomplete }
            var id = UUID().uuid
            let revision = try GatewayRuntimeSettingsRevision(id: withUnsafeBytes(of: &id) { Data($0) },
                selection: selection, activation: activation, previous: expected.active,
                journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory)
            try machine.retainGatewaySettingsTransition(revision)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return try gatewaySettingsProgress(machine: machine, account: account)
        }
    }

    func resumeGatewaySettings(callerUID: uid_t, expected: SetupGatewaySettingsProgress) async throws -> SetupGatewaySettingsProgress {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, expected.supportsSettingsChanges, let operation = gatewaySettingsOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try asynchronousWork.admit()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        let revision = try withMachine(admission: context.0) { machine in
            guard expected.activation.setup.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewaySettingsProgress(machine: machine, account: account) == expected,
                  let revision = try expected.pending else { throw AdministrativeSetupError.staleProgress }
            return revision
        }
        try Task.checkCancellation()
        let report = try await context.2.resume(callerUID, expected.activation, revision, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        return try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewaySettingsProgress(machine: machine, account: account)
            try value.validateCompletion(of: expected)
            guard try report.revisionDigest == revision.digest else { throw AdministrativeSetupError.staleProgress }
            return value
        }
    }

    private func gatewaySettingsProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewaySettingsProgress {
        guard let plan = try machine.gatewayRuntimeActivation(accountID: account.accountID).plan,
              let foreground = try machine.runtimeActivation(accountID: account.accountID).plan else {
            throw GatewayPreparationError.incomplete
        }
        let initial = try GatewayRuntimeSettingsSelection(activation: plan,
            journal: machine.gatewayJournalPreparation(accountID: account.accountID),
            foreground: foreground, inventory: currentInventory(machine))
        return try .init(activation: gatewayActivationProgress(machine: machine, account: account),
            state: machine.gatewaySettingsTransition(accountID: account.accountID), initialSelection: initial,
            supportsSettingsChanges: foreground.consumerHosts != nil)
    }
    private func gatewayActivationProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewayActivationProgress {
        try .init(setup: gatewayProgress(machine: machine, account: account), state: machine.gatewayRuntimeActivation(accountID: account.accountID))
    }
    func activationProgress(callerUID: uid_t) throws -> SetupActivationProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            guard runtime.configurationPublished else { return nil }
            let result = try SetupActivationProgress(account: account, runtime: runtime,
                state: machine.runtimeActivation(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func resumeActivation(callerUID: uid_t, expected: SetupActivationProgress) throws -> SetupActivationProgress {
        try lock.withLock {
            guard !closed, !closing, asynchronousWork.permits(nil) else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            // Activity spans both writer scopes and native registration between them.
            // No native command runs within this first machine-writer scope.
            let context = try machines.useActivation { machine -> (AccountPreparationIntent, AuthorityInitializationIntent, RuntimeActivationPlan, SharedSetupImportIntent?) in
                guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                    throw AdministrativeSetupError.wrongAccount
                }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let state = try machine.runtimeActivation(accountID: account.accountID)
                guard try SetupActivationProgress(account: account, runtime: runtime, state: state) == expected,
                      let initial = try machine.initialization(accountID: account.accountID), initial.complete else {
                    throw AdministrativeSetupError.staleProgress
                }
                let inventory = try currentInventory(machine)
                let imported = try SharedSetupImportActivationScope.current(machine: machine, account: account)
                let relayPlan = try imported.flatMap { try machine.sharedImportRelayPlan(expected: $0) }
                let selectedRelease: SignedReleaseEvidence?
                if state.plan == nil, runtime.reference?.serviceActivity != nil {
                    guard let app = try account.initialAuthority.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
                        throw AdministrativeSetupError.changedInstallation
                    }
                    selectedRelease = try SignedReleaseInspection.inspect(URL(fileURLWithPath: inventory.bundlePath),
                        teamID: app.teamID, appIdentifier: app.identifier)
                } else { selectedRelease = nil }
                let plan = try state.plan ?? RuntimeActivationPlan(account: account, initialization: initial,
                    runtime: runtime, inventory: inventory, gatewaySettingsRelease: selectedRelease, importIntent: imported, relayPlan: relayPlan)
                try machine.retainRuntimeActivation(plan); try activationOperations.didStage(.intentRetained)
                func verify() throws {
                    _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: false, expectedImport: imported)
                }
                try verify()
                try activationOperations.prepare(plan, account, initial, inventory, verify)
                try activationOperations.didStage(.filesPublished); try verify()
                _ = try machine.enrollRuntimeActivation(plan)
                try activationOperations.didStage(.inventoryEnrolled)
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                return (account, initial, plan, imported)
            }
            let (account, initial, plan, imported) = context
            func verifyReady() throws {
                try machines.useActivation { machine in
                    let inventory = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                    try activationOperations.validate(plan, account, initial, inventory, {
                        _ = try self.verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                    })
                }
            }
            try verifyReady()
            for (index, job) in [plan.authorityJob, plan.transportJob].enumerated() {
                try activationOperations.register(job, verifyReady)
                try activationOperations.didStage(index == 0 ? .authorityRegistered : .transportRegistered)
                try verifyReady()
            }
            return try machines.useActivation { machine in
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                try machine.markRuntimeJobsRegistered(plan); try activationOperations.didStage(.completed)
                let value = try SetupActivationProgress(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                    state: machine.runtimeActivation(accountID: account.accountID))
                try value.validateCompletion(of: expected); return value
            }
        }
    }
    private func verifyActivation(machine: PreparationIntentStore, account: AccountPreparationIntent,
                                  initialization: AuthorityInitializationIntent, plan: RuntimeActivationPlan,
                                  callerUID: uid_t, enrolled: Bool, expectedImport: SharedSetupImportIntent?) throws -> InstallationInventory {
        try verifyEnrollment(account, callerUID: callerUID, machine: machine); try machine.validateAccountPreparation(account)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let services = try machine.serviceAccountPlan(accountID: account.accountID)
        guard services.complete, services.plan == plan.reference.services,
              runtime.configurationPublished, runtime.reference == plan.reference,
              try machine.initialization(accountID: account.accountID) == initialization,
              let retained = try machine.runtimeActivation(accountID: account.accountID).plan,
              try retained.encoded == plan.encoded else { throw RuntimeActivationError.changedScope }
        try plan.validate(account: account, reference: plan.reference)
        let inventory = try currentInventory(machine), desired = try plan.enrolledInventory(inventory)
        guard !enrolled || desired == inventory else { throw RuntimeActivationError.incomplete }
        try SharedSetupImportActivationScope.verify(machine: machine, account: account, initialization: initialization,
            plan: plan, inventory: inventory, expected: expectedImport)
        return inventory
    }
    private func verifyEnrollment(_ value: AccountPreparationIntent, callerUID: uid_t, machine: PreparationIntentStore) throws {
        guard value.ownerUID == callerUID else { throw AdministrativeSetupError.wrongAccount }
        let inventory = try currentInventory(machine)
        guard value.macID == inventory.macID, value.installationID == inventory.installationID,
              value.releaseDigest == inventory.releaseDigest,
              let accountCodePolicy, try value.initialAuthority.codePolicy.bytes == accountCodePolicy.bytes else {
            throw AdministrativeSetupError.changedInstallation
        }
        try LocalAccountDirectory.validateOwnership(lookupAccount(callerUID), uid: callerUID, directoryID: value.directoryID)
    }
    private static func initialAuthority(macID: Data, accountID: Data, codePolicy: AuthorityCodePolicy) throws -> AuthorityJournalInitialization {
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(AccountPreparationIntent.randomID()),
            4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1,
            schemaVersion: AuthorityCommandStartupConfiguration.captureSchemaVersion)
        return .init(descriptor: descriptor, codePolicy: codePolicy, capabilities: .init(contracts: [contract: []]),
            allowedContracts: [contract], installCommandReplay: true)
    }
    private func currentInventory(_ machine: PreparationIntentStore) throws -> InstallationInventory {
        try releaseActivity?.validate()
        guard !closed, let inventory = try machine.inventory() else { throw AdministrativeSetupError.unavailable }
        try verifyHost(inventory)
        guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
            throw AdministrativeSetupError.changedInstallation
        }
        return inventory
    }
    private func requireAccount(_ accountID: Data, callerUID: uid_t, machine: PreparationIntentStore) throws {
        guard accountID.count == 16, callerUID > 0, callerUID < UInt32.max,
              try currentInventory(machine).accounts.contains(where: { $0.accountID == accountID && $0.ownerUID == callerUID }) else {
            throw AdministrativeSetupError.wrongAccount
        }
    }
}

/// Local app progress only. It carries no paths, release policy, credential or runtime health assertion.
public struct SetupAccountProgress: Equatable, Sendable {
    public let accountID: Data
    public let setupID: Data
    public let revision: Data
    public let checkpointCaptured: Bool
    public let complete: Bool
    init(_ value: AuthorityInitializationIntent) {
        accountID = value.accountID; setupID = value.setupID; revision = value.revision
        checkpointCaptured = value.checkpoint != nil; complete = value.complete
    }
    public var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(accountID), 2: .bytes(setupID), 3: .bytes(revision),
                4: .unsigned(checkpointCaptured ? 1 : 0), 5: .unsigned(complete ? 1 : 0)]), limits: Self.limits())
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits()), Set(f.keys) == [0, 1, 2, 3, 4, 5],
              f[0] == .unsigned(1), case .bytes(let account) = f[1], account.count == 16,
              case .bytes(let setup) = f[2], setup.count == 16, case .bytes(let revision) = f[3], revision.count == 16,
              case .unsigned(let captured) = f[4], captured <= 1, case .unsigned(let complete) = f[5], complete <= 1,
              complete == 0 || captured == 1 else { throw AdministrativeSetupError.invalidConfiguration }
        let value = Self(accountID: account, setupID: setup, revision: revision, checkpointCaptured: captured == 1, complete: complete == 1)
        guard try value.bytes == bytes else { throw AdministrativeSetupError.invalidConfiguration }; return value
    }
    private init(accountID: Data, setupID: Data, revision: Data, checkpointCaptured: Bool, complete: Bool) {
        self.accountID = accountID; self.setupID = setupID; self.revision = revision
        self.checkpointCaptured = checkpointCaptured; self.complete = complete
    }
    private static func limits() throws -> CBORLimits { try .init(maxBytes: 256, maxDepth: 2, maxItems: 16) }
}
