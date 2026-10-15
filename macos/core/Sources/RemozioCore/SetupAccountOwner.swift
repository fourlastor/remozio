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
    private var closed = false

    public static func open(machineDirectory: String, macID: Data, expectedReleaseDigest: Data) throws -> SetupAccountOwner {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(openMachine: { try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID) },
            expectedReleaseDigest: expectedReleaseDigest,
            resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) })
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
         }, activationOperations: RuntimeActivationOperations = .native) throws {
        try self.init(machines: .scoped(openMachine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations)
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
         }, activationOperations: RuntimeActivationOperations = .native) throws {
        try self.init(machines: .retained(machine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations)
    }
    private init(machines: Machines, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void,
         accountCodePolicy: AuthorityCodePolicy?, lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent,
         prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State,
         prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState,
         activationOperations: RuntimeActivationOperations) throws {
        self.machines = machines; self.expectedReleaseDigest = expectedReleaseDigest; self.resume = resume; self.verifyHost = verifyHost
        self.accountCodePolicy = accountCodePolicy; self.lookupAccount = lookupAccount; self.prepareAccount = prepareAccount; self.prepareServices = prepareServices; self.prepareRuntime = prepareRuntime; self.activationOperations = activationOperations
        do {
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
            try machines.close(); closed = true
        }
    }
    private func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
        try lock.withLock {
            guard !closed else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            return try machines.use(body)
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
            guard !closed else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            // No native command runs within this first machine-writer scope.
            let context = try machines.useActivation { machine -> (AccountPreparationIntent, AuthorityInitializationIntent, RuntimeActivationPlan) in
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
                let plan = try state.plan ?? RuntimeActivationPlan(account: account, initialization: initial, runtime: runtime, inventory: inventory)
                try machine.retainRuntimeActivation(plan); try activationOperations.didStage(.intentRetained)
                func verify() throws {
                    _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: false)
                }
                try verify()
                try activationOperations.prepare(plan, account, initial, inventory, verify)
                try activationOperations.didStage(.filesPublished); try verify()
                _ = try machine.enrollRuntimeActivation(plan)
                try activationOperations.didStage(.inventoryEnrolled)
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true)
                return (account, initial, plan)
            }
            let (account, initial, plan) = context
            func verifyReady() throws {
                try machines.useActivation { machine in
                    let inventory = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true)
                    try activationOperations.validate(plan, account, initial, inventory, {
                        _ = try self.verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true)
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
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true)
                try machine.markRuntimeJobsRegistered(plan); try activationOperations.didStage(.completed)
                let value = try SetupActivationProgress(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                    state: machine.runtimeActivation(accountID: account.accountID))
                try value.validateCompletion(of: expected); return value
            }
        }
    }
    private func verifyActivation(machine: PreparationIntentStore, account: AccountPreparationIntent,
                                  initialization: AuthorityInitializationIntent, plan: RuntimeActivationPlan,
                                  callerUID: uid_t, enrolled: Bool) throws -> InstallationInventory {
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
