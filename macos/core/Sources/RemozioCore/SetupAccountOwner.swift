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
         }) throws {
        try self.init(machines: .scoped(openMachine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount)
    }
    // Logical endpoint fixtures retain actual protected storage. They do not prove production lease lifetime.
    convenience init(machine: PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in },
         accountCodePolicy: AuthorityCodePolicy? = nil,
         lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent = {
             try AccountPreparationController.resume(machine: $0, expected: $1, verifyCurrent: $2)
         }) throws {
        try self.init(machines: .retained(machine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount)
    }
    private init(machines: Machines, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void,
         accountCodePolicy: AuthorityCodePolicy?, lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent) throws {
        self.machines = machines; self.expectedReleaseDigest = expectedReleaseDigest; self.resume = resume; self.verifyHost = verifyHost
        self.accountCodePolicy = accountCodePolicy; self.lookupAccount = lookupAccount; self.prepareAccount = prepareAccount
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
