import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupError: Error, Equatable {
    case invalidConfiguration, unavailable, wrongAccount, changedInstallation, staleProgress
}

/// One serialized owner for administrative account setup. It owns the machine store across all accepted connections.
/// The host must verify its current signed release and protected placement before opening this owner.
public final class SetupAccountOwner: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let machine: PreparationIntentStore
    private let installationID: Data
    private let expectedReleaseDigest: Data
    private let resume: (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent
    private var closed = false

    public static func open(machineDirectory: String, macID: Data, expectedReleaseDigest: Data) throws -> SetupAccountOwner {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(machine: PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID),
            expectedReleaseDigest: expectedReleaseDigest,
            resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) })
    }
    // Ordinary-owner fixtures retain actual protected storage. They cannot establish native administrator consent.
    init(machine: PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent) throws {
        self.machine = machine; self.expectedReleaseDigest = expectedReleaseDigest; self.resume = resume
        do {
            guard expectedReleaseDigest.count == 32, let inventory = try machine.inventory(),
                  inventory.releaseDigest == expectedReleaseDigest else { throw AdministrativeSetupError.invalidConfiguration }
            installationID = inventory.installationID
        } catch { try? machine.close(); throw error }
    }
    deinit { try? close() }
    public func close() throws {
        try lock.withLock {
            guard !closed else { return }
            try machine.close(); closed = true
        }
    }
    func verifyCurrent() throws {
        try lock.withLock { _ = try currentInventory() }
    }
    func progress(accountID: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent? {
        try lock.withLock {
            try requireAccount(accountID, callerUID: callerUID)
            let value = try machine.initialization(accountID: accountID)
            _ = try currentInventory()
            return value
        }
    }
    func resumeAccount(accountID: Data, setupID: Data, expectedRevision: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent {
        try lock.withLock {
            guard setupID.count == 16, expectedRevision.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
            try requireAccount(accountID, callerUID: callerUID)
            guard let expected = try machine.initialization(accountID: accountID), expected.setupID == setupID,
                  expected.revision == expectedRevision else { throw AdministrativeSetupError.staleProgress }
            let result = try resume(machine, expected)
            _ = try currentInventory()
            return result
        }
    }
    private func currentInventory() throws -> InstallationInventory {
        guard !closed, let inventory = try machine.inventory() else { throw AdministrativeSetupError.unavailable }
        guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
            throw AdministrativeSetupError.changedInstallation
        }
        return inventory
    }
    private func requireAccount(_ accountID: Data, callerUID: uid_t) throws {
        guard accountID.count == 16, callerUID > 0, callerUID < UInt32.max,
              try currentInventory().accounts.contains(where: { $0.accountID == accountID && $0.ownerUID == callerUID }) else {
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
