import Darwin
import Foundation

/// Reserves the setup owner without a shared Root activity token. Runtime barriers remain separate live resources.
final class SetupAuditUpgradeScope: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
    let account: AccountPreparationIntent
    let inventory: InstallationInventory
    let initialization: AuthorityInitializationIntent
    private let authorization: SetupAuditUpgradeAuthorization
    private let verifyLease: () throws -> Void
    private let access: ((PreparationIntentStore) throws -> Void) throws -> Void
    private let closeAdmission: () -> Void
    private let lock = NSRecursiveLock()
    private let processID = getpid()
    private var active = false
    private var closed = false
    var description: String { "SetupAuditUpgradeScope(redacted)" }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Successful construction transfers authorization ownership. The factory keeps it with the caller on failure.
    init(account: AccountPreparationIntent, inventory: InstallationInventory, initialization: AuthorityInitializationIntent,
         authorization: SetupAuditUpgradeAuthorization, verifyLease: @escaping () throws -> Void,
         access: @escaping ((PreparationIntentStore) throws -> Void) throws -> Void, closeAdmission: @escaping () -> Void) {
        self.account = account; self.inventory = inventory; self.initialization = initialization; self.authorization = authorization
        self.verifyLease = verifyLease; self.access = access; self.closeAdmission = closeAdmission
    }
    private func validate() throws {
        guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try authorization.validate(); try verifyLease(); try authorization.validate()
    }
    /// No machine-store calls. This is safe inside metadata verification callbacks.
    func validateLifetime() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock { try validate() }
    }
    func withCurrent<Value>(_ body: () throws -> Value) throws -> Value {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try lock.withLock {
            guard !active else { throw AdministrativeSetupError.unavailable }
            active = true; defer { active = false }
            try validate(); let result = try body(); try validate(); return result
        }
    }
    func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
        try withCurrent {
            var result: Result<Value, any Error>?
            try access { result = .success(try body($0)) }
            guard let result else { throw AdministrativeSetupError.unavailable }
            return try result.get()
        }
    }
    /// The operation owner must close its coordinator, pending drain and machine writer before releasing this reservation.
    func close() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !active else { throw AdministrativeSetupError.unavailable }
            guard !closed else { return }
            authorization.close(); closeAdmission(); closed = true
        }
    }
    deinit { if getpid() == processID { authorization.close(); closeAdmission() } }
}
