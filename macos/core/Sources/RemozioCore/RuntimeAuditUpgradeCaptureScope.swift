import Darwin
import Foundation

/// Borrows the current machine writer. No scope value is a quiescence, migration or activation permit.
final class RuntimeAuditUpgradeCaptureScope: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let record: RuntimeAuditUpgradeRecord
    let preparation: RuntimeAuditUpgradePreparation
    let account: AccountPreparationIntent
    let initialization: AuthorityInitializationIntent
    let inventory: InstallationInventory
    let foreground: RuntimeActivationState
    let gateway: GatewayPreparationState
    let journal: GatewayJournalPreparationState
    let gatewayActivation: GatewayRuntimeActivationState
    let settings: GatewayRuntimeSettingsState
    let imported: SharedSetupImportIntent?
    let importRecord: SharedSetupImportCompatibilitySnapshot.Record?
    let installedRelease: SignedReleaseEvidence
    private let machine: PreparationIntentStore
    private let baseline: RuntimeReleaseCompatibilitySnapshot.Inputs
    private let owner: uid_t
    private let native: Bool
    private let verifyOwner: () throws -> Void
    private let verifyPlatform: (AccountPreparationIntent, ServiceReleaseActivityReference) throws -> Void
    private let processID = getpid()
    private var active = true
    var description: String { "RuntimeAuditUpgradeCaptureScope(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// The authorized setup owner holds its release token and the machine writer across this synchronous capture.
    static func capture(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeRecord,
                        installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                        verifyOwner: @escaping () throws -> Void) throws -> RuntimeAuditUpgradeCaptureScope {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            owner: 0, native: true, verifyOwner: verifyOwner, verifyPlatform: { account, activity in
                try verifyOwner()
                try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: account.ownerUID),
                    uid: account.ownerUID, directoryID: account.directoryID)
                let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
                for claim in expected.intent.source.services.claims {
                    try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID)
                }
                try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: activity, verifyCurrent: verifyOwner)
            })
    }
    // Ordinary-owner SQLite and file leases only. This seam cannot supply fake platform validation in a Root process.
    static func captureOwned(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeRecord,
                             installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy, owner: uid_t,
                             verifyOwner: @escaping () throws -> Void = {},
                             verifyPlatform: @escaping (AccountPreparationIntent, ServiceReleaseActivityReference) throws -> Void = { _, _ in }) throws -> RuntimeAuditUpgradeCaptureScope {
        guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        return try .init(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            owner: owner, native: false, verifyOwner: verifyOwner, verifyPlatform: verifyPlatform)
    }
    private init(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeRecord, installedRelease: SignedReleaseEvidence,
                 currentPolicy: AuthorityCodePolicy, owner: uid_t, native: Bool, verifyOwner: @escaping () throws -> Void,
                 verifyPlatform: @escaping (AccountPreparationIntent, ServiceReleaseActivityReference) throws -> Void) throws {
        try verifyOwner()
        try machine.validateStorageLease(nativeDirectory: native ? MachineBootstrap.machineDirectory : nil)
        try RuntimeAuditUpgradeRecord.validatePreparation(expected.intent, release: installedRelease, policy: currentPolicy)
        guard let account = try machine.accountPreparation(ownerUID: expected.intent.source.services.ownerUID),
              let initialization = try machine.initialization(accountID: account.accountID),
              let inventory = try machine.inventory(),
              try machine.runtimeAuditUpgrade(accountID: account.accountID) == expected else { throw RuntimePreparationError.changedScope }
        let foreground = try machine.runtimeActivation(accountID: account.accountID)
        guard let plan = foreground.plan, plan.reference == expected.intent.source,
              try plan.host.codePolicy.bytes == currentPolicy.bytes else { throw RuntimePreparationError.incomplete }
        try RuntimeConfigurationBundle.validateScope(account: account, initialization: initialization,
            reference: expected.intent.source, inventory: inventory)
        let preparation = try RuntimeAuditUpgradePreparation(source: plan, intent: expected.intent,
            installedRelease: installedRelease, currentPolicy: currentPolicy)
        let gateway = try machine.gatewayPreparation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        let activation = try machine.gatewayRuntimeActivation(accountID: account.accountID)
        let settings = try machine.gatewaySettingsTransition(accountID: account.accountID)
        let imported = try machine.withSharedImportJournal { journal in
            try journal?.current(scope: .init(account: account, inventory: inventory))
        }
        let baseline = try machine.retainedRuntimeCompatibilityInputs()
        let importedRecord = baseline.sharedImport?.records.first { $0.accountID == account.accountID }
        guard (imported == nil) == (importedRecord == nil) else { throw RuntimePreparationError.changedScope }
        self.machine = machine; self.record = expected; self.preparation = preparation; self.account = account
        self.initialization = initialization; self.inventory = inventory; self.foreground = foreground
        self.gateway = gateway; self.journal = journal; gatewayActivation = activation; self.settings = settings
        self.imported = imported; importRecord = importedRecord; self.baseline = baseline
        self.installedRelease = installedRelease; self.owner = owner; self.native = native
        self.verifyOwner = verifyOwner; self.verifyPlatform = verifyPlatform
        try validateCurrent()
    }
    /// Lease and caller checks between reads. Full record validation surrounds the complete capture.
    func validateLifetime() throws {
        guard active, getpid() == processID, getuid() == owner, geteuid() == owner else { throw RuntimePreparationError.changedScope }
        try verifyOwner()
        try machine.validateStorageLease(nativeDirectory: native ? MachineBootstrap.machineDirectory : nil)
    }
    func validateCurrent() throws {
        do {
            try validateLifetime()
            try machine.validateAccountPreparation(account)
            guard try machine.initialization(accountID: account.accountID) == initialization,
                  try machine.inventory() == inventory,
                  try machine.runtimeAuditUpgrade(accountID: account.accountID) == record,
                  try machine.gatewayPreparation(accountID: account.accountID) == gateway,
                  try machine.gatewayJournalPreparation(accountID: account.accountID) == journal,
                  try machine.retainedRuntimeCompatibilityInputs() == baseline else { throw RuntimePreparationError.changedScope }
            try machine.withSharedImportJournal { journal in
                guard try journal?.current(scope: .init(account: account, inventory: inventory)) == imported else {
                    throw RuntimePreparationError.changedScope
                }
            }
            guard let activity = record.intent.target.serviceActivity else { throw RuntimePreparationError.changedScope }
            try verifyPlatform(account, activity); try validateLifetime()
        } catch { active = false; throw error }
    }
    func withCurrent<Value>(_ body: () throws -> Value) throws -> Value {
        try validateCurrent()
        do { let value = try body(); try validateCurrent(); return value }
        catch { try? validateCurrent(); throw error }
    }
    func close() { active = false }
    deinit { close() }
}
