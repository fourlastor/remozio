import CryptoKit
import Foundation
import Darwin
import SQLite3

enum PreparationStoreError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongMac, closed, unavailable, transactionActive
    case capacity, notFound, staleRevision, invalidTransition, corruptRecord, inventoryNotEnabled, wrongInstallation
    case stableCommitUnconfirmed
    case storage(Int32)
}

/// Serialized machine-scoped bookkeeping. Stored copy metadata grants no activation authority.
public final class PreparationIntentStore {
    public static let supportedSchemaVersions: Set<Int64> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]
    private let lease: InstallationStorageLease
    private var db: OpaquePointer?
    private let maximumRecords: Int
    private let macID: Data
    private let didCommit: (() throws -> Void)?
    private let inventoryRecordLimit: Int32
    private var active = false
    private var unavailable = false
    private var retainedSetupPromotionAuthorization: RetainedSetupPromotionAuthorization?
    private var stableAccountReservationAuthorization: StableAccountReservationAuthorization?
    private var stableAccountStorageAuthorization: StableAccountStorageAuthorization?
    private var stableServiceAccountAuthorization: StableServiceAccountAuthorization?
    private var stableRuntimePreparationAuthorization: StableRuntimePreparationAuthorization?
    private static let applicationID: Int64 = 0x524D4953

    public static func open(directoryPath: String, macID: Data, maximumRecords: Int = 64,
                     initialize: Bool = false) throws -> PreparationIntentStore {
        try .init(lease: InstallationStorageLease.acquire(directoryPath: directoryPath),
                  macID: macID, maximumRecords: maximumRecords, initialize: initialize)
    }
    // Internal fixture seam. The connection owns the lease even when initialization fails.
    // A fixture may only lower the ordinary record limit, to model records above it with small fixture values.
    init(lease: InstallationStorageLease, macID: Data, maximumRecords: Int, initialize: Bool,
         didCommit: (() throws -> Void)? = nil, inventoryRecordLimit: Int32 = 278_528) throws {
        self.lease = lease; self.maximumRecords = maximumRecords; self.macID = macID; self.didCommit = didCommit
        self.inventoryRecordLimit = inventoryRecordLimit
        do {
            guard macID.count == 16, (1...4096).contains(maximumRecords),
                  (32_768...278_528).contains(inventoryRecordLimit) else { throw PreparationStoreError.invalidConfiguration }
            try lease.validate()
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(lease.databasePath, &connection,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard result == SQLITE_OK, let connection else { throw PreparationStoreError.storage(result) }
            try lease.validate()
            guard sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
                  sqlite3_busy_timeout(connection, 1000) == SQLITE_OK else { throw PreparationStoreError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, 32_768)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_SQL_LENGTH, 8192)
            try exec("PRAGMA trusted_schema=OFF")
            if initialize {
                guard try scalar("SELECT COUNT(*) FROM sqlite_master") == 0,
                      try scalar("PRAGMA user_version") == 0, try scalar("PRAGMA application_id") == 0 else {
                    throw PreparationStoreError.incompatibleStore
                }
            } else { try identity(macID) }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try scalar("PRAGMA synchronous") == 3, try scalar("PRAGMA fullfsync") == 1,
                  try scalar("PRAGMA trusted_schema") == 0,
                  try statement("PRAGMA journal_mode", { row in
                      guard try step(row) == SQLITE_ROW, let value = sqlite3_column_text(row, 0) else { return false }
                      return String(cString: value) == "delete"
                  }) else { throw PreparationStoreError.invalidConfiguration }
            if initialize {
                try transaction(write: true) {
                    try exec("CREATE TABLE installation_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1),mac BLOB NOT NULL CHECK(length(mac)=16)) STRICT")
                    try exec("CREATE TABLE preparation_intents_v1(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT")
                    try statement("INSERT INTO installation_identity_v1 VALUES(1,?)") { row in
                        try bind(macID, column: 1, row: row)
                        guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                    }
                    try exec("PRAGMA application_id=\(Self.applicationID)")
                    try exec("PRAGMA user_version=1")
                }
            }
            try identity(macID)
            if try scalar("PRAGMA user_version") >= 2 { configureInventoryLimit() }
            try lease.validate()
        } catch { shutdown(); throw error }
    }
    deinit { shutdown() }
    /// Validates the held storage lease between read stages.
    func validateStorageLease(nativeDirectory: String? = nil) throws {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        if let nativeDirectory { try lease.requireNativeLocation(nativeDirectory) }
        else { try lease.validate() }
    }

    public func close() throws {
        guard !active else { throw PreparationStoreError.transactionActive }
        shutdown()
    }
    /// Explicit storage upgrade only. It grants no service registration or update activation authority.
    public func enableInventoryStorage() throws {
        try requireRoot(); try upgradeInventoryStorage()
    }
    public func loadInventory() throws -> InstallationInventory? {
        try requireRoot(); return try inventory()
    }
    @discardableResult
    public func initializeInventory(_ value: InstallationInventory) throws -> InstallationInventory {
        try requireRoot(); return try writeInventory(value, expectedRevision: nil)
    }
    @discardableResult
    public func replaceInventory(_ value: InstallationInventory, expectedRevision: Data) throws -> InstallationInventory {
        try requireRoot(); return try writeInventory(value, expectedRevision: expectedRevision)
    }
    private func requireRoot() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
    }

    // Internal ordinary-owner seams retain the same lease, transaction and record checks.
    func upgradeInventoryStorage() throws {
        try transaction(write: true) {
            try identity(macID)
            if try scalar("PRAGMA user_version") >= 2 { return }
            _ = try loadAll()
            try exec("CREATE TABLE installation_inventory_v1(id INTEGER PRIMARY KEY CHECK(id=1),installation BLOB NOT NULL CHECK(length(installation)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 65536)) STRICT")
            try exec("PRAGMA user_version=2")
            try identity(macID)
        }
        configureInventoryLimit()
    }
    func inventory() throws -> InstallationInventory? {
        try transaction(write: false) { try requireInventorySchema(); return try loadInventoryRecord() }
    }
    @discardableResult
    func writeInventory(_ value: InstallationInventory, expectedRevision: Data?) throws -> InstallationInventory {
        guard value.macID == macID, expectedRevision == nil || expectedRevision?.count == 16 else {
            throw PreparationStoreError.invalidConfiguration
        }
        return try transaction(write: true) {
            try requireInventorySchema()
            let previous = try loadInventoryRecord()
            var revision = bytes(UUID())
            while revision == value.revision || revision == previous?.revision { revision = bytes(UUID()) }
            let retained = try InstallationInventory(macID: value.macID, installationID: value.installationID,
                revision: revision, bundlePath: value.bundlePath, releaseDigest: value.releaseDigest,
                accounts: value.accounts, services: value.services, formatVersion: value.formatVersion)
            if let expectedRevision {
                guard let previous else { throw PreparationStoreError.notFound }
                guard previous.revision == expectedRevision else {
                    throw PreparationStoreError.staleRevision
                }
                guard previous.installationID == value.installationID else { throw PreparationStoreError.wrongInstallation }
                guard value.formatVersion >= previous.formatVersion,
                      previous.accounts.isEmpty || !value.accounts.isEmpty else { throw PreparationStoreError.invalidTransition }
                try statement("UPDATE installation_inventory_v1 SET revision=?,record=? WHERE id=1 AND installation=? AND revision=?") { row in
                    try bind(retained.revision, column: 1, row: row)
                    try bind(retained.canonicalBytes, column: 2, row: row)
                    try bind(value.installationID, column: 3, row: row)
                    try bind(expectedRevision, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            } else {
                guard previous == nil else { throw PreparationStoreError.invalidTransition }
                try statement("INSERT INTO installation_inventory_v1 VALUES(1,?,?,?)") { row in
                    try bind(value.installationID, column: 1, row: row)
                    try bind(retained.revision, column: 2, row: row)
                    try bind(retained.canonicalBytes, column: 3, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
                }
            }
            return retained
        }
    }
    private final class SharedImportReadBorrow {
        private let processID = getpid(), thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private var active = true
        let journal: SharedSetupImportJournal
        let directory: ProtectedSetupDirectory
        let owner: uid_t
        let installationID: Data
        init(writer: PreparationIntentStore, journal: SharedSetupImportJournal, directory: ProtectedSetupDirectory,
            owner: uid_t, installationID: Data) {
            self.writer = writer; self.journal = journal; self.directory = directory; self.owner = owner
            self.installationID = installationID
        }
        func validate(in actual: PreparationIntentStore, journal: SharedSetupImportJournal? = nil) throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard active, let writer, writer === actual, !writer.unavailable, writer.db != nil, writer.sharedImportReadBorrow === self,
                  journal == nil || journal === self.journal else { throw JournalLeaseError.invalidated }
            try writer.lease.validate()
            try self.journal.requireDestination(macID: writer.macID, installationID: installationID)
            try self.journal.requireDirectory(directory)
        }
        func capture(in actual: PreparationIntentStore, installationID: Data?) throws -> SharedSetupImportCompatibilitySnapshot {
            try validate(in: actual)
            guard installationID == self.installationID else { throw SharedSetupImportError.wrongScope }
            return try journal.compatibilitySnapshot(directory: directory)
        }
        func expire() { active = false; writer = nil }
    }
    private var sharedImportReadBorrow: SharedImportReadBorrow?
    /// Uses the same actual journal for nested source reads. Every capture remains fresh and the callback expires synchronously.
    func withSharedImportSnapshot<Value>(journal: SharedSetupImportJournal,
        _ body: (ProtectedSetupDirectory, uid_t) throws -> Value) throws -> Value {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        if let borrowed = sharedImportReadBorrow {
            try borrowed.validate(in: self, journal: journal)
            let value = try body(borrowed.directory, borrowed.owner)
            try borrowed.validate(in: self, journal: journal); return value
        }
        guard let inventory = try self.inventory() else { throw PreparationStoreError.inventoryNotEnabled }
        try journal.requireDestination(macID: macID, installationID: inventory.installationID)
        return try lease.withSharedImportRelayDirectory { directory, owner in
            let borrowed = SharedImportReadBorrow(writer: self, journal: journal, directory: directory,
                owner: owner, installationID: inventory.installationID)
            sharedImportReadBorrow = borrowed
            defer { sharedImportReadBorrow = nil; borrowed.expire() }
            try borrowed.validate(in: self)
            let value = try body(directory, owner)
            try borrowed.validate(in: self); return value
        }
    }
    private func sharedImportCompatibilitySnapshot(installationID: Data?) throws -> SharedSetupImportCompatibilitySnapshot? {
        if let borrowed = sharedImportReadBorrow { return try borrowed.capture(in: self, installationID: installationID) }
        return try lease.sharedImportCompatibilitySnapshot(macID: macID, installationID: installationID)
    }

    func withSharedImportJournal<Value>(_ body: (SharedSetupImportJournal?) throws -> Value) throws -> Value {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        guard let inventory = try self.inventory() else { throw PreparationStoreError.inventoryNotEnabled }
        return try lease.withSharedImportJournal(macID: macID, installationID: inventory.installationID, body: body)
    }

    func withSharedImportRelayDirectory<Value>(_ body: (ProtectedSetupDirectory, uid_t) throws -> Value) throws -> Value {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        return try lease.withSharedImportRelayDirectory(body)
    }
    func sharedImportRelayPlan(expected: SharedSetupImportIntent) throws -> SharedSetupImportRelayPlan? {
        guard let inventory = try self.inventory(), let account = try accountPreparation(ownerUID: expected.scope.ownerUID),
              expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
            throw SharedSetupImportError.wrongScope
        }
        return try withSharedImportRelayDirectory { directory, owner in
            try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner)
        }
    }

    func publishSharedImport(_ intent: SharedSetupImportIntent, verifyCurrent: () throws -> Void,
                             didStage: (SharedSetupImportPublication.Stage) throws -> Void) throws -> SharedSetupImportIntent {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        guard let inventory = try self.inventory(), intent.scope.macID == macID,
              let account = try accountPreparation(ownerUID: intent.scope.ownerUID),
              intent.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
            throw SharedSetupImportError.wrongScope
        }
        func verify() throws {
            try verifyCurrent()
            guard try self.inventory() == inventory,
                  try accountPreparation(ownerUID: account.ownerUID) == account else {
                throw AdministrativeSetupError.staleProgress
            }
        }
        try verify()
        let result = try lease.publishSharedImport(intent, verifyCurrent: verify, didStage: didStage)
        try verify(); return result
    }

    func retainedRuntimeCompatibilityInputs() throws -> RuntimeReleaseCompatibilitySnapshot.Inputs {
        try transaction(write: false) { try loadRetainedRuntimeCompatibilityInputs() }
    }
    /// Enumerates protected v6 ownership claims. Directory resolution belongs outside this transaction.
    func retainedSetupCompatibilityOwners(expected: MachineUpdateStableRuntimeSource, candidate: SignedReleaseEvidence)
        throws -> [RuntimeStableCompatibilityOwner] {
        try transaction(write: false) {
            try loadStableRuntimeSource(candidate: candidate).requireSame(as: expected)
            let ids: [Data] = try statement("SELECT account FROM runtime_activation_v1 ORDER BY account") { row in
                var values: [Data] = []
                while try step(row) == SQLITE_ROW {
                    guard values.count < 64 else { throw PreparationStoreError.corruptRecord }
                    values.append(try blob(row, column: 0, maximum: 16))
                }
                return values
            }
            var claims: [RuntimeStableCompatibilityOwner] = []
            for id in ids {
                guard let row = try loadCompatibilityActivation(accountID: id).plan else { throw PreparationStoreError.corruptRecord }
                if case .retained(let plan) = row {
                    guard let account = expected.accounts.first(where: { $0.accountID == id }), account.origin == .retained,
                          let preparation = account.preparation, account.ownerUID == plan.reference.services.ownerUID else {
                        throw PreparationStoreError.corruptRecord
                    }
                    try plan.validate(account: preparation, reference: plan.reference)
                    claims.append(.init(accountID: id, ownerUID: preparation.ownerUID, directoryID: preparation.directoryID))
                }
            }
            try loadStableRuntimeSource(candidate: candidate).requireSame(as: expected)
            return claims
        }
    }

    /// Reads checked stable compatibility without granting ordinary activation or write authority.
    func stableRuntimeCompatibilitySnapshot(expected: MachineUpdateStableRuntimeSource,
        retained: [MachineUpdateRetainedSetupActivationSnapshot], candidate: SignedReleaseEvidence)
        throws -> RuntimeReleaseCompatibilitySnapshot {
        let ids = retained.map { $0.runtime.preparation.accountID }
        guard Set(ids).count == ids.count else { throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot }
        return try transaction(write: false) {
            let context = StableCompatibilityRead(source: expected, retained: retained)
            func capture() throws -> RuntimeReleaseCompatibilitySnapshot.Inputs {
                try self.loadStableRuntimeSource(candidate: candidate).requireSame(as: expected)
                for supplied in retained {
                    guard supplied.state.plan != nil else { throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot }
                    try supplied.runtime.setup.source.requireSame(as: expected)
                    try self.loadRetainedSetupActivationSnapshot(owner: supplied.runtime.setup.owner,
                        candidate: candidate).requireSame(as: supplied)
                }
                return try self.loadRetainedRuntimeCompatibilityInputs(stable: context)
            }
            let inputs = try capture()
            let result = try RuntimeReleaseCompatibilitySnapshot.describe(inputs: inputs)
            guard try capture() == inputs else { throw PreparationStoreError.staleRevision }
            return result
        }
    }
    private struct StableCompatibilityRead {
        let source: MachineUpdateStableRuntimeSource
        let retained: [MachineUpdateRetainedSetupActivationSnapshot]
    }
    private func loadRetainedRuntimeCompatibilityInputs(finishing: MachineUpdateInstalledSourceSnapshot? = nil,
        stable: StableCompatibilityRead? = nil) throws -> RuntimeReleaseCompatibilitySnapshot.Inputs {
        try identity(macID)
        let schema = try scalar("PRAGMA user_version")
        let actualInventory = try schema >= 2 ? loadInventoryRecord() : nil
        if let stable {
            guard case nil = finishing, schema == stable.source.actual.schemaVersion,
                  schema >= 24, actualInventory == stable.source.actual.inventory else { throw PreparationStoreError.staleRevision }
        } else if let finishing {
            guard schema == 23, finishing.actual.inventory == actualInventory else { throw PreparationStoreError.staleRevision }
        } else {
            // The ordinary reader cannot treat a finishing store as a stable runtime.
            guard schema <= 22 else { throw PreparationStoreError.invalidTransition }
        }
        let inventory = finishing?.historicalInventory ?? actualInventory
        let sharedImport = try sharedImportCompatibilitySnapshot(installationID: inventory?.installationID)
        guard schema >= 6 else {
            guard sharedImport?.records.allSatisfy({ $0.runCredential == nil }) ?? true else { throw PreparationStoreError.corruptRecord }
            return .init(schemaVersion: schema, macID: macID, inventory: inventory?.canonicalBytes, runtimes: [], gateways: [], sharedImport: sharedImport)
        }
        func accounts(_ sql: String) throws -> [Data] {
            try statement(sql) { row in
                var result: [Data] = []
                while try step(row) == SQLITE_ROW {
                    guard result.count < 64 else { throw PreparationStoreError.corruptRecord }
                    result.append(try blob(row, column: 0, maximum: 16))
                }
                return result
            }
        }
        let ids = try accounts("SELECT account FROM runtime_preparation_v1 ORDER BY account")
        let activated = try schema >= 7 ? accounts("SELECT account FROM runtime_activation_v1 ORDER BY account") : []
        guard activated.allSatisfy({ ids.contains($0) }) else { throw PreparationStoreError.corruptRecord }
        func historicalInventory(for reference: RuntimeMaterialReference) throws -> InstallationInventory? {
            if let stable {
                return try stable.source.provisioningInventory(accountID: reference.services.accountID,
                    ownerUID: reference.services.ownerUID, releaseDigest: reference.services.releaseDigest)
            }
            return finishing?.historicalInventory
        }
        var retainedIDs = Set<Data>()
        var values: [RuntimeReleaseCompatibilitySnapshot.Runtime] = []
        for id in ids {
            let state = try loadRuntimePreparation(accountID: id)
            guard let reference = state.reference else { throw PreparationStoreError.corruptRecord }
            let historical = try historicalInventory(for: reference)
            try requireRuntimeMaterialScope(reference, historicalInventory: historical)
            var record: Data?, registered = false
            if activated.contains(id) {
                let projection: RuntimeActivationCompatibilityProjection
                if let stable {
                    let row = try loadCompatibilityActivation(accountID: id)
                    guard let plan = row.plan, plan.reference == reference else { throw PreparationStoreError.corruptRecord }
                    projection = plan; registered = row.registered
                    if case .retained(let value) = plan {
                        guard let supplied = stable.retained.first(where: { $0.runtime.preparation.accountID == id }) else {
                            throw RuntimeActivationCompatibilityError.missingRetainedSnapshot
                        }
                        guard try supplied.state.plan?.encoded == value.encoded,
                              supplied.state.jobsRegistered == registered else { throw PreparationStoreError.staleRevision }
                        retainedIDs.insert(id)
                    }
                } else {
                    let activation = try loadRuntimeActivation(accountID: id)
                    guard let plan = activation.plan else { throw PreparationStoreError.corruptRecord }
                    projection = .ordinary(plan); registered = activation.jobsRegistered
                }
                guard projection.reference == reference else { throw PreparationStoreError.corruptRecord }
                if case .ordinary(let plan) = projection {
                    try requireRuntimeActivationScope(plan, historicalInventory: historical)
                    if registered {
                        guard let scope = historical ?? inventory, try plan.enrolledInventory(scope) == scope else {
                            throw PreparationStoreError.corruptRecord
                        }
                    }
                }
                record = try projection.encoded
            }
            values.append(.init(reference: reference, configurationPublished: state.configurationPublished,
                activationRecord: record, jobsRegistered: registered))
        }
        if let stable {
            guard retainedIDs == Set(stable.retained.map { $0.runtime.preparation.accountID }) else {
                throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot
            }
        }
        for record in sharedImport?.records ?? [] {
            if let retained = record.runCredential {
                guard let runtime = values.first(where: { $0.reference.services.accountID == record.accountID }),
                      runtime.configurationPublished, retained.reference.runtime == runtime.reference else {
                    throw PreparationStoreError.corruptRecord
                }
            }
        }
        let gatewayIDs = try schema >= 10 ? accounts("SELECT account FROM gateway_runtime_activation_v1 ORDER BY account") : []
        let settingsIDs = try schema >= 11 ? accounts("SELECT account FROM gateway_settings_transition_v1 ORDER BY account") : []
        guard gatewayIDs.allSatisfy({ activated.contains($0) }), settingsIDs.allSatisfy({ gatewayIDs.contains($0) }) else {
            throw PreparationStoreError.corruptRecord
        }
        var gateways: [RuntimeReleaseCompatibilitySnapshot.Gateway] = []
        for id in gatewayIDs {
            let state = try loadGatewayRuntimeActivation(accountID: id)
            guard let plan = state.plan else { throw PreparationStoreError.corruptRecord }
            guard let reference = values.first(where: { $0.reference.services.accountID == id })?.reference else {
                throw PreparationStoreError.corruptRecord
            }
            let historical = try historicalInventory(for: reference)
            let scope = try requireGatewayRuntimeActivationScope(plan, historicalInventory: historical)
            if state.jobRegistered {
                let proposal = try plan.proposal(journal: scope.journal, foreground: scope.foreground, inventory: scope.inventory)
                guard try proposal.enrolledInventory(scope.inventory) == scope.inventory else { throw PreparationStoreError.corruptRecord }
            }
            let settings = try schema >= 11 ? loadGatewaySettingsTransition(accountID: id) : .empty
            if let revision = settings.pending ?? settings.active { _ = try requireGatewaySettingsScope(revision, historicalInventory: historical) }
            gateways.append(.init(accountID: id, activationRecord: try plan.encoded,
                configurationPublished: state.filesPublished, jobRegistered: state.jobRegistered,
                activeSettings: try settings.active?.encoded, pendingSettings: try settings.pending?.encoded,
                settingsPhase: settings.phase?.rawValue))
        }
        let upgradeIDs = try schema >= 12 ? accounts("SELECT account FROM runtime_audit_upgrade_v1 ORDER BY account") : []
        guard upgradeIDs.allSatisfy({ ids.contains($0) }) else { throw PreparationStoreError.corruptRecord }
        let auditUpgrades = try upgradeIDs.map { id -> RuntimeAuditUpgradeRecord in
            guard let record = try loadRuntimeAuditUpgrade(accountID: id) else { throw PreparationStoreError.corruptRecord }
            try requireRuntimeAuditUpgradeScope(record.intent, allowCommitted: true, historicalInventory: historicalInventory(for: record.intent.source)); return record
        }
        let auditGraphs: [RuntimeAuditUpgradeGraphRecord]
        if schema >= 13 {
            auditGraphs = try statement("SELECT account,content FROM runtime_audit_graph_v1 ORDER BY account,content") { row in
                var records: [RuntimeAuditUpgradeGraphRecord] = []
                while try step(row) == SQLITE_ROW {
                    guard records.count < 64,
                          let record = try loadRuntimeAuditGraph(accountID: blob(row, column: 0, maximum: 16), contentDigest: blob(row, column: 1, maximum: 32)) else {
                        throw PreparationStoreError.corruptRecord
                    }
                    records.append(record)
                }
                return records
            }
        } else { auditGraphs = [] }
        let auditCutovers: [RuntimeAuditUpgradeCutoverRecord] = try schema >= 14 ? accounts("SELECT account FROM runtime_audit_cutover_v1 ORDER BY account").map { id in
            guard let record = try loadRuntimeAuditCutover(accountID: id) else { throw PreparationStoreError.corruptRecord }
            let runtime = try loadRuntimePreparation(accountID: id), intent = record.graph.upgrade.intent
            guard runtime.configurationPublished, runtime.reference == (record.phase == .metadataCommitted ? intent.target : intent.source) else {
                throw RuntimePreparationError.changedScope
            }
            return record
        } : []
        try identity(macID)
        let admission = try schema >= 16 ? loadUpdateAdmissionRegistration()?.encoded : nil
        if let installed = finishing?.actual.installed ?? stable?.source.actual.installed,
           let activation = finishing?.actual.activation ?? stable?.source.actual.activation {
            return try .init(schemaVersion: schema, macID: macID, inventory: actualInventory?.canonicalBytes, runtimes: values,
                gateways: gateways, sharedImport: sharedImport, auditUpgrades: auditUpgrades, auditGraphs: auditGraphs,
                auditCutovers: auditCutovers, updateAdmissionRegistration: admission,
                machineUpdateActivation: activation.encoded,
                machineUpdateConfigurationEpoch: installed.configuration().record.encoded,
                machineUpdateBackendEpoch: installed.backend().record.encoded,
                completionIntent: MachineUpdateActivationRecord.digest(installed.completionIntent().record.encoded),
                completionPublication: MachineUpdateActivationRecord.digest(installed.publicationSource().encoded),
                installedRelease: installed.record.encoded)
        }
        return try .init(schemaVersion: schema, macID: macID, inventory: inventory?.canonicalBytes, runtimes: values, gateways: gateways, sharedImport: sharedImport, auditUpgrades: auditUpgrades, auditGraphs: auditGraphs, auditCutovers: auditCutovers,
            updateAdmissionRegistration: admission, machineUpdateActivation: schema >= 17 ? loadMachineUpdateActivation()?.encoded : nil,
            machineUpdateReplacement: schema >= 18 ? loadMachineUpdateReplacement()?.encoded : nil,
            machineUpdateConfigurationEpoch: schema >= 19 ? loadMachineUpdateConfigurationEpoch()?.record.encoded : nil,
            machineUpdateBackendEpoch: schema >= 20 ? loadRequiredMachineUpdateBackendEpochHeader() : nil,
            completionIntent: schema >= 21 ? completionIntentFingerprint() : nil,
            completionPublication: schema >= 22 ? MachineUpdateActivationRecord.digest(loadCompletionPublication().encoded) : nil)
    }
    func runtimeActivation(accountID: Data) throws -> RuntimeActivationState {
        guard accountID.count == 16 else { throw RuntimeActivationError.invalidPlan }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 7 { return .init(plan: nil, jobsRegistered: false) }
            return try loadRuntimeActivation(accountID: accountID)
        }
    }
    // Freeze intent before publishing jobs. No inventory enrollment or native registration occurs here.
    func retainRuntimeActivation(_ plan: RuntimeActivationPlan) throws {
        let encoded = try plan.encoded
        try transaction(write: true) {
            try identity(macID); try requireRuntimeActivationScope(plan)
            if try scalar("PRAGMA user_version") == 6 {
                try exec("CREATE TABLE runtime_activation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),material BLOB NOT NULL UNIQUE CHECK(length(material)=16),digest BLOB NOT NULL CHECK(length(digest)=32),registered INTEGER NOT NULL CHECK(registered IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262144)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=7")
            }
            let current = try loadRuntimeActivation(accountID: plan.accountID)
            if let retained = current.plan {
                guard try retained.encoded == encoded else { throw RuntimeActivationError.conflictingPlan }; return
            }
            guard try scalar("SELECT COUNT(*) FROM runtime_activation_v1") < 64 else { throw RuntimeActivationError.exhausted }
            try statement("INSERT INTO runtime_activation_v1 VALUES(?,?,?,0,?)") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.reference.materialID, column: 2, row: row)
                try bind(Data(SHA256.hash(data: encoded)), column: 3, row: row); try bind(encoded, column: 4, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    // Publish exact host/job files first. Native registration follows only after this writer's lease is released.
    func enrollRuntimeActivation(_ plan: RuntimeActivationPlan) throws -> InstallationInventory {
        let before: InstallationInventory = try transaction(write: false) {
            try identity(macID); try requireRuntimeActivationScope(plan)
            guard try scalar("PRAGMA user_version") >= 7,
                  let retained = try loadRuntimeActivation(accountID: plan.accountID).plan,
                  try retained.encoded == plan.encoded, let inventory = try loadInventoryRecord() else {
                throw RuntimeActivationError.incomplete
            }
            return inventory
        }
        let after = try plan.enrolledInventory(before)
        if after == before { return before }
        return try writeInventory(after, expectedRevision: before.revision)
    }
    // The controller must independently confirm both native job registrations before retaining this historical marker.
    func markRuntimeJobsRegistered(_ plan: RuntimeActivationPlan) throws {
        try transaction(write: true) {
            try identity(macID); try requireRuntimeActivationScope(plan)
            guard try scalar("PRAGMA user_version") >= 7 else { throw RuntimeActivationError.incomplete }
            let current = try loadRuntimeActivation(accountID: plan.accountID)
            guard let retained = current.plan, try retained.encoded == plan.encoded,
                  let inventory = try loadInventoryRecord(), try plan.enrolledInventory(inventory) == inventory else {
                throw RuntimeActivationError.incomplete
            }
            if current.jobsRegistered { return }
            try statement("UPDATE runtime_activation_v1 SET registered=1 WHERE account=? AND record=? AND registered=0") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw RuntimeActivationError.conflictingPlan }
            }
        }
    }
    private func requireRuntimeActivationScope(_ plan: RuntimeActivationPlan, historicalInventory: InstallationInventory? = nil) throws {
        guard try scalar("PRAGMA user_version") >= 6 else { throw RuntimeActivationError.incomplete }
        try requireRuntimeMaterialScope(plan.reference, historicalInventory: historicalInventory)
        let runtime = try loadRuntimePreparation(accountID: plan.accountID)
        guard runtime.configurationPublished, runtime.reference == plan.reference,
              let account = try loadAccountPreparation(ownerUID: plan.reference.services.ownerUID),
              let inventory = try historicalInventory ?? loadInventoryRecord() else { throw RuntimeActivationError.incomplete }
        try plan.validate(account: account, reference: plan.reference)
        _ = try plan.enrolledInventory(inventory)
    }
    private func loadCompatibilityActivation(accountID: Data)
        throws -> (plan: RuntimeActivationCompatibilityProjection?, registered: Bool) {
        try withRetainedSetupRecordLimit(maximumBytes: RuntimeRetainedSetupActivationPlan.maximumBytes) {
            try statement("SELECT material,digest,registered,record FROM runtime_activation_v1 WHERE account=?") { row in
                try bind(accountID, column: 1, row: row)
                if try step(row) == SQLITE_DONE { return (nil, false) }
                let bytes = try blob(row, column: 3, maximum: RuntimeRetainedSetupActivationPlan.maximumBytes)
                let plan: RuntimeActivationCompatibilityProjection
                do { plan = try .decode(bytes) } catch { throw PreparationStoreError.corruptRecord }
                guard plan.reference.services.accountID == accountID, plan.reference.services.macID == macID,
                      try blob(row, column: 0, maximum: 16) == plan.reference.materialID,
                      try blob(row, column: 1, maximum: 32) == MachineUpdateActivationRecord.digest(bytes),
                      sqlite3_column_type(row, 2) == SQLITE_INTEGER, [0, 1].contains(sqlite3_column_int64(row, 2)) else {
                    throw PreparationStoreError.corruptRecord
                }
                let registered = sqlite3_column_int64(row, 2) == 1
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                return (plan, registered)
            }
        }
    }
    private func loadRuntimeActivation(accountID: Data) throws -> RuntimeActivationState {
        try statement("SELECT material,digest,registered,record FROM runtime_activation_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return .init(plan: nil, jobsRegistered: false) }
            let bytes = try blob(row, column: 3, maximum: 262144), plan: RuntimeActivationPlan
            do { plan = try .decode(bytes) } catch { throw PreparationStoreError.corruptRecord }
            guard plan.accountID == accountID, plan.reference.services.macID == macID,
                  try blob(row, column: 0, maximum: 16) == plan.reference.materialID,
                  try blob(row, column: 1, maximum: 32) == Data(SHA256.hash(data: bytes)),
                  sqlite3_column_type(row, 2) == SQLITE_INTEGER, [0, 1].contains(sqlite3_column_int64(row, 2)) else {
                throw PreparationStoreError.corruptRecord
            }
            let registered = sqlite3_column_int64(row, 2) == 1
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return .init(plan: plan, jobsRegistered: registered)
        }
    }
    func gatewayRuntimeActivation(accountID: Data) throws -> GatewayRuntimeActivationState {
        guard accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 10 { return .init(plan: nil, filesPublished: false, jobRegistered: false) }
            let state = try loadGatewayRuntimeActivation(accountID: accountID)
            if let plan = state.plan { _ = try requireGatewayRuntimeActivationScope(plan) }
            return state
        }
    }
    func retainGatewayRuntimeActivation(_ plan: GatewayRuntimeActivationPlan) throws {
        let encoded = try plan.encoded, digest = try plan.digest
        try transaction(write: true) {
            try identity(macID)
            let scope = try requireGatewayRuntimeActivationScope(plan)
            let version = try scalar("PRAGMA user_version")
            if version >= 10, let retained = try loadGatewayRuntimeActivation(accountID: plan.accountID).plan {
                guard try retained.encoded == encoded else { throw GatewayPreparationError.conflictingMaterial }; return
            }
            guard !scope.inventory.services.contains(where: { $0.accountID == plan.accountID && $0.role == .notificationGateway }) else {
                throw GatewayPreparationError.changedScope
            }
            if version == 9 {
                try exec("CREATE TABLE gateway_runtime_activation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),journal BLOB NOT NULL UNIQUE CHECK(length(journal)=16),material BLOB NOT NULL CHECK(length(material)=16),digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),published INTEGER NOT NULL CHECK(published IN (0,1)),registered INTEGER NOT NULL CHECK(registered IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 270336),CHECK(registered=0 OR published=1)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=10")
            }
            guard try scalar("SELECT COUNT(*) FROM gateway_runtime_activation_v1") < 64 else { throw GatewayPreparationError.exhausted }
            try statement("INSERT INTO gateway_runtime_activation_v1 VALUES(?,?,?,?,0,0,?)") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.journalIntentID, column: 2, row: row)
                try bind(plan.extensions.authority.material.materialID, column: 3, row: row)
                try bind(digest, column: 4, row: row); try bind(encoded, column: 5, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    /// The authorized setup controller verifies every exact artifact before setting this historical marker.
    func markGatewayRuntimePublished(_ plan: GatewayRuntimeActivationPlan) throws {
        try transaction(write: true) {
            try identity(macID); _ = try requireGatewayRuntimeActivationScope(plan)
            guard try scalar("PRAGMA user_version") >= 10 else { throw GatewayPreparationError.incomplete }
            let current = try loadGatewayRuntimeActivation(accountID: plan.accountID)
            guard let retained = current.plan, try retained.encoded == plan.encoded else { throw GatewayPreparationError.changedScope }
            if current.filesPublished { return }
            try statement("UPDATE gateway_runtime_activation_v1 SET published=1 WHERE account=? AND digest=? AND published=0") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.digest, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
        }
    }
    @discardableResult
    func enrollGatewayRuntimeActivation(_ plan: GatewayRuntimeActivationPlan) throws -> InstallationInventory {
        let values = try transaction(write: false) {
            try identity(macID)
            let scope = try requireGatewayRuntimeActivationScope(plan)
            guard try scalar("PRAGMA user_version") >= 10 else { throw GatewayPreparationError.incomplete }
            let current = try loadGatewayRuntimeActivation(accountID: plan.accountID)
            guard current.filesPublished, let retained = current.plan, try retained.encoded == plan.encoded else {
                throw GatewayPreparationError.incomplete
            }
            let proposal = try plan.proposal(journal: scope.journal, foreground: scope.foreground, inventory: scope.inventory)
            return (before: scope.inventory, after: try proposal.enrolledInventory(scope.inventory))
        }
        if values.before == values.after { return values.before }
        return try writeInventory(values.after, expectedRevision: values.before.revision)
    }
    /// The controller must verify the native job independently. This flag asserts no live process or consumer health.
    func markGatewayRuntimeRegistered(_ plan: GatewayRuntimeActivationPlan) throws {
        try transaction(write: true) {
            try identity(macID)
            let scope = try requireGatewayRuntimeActivationScope(plan)
            guard try scalar("PRAGMA user_version") >= 10 else { throw GatewayPreparationError.incomplete }
            let current = try loadGatewayRuntimeActivation(accountID: plan.accountID)
            let proposal = try plan.proposal(journal: scope.journal, foreground: scope.foreground, inventory: scope.inventory)
            guard current.filesPublished, let retained = current.plan, try retained.encoded == plan.encoded,
                  try proposal.enrolledInventory(scope.inventory) == scope.inventory else { throw GatewayPreparationError.incomplete }
            if current.jobRegistered { return }
            try statement("UPDATE gateway_runtime_activation_v1 SET registered=1 WHERE account=? AND digest=? AND registered=0") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.digest, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
        }
    }
    func gatewaySettingsTransition(accountID: Data) throws -> GatewayRuntimeSettingsState {
        guard accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 11 else { return .empty }
            let state = try loadGatewaySettingsTransition(accountID: accountID)
            if let value = state.pending ?? state.active { _ = try requireGatewaySettingsScope(value) }
            return state
        }
    }
    /// Retention compares the exact current revision. This does not stop services or publish configuration.
    func retainGatewaySettingsTransition(_ revision: GatewayRuntimeSettingsRevision) throws {
        let bytes = try revision.encoded
        guard revision.sequence <= UInt64(Int64.max) else { throw GatewayPreparationError.exhausted }
        try transaction(write: true) {
            try identity(macID)
            let activation = try requireGatewaySettingsScope(revision)
            let version = try scalar("PRAGMA user_version")
            let state = try version >= 11 ? loadGatewaySettingsTransition(accountID: revision.accountID) : .empty
            if let pending = state.pending {
                guard try pending.encoded == bytes else { throw GatewayPreparationError.conflictingMaterial }; return
            }
            if let active = state.active, try active.encoded == bytes { return }
            try revision.validateSuccessor(of: state.active, activation: activation)
            if version == 10 {
                try exec("CREATE TABLE gateway_settings_transition_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),activation BLOB NOT NULL CHECK(length(activation)=32),sequence INTEGER NOT NULL CHECK(sequence>=0),digest BLOB NOT NULL CHECK(length(digest)=32),active BLOB CHECK(active IS NULL OR length(active) BETWEEN 1 AND 32768),pending BLOB CHECK(pending IS NULL OR length(pending) BETWEEN 1 AND 32768),phase INTEGER CHECK(phase BETWEEN 0 AND 3),CHECK((sequence=0 AND active IS NULL) OR (sequence>0 AND active IS NOT NULL)),CHECK((pending IS NULL AND phase IS NULL) OR (pending IS NOT NULL AND phase IS NOT NULL))) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=11")
            }
            if state.active == nil {
                guard try scalar("SELECT COUNT(*) FROM gateway_settings_transition_v1") < 64 else { throw GatewayPreparationError.exhausted }
                try statement("INSERT INTO gateway_settings_transition_v1 VALUES(?,?,0,?,NULL,?,0)") { row in
                    try bind(revision.accountID, column: 1, row: row); try bind(revision.activationDigest, column: 2, row: row)
                    try bind(revision.previousDigest, column: 3, row: row); try bind(bytes, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                }
            } else {
                try statement("UPDATE gateway_settings_transition_v1 SET pending=?,phase=0 WHERE account=? AND digest=? AND pending IS NULL") { row in
                    try bind(bytes, column: 1, row: row); try bind(revision.accountID, column: 2, row: row)
                    try bind(revision.previousDigest, column: 3, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            }
            try identity(macID)
        }
    }
    /// The owner verifies each native stage before advancing it. Reading these markers grants no runtime authority.
    func markGatewaySettingsTransition(_ revision: GatewayRuntimeSettingsRevision, phase: GatewayRuntimeSettingsPhase) throws {
        try transaction(write: true) {
            try identity(macID); _ = try requireGatewaySettingsScope(revision)
            guard try scalar("PRAGMA user_version") >= 11 else { throw GatewayPreparationError.incomplete }
            let state = try loadGatewaySettingsTransition(accountID: revision.accountID)
            guard let pending = state.pending, let current = state.phase, try pending.encoded == revision.encoded else {
                throw GatewayPreparationError.changedScope
            }
            if current.rawValue >= phase.rawValue { return }
            guard phase.rawValue == current.rawValue + 1 else { throw PreparationStoreError.invalidTransition }
            try statement("UPDATE gateway_settings_transition_v1 SET phase=? WHERE account=? AND phase=?") { row in
                try bind(phase.rawValue, column: 1, row: row); try bind(revision.accountID, column: 2, row: row)
                try bind(current.rawValue, column: 3, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        }
    }
    /// Completion preserves the original activation and journal. The current revision changes in one transaction.
    func completeGatewaySettingsTransition(_ revision: GatewayRuntimeSettingsRevision) throws {
        try transaction(write: true) {
            try identity(macID); _ = try requireGatewaySettingsScope(revision)
            guard try scalar("PRAGMA user_version") >= 11 else { throw GatewayPreparationError.incomplete }
            let state = try loadGatewaySettingsTransition(accountID: revision.accountID)
            if state.pending == nil, let active = state.active, try active.encoded == revision.encoded { return }
            guard let pending = state.pending, state.phase == .consumersObserved, try pending.encoded == revision.encoded else {
                throw GatewayPreparationError.incomplete
            }
            try statement("UPDATE gateway_settings_transition_v1 SET sequence=?,digest=?,active=pending,pending=NULL,phase=NULL WHERE account=? AND digest=? AND phase=3") { row in
                try bind(Int64(revision.sequence), column: 1, row: row); try bind(revision.digest, column: 2, row: row)
                try bind(revision.accountID, column: 3, row: row); try bind(revision.previousDigest, column: 4, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        }
    }
    private func requireGatewaySettingsScope(_ revision: GatewayRuntimeSettingsRevision, historicalInventory: InstallationInventory? = nil) throws -> GatewayRuntimeActivationPlan {
        guard revision.sequence <= UInt64(Int64.max) else { throw GatewayPreparationError.exhausted }
        guard try scalar("PRAGMA user_version") >= 10 else { throw GatewayPreparationError.incomplete }
        let state = try loadGatewayRuntimeActivation(accountID: revision.accountID)
        guard state.filesPublished, state.jobRegistered, let activation = state.plan else { throw GatewayPreparationError.incomplete }
        let scope = try requireGatewayRuntimeActivationScope(activation, historicalInventory: historicalInventory)
        _ = try revision.proposal(activation: activation, journal: scope.journal, foreground: scope.foreground, inventory: scope.inventory)
        return activation
    }
    private func loadGatewaySettingsTransition(accountID: Data) throws -> GatewayRuntimeSettingsState {
        try statement("SELECT account,activation,sequence,digest,active,pending,phase FROM gateway_settings_transition_v1 ORDER BY account LIMIT 65") { row in
            var result = GatewayRuntimeSettingsState.empty, accounts = Set<Data>()
            while try step(row) == SQLITE_ROW {
                guard accounts.count < 64 else { throw PreparationStoreError.corruptRecord }
                let account = try blob(row, column: 0, maximum: 16), anchor = try blob(row, column: 1, maximum: 32)
                let sequence = sqlite3_column_int64(row, 2), digest = try blob(row, column: 3, maximum: 32)
                guard account.count == 16, anchor.count == 32, digest.count == 32, accounts.insert(account).inserted,
                      sqlite3_column_type(row, 2) == SQLITE_INTEGER, sequence >= 0 else { throw PreparationStoreError.corruptRecord }
                func revision(_ column: Int32) throws -> GatewayRuntimeSettingsRevision? {
                    if sqlite3_column_type(row, column) == SQLITE_NULL { return nil }
                    let value: GatewayRuntimeSettingsRevision
                    do { value = try .decode(blob(row, column: column, maximum: 32768)) }
                    catch { throw PreparationStoreError.corruptRecord }
                    guard value.accountID == account, value.activationDigest == anchor else { throw PreparationStoreError.corruptRecord }
                    return value
                }
                let active = try revision(4), pending = try revision(5)
                let phase: GatewayRuntimeSettingsPhase?
                if sqlite3_column_type(row, 6) == SQLITE_NULL { phase = nil }
                else {
                    guard sqlite3_column_type(row, 6) == SQLITE_INTEGER,
                          let value = GatewayRuntimeSettingsPhase(rawValue: sqlite3_column_int64(row, 6)) else { throw PreparationStoreError.corruptRecord }
                    phase = value
                }
                let activeDigest = try active?.digest
                guard active != nil || pending != nil, (pending == nil) == (phase == nil), sequence == 0 ? active == nil && digest == anchor :
                    active != nil && active?.sequence == UInt64(sequence) && activeDigest == digest else {
                    throw PreparationStoreError.corruptRecord
                }
                if let pending {
                    guard pending.sequence <= UInt64(Int64.max), pending.previousDigest == digest,
                          sequence < Int64.max, pending.sequence == UInt64(sequence) + 1,
                          active?.id != pending.id else { throw PreparationStoreError.corruptRecord }
                }
                if account == accountID { result = .init(active: active, pending: pending, phase: phase) }
            }
            return result
        }
    }
    private func requireGatewayRuntimeActivationScope(_ plan: GatewayRuntimeActivationPlan, historicalInventory: InstallationInventory? = nil) throws
        -> (journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory) {
        guard try scalar("PRAGMA user_version") >= 9 else { throw GatewayPreparationError.incomplete }
        let journal = try loadGatewayJournalPreparation(accountID: plan.accountID)
        let activation = try loadRuntimeActivation(accountID: plan.accountID)
        guard journal.initialized, let intent = journal.intent, activation.jobsRegistered, let foreground = activation.plan,
              let inventory = try historicalInventory ?? loadInventoryRecord(), intent.id == plan.journalIntentID,
              try intent.digest == plan.journalIntentDigest else { throw GatewayPreparationError.incomplete }
        try requireGatewayJournalScope(intent, historicalInventory: historicalInventory)
        _ = try plan.proposal(journal: journal, foreground: foreground, inventory: inventory)
        return (journal, foreground, inventory)
    }
    private func loadGatewayRuntimeActivation(accountID: Data) throws -> GatewayRuntimeActivationState {
        try statement("SELECT account,journal,material,digest,published,registered,record FROM gateway_runtime_activation_v1 ORDER BY account LIMIT 65") { row in
            var result = GatewayRuntimeActivationState(plan: nil, filesPublished: false, jobRegistered: false), accounts = Set<Data>()
            while try step(row) == SQLITE_ROW {
                guard accounts.count < 64 else { throw PreparationStoreError.corruptRecord }
                let plan: GatewayRuntimeActivationPlan
                do { plan = try .decode(blob(row, column: 6, maximum: GatewayRuntimeActivationPlan.maximumBytes)) }
                catch { throw PreparationStoreError.corruptRecord }
                let account = try blob(row, column: 0, maximum: 16), published = sqlite3_column_int64(row, 4), registered = sqlite3_column_int64(row, 5)
                guard accounts.insert(account).inserted, plan.accountID == account,
                      plan.extensions.authority.material.runtime.services.macID == macID,
                      try blob(row, column: 1, maximum: 16) == plan.journalIntentID,
                      try blob(row, column: 2, maximum: 16) == plan.extensions.authority.material.materialID,
                      try blob(row, column: 3, maximum: 32) == plan.digest,
                      sqlite3_column_type(row, 4) == SQLITE_INTEGER, sqlite3_column_type(row, 5) == SQLITE_INTEGER,
                      [0,1].contains(published), [0,1].contains(registered), registered == 0 || published == 1 else {
                    throw PreparationStoreError.corruptRecord
                }
                if account == accountID { result = .init(plan: plan, filesPublished: published == 1, jobRegistered: registered == 1) }
            }
            return result
        }
    }

    func gatewayJournalPreparation(accountID: Data) throws -> GatewayJournalPreparationState {
        guard accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 9 { return .init(intent: nil, initialized: false) }
            let state = try loadGatewayJournalPreparation(accountID: accountID)
            if let intent = state.intent { try requireGatewayJournalScope(intent) }
            return state
        }
    }
    func retainGatewayJournalIntent(_ intent: GatewayJournalSetupIntent) throws {
        let encoded = try intent.encoded, digest = try intent.digest, files = try intent.fileDigest
        try transaction(write: true) {
            try identity(macID); try requireGatewayJournalScope(intent)
            if try scalar("PRAGMA user_version") == 8 {
                try exec("CREATE TABLE gateway_journal_preparation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),intent BLOB NOT NULL UNIQUE CHECK(length(intent)=16),material BLOB NOT NULL CHECK(length(material)=16),files BLOB NOT NULL UNIQUE CHECK(length(files)=32),digest BLOB NOT NULL CHECK(length(digest)=32),initialized INTEGER NOT NULL CHECK(initialized IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 131072)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=9")
            }
            let current = try loadGatewayJournalPreparation(accountID: intent.accountID)
            if let retained = current.intent {
                guard retained == intent else { throw GatewayPreparationError.conflictingMaterial }; return
            }
            guard let inventory = try loadInventoryRecord(), !inventory.services.contains(where: {
                $0.accountID == intent.accountID && $0.role == .notificationGateway
            }) else { throw GatewayPreparationError.changedScope }
            guard try scalar("SELECT COUNT(*) FROM gateway_journal_preparation_v1") < 64 else { throw GatewayPreparationError.exhausted }
            try statement("INSERT INTO gateway_journal_preparation_v1 VALUES(?,?,?,?,?,0,?)") { row in
                try bind(intent.accountID, column: 1, row: row); try bind(intent.id, column: 2, row: row)
                try bind(intent.material.materialID, column: 3, row: row); try bind(files, column: 4, row: row)
                try bind(digest, column: 5, row: row); try bind(encoded, column: 6, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    @discardableResult
    func completeGatewayJournalInitialization(_ intent: GatewayJournalSetupIntent, head: GatewayHeadEvidence) throws -> GatewayJournalPreparationState {
        try transaction(write: true) {
            try identity(macID); try requireGatewayJournalScope(intent)
            guard try scalar("PRAGMA user_version") >= 9 else { throw GatewayPreparationError.incomplete }
            let current = try loadGatewayJournalPreparation(accountID: intent.accountID)
            guard current.intent == intent, head.registration == intent.configuration.registration else { throw GatewayPreparationError.changedScope }
            if current.initialized { return current }
            guard head.revision == 0, head.receipt == nil else { throw GatewayPreparationError.changedScope }
            try statement("UPDATE gateway_journal_preparation_v1 SET initialized=1 WHERE account=? AND digest=? AND initialized=0") { row in
                try bind(intent.accountID, column: 1, row: row); try bind(intent.digest, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
            return .init(intent: intent, initialized: true)
        }
    }
    private func requireGatewayJournalScope(_ intent: GatewayJournalSetupIntent, historicalInventory: InstallationInventory? = nil) throws {
        guard try scalar("PRAGMA user_version") >= 8 else { throw GatewayPreparationError.incomplete }
        try requireGatewayMaterialScope(intent.material, historicalInventory: historicalInventory)
        guard try loadGatewayPreparation(accountID: intent.accountID).reference == intent.material,
              let foreground = try loadRuntimeActivation(accountID: intent.accountID).plan,
              let inventory = try historicalInventory ?? loadInventoryRecord() else { throw GatewayPreparationError.incomplete }
        try intent.validate(foreground: foreground, inventory: inventory)
    }
    private func loadGatewayJournalPreparation(accountID: Data) throws -> GatewayJournalPreparationState {
        try statement("SELECT account,intent,material,files,digest,initialized,record FROM gateway_journal_preparation_v1 ORDER BY account LIMIT 65") { row in
            var result = GatewayJournalPreparationState(intent: nil, initialized: false), accounts = Set<Data>()
            while try step(row) == SQLITE_ROW {
                guard accounts.count < 64 else { throw PreparationStoreError.corruptRecord }
                let intent: GatewayJournalSetupIntent
                do { intent = try .decode(blob(row, column: 6, maximum: 131072)) } catch { throw PreparationStoreError.corruptRecord }
                let account = try blob(row, column: 0, maximum: 16)
                guard accounts.insert(account).inserted, intent.accountID == account, intent.material.runtime.services.macID == macID,
                      try blob(row, column: 1, maximum: 16) == intent.id,
                      try blob(row, column: 2, maximum: 16) == intent.material.materialID,
                      try blob(row, column: 3, maximum: 32) == intent.fileDigest,
                      try blob(row, column: 4, maximum: 32) == intent.digest,
                      sqlite3_column_type(row, 5) == SQLITE_INTEGER, [0, 1].contains(sqlite3_column_int64(row, 5)) else {
                    throw PreparationStoreError.corruptRecord
                }
                if account == accountID { result = .init(intent: intent, initialized: sqlite3_column_int64(row, 5) == 1) }
            }
            return result
        }
    }
    func gatewayPreparation(accountID: Data) throws -> GatewayPreparationState {
        guard accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 8 { return .init(reference: nil) }
            let state = try loadGatewayPreparation(accountID: accountID)
            if let reference = state.reference { try requireGatewayMaterialScope(reference) }
            return state
        }
    }
    // Optional material retention only. This transition never modifies foreground configuration or job registration.
    func retainGatewayMaterial(_ reference: GatewayMaterialReference) throws {
        let encoded = try reference.encoded
        try transaction(write: true) {
            try identity(macID); try requireGatewayMaterialScope(reference)
            if try scalar("PRAGMA user_version") == 7 {
                try exec("CREATE TABLE gateway_preparation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),material BLOB NOT NULL UNIQUE CHECK(length(material)=16),receipt BLOB NOT NULL UNIQUE CHECK(length(receipt)=65),credential BLOB NOT NULL UNIQUE CHECK(length(credential)=16),wake BLOB NOT NULL UNIQUE CHECK(length(wake)=65),digest BLOB NOT NULL CHECK(length(digest)=32),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=8")
            }
            let current = try loadGatewayPreparation(accountID: reference.runtime.services.accountID)
            if let retained = current.reference {
                guard retained == reference else { throw GatewayPreparationError.conflictingMaterial }; return
            }
            guard try scalar("SELECT COUNT(*) FROM gateway_preparation_v1") < 64 else { throw GatewayPreparationError.exhausted }
            try statement("SELECT COUNT(*) FROM gateway_preparation_v1 WHERE material=? OR receipt=? OR credential=? OR wake=?") { row in
                try bind(reference.materialID, column: 1, row: row); try bind(reference.phonePush.gatewayReceiptPublicKey, column: 2, row: row)
                try bind(reference.wakeCredentialID, column: 3, row: row); try bind(reference.wakePublicKey, column: 4, row: row)
                guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 0 else { throw GatewayPreparationError.conflictingMaterial }
            }
            try statement("INSERT INTO gateway_preparation_v1 VALUES(?,?,?,?,?,?,?)") { row in
                try bind(reference.runtime.services.accountID, column: 1, row: row); try bind(reference.materialID, column: 2, row: row)
                try bind(reference.phonePush.gatewayReceiptPublicKey, column: 3, row: row); try bind(reference.wakeCredentialID, column: 4, row: row)
                try bind(reference.wakePublicKey, column: 5, row: row); try bind(reference.materialDigest, column: 6, row: row)
                try bind(encoded, column: 7, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    private func requireGatewayMaterialScope(_ reference: GatewayMaterialReference, historicalInventory: InstallationInventory? = nil) throws {
        try requireRuntimeMaterialScope(reference.runtime, historicalInventory: historicalInventory)
        guard try scalar("PRAGMA user_version") >= 7 else { throw GatewayPreparationError.incomplete }
        let runtime = try loadRuntimePreparation(accountID: reference.runtime.services.accountID)
        let activation = try loadRuntimeActivation(accountID: reference.runtime.services.accountID)
        guard runtime.configurationPublished, runtime.reference == reference.runtime, activation.jobsRegistered,
              let plan = activation.plan, plan.reference == reference.runtime,
              let inventory = try historicalInventory ?? loadInventoryRecord(), try plan.enrolledInventory(inventory) == inventory else {
            throw GatewayPreparationError.incomplete
        }
        try requireRuntimeActivationScope(plan, historicalInventory: historicalInventory)
    }
    private func loadGatewayPreparation(accountID: Data) throws -> GatewayPreparationState {
        try statement("SELECT account,material,receipt,credential,wake,digest,record FROM gateway_preparation_v1 ORDER BY account LIMIT 65") { row in
            var selected: GatewayMaterialReference?, accounts = Set<Data>()
            while try step(row) == SQLITE_ROW {
                guard accounts.count < 64 else { throw PreparationStoreError.corruptRecord }
                let reference: GatewayMaterialReference
                do { reference = try .decode(blob(row, column: 6, maximum: 16384)) }
                catch { throw PreparationStoreError.corruptRecord }
                let account = try blob(row, column: 0, maximum: 16)
                guard accounts.insert(account).inserted, reference.runtime.services.accountID == account,
                      reference.runtime.services.macID == macID,
                      try blob(row, column: 1, maximum: 16) == reference.materialID,
                      try blob(row, column: 2, maximum: 65) == reference.phonePush.gatewayReceiptPublicKey,
                      try blob(row, column: 3, maximum: 16) == reference.wakeCredentialID,
                      try blob(row, column: 4, maximum: 65) == reference.wakePublicKey,
                      try blob(row, column: 5, maximum: 32) == reference.materialDigest else {
                    throw PreparationStoreError.corruptRecord
                }
                if account == accountID { selected = reference }
            }
            return .init(reference: selected)
        }
    }
    func runtimeAuditUpgrade(accountID: Data) throws -> RuntimeAuditUpgradeRecord? {
        guard accountID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 12 else { return nil }
            let record = try loadRuntimeAuditUpgrade(accountID: accountID)
            if let record { try requireRuntimeAuditUpgradeScope(record.intent, allowCommitted: true) }
            return record
        }
    }
    // The owner supplies current protected policy. This retains intent only, before any staging or cutover.
    func retainRuntimeAuditUpgrade(_ intent: RuntimeAuditUpgradeIntent, currentPolicy: AuthorityCodePolicy, installedRelease: SignedReleaseEvidence) throws -> RuntimeAuditUpgradeRecord {
        try RuntimeAuditUpgradeRecord.validatePreparation(intent, release: installedRelease, policy: currentPolicy)
        return try transaction(write: true) {
            try identity(macID); try requireRuntimeAuditUpgradeScope(intent)
            if try scalar("PRAGMA user_version") >= 12, let existing = try loadRuntimeAuditUpgrade(accountID: intent.source.services.accountID) {
                guard existing.intent == intent else { throw RuntimePreparationError.conflictingMaterial }; return existing
            }
            try upgradeAuditPreparationStorage()
            guard try scalar("SELECT COUNT(*) FROM runtime_audit_upgrade_v1") < 64 else { throw RuntimePreparationError.exhausted }
            let value = try RuntimeAuditUpgradeRecord(intent: intent, phase: .retained), encoded = try value.encoded
            try statement("INSERT INTO runtime_audit_upgrade_v1 VALUES(?,?,?,?,?,?)") { row in
                try bind(intent.source.services.accountID, column: 1, row: row); try bind(intent.id, column: 2, row: row)
                try bind(value.revision, column: 3, row: row); try bind(Int64(value.phase.rawValue), column: 4, row: row)
                try bind(Data(SHA256.hash(data: encoded)), column: 5, row: row); try bind(encoded, column: 6, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            return value
        }
    }
    // The protected owner verifies the actual staged artifact first. This marker is not a file operation or a cutover permit.
    func markRuntimeAuditMaterialStaged(_ expected: RuntimeAuditUpgradeRecord, currentPolicy: AuthorityCodePolicy, installedRelease: SignedReleaseEvidence) throws -> RuntimeAuditUpgradeRecord {
        try RuntimeAuditUpgradeRecord.validatePreparation(expected.intent, release: installedRelease, policy: currentPolicy)
        return try transaction(write: true) {
            try identity(macID); try requireRuntimeAuditUpgradeScope(expected.intent)
            guard try scalar("PRAGMA user_version") >= 12,
                  let current = try loadRuntimeAuditUpgrade(accountID: expected.intent.source.services.accountID),
                  current.intent == expected.intent else { throw RuntimePreparationError.incomplete }
            if current.phase == .materialStaged {
                guard expected.phase == .retained || expected == current else { throw PreparationStoreError.staleRevision }
                return current
            }
            guard expected == current else { throw PreparationStoreError.staleRevision }
            let next = try RuntimeAuditUpgradeRecord(intent: current.intent, phase: .materialStaged), encoded = try next.encoded
            try statement("UPDATE runtime_audit_upgrade_v1 SET revision=?,phase=2,digest=?,record=? WHERE account=? AND revision=? AND phase=1") { row in
                try bind(next.revision, column: 1, row: row); try bind(Data(SHA256.hash(data: encoded)), column: 2, row: row)
                try bind(encoded, column: 3, row: row); try bind(current.intent.source.services.accountID, column: 4, row: row)
                try bind(current.revision, column: 5, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
            return next
        }
    }
    private func requireRuntimeAuditUpgradeScope(_ intent: RuntimeAuditUpgradeIntent, allowCommitted: Bool = false,
        historicalInventory: InstallationInventory? = nil) throws {
        guard try scalar("PRAGMA user_version") >= 6 else { throw RuntimePreparationError.incomplete }
        try requireRuntimeMaterialScope(intent.source, historicalInventory: historicalInventory)
        let current = try loadRuntimePreparation(accountID: intent.source.services.accountID)
        guard current.configurationPublished else { throw RuntimePreparationError.changedScope }
        if current.reference == intent.source { return }
        guard allowCommitted, current.reference == intent.target, try scalar("PRAGMA user_version") >= 14,
              let cutover = try loadRuntimeAuditCutover(accountID: intent.source.services.accountID),
              cutover.phase == .metadataCommitted, cutover.graph.upgrade.intent == intent,
              try loadRuntimeAuditGraph(accountID: intent.source.services.accountID, contentDigest: cutover.graph.contentDigest) == cutover.graph else {
            throw RuntimePreparationError.changedScope
        }
    }
    func runtimeAuditGraph(accountID: Data, contentDigest: Data) throws -> RuntimeAuditUpgradeGraphRecord? {
        guard accountID.count == 16, contentDigest.count == 32 else { throw RuntimePreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 13 else { return nil }
            return try loadRuntimeAuditGraph(accountID: accountID, contentDigest: contentDigest)
        }
    }
    // The public reference and private recovery bytes commit together, before any external graph file is published.
    func retainRuntimeAuditGraph(_ graph: RuntimeAuditUpgradeGraph, installedRelease: SignedReleaseEvidence,
                                currentPolicy: AuthorityCodePolicy) throws -> RuntimeAuditUpgradeGraphRecord {
        try graph.requireOwner(getuid())
        try RuntimeAuditUpgradeGraphRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        return try transaction(write: true) {
            try identity(macID); try requireRuntimeAuditGraphSource(graph)
            let schema = try scalar("PRAGMA user_version"), account = graph.upgrade.intent.source.services.accountID
            if schema >= 13, let existing = try loadRuntimeAuditGraph(accountID: account, contentDigest: graph.digest) {
                try existing.validate(graph)
                guard try loadRuntimeAuditGraphBytes(existing) == graph.bytes else { throw PreparationStoreError.corruptRecord }
                return existing
            }
            if schema == 12 {
                try exec("CREATE TABLE runtime_audit_graph_v1(account BLOB NOT NULL CHECK(length(account)=16),attempt BLOB NOT NULL CHECK(length(attempt)=16),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase IN (1,2)),content BLOB NOT NULL CHECK(length(content)=32),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 28672),PRIMARY KEY(account,content)) STRICT, WITHOUT ROWID")
                try exec("CREATE TABLE runtime_audit_graph_chunks_v1(account BLOB NOT NULL CHECK(length(account)=16),content BLOB NOT NULL CHECK(length(content)=32),part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 511),bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 16384),PRIMARY KEY(account,content,part)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=13")
            } else { guard (13...16).contains(schema) else { throw PreparationStoreError.incompatibleStore } }
            guard try scalar("SELECT COUNT(*) FROM runtime_audit_graph_v1") < 64 else { throw RuntimePreparationError.exhausted }
            let record = try RuntimeAuditUpgradeGraphRecord(upgrade: graph.upgrade, contentDigest: graph.digest)
            try statement("INSERT INTO runtime_audit_graph_v1 VALUES(?,?,?,?,?,?)") { row in
                try bind(account, column: 1, row: row); try bind(graph.upgrade.intent.id, column: 2, row: row)
                try bind(record.revision, column: 3, row: row); try bind(Int64(record.phase.rawValue), column: 4, row: row)
                try bind(record.contentDigest, column: 5, row: row); try bind(record.encoded, column: 6, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            for offset in stride(from: 0, to: graph.bytes.count, by: 16384) {
                try statement("INSERT INTO runtime_audit_graph_chunks_v1 VALUES(?,?,?,?)") { row in
                    try bind(account, column: 1, row: row); try bind(record.contentDigest, column: 2, row: row)
                    try bind(Int64(offset / 16384), column: 3, row: row)
                    try bind(graph.bytes.subdata(in: offset..<min(offset + 16384, graph.bytes.count)), column: 4, row: row)
                    guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                }
            }
            return record
        }
    }
    func runtimeAuditGraphBytes(_ expected: RuntimeAuditUpgradeGraphRecord) throws -> Data {
        try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 13,
                  let current = try loadRuntimeAuditGraph(accountID: expected.upgrade.intent.source.services.accountID, contentDigest: expected.contentDigest),
                  current == expected || (current.phase == .fileStored && current.upgrade == expected.upgrade) else { throw PreparationStoreError.staleRevision }
            return try loadRuntimeAuditGraphBytes(current)
        }
    }
    // The actual file is verified first. This is historical copy progress, independent of later settings changes.
    func markRuntimeAuditGraphStored(_ expected: RuntimeAuditUpgradeGraphRecord, graph: RuntimeAuditUpgradeGraph,
                                    installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy) throws -> RuntimeAuditUpgradeGraphRecord {
        try RuntimeAuditUpgradeGraphRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try expected.validate(graph); try graph.requireOwner(getuid())
        return try transaction(write: true) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 13,
                  let current = try loadRuntimeAuditGraph(accountID: graph.upgrade.intent.source.services.accountID, contentDigest: graph.digest) else { throw RuntimePreparationError.incomplete }
            try current.validate(graph)
            guard try loadRuntimeAuditGraphBytes(current) == graph.bytes else { throw PreparationStoreError.corruptRecord }
            if current.phase == .fileStored { return current }
            guard current == expected else { throw PreparationStoreError.staleRevision }
            let next = try RuntimeAuditUpgradeGraphRecord(upgrade: current.upgrade, contentDigest: current.contentDigest, phase: .fileStored)
            try statement("UPDATE runtime_audit_graph_v1 SET revision=?,phase=2,record=? WHERE account=? AND content=? AND revision=? AND phase=1") { row in
                try bind(next.revision, column: 1, row: row); try bind(next.encoded, column: 2, row: row)
                try bind(current.upgrade.intent.source.services.accountID, column: 3, row: row); try bind(current.contentDigest, column: 4, row: row)
                try bind(current.revision, column: 5, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
            return next
        }
    }
    private func loadRuntimeAuditGraphBytes(_ record: RuntimeAuditUpgradeGraphRecord) throws -> Data {
        try statement("SELECT part,bytes FROM runtime_audit_graph_chunks_v1 WHERE account=? AND content=? ORDER BY part") { row in
            try bind(record.upgrade.intent.source.services.accountID, column: 1, row: row); try bind(record.contentDigest, column: 2, row: row)
            var bytes = Data(), part: Int64 = 0
            while try step(row) == SQLITE_ROW {
                guard part < 512, sqlite3_column_type(row, 0) == SQLITE_INTEGER, sqlite3_column_int64(row, 0) == part else { throw PreparationStoreError.corruptRecord }
                let chunk = try blob(row, column: 1, maximum: 16384)
                guard !chunk.isEmpty, bytes.count == Int(part) * 16384,
                      bytes.count + chunk.count <= RuntimeAuditUpgradeGraph.maximumBytes else { throw PreparationStoreError.corruptRecord }
                bytes.append(chunk); part += 1
            }
            guard !bytes.isEmpty, Data(SHA256.hash(data: bytes)) == record.contentDigest else { throw PreparationStoreError.corruptRecord }
            return bytes
        }
    }
    private func requireRuntimeAuditGraphSource(_ graph: RuntimeAuditUpgradeGraph, verifyImport: Bool = true) throws {
        let p = graph.snapshot.plan, account = p.sourceAccount.accountID
        try requireRuntimeAuditUpgradeScope(graph.upgrade.intent); try requireAccountPreparation(p.sourceAccount)
        guard try loadRuntimeAuditUpgrade(accountID: account) == graph.upgrade,
              try loadInitialization(accountID: account) == p.sourceInitialization,
              try loadInventoryRecord() == p.sourceInventory else { throw RuntimePreparationError.changedScope }
        let foreground = try loadRuntimeActivation(accountID: account), gateway = try loadGatewayRuntimeActivation(accountID: account)
        let settings = try scalar("PRAGMA user_version") >= 11 ? loadGatewaySettingsTransition(accountID: account) : .empty
        guard try foreground.plan?.encoded == p.preparation.source.encoded, foreground.jobsRegistered == p.sourceJobsRegistered,
              try loadGatewayPreparation(accountID: account).reference == p.sourceGateway.reference,
              try loadGatewayJournalPreparation(accountID: account) == p.sourceGateway.journal,
              try gateway.plan?.encoded == p.sourceGateway.activation.plan?.encoded,
              gateway.filesPublished == p.sourceGateway.activation.filesPublished, gateway.jobRegistered == p.sourceGateway.activation.jobRegistered,
              try settings.active?.encoded == p.sourceGateway.settings.active?.encoded,
              try settings.pending?.encoded == p.sourceGateway.settings.pending?.encoded, settings.phase == p.sourceGateway.settings.phase else {
            throw RuntimePreparationError.changedScope
        }
        if verifyImport {
            let imports = try sharedImportCompatibilitySnapshot(installationID: p.sourceInventory.installationID)
            guard imports?.records.first(where: { $0.accountID == account }) == p.sourceImport?.source else { throw RuntimePreparationError.changedScope }
        }
    }
    private func loadRuntimeAuditGraph(accountID: Data, contentDigest: Data) throws -> RuntimeAuditUpgradeGraphRecord? {
        try statement("SELECT attempt,revision,phase,content,record FROM runtime_audit_graph_v1 WHERE account=? AND content=?") { row in
            try bind(accountID, column: 1, row: row); try bind(contentDigest, column: 2, row: row)
            if try step(row) == SQLITE_DONE { return nil }
            let bytes = try blob(row, column: 4, maximum: 28672), record = try RuntimeAuditUpgradeGraphRecord.decode(bytes)
            guard record.upgrade.intent.source.services.accountID == accountID, record.upgrade.intent.source.services.macID == macID,
                  try blob(row, column: 0, maximum: 16) == record.upgrade.intent.id,
                  try blob(row, column: 1, maximum: 16) == record.revision,
                  sqlite3_column_type(row, 2) == SQLITE_INTEGER, sqlite3_column_int64(row, 2) == Int64(record.phase.rawValue),
                  try blob(row, column: 3, maximum: 32) == record.contentDigest, record.contentDigest == contentDigest,
                  try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return record
        }
    }

    func runtimeAuditCutover(accountID: Data) throws -> RuntimeAuditUpgradeCutoverRecord? {
        guard accountID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 14 else { return nil }
            let current = try loadRuntimeAuditCutover(accountID: accountID)
            if let current {
                let runtime = try loadRuntimePreparation(accountID: accountID)
                let intent = current.graph.upgrade.intent
                guard runtime.configurationPublished,
                      runtime.reference == (current.phase == .metadataCommitted ? intent.target : intent.source) else {
                    throw RuntimePreparationError.changedScope
                }
            }
            return current
        }
    }
    // Selection alone does not freeze settings. Replacing an unstarted selection requires its exact revision.
    func selectRuntimeAuditCutover(_ graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                                   replacing: RuntimeAuditUpgradeCutoverRecord? = nil,
                                   installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy) throws -> RuntimeAuditUpgradeCutoverRecord {
        try graph.requireOwner(getuid()); try record.validate(graph)
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        return try transaction(write: true) {
            try identity(macID)
            let schema = try scalar("PRAGMA user_version"), account = graph.snapshot.plan.sourceAccount.accountID
            guard schema >= 13, record.phase == .fileStored,
                  try loadRuntimeAuditGraph(accountID: account, contentDigest: graph.digest) == record,
                  try loadRuntimeAuditGraphBytes(record) == graph.bytes else { throw RuntimePreparationError.incomplete }
            let old = try schema >= 14 ? loadRuntimeAuditCutover(accountID: account) : nil
            if let old, old.graph == record {
                try requireRuntimeAuditCutoverMetadata(graph, target: old.phase == .metadataCommitted)
                return old
            }
            if let old {
                guard old.phase == .selected, old == replacing else { throw PreparationStoreError.staleRevision }
                let existingFence: Data?
                if graph.snapshot.ownership == .native {
                    existingFence = try ProtectedServiceConfiguration.readOptionalAuditFence(accountID: account)
                } else {
                    guard let parent = graph.snapshot.retainedParents[.services] else { throw RuntimePreparationError.changedScope }
                    existingFence = try ProtectedServiceConfiguration.readOptional(anchor: parent.path,
                        relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid())
                }
                guard existingFence == nil else { throw RuntimeAuditUpgradeStartupError.recoveryRequired }
            } else { guard replacing == nil else { throw PreparationStoreError.staleRevision } }
            try requireRuntimeAuditGraphSource(graph)
            if schema == 13 {
                try exec("CREATE TABLE runtime_audit_cutover_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),attempt BLOB NOT NULL CHECK(length(attempt)=16),content BLOB NOT NULL CHECK(length(content)=32),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 4),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 30720)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=14")
            }
            let next = try RuntimeAuditUpgradeCutoverRecord(graph: record)
            if let old { try writeRuntimeAuditCutover(next, replacing: old) }
            else {
                guard try scalar("SELECT COUNT(*) FROM runtime_audit_cutover_v1") < 64 else { throw RuntimePreparationError.exhausted }
                try statement("INSERT INTO runtime_audit_cutover_v1 VALUES(?,?,?,?,1,?)") { row in
                    try bind(account, column: 1, row: row); try bind(graph.upgrade.intent.id, column: 2, row: row)
                    try bind(graph.digest, column: 3, row: row); try bind(next.revision, column: 4, row: row)
                    try bind(next.encoded, column: 5, row: row)
                    guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                }
            }
            try identity(macID); return next
        }
    }
    // The controller holds its live barrier and verifies files independently. No persisted phase recreates that authority.
    func advanceRuntimeAuditCutover(_ expected: RuntimeAuditUpgradeCutoverRecord, graph: RuntimeAuditUpgradeGraph,
                                   to phase: RuntimeAuditUpgradeCutoverRecord.Phase, installedRelease: SignedReleaseEvidence,
                                   currentPolicy: AuthorityCodePolicy, verifyBarrierAndArtifacts: () throws -> Void) throws -> RuntimeAuditUpgradeCutoverRecord {
        guard phase == .filesChanging || phase == .filesVerified,
              phase.rawValue == expected.phase.rawValue + 1 else { throw PreparationStoreError.invalidTransition }
        try graph.requireOwner(getuid()); try expected.graph.validate(graph)
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        try verifyBarrierAndArtifacts()
        return try transaction(write: true) {
            try identity(macID)
            let current = try requireRuntimeAuditCutover(expected, graph: graph)
            try requireRuntimeAuditCutoverMetadata(graph, target: false)
            try requireRuntimeAuditCutoverImport(graph, target: phase == .filesVerified)
            try verifyBarrierAndArtifacts()
            if current.phase == phase { return current }
            guard current == expected else { throw PreparationStoreError.staleRevision }
            let next = try RuntimeAuditUpgradeCutoverRecord(graph: current.graph, phase: phase)
            try writeRuntimeAuditCutover(next, replacing: current)
            try verifyBarrierAndArtifacts(); return next
        }
    }
    enum AuditCutoverMetadataStage: CaseIterable {
        case foregroundMaterial, foregroundActivation, gatewayMaterial, gatewayJournal, gatewayActivation, gatewaySettings, cutoverRecord
    }
    // All related machine rows move together. The owner must freshly verify every live target and the complete runtime barrier.
    func commitRuntimeAuditCutover(_ expected: RuntimeAuditUpgradeCutoverRecord, graph: RuntimeAuditUpgradeGraph,
                                  installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                  verifyBarrierAndTargets: () throws -> Void,
                                  didUpdate: (AuditCutoverMetadataStage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeCutoverRecord {
        guard expected.phase == .filesVerified else { throw PreparationStoreError.invalidTransition }
        try graph.requireOwner(getuid()); try expected.graph.validate(graph)
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        try verifyBarrierAndTargets()
        return try transaction(write: true) {
            try identity(macID)
            let current = try requireRuntimeAuditCutover(expected, graph: graph)
            try requireRuntimeAuditCutoverMetadata(graph, target: current.phase == .metadataCommitted)
            try requireRuntimeAuditCutoverImport(graph, target: true); try verifyBarrierAndTargets()
            if current.phase == .metadataCommitted { return current }
            guard current == expected else { throw PreparationStoreError.staleRevision }
            let p = graph.snapshot.plan, account = p.sourceAccount.accountID, next = p.preparation.target
            try replaceRuntimeAuditRow("UPDATE runtime_preparation_v1 SET digest=?,record=? WHERE account=? AND record=?",
                account: account, before: p.preparation.intent.source.encoded, after: p.preparation.intent.target.encoded,
                digest: p.preparation.intent.target.materialDigest)
            try didUpdate(.foregroundMaterial)
            try replaceRuntimeAuditRow("UPDATE runtime_activation_v1 SET digest=?,record=? WHERE account=? AND record=?",
                account: account, before: p.preparation.source.encoded, after: next.encoded, digest: Data(SHA256.hash(data: next.encoded)))
            try didUpdate(.foregroundActivation)
            if let old = p.sourceGateway.reference, let new = p.gateway.reference {
                try replaceRuntimeAuditRow("UPDATE gateway_preparation_v1 SET digest=?,record=? WHERE account=? AND record=?",
                    account: account, before: old.encoded, after: new.encoded, digest: new.materialDigest)
            }
            try didUpdate(.gatewayMaterial)
            if let old = p.sourceGateway.journal.intent, let new = p.gateway.journal.intent {
                guard try old.fileDigest == new.fileDigest else { throw RuntimePreparationError.changedScope }
                try replaceRuntimeAuditRow("UPDATE gateway_journal_preparation_v1 SET digest=?,record=? WHERE account=? AND record=?",
                    account: account, before: old.encoded, after: new.encoded, digest: new.digest)
            }
            try didUpdate(.gatewayJournal)
            if let old = p.sourceGateway.activation.plan, let new = p.gateway.activation.plan {
                try replaceRuntimeAuditRow("UPDATE gateway_runtime_activation_v1 SET digest=?,record=? WHERE account=? AND record=?",
                    account: account, before: old.encoded, after: new.encoded, digest: new.digest)
            }
            try didUpdate(.gatewayActivation)
            if p.sourceGateway.settings.active != nil || p.sourceGateway.settings.pending != nil {
                guard let newActivation = p.gateway.activation.plan else { throw RuntimePreparationError.changedScope }
                try statement("UPDATE gateway_settings_transition_v1 SET activation=?,digest=?,active=?,pending=? WHERE account=?") { row in
                    try bind(newActivation.digest, column: 1, row: row)
                    try bind(p.gateway.settings.active?.digest ?? newActivation.digest, column: 2, row: row)
                    for (column, bytes) in [(Int32(3), try p.gateway.settings.active?.encoded), (Int32(4), try p.gateway.settings.pending?.encoded)] {
                        if let bytes { try bind(bytes, column: column, row: row) }
                        else { guard sqlite3_bind_null(row, column) == SQLITE_OK else { throw PreparationStoreError.corruptRecord } }
                    }
                    try bind(account, column: 5, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            }
            try didUpdate(.gatewaySettings)
            try requireRuntimeAuditCutoverMetadata(graph, target: true)
            try requireRuntimeAuditCutoverImport(graph, target: true); try verifyBarrierAndTargets()
            let committed = try RuntimeAuditUpgradeCutoverRecord(graph: current.graph, phase: .metadataCommitted)
            try writeRuntimeAuditCutover(committed, replacing: current); try didUpdate(.cutoverRecord)
            try requireRuntimeAuditUpgradeScope(graph.upgrade.intent, allowCommitted: true)
            return committed
        }
    }
    private func replaceRuntimeAuditRow(_ sql: String, account: Data, before: Data, after: Data, digest: Data) throws {
        try statement(sql) { row in
            try bind(digest, column: 1, row: row); try bind(after, column: 2, row: row)
            try bind(account, column: 3, row: row); try bind(before, column: 4, row: row)
            guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
        }
    }
    private func requireRuntimeAuditCutover(_ expected: RuntimeAuditUpgradeCutoverRecord, graph: RuntimeAuditUpgradeGraph) throws -> RuntimeAuditUpgradeCutoverRecord {
        guard try scalar("PRAGMA user_version") >= 14,
              let current = try loadRuntimeAuditCutover(accountID: graph.snapshot.plan.sourceAccount.accountID),
              current.graph == expected.graph, try loadRuntimeAuditGraphBytes(current.graph) == graph.bytes else {
            throw PreparationStoreError.staleRevision
        }
        return current
    }
    private func requireRuntimeAuditCutoverMetadata(_ graph: RuntimeAuditUpgradeGraph, target: Bool) throws {
        if !target { try requireRuntimeAuditGraphSource(graph, verifyImport: false); return }
        let p = graph.snapshot.plan, account = p.sourceAccount.accountID
        try requireRuntimeMaterialScope(p.preparation.intent.target); try requireAccountPreparation(p.sourceAccount)
        guard try loadRuntimeAuditUpgrade(accountID: account) == graph.upgrade,
              try loadInitialization(accountID: account) == p.sourceInitialization,
              try loadInventoryRecord() == p.sourceInventory else { throw RuntimePreparationError.changedScope }
        let runtime = try loadRuntimePreparation(accountID: account), foreground = try loadRuntimeActivation(accountID: account)
        let gateway = try loadGatewayRuntimeActivation(accountID: account), settings = try loadGatewaySettingsTransition(accountID: account)
        guard runtime.configurationPublished, runtime.reference == p.preparation.intent.target,
              try foreground.plan?.encoded == p.preparation.target.encoded, foreground.jobsRegistered == p.sourceJobsRegistered,
              try loadGatewayPreparation(accountID: account).reference == p.gateway.reference,
              try loadGatewayJournalPreparation(accountID: account) == p.gateway.journal,
              try gateway.plan?.encoded == p.gateway.activation.plan?.encoded,
              gateway.filesPublished == p.gateway.activation.filesPublished, gateway.jobRegistered == p.gateway.activation.jobRegistered,
              try settings.active?.encoded == p.gateway.settings.active?.encoded,
              try settings.pending?.encoded == p.gateway.settings.pending?.encoded, settings.phase == p.gateway.settings.phase else {
            throw RuntimePreparationError.changedScope
        }
    }
    private func requireRuntimeAuditCutoverImport(_ graph: RuntimeAuditUpgradeGraph, target: Bool) throws {
        let p = graph.snapshot.plan
        let imports = try sharedImportCompatibilitySnapshot(installationID: p.sourceInventory.installationID)
        let current = imports?.records.first { $0.accountID == p.sourceAccount.accountID }
        if !target { guard current == p.sourceImport?.source else { throw RuntimePreparationError.changedScope }; return }
        guard let old = p.sourceImport?.source else {
            guard current == nil else { throw RuntimePreparationError.changedScope }; return
        }
        guard let current, current.accountID == old.accountID, current.operationID == old.operationID,
              current.revision == old.revision, current.phase == old.phase, current.digest == old.digest,
              current.portableVersion == old.portableVersion, current.settingsVersion == old.settingsVersion,
              current.relay == old.relay, current.relayProvisioning == old.relayProvisioning,
              current.accessApplication == old.accessApplication, current.dnsRecord == old.dnsRecord else {
            throw RuntimePreparationError.changedScope
        }
        if let reference = p.sourceImport?.targetReference {
            guard current.runCredential?.reference == reference,
                  try current.runCredential?.digest == Data(SHA256.hash(data: reference.encoded)) else { throw RuntimePreparationError.changedScope }
        } else { guard current.runCredential == nil else { throw RuntimePreparationError.changedScope } }
    }
    private func writeRuntimeAuditCutover(_ next: RuntimeAuditUpgradeCutoverRecord, replacing old: RuntimeAuditUpgradeCutoverRecord) throws {
        try statement("UPDATE runtime_audit_cutover_v1 SET content=?,revision=?,phase=?,record=? WHERE account=? AND revision=?") { row in
            try bind(next.graph.contentDigest, column: 1, row: row); try bind(next.revision, column: 2, row: row)
            try bind(Int64(next.phase.rawValue), column: 3, row: row); try bind(next.encoded, column: 4, row: row)
            try bind(old.graph.upgrade.intent.source.services.accountID, column: 5, row: row); try bind(old.revision, column: 6, row: row)
            guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
        }
    }
    private func loadRuntimeAuditCutover(accountID: Data) throws -> RuntimeAuditUpgradeCutoverRecord? {
        try statement("SELECT attempt,content,revision,phase,record FROM runtime_audit_cutover_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return nil }
            let record = try RuntimeAuditUpgradeCutoverRecord.decode(blob(row, column: 4, maximum: 30720))
            guard record.graph.upgrade.intent.source.services.accountID == accountID,
                  record.graph.upgrade.intent.source.services.macID == macID,
                  try blob(row, column: 0, maximum: 16) == record.graph.upgrade.intent.id,
                  try blob(row, column: 1, maximum: 32) == record.graph.contentDigest,
                  try blob(row, column: 2, maximum: 16) == record.revision,
                  sqlite3_column_type(row, 3) == SQLITE_INTEGER, sqlite3_column_int64(row, 3) == Int64(record.phase.rawValue),
                  try step(row) == SQLITE_DONE,
                  try loadRuntimeAuditGraph(accountID: accountID, contentDigest: record.graph.contentDigest) == record.graph,
                  try loadRuntimeAuditUpgrade(accountID: accountID) == record.graph.upgrade else {
                throw PreparationStoreError.corruptRecord
            }
            return record
        }
    }

    private func loadRuntimeAuditUpgrade(accountID: Data) throws -> RuntimeAuditUpgradeRecord? {
        try statement("SELECT attempt,revision,phase,digest,record FROM runtime_audit_upgrade_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return nil }
            let bytes = try blob(row, column: 4, maximum: 24576), record: RuntimeAuditUpgradeRecord
            do { record = try .decode(bytes) } catch { throw PreparationStoreError.corruptRecord }
            guard record.intent.source.services.macID == macID, record.intent.source.services.accountID == accountID,
                  try blob(row, column: 0, maximum: 16) == record.intent.id,
                  try blob(row, column: 1, maximum: 16) == record.revision,
                  sqlite3_column_type(row, 2) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 2) == Int64(record.phase.rawValue),
                  try blob(row, column: 3, maximum: 32) == Data(SHA256.hash(data: bytes)),
                  try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return record
        }
    }
    private func upgradeAuditPreparationStorage() throws {
        var version = try scalar("PRAGMA user_version")
        guard version >= 6 else { throw RuntimePreparationError.incomplete }
        if version == 6 {
            try exec("CREATE TABLE runtime_activation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),material BLOB NOT NULL UNIQUE CHECK(length(material)=16),digest BLOB NOT NULL CHECK(length(digest)=32),registered INTEGER NOT NULL CHECK(registered IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262144)) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=7"); version = 7
        }
        if version == 7 {
            try exec("CREATE TABLE gateway_preparation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),material BLOB NOT NULL UNIQUE CHECK(length(material)=16),receipt BLOB NOT NULL UNIQUE CHECK(length(receipt)=65),credential BLOB NOT NULL UNIQUE CHECK(length(credential)=16),wake BLOB NOT NULL UNIQUE CHECK(length(wake)=65),digest BLOB NOT NULL CHECK(length(digest)=32),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=8"); version = 8
        }
        if version == 8 {
            try exec("CREATE TABLE gateway_journal_preparation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),intent BLOB NOT NULL UNIQUE CHECK(length(intent)=16),material BLOB NOT NULL CHECK(length(material)=16),files BLOB NOT NULL UNIQUE CHECK(length(files)=32),digest BLOB NOT NULL CHECK(length(digest)=32),initialized INTEGER NOT NULL CHECK(initialized IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 131072)) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=9"); version = 9
        }
        if version == 9 {
            try exec("CREATE TABLE gateway_runtime_activation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),journal BLOB NOT NULL UNIQUE CHECK(length(journal)=16),material BLOB NOT NULL CHECK(length(material)=16),digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),published INTEGER NOT NULL CHECK(published IN (0,1)),registered INTEGER NOT NULL CHECK(registered IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 270336),CHECK(registered=0 OR published=1)) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=10"); version = 10
        }
        if version == 10 {
            try exec("CREATE TABLE gateway_settings_transition_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),activation BLOB NOT NULL CHECK(length(activation)=32),sequence INTEGER NOT NULL CHECK(sequence>=0),digest BLOB NOT NULL CHECK(length(digest)=32),active BLOB CHECK(active IS NULL OR length(active) BETWEEN 1 AND 32768),pending BLOB CHECK(pending IS NULL OR length(pending) BETWEEN 1 AND 32768),phase INTEGER CHECK(phase BETWEEN 0 AND 3),CHECK((sequence=0 AND active IS NULL) OR (sequence>0 AND active IS NOT NULL)),CHECK((pending IS NULL AND phase IS NULL) OR (pending IS NOT NULL AND phase IS NOT NULL))) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=11"); version = 11
        }
        if version == 11 {
            try exec("CREATE TABLE runtime_audit_upgrade_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),attempt BLOB NOT NULL UNIQUE CHECK(length(attempt)=16),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase IN (1,2)),digest BLOB NOT NULL CHECK(length(digest)=32),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 24576)) STRICT, WITHOUT ROWID")
            try exec("PRAGMA user_version=12"); version = 12
        }
        try identity(macID)
    }

    func runtimePreparation(accountID: Data) throws -> RuntimePreparationState {
        guard accountID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 6 { return .init(reference: nil, configurationPublished: false) }
            let state = try loadRuntimePreparation(accountID: accountID)
            if let reference = state.reference { try requireRuntimeMaterialScope(reference) }
            return state
        }
    }
    // Retain the secret-file digest and public identities before any service-readable publication.
    func retainRuntimeMaterial(_ reference: RuntimeMaterialReference) throws {
        try transaction(write: true) {
            try identity(macID); try requireRuntimeMaterialScope(reference)
            if try scalar("PRAGMA user_version") == 5 {
                try exec("CREATE TABLE runtime_preparation_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),material BLOB NOT NULL UNIQUE CHECK(length(material)=16),pin BLOB NOT NULL UNIQUE CHECK(length(pin)=91),digest BLOB NOT NULL CHECK(length(digest)=32),complete INTEGER NOT NULL CHECK(complete IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 8192)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=6")
            }
            let current = try loadRuntimePreparation(accountID: reference.services.accountID)
            if let retained = current.reference {
                guard retained == reference else { throw RuntimePreparationError.conflictingMaterial }
                return
            }
            guard try scalar("SELECT COUNT(*) FROM runtime_preparation_v1") < 64 else { throw RuntimePreparationError.exhausted }
            try statement("SELECT COUNT(*) FROM runtime_preparation_v1 WHERE material=? OR pin=?") { row in
                try bind(reference.materialID, column: 1, row: row); try bind(reference.transportPublicKeyInfo, column: 2, row: row)
                guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 0 else { throw RuntimePreparationError.conflictingMaterial }
            }
            try statement("INSERT INTO runtime_preparation_v1 VALUES(?,?,?,?,0,?)") { row in
                try bind(reference.services.accountID, column: 1, row: row); try bind(reference.materialID, column: 2, row: row)
                try bind(reference.transportPublicKeyInfo, column: 3, row: row); try bind(reference.materialDigest, column: 4, row: row)
                try bind(reference.encoded, column: 5, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    // The typed controller verifies all fixed artifacts first. This marker grants no registration or execution authority.
    func completeRuntimePublication(_ reference: RuntimeMaterialReference) throws {
        try transaction(write: true) {
            try identity(macID); try requireRuntimeMaterialScope(reference)
            guard try scalar("PRAGMA user_version") >= 6 else { throw RuntimePreparationError.incomplete }
            let current = try loadRuntimePreparation(accountID: reference.services.accountID)
            guard current.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
            if current.configurationPublished { return }
            try statement("UPDATE runtime_preparation_v1 SET complete=1 WHERE account=? AND record=? AND complete=0") { row in
                try bind(reference.services.accountID, column: 1, row: row); try bind(reference.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw RuntimePreparationError.conflictingMaterial }
            }
        }
    }
    private func requireRuntimeMaterialScope(_ reference: RuntimeMaterialReference, historicalInventory: InstallationInventory? = nil) throws {
        try requireServiceAccountScope(reference.services, historicalInventory: historicalInventory)
        guard try scalar("PRAGMA user_version") >= 5 else { throw RuntimePreparationError.incomplete }
        let current = try loadServiceAccountPlan(accountID: reference.services.accountID)
        guard current.plan == reference.services, current.complete else { throw RuntimePreparationError.incomplete }
    }
    private func loadRuntimePreparation(accountID: Data) throws -> RuntimePreparationState {
        try statement("SELECT material,pin,digest,complete,record FROM runtime_preparation_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return .init(reference: nil, configurationPublished: false) }
            let reference: RuntimeMaterialReference
            do { reference = try .decode(blob(row, column: 4, maximum: 8192)) }
            catch { throw PreparationStoreError.corruptRecord }
            guard reference.services.accountID == accountID, reference.services.macID == macID,
                  try blob(row, column: 0, maximum: 16) == reference.materialID,
                  try blob(row, column: 1, maximum: 91) == reference.transportPublicKeyInfo,
                  try blob(row, column: 2, maximum: 32) == reference.materialDigest,
                  sqlite3_column_type(row, 3) == SQLITE_INTEGER,
                  [0, 1].contains(sqlite3_column_int64(row, 3)) else { throw PreparationStoreError.corruptRecord }
            let complete = sqlite3_column_int64(row, 3) == 1
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return .init(reference: reference, configurationPublished: complete)
        }
    }
    func serviceAccountPlan(accountID: Data) throws -> ServiceAccountPlanStorage.State {
        guard accountID.count == 16 else { throw ServiceAccountProvisioningError.invalidPlan }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 5 { return .init(plan: nil, complete: false) }
            return try loadServiceAccountPlan(accountID: accountID)
        }
    }
    func reservedServiceAccountNumbers() throws -> Set<UInt32> {
        try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 5 { return [] }
            return try loadReservedServiceAccountNumbers()
        }
    }

    private func loadReservedServiceAccountNumbers() throws -> Set<UInt32> {
        try statement("SELECT account FROM service_accounts_v1 ORDER BY account LIMIT 65") { row in
            var numbers = Set<UInt32>(), count = 0
            while try step(row) == SQLITE_ROW {
                guard count < 64 else { throw PreparationStoreError.corruptRecord }; count += 1
                let account = try blob(row, column: 0, maximum: 16)
                guard let plan = try loadServiceAccountPlan(accountID: account).plan else { throw PreparationStoreError.corruptRecord }
                for claim in plan.claims {
                    guard numbers.insert(claim.number).inserted else { throw PreparationStoreError.corruptRecord }
                }
            }
            return numbers
        }
    }

    func retainServiceAccountPlan(_ plan: ServiceAccountPlan) throws {
        try transaction(write: true) {
            try requireInventorySchema(); try requireServiceAccountScope(plan)
            if try scalar("PRAGMA user_version") == 4 {
                try exec("CREATE TABLE service_accounts_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),transport INTEGER NOT NULL UNIQUE CHECK(transport>0 AND transport<4294967295),gateway INTEGER NOT NULL UNIQUE CHECK(gateway>0 AND gateway<4294967295 AND gateway!=transport),complete INTEGER NOT NULL CHECK(complete IN (0,1)),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=5")
            }
            let current = try loadServiceAccountPlan(accountID: plan.accountID)
            if let retained = current.plan {
                guard retained == plan else { throw ServiceAccountProvisioningError.conflictingRecord }
                return
            }
            guard try scalar("SELECT COUNT(*) FROM service_accounts_v1") < 64 else { throw ServiceAccountProvisioningError.exhausted }
            let transport = try serviceAccountNumber(plan, role: .transport), gateway = try serviceAccountNumber(plan, role: .gateway)
            // BEGIN IMMEDIATE covers this cross-column check and insertion. Two pending plans cannot reserve overlapping IDs.
            try statement("SELECT COUNT(*) FROM service_accounts_v1 WHERE transport IN (?,?) OR gateway IN (?,?)") { row in
                for (index, number) in [transport, gateway, transport, gateway].enumerated() {
                    guard sqlite3_bind_int64(row, Int32(index + 1), Int64(number)) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
                }
                guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 0 else { throw ServiceAccountProvisioningError.conflictingRecord }
            }
            try statement("INSERT INTO service_accounts_v1 VALUES(?,?,?,0,?)") { row in
                try bind(plan.accountID, column: 1, row: row)
                guard sqlite3_bind_int64(row, 2, Int64(transport)) == SQLITE_OK,
                      sqlite3_bind_int64(row, 3, Int64(gateway)) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
                try bind(plan.encoded, column: 4, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
        }
    }
    func completeServiceAccountPlan(_ plan: ServiceAccountPlan) throws {
        try transaction(write: true) {
            try identity(macID); try requireServiceAccountScope(plan)
            guard try scalar("PRAGMA user_version") >= 5 else { throw ServiceAccountProvisioningError.missingRecord }
            let current = try loadServiceAccountPlan(accountID: plan.accountID)
            guard current.plan == plan else { throw ServiceAccountProvisioningError.conflictingRecord }
            if current.complete { return }
            try statement("UPDATE service_accounts_v1 SET complete=1 WHERE account=? AND record=? AND complete=0") { row in
                try bind(plan.accountID, column: 1, row: row); try bind(plan.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw ServiceAccountProvisioningError.conflictingRecord }
            }
        }
    }
    private func requireServiceAccountScope(_ plan: ServiceAccountPlan, historicalInventory: InstallationInventory? = nil) throws {
        guard plan.macID == macID, try scalar("PRAGMA user_version") >= 4,
              let account = try loadAccountPreparation(ownerUID: plan.ownerUID),
              let inventory = try historicalInventory ?? loadInventoryRecord(), inventory.installationID == plan.installationID,
              inventory.releaseDigest == plan.releaseDigest else { throw ServiceAccountProvisioningError.changedScope }
        try plan.validate(account: account)
    }
    private func serviceAccountNumber(_ plan: ServiceAccountPlan, role: ServiceAccountRole) throws -> UInt32 {
        guard let claim = plan.claims.first(where: { $0.role == role }) else { throw PreparationStoreError.corruptRecord }
        return claim.number
    }
    private func loadServiceAccountPlan(accountID: Data) throws -> ServiceAccountPlanStorage.State {
        try statement("SELECT transport,gateway,complete,record FROM service_accounts_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return .init(plan: nil, complete: false) }
            let plan: ServiceAccountPlan
            do { plan = try .decode(blob(row, column: 3, maximum: 4096)) } catch { throw PreparationStoreError.corruptRecord }
            guard plan.macID == macID, plan.accountID == accountID,
                  sqlite3_column_type(row, 0) == SQLITE_INTEGER, sqlite3_column_type(row, 1) == SQLITE_INTEGER,
                  sqlite3_column_type(row, 2) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == Int64(try serviceAccountNumber(plan, role: .transport)),
                  sqlite3_column_int64(row, 1) == Int64(try serviceAccountNumber(plan, role: .gateway)),
                  [0, 1].contains(sqlite3_column_int64(row, 2)) else { throw PreparationStoreError.corruptRecord }
            let complete = sqlite3_column_int64(row, 2) == 1
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return .init(plan: plan, complete: complete)
        }
    }
    // Account reservation precedes any key, journal or service creation. Only the authenticated setup owner calls this.
    func beginAccountPreparation(owner: LocalAccountIdentity, allowedTargetUIDs: Set<UInt32>,
                                 disclosureAccepted: Bool, expectedInventoryRevision: Data,
                                 makeInitial: (Data, Data) throws -> AuthorityJournalInitialization) throws -> AccountPreparationIntent {
        return try transaction(write: true) {
            try requireInventorySchema()
            guard let inventory = try loadInventoryRecord(), inventory.revision == expectedInventoryRevision else {
                throw AccountPreparationError.staleRevision
            }
            if try scalar("PRAGMA user_version") >= 4, let retained = try loadAccountPreparation(ownerUID: owner.uid) {
                try LocalAccountDirectory.validateOwnership(owner, uid: retained.ownerUID, directoryID: retained.directoryID)
                guard retained.installationID == inventory.installationID, retained.releaseDigest == inventory.releaseDigest,
                      disclosureAccepted, try retained.commandPolicy.allowedTargetUIDs == allowedTargetUIDs else {
                    throw AccountPreparationError.conflict
                }
                return retained
            }
            guard !inventory.accounts.contains(where: { $0.ownerUID == owner.uid }),
                  try scalar("PRAGMA user_version") < 4 || scalar("SELECT COUNT(*) FROM account_preparation_v1") < 64 else {
                throw AccountPreparationError.conflict
            }
            var accountID = AccountPreparationIntent.randomID()
            while inventory.accounts.contains(where: { $0.accountID == accountID }) { accountID = AccountPreparationIntent.randomID() }
            let policy = try CommandElevationPolicy(macID: macID, accountID: accountID, callerUID: owner.uid,
                allowedTargetUIDs: allowedTargetUIDs, independentPolicyDisclosureAccepted: disclosureAccepted)
            let initial = try makeInitial(macID, accountID)
            let value = try AccountPreparationIntent(setupID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
                macID: macID, installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, accountID: accountID,
                ownerUID: owner.uid, directoryID: owner.directoryID, policyBytes: policy.canonicalBytes, initializationBytes: initial.initializationBytes)
            if try scalar("PRAGMA user_version") == 2 { try upgradeInitializationStorage() }
            if try scalar("PRAGMA user_version") == 3 {
                try exec("CREATE TABLE account_preparation_v1(owner INTEGER PRIMARY KEY CHECK(owner>0 AND owner<4294967295),account BLOB UNIQUE NOT NULL CHECK(length(account)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 147456)) STRICT")
                try exec("PRAGMA user_version=4")
            }
            try statement("INSERT INTO account_preparation_v1 VALUES(?,?,?,?)") { row in
                guard sqlite3_bind_int64(row, 1, Int64(owner.uid)) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
                try bind(accountID, column: 2, row: row); try bind(value.revision, column: 3, row: row)
                try bind(value.bytes, column: 4, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            try identity(macID)
            return value
        }
    }
    func accountPreparation(ownerUID: UInt32) throws -> AccountPreparationIntent? {
        guard ownerUID > 0, ownerUID < UInt32.max else { throw AccountPreparationError.invalidRecord }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 4 { return nil }
            return try loadAccountPreparation(ownerUID: ownerUID)
        }
    }
    func pinAccountPreparation(expected: AccountPreparationIntent, publicKey: Data) throws -> AccountPreparationIntent {
        try changeAccountPreparation(expected: expected) { try $0.pinning(publicKey) }
    }
    func completeAccountPreparation(expected: AccountPreparationIntent) throws -> AccountPreparationIntent {
        try changeAccountPreparation(expected: expected) { current in
            guard let initial = try loadInitialization(accountID: current.accountID) else { throw AccountPreparationError.incomplete }
            return try current.prepared(initialization: initial)
        }
    }
    func validateAccountPreparation(_ expected: AccountPreparationIntent) throws {
        try transaction(write: false) { try requireAccountPreparation(expected) }
    }
    private func requireAccountPreparation(_ expected: AccountPreparationIntent) throws {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 4,
              let current = try loadAccountPreparation(ownerUID: expected.ownerUID) else { throw AccountPreparationError.missing }
        guard current == expected else { throw AccountPreparationError.staleRevision }
        guard let inventory = try loadInventoryRecord(), inventory.installationID == current.installationID,
              inventory.releaseDigest == current.releaseDigest else { throw AccountPreparationError.conflict }
    }
    private func changeAccountPreparation(expected: AccountPreparationIntent,
                                         transform: (AccountPreparationIntent) throws -> AccountPreparationIntent) throws -> AccountPreparationIntent {
        try transaction(write: true) {
            try requireAccountPreparation(expected)
            let value = try transform(expected)
            if value == expected { return expected }
            try statement("UPDATE account_preparation_v1 SET revision=?,record=? WHERE owner=? AND revision=?") { row in
                try bind(value.revision, column: 1, row: row); try bind(value.bytes, column: 2, row: row)
                guard sqlite3_bind_int64(row, 3, Int64(value.ownerUID)) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
                try bind(expected.revision, column: 4, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw AccountPreparationError.staleRevision }
            }
            return value
        }
    }
    private func loadAccountPreparation(ownerUID: UInt32) throws -> AccountPreparationIntent? {
        try statement("SELECT account,revision,record FROM account_preparation_v1 WHERE owner=?") { row in
            guard sqlite3_bind_int64(row, 1, Int64(ownerUID)) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
            if try step(row) == SQLITE_DONE { return nil }
            let value: AccountPreparationIntent
            do { value = try .decode(blob(row, column: 2, maximum: AccountPreparationIntent.maximumBytes)) }
            catch { throw PreparationStoreError.corruptRecord }
            guard value.macID == macID, value.ownerUID == ownerUID,
                  try blob(row, column: 0, maximum: 16) == value.accountID,
                  try blob(row, column: 1, maximum: 16) == value.revision, try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }
    private func upgradeInitializationStorage() throws {
        try exec("CREATE TABLE authority_initialization_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 147456)) STRICT, WITHOUT ROWID")
        try exec("PRAGMA user_version=3")
    }
    private func containsInitializationScope(_ inventory: InstallationInventory, initial: AuthorityJournalInitialization) throws -> Bool {
        if inventory.accounts.contains(where: { $0.accountID == initial.descriptor.accountID }) { return true }
        guard try scalar("PRAGMA user_version") >= 4 else { return false }
        return try statement("SELECT owner FROM account_preparation_v1 WHERE account=?") { row in
            try bind(initial.descriptor.accountID, column: 1, row: row)
            guard try step(row) == SQLITE_ROW, let uid = UInt32(exactly: sqlite3_column_int64(row, 0)),
                  let retained = try loadAccountPreparation(ownerUID: uid) else { return false }
            guard retained.authorityPublicKey != nil, retained.installationID == inventory.installationID,
                  retained.releaseDigest == inventory.releaseDigest,
                  retained.initializationBytes == (try initial.initializationBytes) else { return false }
            return true
        }
    }
    /// Root setup only, after administrator, signed-code and fresh-account checks.
    /// This record is not evidence of those checks. Retained or completed intents cannot be replaced.
    public func beginAuthorityInitialization(initial: AuthorityJournalInitialization, journalPath: String, continuityPath: String,
                                             expectedInventoryRevision: Data) throws -> AuthorityInitializationIntent {
        try requireRoot()
        return try beginInitialization(initial: initial, journalPath: journalPath, continuityPath: continuityPath,
            expectedInventoryRevision: expectedInventoryRevision)
    }
    public func loadAuthorityInitialization(accountID: Data) throws -> AuthorityInitializationIntent? {
        try requireRoot(); return try initialization(accountID: accountID)
    }
    /// Captures the exact pristine journal boundary. A retained boundary cannot be replaced after a crash.
    public func captureAuthorityInitialization(expected: AuthorityInitializationIntent, initial: AuthorityJournalInitialization,
                                               journal: JournalDatabase) throws -> AuthorityInitializationIntent {
        try requireRoot(); return try captureInitialization(expected: expected, initial: initial, journal: journal)
    }
    /// Completion requires both live stores at the retained boundary. It grants no runtime admission.
    public func completeAuthorityInitialization(expected: AuthorityInitializationIntent, journal: JournalDatabase,
                                                continuity: ContinuityStore) throws -> AuthorityInitializationIntent {
        try requireRoot(); return try completeInitialization(expected: expected, journal: journal, continuity: continuity)
    }
    func initialization(accountID: Data) throws -> AuthorityInitializationIntent? {
        guard accountID.count == 16 else { throw AuthorityInitializationError.invalidIntent }
        return try transaction(write: false) {
            try identity(macID)
            if try scalar("PRAGMA user_version") < 3 { return nil }
            return try loadInitialization(accountID: accountID)
        }
    }
    func beginInitialization(initial: AuthorityJournalInitialization, journalPath: String, continuityPath: String,
                             expectedInventoryRevision: Data) throws -> AuthorityInitializationIntent {
        let digest = try initial.initializationDigest
        return try transaction(write: true) {
            try requireInventorySchema()
            guard let inventory = try loadInventoryRecord(), inventory.revision == expectedInventoryRevision,
                  initial.descriptor.macID == macID,
                  try containsInitializationScope(inventory, initial: initial) else {
                throw AuthorityInitializationError.conflictingIntent
            }
            if try scalar("PRAGMA user_version") == 2 {
                try upgradeInitializationStorage()
            }
            guard try loadInitialization(accountID: initial.descriptor.accountID) == nil else {
                throw AuthorityInitializationError.conflictingIntent
            }
            let value = try AuthorityInitializationIntent(setupID: bytes(UUID()), revision: bytes(UUID()),
                installationID: inventory.installationID, macID: macID, accountID: initial.descriptor.accountID,
                releaseDigest: inventory.releaseDigest, initializationDigest: digest, initializationBytes: initial.initializationBytes, journalPath: journalPath, continuityPath: continuityPath)
            try statement("INSERT INTO authority_initialization_v1 VALUES(?,?,?)") { row in
                try bind(value.accountID, column: 1, row: row); try bind(value.revision, column: 2, row: row)
                try bind(value.bytes, column: 3, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            return value
        }
    }
    func captureInitialization(expected: AuthorityInitializationIntent, initial: AuthorityJournalInitialization,
                               journal: JournalDatabase) throws -> AuthorityInitializationIntent {
        guard expected.initializationDigest == (try initial.initializationDigest), expected.macID == initial.descriptor.macID,
              expected.accountID == initial.descriptor.accountID else { throw AuthorityInitializationError.conflictingIntent }
        return try transaction(write: true) {
            try requireInitialization(expected)
            guard !expected.complete else { throw AuthorityInitializationError.completed }
            let checkpoint = try journal.initialAuthorityCheckpoint(initial: initial, databasePath: expected.journalPath)
            if let retained = expected.checkpoint {
                guard retained == checkpoint else { throw AuthorityInitializationError.invalidBoundary }
                return expected
            }
            let value = try expected.advancing(checkpoint: checkpoint, complete: false)
            try saveInitialization(value, expected: expected); return value
        }
    }
    func completeInitialization(expected: AuthorityInitializationIntent, journal: JournalDatabase,
                                continuity: ContinuityStore) throws -> AuthorityInitializationIntent {
        return try transaction(write: true) {
            try requireInitialization(expected)
            guard let checkpoint = expected.checkpoint else { throw AuthorityInitializationError.invalidBoundary }
            try journal.requireInitializationPath(expected.journalPath)
            try continuity.requireInitializationScope(path: expected.continuityPath, mac: expected.macID, account: expected.accountID)
            guard let journalDirectory = try journal.directoryIdentities().last,
                  let continuityDirectory = try continuity.directoryIdentities().last,
                  journalDirectory != continuityDirectory,
                  !(try continuity.directoryIdentities()).contains(journalDirectory),
                  !(try journal.directoryIdentities()).contains(continuityDirectory) else { throw AuthorityInitializationError.invalidBoundary }
            let state = try continuity.read()
            guard !state.recoveryRequired, state.pending == nil, state.committed == checkpoint,
                  try journal.read({ try CheckpointedJournal.checkpoint(transaction: $0, epoch: checkpoint.journalEpoch,
                    generation: 1, authorityGeneration: 1) }) == checkpoint else {
                throw AuthorityInitializationError.invalidBoundary
            }
            if expected.complete { return expected }
            let value = try expected.advancing(checkpoint: checkpoint, complete: true)
            try saveInitialization(value, expected: expected); return value
        }
    }
    // Validate retained scope and revision before each controller storage step.
    func validateInitialization(_ expected: AuthorityInitializationIntent) throws {
        try transaction(write: false) { try requireInitialization(expected) }
    }
    private func requireInitialization(_ expected: AuthorityInitializationIntent) throws {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 3,
              let retained = try loadInitialization(accountID: expected.accountID) else { throw AuthorityInitializationError.missingIntent }
        guard retained == expected else { throw AuthorityInitializationError.staleRevision }
        guard let inventory = try loadInventoryRecord(), inventory.installationID == expected.installationID,
              inventory.releaseDigest == expected.releaseDigest,
              try containsInitializationScope(inventory, initial: expected.initialAuthority) else {
            throw AuthorityInitializationError.conflictingIntent
        }
    }
    private func saveInitialization(_ value: AuthorityInitializationIntent, expected: AuthorityInitializationIntent) throws {
        try statement("UPDATE authority_initialization_v1 SET revision=?,record=? WHERE account=? AND revision=?") { row in
            try bind(value.revision, column: 1, row: row); try bind(value.bytes, column: 2, row: row)
            try bind(value.accountID, column: 3, row: row); try bind(expected.revision, column: 4, row: row)
            guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw AuthorityInitializationError.staleRevision }
        }
    }
    private func loadInitialization(accountID: Data) throws -> AuthorityInitializationIntent? {
        try statement("SELECT revision,record FROM authority_initialization_v1 WHERE account=?") { row in
            try bind(accountID, column: 1, row: row)
            if try step(row) == SQLITE_DONE { return nil }
            let value: AuthorityInitializationIntent
            do { value = try .decode(blob(row, column: 1, maximum: AuthorityInitializationIntent.maximumBytes)) }
            catch { throw PreparationStoreError.corruptRecord }
            guard value.macID == macID, value.accountID == accountID,
                  try blob(row, column: 0, maximum: 16) == value.revision, try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }
    private func configureInventoryLimit() {
        if let db { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, inventoryRecordLimit) }
    }
    private func requireInventorySchema() throws {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 2 else { throw PreparationStoreError.inventoryNotEnabled }
    }
    private func loadInventoryRecord() throws -> InstallationInventory? {
        try statement("SELECT id,installation,revision,record FROM installation_inventory_v1 ORDER BY id") { row in
            let result = try step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
            let value: InstallationInventory
            do { value = try .decode(blob(row, column: 3, maximum: 65_536), expectedMacID: macID) }
            catch { throw PreparationStoreError.corruptRecord }
            guard try blob(row, column: 1, maximum: 16) == value.installationID,
                  try blob(row, column: 2, maximum: 16) == value.revision, try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }
    func records() throws -> [PreparationIntentRecord] { try transaction(write: false) { try loadAll() } }
    func begin(parent: String, ancestry: [PreparationFileIdentity]) throws -> PreparationIntentRecord {
        try transaction(write: true) {
            let retained = try loadAll()
            guard retained.count < maximumRecords, retained.count < 4096 else { throw PreparationStoreError.capacity }
            let value = try PreparationIntentRecord(id: UUID(), revision: UUID(), parent: parent, ancestry: ancestry, phase: .intent)
            try statement("INSERT INTO preparation_intents_v1 VALUES(?,?,?)") { row in
                try bind(bytes(value.id), column: 1, row: row)
                try bind(bytes(value.revision), column: 2, row: row)
                try bind(value.encoded, column: 3, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            return value
        }
    }
    func recordCopy(id: UUID, expectedRevision: UUID, identity: PreparationFileIdentity,
                    digest: Data) throws -> PreparationIntentRecord {
        try change(id: id, expectedRevision: expectedRevision, phase: .copyRecorded, identity: identity, digest: digest)
    }
    func abandon(id: UUID, expectedRevision: UUID) throws -> PreparationIntentRecord {
        try change(id: id, expectedRevision: expectedRevision, phase: .abandoned, identity: nil, digest: nil)
    }
    // Only the Core reconciler calls this after confirming copy absence under the bound destination lease.
    func forgetAbsentAbandoned(id: UUID, expectedRevision: UUID) throws {
        try transaction(write: true) {
            guard let previous = try loadAll().first(where: { $0.id == id }) else { throw PreparationStoreError.notFound }
            guard previous.revision == expectedRevision else { throw PreparationStoreError.staleRevision }
            guard previous.phase == .abandoned else { throw PreparationStoreError.invalidTransition }
            try statement("DELETE FROM preparation_intents_v1 WHERE id=? AND revision=?") { row in
                try bind(bytes(id), column: 1, row: row)
                try bind(bytes(expectedRevision), column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        }
    }
    private func change(id: UUID, expectedRevision: UUID, phase: PreparationRecordPhase,
                        identity: PreparationFileIdentity?, digest: Data?) throws -> PreparationIntentRecord {
        try transaction(write: true) {
            guard let previous = try loadAll().first(where: { $0.id == id }) else { throw PreparationStoreError.notFound }
            guard previous.revision == expectedRevision else { throw PreparationStoreError.staleRevision }
            guard previous.phase != .abandoned,
                  phase == .abandoned || previous.phase == .intent else { throw PreparationStoreError.invalidTransition }
            if phase == .abandoned, try scalar("PRAGMA user_version") >= 15,
               let current = try loadUpdateCandidate(), current.selected, current.preparation.id == id {
                throw PreparationStoreError.invalidTransition
            }
            let value = try PreparationIntentRecord(id: id, revision: UUID(), parent: previous.parent,
                ancestry: previous.ancestry, phase: phase, copyIdentity: identity ?? previous.copyIdentity,
                copyDigest: digest ?? previous.copyDigest)
            try statement("UPDATE preparation_intents_v1 SET revision=?,record=? WHERE id=? AND revision=?") { row in
                try bind(bytes(value.revision), column: 1, row: row)
                try bind(value.encoded, column: 2, row: row)
                try bind(bytes(id), column: 3, row: row)
                try bind(bytes(expectedRevision), column: 4, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
            return value
        }
    }
    /// Explicit storage upgrade. The caller first verifies the installed reader declarations.
    func upgradeUpdateCandidateStorage(expectedInstalledReleaseDigest: Data) throws {
        try transaction(write: true) {
            try identity(macID)
            var version = try scalar("PRAGMA user_version")
            guard version >= 6 else { throw RuntimePreparationError.incomplete }
            guard expectedInstalledReleaseDigest.count == 32, let inventory = try loadInventoryRecord(),
                  inventory.releaseDigest == expectedInstalledReleaseDigest else { throw RuntimePreparationError.changedScope }
            if version >= 15 { _ = try loadUpdateCandidate(); return }
            _ = try loadAll()
            if version < 12 { try upgradeAuditPreparationStorage(); version = try scalar("PRAGMA user_version") }
            if version == 12 {
                try exec("CREATE TABLE runtime_audit_graph_v1(account BLOB NOT NULL CHECK(length(account)=16),attempt BLOB NOT NULL CHECK(length(attempt)=16),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase IN (1,2)),content BLOB NOT NULL CHECK(length(content)=32),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 28672),PRIMARY KEY(account,content)) STRICT, WITHOUT ROWID")
                try exec("CREATE TABLE runtime_audit_graph_chunks_v1(account BLOB NOT NULL CHECK(length(account)=16),content BLOB NOT NULL CHECK(length(content)=32),part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 511),bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 16384),PRIMARY KEY(account,content,part)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=13"); version = 13
            }
            if version == 13 {
                try exec("CREATE TABLE runtime_audit_cutover_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),attempt BLOB NOT NULL CHECK(length(attempt)=16),content BLOB NOT NULL CHECK(length(content)=32),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 4),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 30720)) STRICT, WITHOUT ROWID")
                try exec("PRAGMA user_version=14"); version = 14
            }
            guard version == 14 else { throw PreparationStoreError.incompatibleStore }
            try exec("CREATE TABLE update_scheduling_candidate_v1(id INTEGER PRIMARY KEY CHECK(id=1),generation BLOB NOT NULL CHECK(length(generation)=8),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 32768)) STRICT")
            try exec("PRAGMA user_version=15")
            try identity(macID)
        }
    }
    func updateCandidate() throws -> UpdateSchedulingCandidateRecord? {
        try transaction(write: false) {
            try identity(macID)
            return try scalar("PRAGMA user_version") >= 15 ? loadUpdateCandidate() : nil
        }
    }
    func selectUpdateCandidate(preparation: PreparationIntentRecord, runtime: RuntimeReleaseCompatibilitySnapshot.Inputs,
                               replacing expected: UpdateSchedulingCandidateRecord?) throws -> UpdateSchedulingCandidateRecord {
        try transaction(write: true) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 15 else { throw PreparationStoreError.incompatibleStore }
            guard try loadRetainedRuntimeCompatibilityInputs() == runtime,
                  let inventory = try loadInventoryRecord(), inventory.macID == macID,
                  preparation.phase == .copyRecorded,
                  try loadAll().first(where: { $0.id == preparation.id }) == preparation else {
                throw RuntimePreparationError.changedScope
            }
            let previous = try loadUpdateCandidate()
            guard previous == expected else { throw PreparationStoreError.staleRevision }
            if let previous, previous.selected, previous.preparation == preparation,
               previous.inventoryRevision == inventory.revision, previous.installationID == inventory.installationID {
                return previous
            }
            guard previous?.generation != UInt64.max else { throw RuntimePreparationError.exhausted }
            let value = try UpdateSchedulingCandidateRecord(macID: macID, installationID: inventory.installationID,
                inventoryRevision: inventory.revision, preparation: preparation, generation: (previous?.generation ?? 0) + 1)
            try writeUpdateCandidate(value, replacing: previous)
            return value
        }
    }
    /// The callback cannot retain machine authority after this synchronous boundary ends.
    func withSelectedUpdateCandidate<Value>(_ expected: UpdateSchedulingCandidateRecord,
        runtime: RuntimeReleaseCompatibilitySnapshot.Inputs, _ body: () throws -> Value) throws -> Value {
        try withValidatedUpdateCandidate(expected, runtime: runtime) { _ in try body() }
    }

    /// Holds the sole machine writer while the account owner commits. Callbacks cannot await or reenter this store.
    func withValidatedUpdateCandidate<Value>(_ expected: UpdateSchedulingCandidateRecord,
        runtime: RuntimeReleaseCompatibilitySnapshot.Inputs, _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try transaction(write: false) {
            var scopeActive = true
            let processID = getpid()
            defer { scopeActive = false }
            let requireCurrent: () throws -> Void = { [weak self] in
                guard scopeActive, getpid() == processID, let self else { throw UpdateSchedulingCandidateLeaseError.expired }
                try self.lease.validate()
                try self.identity(self.macID)
                guard try self.scalar("PRAGMA user_version") >= 15, expected.selected,
                      try self.loadUpdateCandidate() == expected,
                      try self.loadRetainedRuntimeCompatibilityInputs() == runtime,
                      let inventory = try self.loadInventoryRecord(), expected.macID == self.macID,
                      expected.installationID == inventory.installationID, expected.inventoryRevision == inventory.revision,
                      try self.loadAll().first(where: { $0.id == expected.preparation.id }) == expected.preparation else {
                    throw PreparationStoreError.staleRevision
                }
            }
            try requireCurrent()
            let value = try body(requireCurrent)
            try requireCurrent()
            return value
        }
    }
    /// Withdraws a candidate only. It does not cancel a drain, restore admission or undo activation.
    func retireUpdateCandidate(_ expected: UpdateSchedulingCandidateRecord) throws -> UpdateSchedulingCandidateRecord {
        try transaction(write: true) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 15, try loadUpdateCandidate() == expected else {
                throw PreparationStoreError.staleRevision
            }
            if !expected.selected { return expected }
            let value = try UpdateSchedulingCandidateRecord(macID: expected.macID, installationID: expected.installationID,
                inventoryRevision: expected.inventoryRevision, preparation: expected.preparation,
                generation: expected.generation, selected: false)
            try writeUpdateCandidate(value, replacing: expected)
            return value
        }
    }
    private func writeUpdateCandidate(_ value: UpdateSchedulingCandidateRecord,
                                      replacing old: UpdateSchedulingCandidateRecord?) throws {
        if let old {
            try statement("UPDATE update_scheduling_candidate_v1 SET generation=?,revision=?,record=? WHERE id=1 AND revision=?") { row in
                try bind(candidateGeneration(value.generation), column: 1, row: row)
                try bind(bytes(value.revision), column: 2, row: row); try bind(value.encoded, column: 3, row: row)
                try bind(bytes(old.revision), column: 4, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        } else {
            try statement("INSERT INTO update_scheduling_candidate_v1 VALUES(1,?,?,?)") { row in
                try bind(candidateGeneration(value.generation), column: 1, row: row)
                try bind(bytes(value.revision), column: 2, row: row); try bind(value.encoded, column: 3, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
        }
    }
    private func loadUpdateCandidate() throws -> UpdateSchedulingCandidateRecord? {
        try statement("SELECT id,generation,revision,record FROM update_scheduling_candidate_v1") { row in
            guard try step(row) == SQLITE_ROW else { return nil }
            guard sqlite3_column_type(row, 0) == SQLITE_INTEGER, sqlite3_column_int64(row, 0) == 1 else {
                throw PreparationStoreError.corruptRecord
            }
            let generation = try blob(row, column: 1, maximum: 8)
            let revision = try blob(row, column: 2, maximum: 16)
            let record = try blob(row, column: 3, maximum: UpdateSchedulingCandidateRecord.maximumBytes)
            let value = try UpdateSchedulingCandidateRecord.decode(record)
            guard generation.count == 8, generation == candidateGeneration(value.generation),
                  revision == bytes(value.revision), value.macID == macID, try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }
    private func candidateGeneration(_ value: UInt64) -> Data {
        var bytes = value.bigEndian
        return withUnsafeBytes(of: &bytes) { Data($0) }
    }

    /// Explicit storage upgrade. It leaves the inventory, selected copy and existing work unchanged.
    func upgradeUpdateAdmissionStorage(expectedInstalledReleaseDigest: Data) throws {
        if try retainedRuntimeCompatibilityInputs().schemaVersion < 15 {
            try upgradeUpdateCandidateStorage(expectedInstalledReleaseDigest: expectedInstalledReleaseDigest)
        }
        try transaction(write: true) {
            try identity(macID)
            guard let inventory = try loadInventoryRecord(), inventory.releaseDigest == expectedInstalledReleaseDigest else {
                throw RuntimePreparationError.changedScope
            }
            let version = try scalar("PRAGMA user_version")
            if version >= 16 { _ = try loadUpdateAdmissionRegistration(); return }
            guard version == 15 else { throw PreparationStoreError.incompatibleStore }
            _ = try loadAll(); _ = try loadUpdateCandidate()
            try exec("CREATE TABLE update_admission_registration_v1(id INTEGER PRIMARY KEY CHECK(id=1),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 32768)) STRICT")
            try exec("PRAGMA user_version=16"); try identity(macID)
        }
    }

    func updateAdmissionRegistration() throws -> UpdateAdmissionRegistrationRecord? {
        try transaction(write: false) {
            try identity(macID)
            return try scalar("PRAGMA user_version") >= 16 ? loadUpdateAdmissionRegistration() : nil
        }
    }

    /// Stores exact references under the machine writer. The caller must validate the actual files before and after the write.
    func retainUpdateAdmissionRegistration(_ value: UpdateAdmissionRegistrationRecord, replacing expected: UpdateAdmissionRegistrationRecord?,
        runtime: RuntimeReleaseCompatibilitySnapshot.Inputs, verifyFiles: () throws -> Void) throws -> UpdateAdmissionRegistrationRecord {
        try transaction(write: true) {
            try retainUpdateAdmissionRegistrationInTransaction(value, replacing: expected, runtime: runtime, verifyFiles: verifyFiles)
        }
    }

    func validateUpdateAdmissionDirectory(_ directory: ReleaseDestinationLease) throws {
        try validateStorageLease(); try requireUpdateAdmissionDirectory(directory)
    }

    /// Retains the machine writer through provisioning, validation and commit. The scoped callback cannot outlive preparation.
    func prepareUpdateAdmissionRegistration(directory: ReleaseDestinationLease, replacing expected: UpdateAdmissionRegistrationRecord?,
        runtime: RuntimeReleaseCompatibilitySnapshot.Inputs,
        prepare: (UpdateAdmissionRegistrationRecord?, _ validate: @escaping () throws -> Void) throws -> UpdateAdmissionRegistrationRecord,
        verifyFiles: (UpdateAdmissionRegistrationRecord) throws -> Void) throws -> UpdateAdmissionRegistrationRecord {
        let value = try transaction(write: true) {
            try identity(macID); try requireUpdateAdmissionDirectory(directory)
            guard try scalar("PRAGMA user_version") >= 16 else { throw PreparationStoreError.incompatibleStore }
            guard try loadRetainedRuntimeCompatibilityInputs() == runtime,
                  try loadUpdateAdmissionRegistration() == expected else { throw PreparationStoreError.staleRevision }
            var preparing = true
            let processID = getpid()
            let validate: () throws -> Void = { [weak self] in
                guard preparing, getpid() == processID, let self, self.active else { throw JournalLeaseError.invalidated }
                try self.identity(self.macID); try self.requireUpdateAdmissionDirectory(directory)
                guard try self.loadRetainedRuntimeCompatibilityInputs() == runtime,
                      try self.loadUpdateAdmissionRegistration() == expected else { throw PreparationStoreError.staleRevision }
            }
            let prepared: UpdateAdmissionRegistrationRecord
            do {
                defer { preparing = false }
                try validate(); prepared = try prepare(expected, validate); try validate()
            }
            return try retainUpdateAdmissionRegistrationInTransaction(prepared, replacing: expected, runtime: runtime) {
                try self.requireUpdateAdmissionDirectory(directory); try verifyFiles(prepared)
            }
        }
        do {
            return try transaction(write: false) {
                try identity(macID); try requireUpdateAdmissionDirectory(directory)
                guard try loadUpdateAdmissionRegistration() == value else { throw PreparationStoreError.staleRevision }
                try verifyFiles(value); try requireUpdateAdmissionDirectory(directory)
                guard try loadUpdateAdmissionRegistration() == value else { throw PreparationStoreError.staleRevision }
                return value
            }
        } catch {
            unavailable = true; shutdown(); throw error
        }
    }

    private func requireUpdateAdmissionDirectory(_ directory: ReleaseDestinationLease) throws {
        try lease.validate()
        guard let held = try lease.directoryIdentities().last,
              let target = try directory.preparationAncestry().last,
              UInt32(bitPattern: held.device) == target.device, held.inode == target.inode else {
            throw RuntimePreparationError.changedScope
        }
    }

    private func retainUpdateAdmissionRegistrationInTransaction(_ value: UpdateAdmissionRegistrationRecord,
        replacing expected: UpdateAdmissionRegistrationRecord?, runtime: RuntimeReleaseCompatibilitySnapshot.Inputs,
        verifyFiles: () throws -> Void) throws -> UpdateAdmissionRegistrationRecord {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 16 else { throw PreparationStoreError.incompatibleStore }
        guard try loadRetainedRuntimeCompatibilityInputs() == runtime,
              let inventory = try loadInventoryRecord(), value.macID == macID, value.installationID == inventory.installationID else {
            throw RuntimePreparationError.changedScope
        }
        let previous = try loadUpdateAdmissionRegistration()
        guard previous == expected else { throw PreparationStoreError.staleRevision }
        _ = try value.encoded
        if let previous {
            guard value.machine == previous.machine,
                  previous.accounts.allSatisfy({ value.accounts.contains($0) }),
                  previous.designatedOwner == nil || value.designatedOwner == previous.designatedOwner else {
                throw PreparationStoreError.invalidTransition
            }
        }
        let added = value.accounts.filter { !(previous?.accounts.contains($0) ?? false) }
        guard added.allSatisfy({ reference in inventory.accounts.contains { $0.accountID == reference.accountID } }),
              value.designatedOwner == previous?.designatedOwner ||
                inventory.accounts.contains(where: { $0.accountID == value.designatedOwner }) else {
            throw RuntimePreparationError.changedScope
        }
        try verifyFiles()
        if value == previous { try verifyFiles(); return value }
        guard value.revision != previous?.revision else { throw PreparationStoreError.staleRevision }
        if let previous {
            try statement("UPDATE update_admission_registration_v1 SET revision=?,record=? WHERE id=1 AND revision=?") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                try bind(bytes(previous.revision), column: 3, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        } else {
            try statement("INSERT INTO update_admission_registration_v1 VALUES(1,?,?)") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
        }
        try verifyFiles(); return value
    }

    private func loadUpdateAdmissionRegistration() throws -> UpdateAdmissionRegistrationRecord? {
        try statement("SELECT id,revision,record FROM update_admission_registration_v1 ORDER BY id") { row in
            let result = try step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
            let value = try UpdateAdmissionRegistrationRecord.decode(blob(row, column: 2, maximum: UpdateAdmissionRegistrationRecord.maximumBytes))
            guard value.macID == macID, let inventory = try loadInventoryRecord(), value.installationID == inventory.installationID,
                  try blob(row, column: 1, maximum: 16) == bytes(value.revision), try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }

    func upgradeMachineUpdateActivationStorage(expectedInstalledReleaseDigest: Data) throws {
        try transaction(write: true, activationWrite: true) {
            try identity(macID)
            guard let inventory = try loadInventoryRecord(), inventory.releaseDigest == expectedInstalledReleaseDigest else {
                throw RuntimePreparationError.changedScope
            }
            let version = try scalar("PRAGMA user_version")
            if version >= 17 { _ = try loadMachineUpdateActivation(); return }
            guard version == 16 else { throw PreparationStoreError.incompatibleStore }
            try exec("CREATE TABLE machine_update_activation_v1(id INTEGER PRIMARY KEY CHECK(id=1),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)) STRICT")
            try exec("PRAGMA user_version=17"); try identity(macID)
        }
    }

    /// Reads the admission scope and phase together without upgrading or writing machine metadata.
    func updateAdmissionState() throws -> MachineUpdateAdmissionState {
        try transaction(write: false) {
            try identity(macID)
            let schema = try scalar("PRAGMA user_version")
            return try .init(inventory: schema >= 2 ? loadInventoryRecord() : nil,
                registration: schema >= 16 ? loadUpdateAdmissionRegistration() : nil,
                activation: schema >= 17 ? loadMachineUpdateActivation() : nil)
        }
    }

    func machineUpdateActivation() throws -> MachineUpdateActivationRecord? {
        try transaction(write: false) {
            try identity(macID)
            return try scalar("PRAGMA user_version") >= 17 ? loadMachineUpdateActivation() : nil
        }
    }

    /// Retains a phase only. The live file boundary and current copy validation remain separate requirements.
    func beginMachineUpdateActivation(candidate: UpdateSchedulingCandidateRecord,
        registration: UpdateAdmissionRegistrationRecord, runtime: RuntimeReleaseCompatibilitySnapshot.Inputs,
        replacing previous: MachineUpdateActivationRecord?, directory: ReleaseDestinationLease,
        drain: UpdateAdmissionDrain, verifyCurrent: () throws -> Void) throws -> MachineUpdateActivationRecord {
        try withoutActuallyEscaping(verifyCurrent) { verifyCurrent in
            try drain.withClosedAdmission {
                let verify = { try drain.validateMachineBoundary(directory: directory, expected: registration.machine); try verifyCurrent() }
                let value = try transaction(write: true, activationWrite: true) {
                    try identity(macID); try requireUpdateAdmissionDirectory(directory)
                    guard try scalar("PRAGMA user_version") >= 17, try loadRetainedRuntimeCompatibilityInputs() == runtime,
                          try loadMachineUpdateActivation() == previous,
                          previous?.phase.blocksMachineWrites != true,
                          try loadUpdateCandidate() == candidate, try loadUpdateAdmissionRegistration() == registration,
                          try loadAll().first(where: { $0.id == candidate.preparation.id }) == candidate.preparation,
                          let inventory = try loadInventoryRecord() else { throw PreparationStoreError.staleRevision }
                    try verify()
                    let value = try MachineUpdateActivationRecord(candidate: candidate, inventory: inventory, admission: registration)
                    try writeMachineUpdateActivation(value, replacing: previous); try verify(); return value
                }
                return try finishMachineUpdateMutation(value, verify: verify)
            }
        }
    }

    func cancelMachineUpdateActivation(_ expected: MachineUpdateActivationRecord, directory: ReleaseDestinationLease,
        drain: UpdateAdmissionDrain, verifyCurrent: () throws -> Void) throws -> MachineUpdateActivationRecord {
        _ = try expected.advancing(to: .cancelled)
        return try drain.withClosedAdmission {
            try advanceMachineUpdateActivation(expected, to: .cancelled, directory: directory, verify: {
                try drain.validateMachineBoundary(directory: directory, expected: expected.machineAdmission); try verifyCurrent()
            })
        }
    }

    func cancelMachineUpdateActivation(_ expected: MachineUpdateActivationRecord, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verifyCurrent: () throws -> Void) throws -> MachineUpdateActivationRecord {
        _ = try expected.advancing(to: .cancelled)
        return try quiescence.withExclusiveActivity { _ in
            try advanceMachineUpdateActivation(expected, to: .cancelled, directory: directory, verify: {
                try quiescence.validateMachineBoundary(directory: directory, expected: expected.machineAdmission); try verifyCurrent()
            })
        }
    }

    func machineUpdatePolicyPreflightSource(_ activation: MachineUpdateActivationRecord,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease) throws -> MachineUpdateRestartSource {
        guard activation.phase == .draining else { throw MachineUpdateReplacementError.wrongPhase }
        return try transaction(write: false) {
            try requireUpdateAdmissionDirectory(directory)
            let source = try loadMachineUpdatePolicyPreflightSource(activation)
            try quiescence.validateMachineBoundary(directory: directory, expected: source.replacement.admission.machine)
            return source
        }
    }
    private func loadMachineUpdatePolicyPreflightSource(_ activation: MachineUpdateActivationRecord) throws -> MachineUpdateRestartSource {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 17, try loadMachineUpdateActivation() == activation,
              activation.phase == .draining || activation.phase == .activationStarted,
              let inventory = try loadInventoryRecord(), let candidate = try loadUpdateCandidate(),
              let admission = try loadUpdateAdmissionRegistration() else { throw PreparationStoreError.staleRevision }
        try activation.requireScope(candidate: candidate, inventory: inventory, admission: admission)
        let runtime = try loadRetainedRuntimeCompatibilityInputs()
        let context = MachineUpdateReplacementContext(activation: activation, inventory: inventory, candidate: candidate,
            admission: admission, replacement: nil, runtime: runtime)
        let accounts = try loadMachineUpdateAccounts(context)
        // These schemas cannot contain an installed-release archive. Later readers must load its exact history.
        guard try [Int64(17), 18, 19, 20, 21, 22].contains(scalar("PRAGMA user_version")) else { throw PreparationStoreError.incompatibleStore }
        let history: MachineUpdateProvisioningHistory? = nil
        return .init(replacement: context, accounts: accounts, provisioningHistory: history)
    }

    /// Every new irreversible marker binds a live all-account policy preflight before replacement begins.
    /// Enable storage schema 18 first: at schema 17 a started attempt can neither swap nor reach restart checking, and it is too late to cancel.
    func markMachineUpdateActivationStarted(_ expected: MachineUpdateActivationRecord,
        preflight: MachineUpdatePolicyPreflight, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verifyCurrent: () throws -> Void) throws -> MachineUpdateActivationRecord {
        guard preflight.source.replacement.activation == expected else { throw PreparationStoreError.staleRevision }
        let next = try expected.starting(policyPreflightDigest: preflight.digest)
        let nextSource = try preflight.source.replacingActivation(next)
        return try quiescence.withExclusiveActivity { _ in
            func external() throws {
                try quiescence.validateMachineBoundary(directory: directory, expected: expected.machineAdmission)
                try preflight.validateExternal(); try verifyCurrent()
            }
            let value = try transaction(write: true, activationWrite: true) {
                try requireUpdateAdmissionDirectory(directory)
                guard try loadMachineUpdatePolicyPreflightSource(expected) == preflight.source else { throw PreparationStoreError.staleRevision }
                try external(); try writeMachineUpdateActivation(next, replacing: expected)
                guard try loadMachineUpdatePolicyPreflightSource(next) == nextSource else { throw PreparationStoreError.staleRevision }
                try external(); return next
            }
            return try finishMachineUpdateMutation(value, verify: {
                guard try self.loadMachineUpdatePolicyPreflightSource(next) == nextSource else { throw PreparationStoreError.staleRevision }
                try external()
            })
        }
    }

    func markMachineUpdateRestartChecking(_ expected: MachineUpdateActivationRecord, directory: ReleaseDestinationLease,
        restart: UpdateRestartAdmissionLease, verifyCurrent: () throws -> Void) throws -> MachineUpdateActivationRecord {
        try restart.withClosedAdmission {
            // Restart checking follows the observed swap of this attempt. Without it the attempt could neither swap nor cancel.
            try advanceMachineUpdateActivation(expected, to: .restartChecking, directory: directory, require: {
                guard try self.scalar("PRAGMA user_version") >= 18, let replacement = try self.loadMachineUpdateReplacement(),
                      replacement.phase == .observed, replacement.activationAttempt == expected.attemptID else {
                    throw PreparationStoreError.invalidTransition
                }
            }, verify: {
                try restart.validateMachineBoundary(directory: directory, expected: expected.machineAdmission); try verifyCurrent()
            })
        }
    }

    private func advanceMachineUpdateActivation(_ expected: MachineUpdateActivationRecord, to phase: MachineUpdateActivationRecord.Phase,
        directory: ReleaseDestinationLease, require: () throws -> Void = {},
        verify: () throws -> Void) throws -> MachineUpdateActivationRecord {
        let next = try expected.advancing(to: phase)
        let result = try transaction(write: true, activationWrite: true) {
            try identity(macID); try requireUpdateAdmissionDirectory(directory)
            guard try scalar("PRAGMA user_version") >= 17, try loadMachineUpdateActivation() == expected else {
                throw PreparationStoreError.staleRevision
            }
            try require(); try verify(); try writeMachineUpdateActivation(next, replacing: expected); try verify(); return next
        }
        return try finishMachineUpdateMutation(result, verify: verify)
    }

    private func finishMachineUpdateMutation(_ expected: MachineUpdateActivationRecord,
        verify: () throws -> Void) throws -> MachineUpdateActivationRecord {
        do {
            return try transaction(write: false) {
                guard try loadMachineUpdateActivation() == expected else { throw PreparationStoreError.staleRevision }
                try verify(); return expected
            }
        } catch { unavailable = true; shutdown(); throw error }
    }

    private func loadMachineUpdateActivationRecord() throws -> MachineUpdateActivationRecord? {
        try statement("SELECT id,revision,record FROM machine_update_activation_v1 ORDER BY id") { row in
            let rc = try step(row); if rc == SQLITE_DONE { return nil }
            guard sqlite3_column_type(row, 0) == SQLITE_INTEGER, sqlite3_column_int64(row, 0) == 1 else {
                throw PreparationStoreError.corruptRecord
            }
            let record = try blob(row, column: 2, maximum: MachineUpdateActivationRecord.maximumBytes)
            let value = try MachineUpdateActivationRecord.decode(record)
            guard value.macID == macID, try blob(row, column: 1, maximum: 16) == bytes(value.revision),
                  try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return value
        }
    }

    private func loadMachineUpdateActivation() throws -> MachineUpdateActivationRecord? {
        guard let value = try loadMachineUpdateActivationRecord() else { return nil }
        guard value.phase != .completed else { throw PreparationStoreError.incompatibleStore }
        if value.phase.blocksMachineWrites {
            guard let inventory = try loadInventoryRecord(), let candidate = try loadUpdateCandidate(),
                  let admission = try loadUpdateAdmissionRegistration(),
                  try loadAll().first(where: { $0.id == candidate.preparation.id }) == candidate.preparation else {
                throw PreparationStoreError.corruptRecord
            }
            do {
                if value.phase == .finishing {
                    try requireFinishingActivation(value, inventory: inventory, candidate: candidate, admission: admission)
                } else {
                    try value.requireScope(candidate: candidate, inventory: inventory, admission: admission)
                }
            } catch { throw PreparationStoreError.corruptRecord }
        }
        return value
    }

    private func writeMachineUpdateActivation(_ value: MachineUpdateActivationRecord,
        replacing previous: MachineUpdateActivationRecord?, allowFinishing: Bool = false) throws {
        guard value.phase != .completed else { throw PreparationStoreError.invalidTransition }
        if value.phase == .finishing {
            guard allowFinishing, let previous else { throw PreparationStoreError.invalidTransition }
            try value.requireFinalizationSource(previous)
        }
        if let previous {
            try statement("UPDATE machine_update_activation_v1 SET revision=?,record=? WHERE id=1 AND revision=?") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                try bind(bytes(previous.revision), column: 3, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        } else {
            try statement("INSERT INTO machine_update_activation_v1 VALUES(1,?,?)") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
        }
    }

    private func loadAccountPreparations() throws -> [AccountPreparationIntent] {
        try statement("SELECT owner FROM account_preparation_v1 ORDER BY owner LIMIT 65") { row in
            var values: [AccountPreparationIntent] = []
            while try step(row) == SQLITE_ROW {
                guard values.count < 64, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                      let owner = UInt32(exactly: sqlite3_column_int64(row, 0)),
                      let account = try loadAccountPreparation(ownerUID: owner) else { throw PreparationStoreError.corruptRecord }
                values.append(account)
            }
            return values
        }
    }

    private func loadMachineUpdateAccounts(_ context: MachineUpdateReplacementContext) throws -> [MachineUpdateRestartSource.Account] {
        let reservations = try loadAccountPreparations()
        var owners = Dictionary(uniqueKeysWithValues: context.inventory.accounts.map { ($0.accountID, $0.ownerUID) })
        for account in reservations {
            guard account.macID == context.inventory.macID, account.installationID == context.inventory.installationID,
                  owners[account.accountID] == nil || owners[account.accountID] == account.ownerUID,
                  !owners.contains(where: { $0.key != account.accountID && $0.value == account.ownerUID }) else {
                throw RuntimePreparationError.changedScope
            }
            owners[account.accountID] = account.ownerUID
        }
        let accounts = try owners.keys.sorted { $0.lexicographicallyPrecedes($1) }.map { id -> MachineUpdateRestartSource.Account in
            let owner = owners[id]!
            let preparation = reservations.first { $0.accountID == id }
            let initial = try loadInitialization(accountID: id)
            let services = try loadServiceAccountPlan(accountID: id)
            if let initial {
                guard initial.macID == macID, initial.accountID == id,
                      initial.installationID == context.inventory.installationID else { throw RuntimePreparationError.changedScope }
            }
            if let preparation, let initial {
                guard initial.releaseDigest == preparation.releaseDigest,
                      initial.initializationBytes == preparation.initializationBytes else { throw RuntimePreparationError.changedScope }
            }
            if let plan = services.plan {
                guard plan.macID == macID, plan.accountID == id, plan.ownerUID == owner,
                      plan.installationID == context.inventory.installationID else { throw RuntimePreparationError.changedScope }
                if let preparation { try plan.validate(account: preparation) }
            }
            return .init(accountID: id, ownerUID: owner, preparation: preparation, initialization: initial,
                services: services.plan, servicesComplete: services.complete)
        }
        let ids = Set(accounts.map(\.accountID))
        guard context.runtime.runtimes.allSatisfy({ ids.contains($0.reference.services.accountID) }),
              context.runtime.gateways.allSatisfy({ ids.contains($0.accountID) }) else { throw RuntimePreparationError.changedScope }
        return accounts
    }

    func upgradeMachineUpdateReplacementStorage(expectedInstalledReleaseDigest: Data) throws {
        try transaction(write: true, activationWrite: true) {
            try identity(macID)
            guard let inventory = try loadInventoryRecord(), inventory.releaseDigest == expectedInstalledReleaseDigest else {
                throw RuntimePreparationError.changedScope
            }
            let version = try scalar("PRAGMA user_version")
            if version >= 18 { _ = try loadMachineUpdateReplacement(); return }
            guard version == 17 else { throw PreparationStoreError.incompatibleStore }
            guard try loadMachineUpdateActivation()?.phase.blocksMachineWrites != true else { throw PreparationStoreError.invalidTransition }
            try exec("CREATE TABLE machine_update_replacement_v1(id INTEGER PRIMARY KEY CHECK(id=1),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT")
            try exec("PRAGMA user_version=18"); try identity(macID)
        }
    }

    func upgradeMachineUpdateConfigurationEpochStorage(expectedInstalledReleaseDigest: Data) throws {
        try transaction(write: true, activationWrite: true) {
            try identity(macID)
            guard let inventory = try loadInventoryRecord(), inventory.releaseDigest == expectedInstalledReleaseDigest else {
                throw RuntimePreparationError.changedScope
            }
            let version = try scalar("PRAGMA user_version")
            if version >= 19 { _ = try loadMachineUpdateConfigurationEpoch(); return }
            guard version == 18 else { throw PreparationStoreError.incompatibleStore }
            guard try loadMachineUpdateActivation()?.phase.blocksMachineWrites != true else { throw PreparationStoreError.invalidTransition }
            try createConfigurationEpochStorage()
        }
    }

    private func createConfigurationEpochStorage() throws {
        try exec("CREATE TABLE machine_update_configuration_epoch_v1(kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 9),account BLOB NOT NULL CHECK(length(account)=CASE WHEN kind IN(0,5,6,7,8,9) THEN 1 ELSE 16 END),epoch BLOB NOT NULL CHECK(length(epoch)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262400),PRIMARY KEY(kind,account)) STRICT")
        try exec("PRAGMA user_version=19"); try identity(macID)
    }

    /// The selected installed candidate owns this irreversible migration. The old release need not advertise the new archive.
    func upgradeConfigurationEpochForInstalledRecovery(expected: MachineUpdateRestartSource, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        verifyCurrent: () throws -> Void) throws -> MachineUpdateRestartSource {
        try quiescence.withExclusiveActivity { _ in
            try transaction(write: true, activationWrite: true) {
                try identity(macID)
                guard try loadMachineUpdateRestartSource(expected.replacement.activation) == expected,
                      expected.replacement.activation.phase.irreversible, expected.replacement.replacement?.phase == .observed,
                      try DurableReleasePreparation.digest(candidate) == expected.replacement.activation.updateID else {
                    throw PreparationStoreError.staleRevision
                }
                try MachineUpdateConfigurationEpoch.requireArchiveFormats(candidate)
                try requireUpdateAdmissionDirectory(directory)
                try quiescence.validateMachineBoundary(directory: directory, expected: expected.replacement.admission.machine)
                try verifyCurrent()
                let schema = try scalar("PRAGMA user_version")
                guard schema == 18 || schema == 19 else { throw PreparationStoreError.incompatibleStore }
                if schema == 18 { try createConfigurationEpochStorage() }
                try verifyCurrent()
                try quiescence.validateMachineBoundary(directory: directory, expected: expected.replacement.admission.machine)
            }
            return try transaction(write: false) {
                try verifyCurrent(); try requireUpdateAdmissionDirectory(directory)
                let current = try loadMachineUpdateRestartSource(expected.replacement.activation)
                guard current.accounts == expected.accounts, current.replacement.inventory == expected.replacement.inventory,
                      current.replacement.candidate == expected.replacement.candidate, current.replacement.admission == expected.replacement.admission,
                      current.replacement.replacement == expected.replacement.replacement else { throw PreparationStoreError.staleRevision }
                try quiescence.validateMachineBoundary(directory: directory, expected: current.replacement.admission.machine)
                try verifyCurrent(); return current
            }
        }
    }

    /// Reads retained bytes only. Callers must acquire fresh native and account capabilities before using them.
    func machineUpdateConfigurationEpoch() throws -> MachineUpdateConfigurationEpoch.Archive? {
        try transaction(write: false) {
            try identity(macID)
            return try scalar("PRAGMA user_version") >= 19 ? loadMachineUpdateConfigurationEpoch() : nil
        }
    }

    func retainMachineUpdateConfigurationEpoch(expected: MachineUpdateRestartSource,
        replacing previous: MachineUpdateConfigurationEpochRecord? = nil,
        candidate: SignedReleaseEvidence, policies: [MachineUpdateConfigurationEpoch.PolicyCapture],
        configurations: [MachineUpdateConfigurationEpoch.Configuration], directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verifyCurrent: () throws -> Void) throws -> MachineUpdateConfigurationEpochRecord {
        try quiescence.withExclusiveActivity { _ in
            let value = try transaction(write: true, activationWrite: true) {
                try identity(macID)
                guard try scalar("PRAGMA user_version") == 19,
                      try loadMachineUpdateRestartSource(expected.replacement.activation) == expected else { throw PreparationStoreError.staleRevision }
                try requireUpdateAdmissionDirectory(directory)
                try quiescence.validateMachineBoundary(directory: directory, expected: expected.replacement.admission.machine)
                try verifyCurrent()
                let existing = try loadMachineUpdateConfigurationEpoch()
                guard existing?.record == previous else { throw PreparationStoreError.staleRevision }
                for policy in policies.compactMap(\.snapshot) {
                    try ReleaseCompatibilityPreflight.validate(candidate, policy: policy.policy,
                        requirements: .init(formats: MachineUpdateConfigurationEpochRecord.requirements, requests: []))
                }
                let record = try MachineUpdateConfigurationEpochRecord(id: previous?.id ?? UUID(), revision: previous?.revision ?? UUID(),
                    source: expected, candidate: candidate, sourceMachineDigest: machineEpochSourceDigest(), policies: policies, configurations: configurations)
                let provenance = try MachineUpdateConfigurationEpoch.provisioningHistory(source: expected, candidate: candidate)
                let artifacts = try MachineUpdateConfigurationEpoch.artifacts(source: expected, policies: policies,
                    configurations: configurations, provenance: provenance)
                let archive = MachineUpdateConfigurationEpoch.Archive(record: record, artifacts: artifacts); try archive.validate()
                if let existing {
                    guard existing.record == record, existing.artifacts == artifacts else { throw PreparationStoreError.staleRevision }
                } else {
                    for item in [MachineUpdateConfigurationEpoch.Artifact(kind: 0, account: MachineUpdateConfigurationEpoch.global, bytes: try record.encoded)] + artifacts {
                        try statement("INSERT INTO machine_update_configuration_epoch_v1 VALUES(?,?,?,?,?)") { row in
                            try bind(item.kind, column: 1, row: row); try bind(item.account, column: 2, row: row)
                            try bind(bytes(record.id), column: 3, row: row); try bind(bytes(record.revision), column: 4, row: row)
                            try bind(item.bytes, column: 5, row: row)
                            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                        }
                    }
                }
                try requireCurrentConfigurationEpoch(record, directory: directory, quiescence: quiescence)
                try verifyCurrent(); return record
            }
            // Unknown commit acknowledgements leave the connection unavailable. Reopen and read the retained archive.
            return try transaction(write: false) {
                try requireCurrentConfigurationEpoch(value, directory: directory, quiescence: quiescence)
                try verifyCurrent()
                try requireCurrentConfigurationEpoch(value, directory: directory, quiescence: quiescence)
                return value
            }
        }
    }

    /// The native owner verifies actual files against the proposed durable state before and after its commit.
    func advanceMachineUpdatePublication(_ expected: MachineUpdateConfigurationEpochRecord,
        operation: MachineUpdatePublicationOperation, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verifyCurrent: (MachineUpdateConfigurationEpochRecord) throws -> Void) throws -> MachineUpdateConfigurationEpochRecord {
        try MachineUpdateConfigurationEpoch.requirePublicationFormats(candidate, provenance: expected.carriesProvenance)
        guard try InstallationInventory.digest(candidate) == expected.installedReleaseDigest,
              try DurableReleasePreparation.digest(candidate) == expected.updateID else { throw RuntimePreparationError.changedScope }
        let next = try expected.applying(operation)
        return try quiescence.withExclusiveActivity { _ in
            let value = try transaction(write: true, activationWrite: true) {
                try requireCurrentConfigurationEpoch(expected, directory: directory, quiescence: quiescence)
                try verifyCurrent(expected); try verifyCurrent(next)
                try statement("UPDATE machine_update_configuration_epoch_v1 SET revision=? WHERE epoch=?") { row in
                    try bind(bytes(next.revision), column: 1, row: row); try bind(bytes(next.id), column: 2, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == Int32(next.operands.count + 1) else { throw PreparationStoreError.staleRevision }
                }
                try statement("UPDATE machine_update_configuration_epoch_v1 SET record=? WHERE kind=0 AND epoch=? AND revision=?") { row in
                    try bind(next.encoded, column: 1, row: row); try bind(bytes(next.id), column: 2, row: row)
                    try bind(bytes(next.revision), column: 3, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
                try requireCurrentConfigurationEpoch(next, directory: directory, quiescence: quiescence)
                try verifyCurrent(next); return next
            }
            do {
                return try transaction(write: false) {
                    try requireCurrentConfigurationEpoch(value, directory: directory, quiescence: quiescence)
                    try verifyCurrent(value); return value
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    /// The verifier expires when the callback returns. It holds neither native code identity nor an account journal lease.
    func withCurrentMachineUpdateConfigurationEpoch<Value>(_ expected: MachineUpdateConfigurationEpochRecord,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try quiescence.withExclusiveActivity { _ in
            try transaction(write: false) {
                let processID = getpid()
                var scopeActive = true; defer { scopeActive = false }
                let validate: () throws -> Void = { [weak self] in
                    guard scopeActive, getpid() == processID, let self else { throw JournalLeaseError.invalidated }
                    try self.requireCurrentConfigurationEpoch(expected, directory: directory, quiescence: quiescence)
                }
                try validate(); let value = try body(validate); try validate(); return value
            }
        }
    }

    private func requireCurrentConfigurationEpoch(_ expected: MachineUpdateConfigurationEpochRecord,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease) throws {
        let source = try requireCurrentConfigurationEpoch(expected, directory: directory)
        try quiescence.validateMachineBoundary(directory: directory, expected: source.replacement.admission.machine)
    }

    private func requireCurrentConfigurationEpoch(_ expected: MachineUpdateConfigurationEpochRecord,
        directory: ReleaseDestinationLease, allowCompletionSchema: Bool = false) throws -> MachineUpdateRestartSource {
        try identity(macID); try requireUpdateAdmissionDirectory(directory)
        let schema = try scalar("PRAGMA user_version")
        guard schema == 19 || schema == 20 || (allowCompletionSchema && (schema == 21 || schema == 22)), let epoch = try loadMachineUpdateConfigurationEpoch(), epoch.record == expected,
              let activation = try loadMachineUpdateActivation(), activation.phase.irreversible else { throw PreparationStoreError.staleRevision }
        let source = try loadMachineUpdateRestartSource(activation), context = source.replacement
        if schema >= 20 {
            guard let backend = try loadMachineUpdateBackendEpoch(epoch: epoch),
                  try machineEpochSourceDigest(normalizedSchema: 19) == expected.sourceMachineDigest,
                  try machineEpochSourceDigest(normalizedSchema: 20) == backend.record.currentSourceDigest else { throw PreparationStoreError.staleRevision }
            try backend.record.requireScope(epoch)
        } else {
            guard try machineEpochSourceDigest() == expected.sourceMachineDigest else { throw PreparationStoreError.staleRevision }
        }
        guard activation.attemptID == expected.activationAttempt, activation.updateID == expected.updateID,
              activation.candidateDigest == expected.candidateDigest, activation.inventoryDigest == expected.inventoryDigest,
              activation.admissionDigest == expected.admissionDigest, context.inventory.macID == expected.macID,
              context.inventory.installationID == expected.installationID, context.replacement?.phase == .observed,
              source.accounts.count == expected.accounts.count else { throw PreparationStoreError.staleRevision }
        for account in expected.accounts {
            guard try source.accountDigest(accountID: account.accountID) == account.sourceDigest else { throw PreparationStoreError.staleRevision }
        }
        return source
    }

    private func loadMachineUpdateConfigurationEpoch() throws -> MachineUpdateConfigurationEpoch.Archive? {
        typealias Row = MachineUpdateConfigurationEpochRows.Row
        let rows: [Row] = try statement("SELECT kind,account,epoch,revision,record FROM machine_update_configuration_epoch_v1 ORDER BY kind,account") { row in
            var values: [Row] = []
            while try step(row) == SQLITE_ROW {
                guard values.count < 518, sqlite3_column_type(row, 0) == SQLITE_INTEGER else { throw PreparationStoreError.corruptRecord }
                values.append(try Row(kind: sqlite3_column_int64(row, 0),
                    account: blob(row, column: 1, maximum: 16), epoch: blob(row, column: 2, maximum: 16),
                    revision: blob(row, column: 3, maximum: 16),
                    payload: blob(row, column: 4, maximum: RuntimeReleaseConfigurationSource.maximumBytes)))
            }
            return values
        }
        guard let header = try MachineUpdateConfigurationEpochRows.decodeRecord(rows, macID: macID) else { return nil }
        let artifacts = rows.dropFirst().map {
            MachineUpdateConfigurationEpoch.Artifact(kind: $0.kind, account: $0.account, bytes: $0.payload)
        }
        let archive = MachineUpdateConfigurationEpoch.Archive(record: header, artifacts: artifacts)
        try archive.validate()
        return archive
    }

    func upgradeMachineUpdateBackendEpochStorage(expected: MachineUpdateConfigurationEpochRecord,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        verifyCurrent: () throws -> Void) throws -> MachineUpdateBackendEpochRecord {
        try quiescence.withExclusiveActivity { _ in
            let value = try transaction(write: true, activationWrite: true) {
                try requireCurrentConfigurationEpoch(expected, directory: directory, quiescence: quiescence)
                guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                try MachineUpdateBackendEpoch.requireFormats(candidate, epoch: epoch)
                try verifyCurrent()
                let version = try scalar("PRAGMA user_version")
                if version == 20 {
                    guard let existing = try loadMachineUpdateBackendEpoch(epoch: epoch) else { throw PreparationStoreError.corruptRecord }
                    try requireCurrentBackendEpoch(existing.record, epoch: epoch, directory: directory, quiescence: quiescence)
                    try verifyCurrent(); return existing.record
                }
                guard version == 19, expected.publication?.complete == true else { throw PreparationStoreError.invalidTransition }
                try exec("CREATE TABLE machine_update_backend_epoch_v1(kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 3),account BLOB NOT NULL CHECK(length(account)=CASE WHEN kind=0 THEN 1 ELSE 16 END),epoch BLOB NOT NULL CHECK(length(epoch)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND CASE WHEN kind=0 THEN 131072 WHEN kind=1 THEN 1048576 ELSE 2097152 END),PRIMARY KEY(kind,account)) STRICT")
                try exec("PRAGMA user_version=20"); try identity(macID)
                guard try machineEpochSourceDigest(normalizedSchema: 19) == expected.sourceMachineDigest else { throw PreparationStoreError.staleRevision }
                let record = try MachineUpdateBackendEpochRecord(epoch: epoch, currentSourceDigest: machineEpochSourceDigest())
                try writeBackendEpochRow(kind: 0, account: MachineUpdateBackendEpoch.global, bytes: record.encoded, record: record)
                try requireCurrentBackendEpoch(record, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent(); return record
            }
            return try transaction(write: false) {
                guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                try requireCurrentBackendEpoch(value, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent(); return value
            }
        }
    }

    func machineUpdateRestartSnapshot(expected: MachineUpdateRestartSource, directory: ReleaseDestinationLease,
        restart: UpdateRestartAdmissionLease) throws -> MachineUpdateRestartSnapshot {
        try restart.withClosedAdmission {
            try transaction(write: false) {
                try loadMachineUpdateRestartSnapshot(expected: expected, directory: directory) {
                    try restart.validateMachineBoundary(directory: directory, expected: $0)
                }
            }
        }
    }

    /// An active health owner must read through its loan from the original drain.
    func machineUpdateRestartSnapshot(expected: MachineUpdateRestartSource, directory: ReleaseDestinationLease,
        readiness: MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot {
        try readiness.withClosedAdmission {
            try transaction(write: false) {
                try loadMachineUpdateRestartSnapshot(expected: expected, directory: directory) {
                    try Self.requireRestartSnapshotLoan(readiness, source: expected, directory: directory, machine: $0)
                }
            }
        }
    }

    /// A callback-bound read of the current machine transaction. It cannot cross a thread or survive the callback.
    final class HealthSnapshotScope: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private let snapshot: MachineUpdateRestartSnapshot
        private let verifyCurrent: () throws -> Void
        private var active = true

        fileprivate init(snapshot: MachineUpdateRestartSnapshot, verifyCurrent: @escaping () throws -> Void) {
            self.snapshot = snapshot; self.verifyCurrent = verifyCurrent
        }
        var isOnOpeningThread: Bool { getpid() == processID && pthread_equal(pthread_self(), thread) != 0 }
        func read() throws -> MachineUpdateRestartSnapshot {
            guard isOnOpeningThread else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard active else { throw JournalLeaseError.invalidated }
                do {
                    try verifyCurrent()
                    guard active else { throw JournalLeaseError.invalidated }
                    return snapshot
                } catch { active = false; throw error }
            }
        }
        fileprivate func expire() { lock.withLock { active = false } }
    }

    func withCurrentMachineUpdateRestartSnapshot<Value>(_ expected: MachineUpdateRestartSnapshot,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (HealthSnapshotScope) throws -> Value) throws -> Value {
        try restart.withClosedAdmission {
            try withRestartSnapshotScope(expected, directory: directory, validateBoundary: {
                try restart.validate()
                try restart.validateMachineBoundary(directory: directory, expected: $0)
            }, body)
        }
    }

    func withCurrentMachineUpdateRestartSnapshot<Value>(_ expected: MachineUpdateRestartSnapshot,
        directory: ReleaseDestinationLease, readiness: MachineUpdateRestartReadinessLoan,
        _ body: (HealthSnapshotScope) throws -> Value) throws -> Value {
        try readiness.withClosedAdmission {
            try withRestartSnapshotScope(expected, directory: directory, validateBoundary: {
                try Self.requireRestartSnapshotLoan(readiness, source: expected.source, directory: directory, machine: $0)
            }, body)
        }
    }

    private static func requireRestartSnapshotLoan(_ readiness: MachineUpdateRestartReadinessLoan,
        source: MachineUpdateRestartSource, directory: ReleaseDestinationLease, machine: PreparationFileIdentity) throws {
        let activation = source.replacement.activation
        try readiness.requireScope(macID: activation.macID, installationID: activation.installationID,
            activationAttempt: activation.attemptID)
        try readiness.validateMachineBoundary(directory: directory, expected: machine)
    }

    private func withRestartSnapshotScope<Value>(_ expected: MachineUpdateRestartSnapshot,
        directory: ReleaseDestinationLease, validateBoundary: @escaping (PreparationFileIdentity) throws -> Void,
        _ body: (HealthSnapshotScope) throws -> Value) throws -> Value {
        try transaction(write: false) {
            let initial = try loadMachineUpdateRestartSnapshot(expected: expected.source, directory: directory,
                validateBoundary: validateBoundary)
            try initial.requireSame(as: expected)
            let scope = HealthSnapshotScope(snapshot: initial, verifyCurrent: { [weak self] in
                guard let self, self.active else { throw JournalLeaseError.invalidated }
                let current = try self.loadMachineUpdateRestartSnapshot(expected: expected.source, directory: directory,
                    validateBoundary: validateBoundary)
                try current.requireSame(as: initial)
            })
            defer { scope.expire() }
            _ = try scope.read()
            let value = try body(scope)
            _ = try scope.read()
            return value
        }
    }

    private func loadMachineUpdateRestartSnapshot(expected: MachineUpdateRestartSource,
        directory: ReleaseDestinationLease, validateBoundary: (PreparationFileIdentity) throws -> Void) throws -> MachineUpdateRestartSnapshot {
        try identity(macID)
        guard expected.replacement.activation.phase == .restartChecking, try scalar("PRAGMA user_version") == 20,
              let configuration = try loadMachineUpdateConfigurationEpoch(),
              configuration.record.publication?.complete == true,
              let backend = try loadMachineUpdateBackendEpoch(epoch: configuration),
              backend.record.accounts != nil, backend.record.publication?.complete == true else {
            throw PreparationStoreError.staleRevision
        }
        let current = try requireCurrentConfigurationEpoch(configuration.record, directory: directory)
        guard current == expected, try machineEpochSourceDigest() == backend.record.currentSourceDigest else {
            throw PreparationStoreError.staleRevision
        }
        try validateBoundary(current.replacement.admission.machine)
        return .init(source: current, configuration: configuration, backend: backend)
    }

    enum CompletionIntentStorageStage: CaseIterable {
        case beforeTransaction, inTransaction, afterMutation, afterCommit
    }

    /// Reads bounded completion facts. It grants no policy writer or admission authority.
    func machineUpdateCompletionIntent() throws -> MachineUpdateCompletionIntentArchive? {
        try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 21 else { return nil }
            return try loadMachineUpdateCompletionIntent()
        }
    }

    /// A synchronous loan for initial intent retention. It distinguishes the proposal from a retained header and actual runtime.
    final class CompletionPreparationScope: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private let snapshot: MachineUpdateCompletionPreparationSnapshot
        private var verifyCurrent: (() throws -> Void)?
        private var active = true
        fileprivate init(snapshot: MachineUpdateCompletionPreparationSnapshot, verifyCurrent: @escaping () throws -> Void) {
            self.snapshot = snapshot; self.verifyCurrent = verifyCurrent
        }
        func read() throws -> MachineUpdateCompletionPreparationSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard active, let verifyCurrent else { throw JournalLeaseError.invalidated }
                do {
                    try verifyCurrent(); guard active else { throw JournalLeaseError.invalidated }; return snapshot
                } catch { expire(); throw error }
            }
        }
        fileprivate func expire() { lock.withLock { active = false; verifyCurrent = nil } }
    }
    private func completionPreparationSnapshot(expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease) throws -> MachineUpdateCompletionPreparationSnapshot {
        try expected.validate(); try requireCompletionIntentFormats(candidate)
        guard expected.policies.allSatisfy({ $0.phase == .prepared }) else { throw PreparationStoreError.invalidTransition }
        let version = try scalar("PRAGMA user_version")
        let current: MachineUpdateRestartSnapshot
        switch version {
        case 20:
            current = try loadMachineUpdateRestartSnapshot(expected: restartSnapshot.source, directory: directory) {
                try restart.validateMachineBoundary(directory: directory, expected: $0)
            }
        case 21:
            let recovered = try loadCompletionRecoverySnapshot(candidate: candidate, directory: directory)
            guard recovered.intent == expected else { throw PreparationStoreError.staleRevision }
            current = recovered.restart
            try restart.validateMachineBoundary(directory: directory, expected: current.source.replacement.admission.machine)
        default:
            throw PreparationStoreError.invalidTransition
        }
        try current.requireSame(as: restartSnapshot)
        try expected.requireSnapshot(current, candidate: candidate, currentSourceDigest: machineEpochSourceDigest(normalizedSchema: 20))
        let retained = version == 21
        let runtime = try loadRetainedRuntimeCompatibilityInputs()
        guard runtime.schemaVersion == version, (runtime.completionIntent != nil) == retained else { throw PreparationStoreError.staleRevision }
        return .init(restart: restartSnapshot, proposal: expected, intentRetained: retained, runtime: runtime)
    }
    private func withCompletionPreparationScopeInTransaction<Value>(expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionPreparationScope) throws -> Value) throws -> Value {
        let snapshot = try completionPreparationSnapshot(expected: expected, restartSnapshot: restartSnapshot,
            candidate: candidate, directory: directory, restart: restart)
        let scope = CompletionPreparationScope(snapshot: snapshot, verifyCurrent: { [weak self] in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            try self.completionPreparationSnapshot(expected: expected, restartSnapshot: restartSnapshot,
                candidate: candidate, directory: directory, restart: restart).requireSame(as: snapshot)
        })
        defer { scope.expire() }
        _ = try scope.read(); let value = try body(scope); _ = try scope.read(); return value
    }

    /// Persists the header and every account marker in one explicit schema transition.
    func retainMachineUpdateCompletionIntent(_ expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyPreparationScoped: (CompletionIntentStorageStage, CompletionPreparationScope) throws -> Void)
        throws -> MachineUpdateCompletionIntentArchive {
        try retainingCompletionIntent(expected, snapshot: snapshot, candidate: candidate, directory: directory,
            restart: restart, verifyBefore: {
                try transaction(write: false) {
                    try withCompletionPreparationScopeInTransaction(expected: expected, restartSnapshot: snapshot,
                        candidate: candidate, directory: directory, restart: restart) { try verifyPreparationScoped(.beforeTransaction, $0) }
                }
            }, verifyPreparationScoped: verifyPreparationScoped)
    }
    private func retainingCompletionIntent(_ expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease, verifyBefore: () throws -> Void,
        verifyPreparationScoped: (CompletionIntentStorageStage, CompletionPreparationScope) throws -> Void)
        throws -> MachineUpdateCompletionIntentArchive {
        try restart.withClosedAdmission {
            try expected.validate()
            guard expected.policies.allSatisfy({ $0.phase == .prepared }) else { throw PreparationStoreError.invalidTransition }
            try requireCompletionIntentFormats(candidate)
            try verifyBefore(); try restart.validate()
            let value = try transaction(write: true, activationWrite: true) {
                let version = try scalar("PRAGMA user_version")
                try withCompletionPreparationScopeInTransaction(expected: expected, restartSnapshot: snapshot,
                    candidate: candidate, directory: directory, restart: restart) { try verifyPreparationScoped(.inTransaction, $0) }
                if version == 21 { return expected }
                guard version == 20, snapshot.source.replacement.runtime.schemaVersion == 20 else { throw PreparationStoreError.invalidTransition }
                try exec("CREATE TABLE machine_update_completion_intent_v1(kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),account BLOB NOT NULL CHECK(length(account)=CASE WHEN kind=0 THEN 1 ELSE 16 END),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND CASE WHEN kind=0 THEN 131072 ELSE 262144 END),PRIMARY KEY(kind,account)) STRICT")
                try exec("PRAGMA user_version=21"); try identity(macID); try writeCompletionIntent(expected)
                try withCompletionPreparationScopeInTransaction(expected: expected, restartSnapshot: snapshot,
                    candidate: candidate, directory: directory, restart: restart) { try verifyPreparationScoped(.afterMutation, $0) }
                return expected
            }
            do {
                return try transaction(write: false) {
                    try withCompletionPreparationScopeInTransaction(expected: value, restartSnapshot: snapshot,
                        candidate: candidate, directory: directory, restart: restart) { try verifyPreparationScoped(.afterCommit, $0) }
                    return value
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    /// This callback lends one finalization frame on its opening thread while admission stays closed.
    final class CompletionFinalizationScope: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private let frame: MachineUpdateFinalizationFrame
        private var verifyCurrent: (() throws -> Void)?
        private var readSource: ((MachineUpdateFinalizationSnapshot) throws -> MachineUpdateInstalledSourceSnapshot)?
        private var readRuntime: ((MachineUpdateInstalledSourceSnapshot) throws -> RuntimeReleaseCompatibilitySnapshot)?
        fileprivate init(frame: MachineUpdateFinalizationFrame, verifyCurrent: @escaping () throws -> Void,
            readSource: @escaping (MachineUpdateFinalizationSnapshot) throws -> MachineUpdateInstalledSourceSnapshot,
            readRuntime: @escaping (MachineUpdateInstalledSourceSnapshot) throws -> RuntimeReleaseCompatibilitySnapshot) {
            self.frame = frame; self.verifyCurrent = verifyCurrent
            self.readSource = readSource; self.readRuntime = readRuntime
        }
        func read() throws -> MachineUpdateFinalizationFrame {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            return try lock.withLock {
                guard let verifyCurrent else { throw JournalLeaseError.invalidated }
                do { try verifyCurrent(); return frame }
                catch { expire(); throw error }
            }
        }
        func readRetainedSource() throws -> MachineUpdateInstalledSourceSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            return try lock.withLock {
                guard case .installed(let installed) = try read() else { throw PreparationStoreError.invalidTransition }
                guard let readSource else { throw JournalLeaseError.invalidated }
                do {
                    let result = try readSource(installed)
                    _ = try read()
                    return result
                } catch { expire(); throw error }
            }
        }
        func readCompatibility() throws -> MachineUpdateInstalledCompatibilitySnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            return try lock.withLock {
                let source = try readRetainedSource()
                guard let readRuntime else { throw JournalLeaseError.invalidated }
                do {
                    let runtime = try readRuntime(source)
                    try readRetainedSource().requireSame(as: source)
                    return .init(source: source, runtime: runtime)
                } catch { expire(); throw error }
            }
        }
        fileprivate func expire() { lock.withLock { verifyCurrent = nil; readSource = nil; readRuntime = nil } }
    }

    private static let completionRetirementTables = ["machine_update_completion_publication_v1",
        "machine_update_completion_intent_v1", "machine_update_backend_epoch_v1",
        "machine_update_configuration_epoch_v1", "machine_update_replacement_v1"]

    private func withFinalizationScope<Value>(_ capture: @escaping () throws -> MachineUpdateFinalizationFrame,
        _ body: (CompletionFinalizationScope) throws -> Value) throws -> Value {
        let frame = try capture()
        let scope = CompletionFinalizationScope(frame: frame, verifyCurrent: { [weak self] in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            try capture().requireSame(as: frame)
        }, readSource: { [weak self] actual in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            return try self.loadInstalledRuntimeSource(actual: actual)
        }, readRuntime: { [weak self] source in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            let inputs = try self.loadRetainedRuntimeCompatibilityInputs(finishing: source)
            return try RuntimeReleaseCompatibilitySnapshot.describe(inputs: inputs)
        })
        defer { scope.expire() }
        _ = try scope.read()
        let result = try body(scope)
        _ = try scope.read()
        return result
    }

    /// Commits the inventory and retained operands together. The finishing phase keeps admission closed.
    func finalizeMachineUpdateCompletion(_ installed: MachineUpdateInstalledReleaseEpoch.Archive,
        publication: MachineUpdateCompletionPublicationRecord, plan: MachineUpdateCompletionPublicationPlan,
        expected: MachineUpdateCompletionIntentArchive, restartSnapshot: MachineUpdateRestartSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        ownedFileDirectory: ((MachineUpdateCompletionPublicationPlan.Entry) throws -> ProtectedSetupDirectory)? = nil,
        verifyScoped: (CompletionIntentStorageStage, CompletionFinalizationScope) throws -> Void) throws -> MachineUpdateFinalizationSnapshot {
        try requireInstalledReleaseFormats(candidate)
        try installed.validate(candidate: candidate)
        guard publication.filesPublished, publication.inventoryState == .pending,
              try installed.publicationSource() == publication, installed.record.sourceSchemaVersion == 22,
              try installed.completionIntent() == expected, try installed.inventory() == plan.inventory,
              try installed.configuration().record == restartSnapshot.configuration.record,
              try installed.configuration().artifacts == restartSnapshot.configuration.artifacts,
              try installed.backend().record == restartSnapshot.backend.record,
              try installed.backend().artifacts == restartSnapshot.backend.artifacts else { throw PreparationStoreError.staleRevision }
        func verifyFiles() throws {
            func verifyAdmission() throws {
                try restart.validate()
                try restart.validateMachineBoundary(directory: directory, expected: restartSnapshot.source.replacement.admission.machine)
            }
            if let ownedFileDirectory {
                try MachineUpdateCompletionPublicationFiles.requireInLeases(plan, publication: publication, owner: getuid(),
                    directory: ownedFileDirectory, verifyCurrent: verifyAdmission)
            } else {
                try MachineUpdateCompletionPublicationFiles.requireBackendMetadataNative(restartSnapshot, verifyCurrent: verifyAdmission)
                try MachineUpdateCompletionPublicationFiles.requireNative(plan, publication: publication, verifyCurrent: verifyAdmission)
            }
        }
        let before: () throws -> MachineUpdateFinalizationFrame = {
            guard try self.scalar("PRAGMA user_version") == 22 else { throw PreparationStoreError.staleRevision }
            let current = try self.completionPublicationSnapshot(expected: expected, publication: publication, plan: plan,
                restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart)
            try verifyFiles()
            return .publication(current)
        }
        let after: () throws -> MachineUpdateFinalizationFrame = {
            try self.requireUpdateAdmissionDirectory(directory)
            let actual = try self.loadMachineUpdateFinalization(candidate: candidate)
            guard actual.installed.record == installed.record, actual.installed.artifacts == installed.artifacts else {
                throw PreparationStoreError.staleRevision
            }
            try restart.validate()
            try restart.validateMachineBoundary(directory: directory, expected: actual.admission.machine)
            try verifyFiles()
            return .installed(actual)
        }
        return try restart.withClosedAdmission {
            try transaction(write: false) {
                try withFinalizationScope(before) { try verifyScoped(.beforeTransaction, $0) }
            }
            try transaction(write: true, activationWrite: true) {
                try withFinalizationScope(before) { try verifyScoped(.inTransaction, $0) }
                let context = restartSnapshot.source.replacement, next = try context.activation.finalizing()
                let retired = try UpdateSchedulingCandidateRecord(macID: context.candidate.macID,
                    installationID: context.candidate.installationID, inventoryRevision: context.candidate.inventoryRevision,
                    preparation: context.candidate.preparation, generation: context.candidate.generation, selected: false)
                try exec("CREATE TABLE installed_release_state_v1(kind INTEGER NOT NULL CHECK(kind IN(0,1,2,3,4,5,101,102,103,104,105,106,107,108,109,201,202,203,300)),account BLOB NOT NULL CHECK(length(account)=CASE WHEN kind IN(0,1,2,3,4,5,105,106,107,108,109) THEN 1 ELSE 16 END),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND CASE WHEN kind=1 THEN 65536 WHEN kind IN(2,3,4) THEN 131072 WHEN kind=5 THEN 524288 WHEN kind=201 THEN 1048576 WHEN kind IN(202,203) THEN 2097152 ELSE 262400 END),PRIMARY KEY(kind,account)) STRICT")
                try writeInstalledReleaseRow(kind: 0, account: MachineUpdateInstalledReleaseEpoch.global,
                    record: installed.record.encoded, header: installed.record)
                for artifact in installed.artifacts {
                    try writeInstalledReleaseRow(kind: artifact.kind, account: artifact.accountID,
                        record: artifact.bytes, header: installed.record)
                }
                try writeMachineUpdateActivation(next, replacing: context.activation, allowFinishing: true)
                try writeUpdateCandidate(retired, replacing: context.candidate)
                guard try loadInventoryRecord() == context.inventory else { throw PreparationStoreError.staleRevision }
                try statement("UPDATE installation_inventory_v1 SET revision=?,record=? WHERE id=1 AND installation=? AND revision=?") { row in
                    try bind(plan.inventory.revision, column: 1, row: row); try bind(plan.inventory.canonicalBytes, column: 2, row: row)
                    try bind(context.inventory.installationID, column: 3, row: row); try bind(context.inventory.revision, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
                for table in Self.completionRetirementTables { try exec("DELETE FROM \(table)") }
                try exec("PRAGMA user_version=23")
                try withFinalizationScope(after) { try verifyScoped(.afterMutation, $0) }
            }
            do {
                return try transaction(write: false) {
                    try withFinalizationScope(after) { scope in
                        try verifyScoped(.afterCommit, scope)
                        guard case .installed(let actual) = try scope.read() else { throw PreparationStoreError.staleRevision }
                        return actual
                    }
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    /// Supplies a new finishing read to one live readiness owner under its shared admission loan.
    func withCurrentMachineUpdateReadiness<Value>(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, loan: MachineUpdateRestartReadinessLoan,
        _ body: (CompletionFinalizationScope) throws -> Value) throws -> Value {
        try loan.withClosedAdmission {
            try transaction(write: false) {
                try withFinalizationScope({
                    try self.requireUpdateAdmissionDirectory(directory)
                    let actual = try self.loadMachineUpdateFinalization(candidate: candidate)
                    try loan.requireScope(macID: actual.inventory.macID, installationID: actual.inventory.installationID,
                        activationAttempt: actual.activation.attemptID)
                    try loan.validateMachineBoundary(directory: directory, expected: actual.admission.machine)
                    return .installed(actual)
                }, body)
            }
        }
    }

    func machineUpdateFinalizationSnapshot(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease) throws -> MachineUpdateFinalizationSnapshot {
        try transaction(write: false) {
            try requireUpdateAdmissionDirectory(directory)
            return try loadMachineUpdateFinalization(candidate: candidate)
        }
    }

    func withCurrentMachineUpdateFinalization<Value>(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionFinalizationScope) throws -> Value) throws -> Value {
        try restart.withClosedAdmission {
            try transaction(write: false) {
                try withFinalizationScope({
                    try self.requireUpdateAdmissionDirectory(directory)
                    let current = try self.loadMachineUpdateFinalization(candidate: candidate)
                    try restart.validateMachineBoundary(directory: directory, expected: current.admission.machine)
                    return .installed(current)
                }, body)
            }
        }
    }

    /// The transaction lends its actual current frame. It grants no admission release.
    final class StableCompletionScope: @unchecked Sendable {
        private let processID = getpid()
        private let thread = pthread_self()
        private let lock = NSRecursiveLock()
        private let expected: MachineUpdateStableCompletionFrame
        private var capture: (() throws -> MachineUpdateStableCompletionFrame)?

        fileprivate init(expected: MachineUpdateStableCompletionFrame,
            capture: @escaping () throws -> MachineUpdateStableCompletionFrame) {
            self.expected = expected
            self.capture = capture
        }

        func read() throws -> MachineUpdateStableCompletionFrame {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard let capture else { throw JournalLeaseError.invalidated }
                do {
                    let current = try capture()
                    try current.requireSame(as: expected)
                    return current
                } catch {
                    self.capture = nil
                    throw error
                }
            }
        }

        fileprivate func expire() { lock.withLock { capture = nil } }
    }

    /// Confirms the exact durable stable state and the checks run during its read. It grants no admission.
    final class StableCompletionCommit: Sendable {
        private let processID = getpid()
        private let snapshot: MachineUpdateStableReleaseSnapshot

        fileprivate init(snapshot: MachineUpdateStableReleaseSnapshot) { self.snapshot = snapshot }

        func read() throws -> MachineUpdateStableReleaseSnapshot {
            guard getpid() == processID else { throw JournalLeaseError.invalidated }
            return snapshot
        }

        func requireSource(_ plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence) throws {
            try read().requireInitialTransition(from: plan, release: candidate)
        }

        func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
            try machine.stableMachineUpdateSnapshot(candidate: candidate).requireSame(as: read())
        }
    }

    /// Native readiness is checked against both sides of the transition under the original admission loan.
    func commitStableMachineUpdate(expected: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, loan: MachineUpdateRestartReadinessLoan,
        verifyScoped: (CompletionIntentStorageStage, StableCompletionScope) throws -> Void) throws -> StableCompletionCommit {
        try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        let source = expected.view.compatibility.source.actual
        let completed = try source.activation.completing()
        let seal = try MachineUpdateStableReleaseRecord(readiness: expected, completed: completed, candidate: candidate)

        func verifyAdmission() throws {
            try requireUpdateAdmissionDirectory(directory)
            try loan.requireScope(macID: source.inventory.macID, installationID: source.inventory.installationID,
                activationAttempt: source.activation.attemptID)
            try loan.validateMachineBoundary(directory: directory, expected: source.admission.machine)
        }

        func before() throws -> MachineUpdateStableCompletionFrame {
            try verifyAdmission()
            let plan = try withFinalizationScope({
                .installed(try self.loadMachineUpdateFinalization(candidate: candidate))
            }) { scope in
                try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)
            }
            try plan.requireSame(as: expected)
            try verifyAdmission()
            return .finishing(plan)
        }

        func after() throws -> MachineUpdateStableCompletionFrame {
            try verifyAdmission()
            let snapshot = try loadStableMachineUpdate(candidate: candidate)
            try snapshot.requireInitialTransition(from: expected, release: candidate)
            guard try snapshot.seal.encoded == seal.encoded else { throw PreparationStoreError.staleRevision }
            try verifyAdmission()
            return .stable(snapshot)
        }

        func verify(_ stage: CompletionIntentStorageStage,
            capture: @escaping () throws -> MachineUpdateStableCompletionFrame) throws -> MachineUpdateStableCompletionFrame {
            let scope = try StableCompletionScope(expected: capture(), capture: capture)
            defer { scope.expire() }
            try verifyScoped(stage, scope)
            return try scope.read()
        }

        var commitAttempted = false
        do {
            try loan.withClosedAdmission {
                try transaction(write: false) { _ = try verify(.beforeTransaction, capture: before) }
                try transaction(write: true, activationWrite: true, willCommit: { commitAttempted = true }) {
                    _ = try verify(.inTransaction, capture: before)
                    try exec("CREATE TABLE stable_release_state_v1(id INTEGER PRIMARY KEY CHECK(id=1),epoch BLOB NOT NULL CHECK(length(epoch)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT")
                    try statement("INSERT INTO stable_release_state_v1 VALUES(1,?,?,?)") { row in
                        try bind(bytes(seal.id), column: 1, row: row)
                        try bind(bytes(seal.revision), column: 2, row: row)
                        try bind(seal.encoded, column: 3, row: row)
                        guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                    }
                    try statement("UPDATE machine_update_activation_v1 SET revision=?,record=? WHERE id=1 AND revision=? AND record=?") { row in
                        try bind(bytes(completed.revision), column: 1, row: row)
                        try bind(completed.encoded, column: 2, row: row)
                        try bind(bytes(source.activation.revision), column: 3, row: row)
                        try bind(source.activation.encoded, column: 4, row: row)
                        guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                    }
                    try exec("PRAGMA user_version=24")
                    _ = try verify(.afterMutation, capture: after)
                }
            }
            return try adoptStableMachineUpdate(expected: expected, candidate: candidate, directory: directory,
                loan: loan, verifyScoped: verifyScoped)
        } catch {
            guard commitAttempted else { throw error }
            unavailable = true
            shutdown()
            throw PreparationStoreError.stableCommitUnconfirmed
        }
    }

    /// Verifies the expected finishing plan and durable stable rows under the original loan before issuing a receipt.
    /// The native caller must check the live installation in the scoped callback. This path never writes.
    func adoptStableMachineUpdate(expected: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, loan: MachineUpdateRestartReadinessLoan,
        verifyScoped: (CompletionIntentStorageStage, StableCompletionScope) throws -> Void) throws -> StableCompletionCommit {
        try loan.withClosedAdmission {
            try transaction(write: false) {
                func read() throws -> MachineUpdateStableCompletionFrame {
                    try self.requireUpdateAdmissionDirectory(directory)
                    let snapshot = try self.loadStableMachineUpdate(candidate: candidate)
                    try loan.requireScope(macID: snapshot.inventory.macID, installationID: snapshot.inventory.installationID,
                        activationAttempt: snapshot.activation.attemptID)
                    try loan.validateMachineBoundary(directory: directory, expected: snapshot.admission.machine)
                    try snapshot.requireInitialTransition(from: expected, release: candidate)
                    return .stable(snapshot)
                }
                let scope = try StableCompletionScope(expected: read(), capture: read)
                defer { scope.expire() }
                try verifyScoped(.afterCommit, scope)
                guard case .stable(let snapshot) = try scope.read() else { throw PreparationStoreError.invalidTransition }
                return StableCompletionCommit(snapshot: snapshot)
            }
        }
    }

    func installedRuntimeSource(candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease)
        throws -> MachineUpdateInstalledSourceSnapshot {
        try transaction(write: false) {
            try requireUpdateAdmissionDirectory(directory)
            return try loadInstalledRuntimeSource(actual: loadMachineUpdateFinalization(candidate: candidate))
        }
    }

    private enum HistoricalMachineColumn {
        case integer(Int64), blob(Data)
    }

    /// Recreates the original row hash for a singleton replaced by finalization.
    private func historicalSingletonTableDigest(_ table: String, columns: [HistoricalMachineColumn]) throws -> Data {
        var row = SHA256(); row.update(data: Data("Remozio/MachineEpochRow/v1\0".utf8))
        row.update(data: candidateGeneration(UInt64(columns.count)))
        for column in columns {
            switch column {
            case .integer(let value):
                row.update(data: Data([UInt8(SQLITE_INTEGER)]))
                row.update(data: candidateGeneration(UInt64(bitPattern: value)))
            case .blob(let bytes):
                guard bytes.count <= 278528 else { throw PreparationStoreError.corruptRecord }
                row.update(data: Data([UInt8(SQLITE_BLOB)]))
                row.update(data: candidateGeneration(UInt64(bytes.count)))
                row.update(data: bytes)
            }
        }
        return machineEpochTableDigest(table, rows: [Data(row.finalize())])
    }

    private func loadInstalledRuntimeSource(actual: MachineUpdateFinalizationSnapshot) throws
        -> MachineUpdateInstalledSourceSnapshot {
        try identity(macID)
        guard actual.schemaVersion == 23, try scalar("PRAGMA user_version") == 23,
              actual.activation.phase == .finishing, try loadInventoryRecord() == actual.inventory else {
            throw PreparationStoreError.staleRevision
        }
        let current = try installedCurrentSourceProjection(inventory: actual.inventory, installed: actual.installed, schema: 23)
        guard try current.digest == actual.installed.backend().record.currentSourceDigest,
              try current.digest == actual.installed.completionIntent().record.sourceMachineDigest else {
            throw PreparationStoreError.staleRevision
        }
        return .init(actual: actual, historicalInventory: current.historicalInventory,
            historicalSchemaVersion: current.historicalSchemaVersion, historicalSourceDigest: current.digest)
    }

    /// Hashes the current protected rows with the original inventory, candidate and replacement operands.
    private func installedCurrentSourceProjection(inventory: InstallationInventory,
        installed: MachineUpdateInstalledReleaseEpoch.Archive, schema: Int64)
        throws -> (historicalInventory: InstallationInventory, historicalSchemaVersion: Int64, digest: Data) {
        guard (23...MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion).contains(schema),
              try scalar("PRAGMA user_version") == schema,
              try loadInventoryRecord() == inventory else { throw PreparationStoreError.staleRevision }
        let configuration = try installed.configuration(), intent = try installed.completionIntent()
        guard intent.record.sourceSchemaVersion == 20 else { throw PreparationStoreError.incompatibleStore }
        let historical = try InstallationInventory.decode(configuration.artifact(5), expectedMacID: macID)
        let candidate = try UpdateSchedulingCandidateRecord.decode(configuration.artifact(6))
        let replacement = try MachineUpdateReplacementRecord.decode(configuration.artifact(9))
        guard historical.installationID == inventory.installationID,
              historical.revision == candidate.inventoryRevision,
              historical.revision == intent.record.sourceInventoryRevision else { throw PreparationStoreError.staleRevision }

        let historicalTables = [
            "installation_inventory_v1": try historicalSingletonTableDigest("installation_inventory_v1", columns: [
                .integer(1), .blob(historical.installationID), .blob(historical.revision), .blob(historical.canonicalBytes)]),
            "update_scheduling_candidate_v1": try historicalSingletonTableDigest("update_scheduling_candidate_v1", columns: [
                .integer(1), .blob(candidateGeneration(candidate.generation)), .blob(bytes(candidate.revision)), .blob(candidate.encoded)]),
            "machine_update_replacement_v1": try historicalSingletonTableDigest("machine_update_replacement_v1", columns: [
                .integer(1), .blob(bytes(replacement.revision)), .blob(replacement.encoded)]),
        ]
        let digest = try machineEpochSourceDigest(schema: schema, digestSchema: intent.record.sourceSchemaVersion,
            installationID: inventory.installationID, historicalTables: historicalTables)
        return (historical, intent.record.sourceSchemaVersion, digest)
    }

    private func requireInstalledReleaseFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try MachineUpdateInstalledReleaseRecord.requirements + MachineUpdateActivationRecord.finalizationRequirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }

    private func writeInstalledReleaseRow(kind: Int64, account: Data, record: Data,
        header: MachineUpdateInstalledReleaseRecord) throws {
        try withBackendRecordLimit {
            try statement("INSERT INTO installed_release_state_v1 VALUES(?,?,?,?,?)") { row in
                try bind(kind, column: 1, row: row); try bind(account, column: 2, row: row)
                try bind(bytes(header.id), column: 3, row: row); try bind(bytes(header.revision), column: 4, row: row)
                try bind(record, column: 5, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
        }
    }

    private func loadInstalledReleaseRows() throws -> (MachineUpdateInstalledReleaseRecord, [MachineUpdateInstalledReleaseEpoch.Artifact]) {
        try withBackendRecordLimit {
            try statement("SELECT kind,account,id,revision,record FROM installed_release_state_v1 ORDER BY kind,account") { row in
                guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                      sqlite3_column_int64(row, 0) == 0,
                      try blob(row, column: 1, maximum: 16) == MachineUpdateInstalledReleaseEpoch.global else { throw PreparationStoreError.corruptRecord }
                let header = try MachineUpdateInstalledReleaseRecord.decode(blob(row, column: 4, maximum: MachineUpdateInstalledReleaseRecord.maximumBytes))
                guard try blob(row, column: 2, maximum: 16) == bytes(header.id),
                      try blob(row, column: 3, maximum: 16) == bytes(header.revision) else { throw PreparationStoreError.corruptRecord }
                var rows: [MachineUpdateInstalledReleaseEpoch.Artifact] = []
                for operand in header.operands {
                    guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                          sqlite3_column_int64(row, 0) == operand.kind,
                          try blob(row, column: 1, maximum: 16) == operand.accountID,
                          try blob(row, column: 2, maximum: 16) == bytes(header.id),
                          try blob(row, column: 3, maximum: 16) == bytes(header.revision) else { throw PreparationStoreError.corruptRecord }
                    let data = try blob(row, column: 4, maximum: MachineUpdateInstalledReleaseRecord.maximumArtifactBytes(kind: operand.kind))
                    guard data.count == operand.length, MachineUpdateActivationRecord.digest(data) == operand.digest else { throw PreparationStoreError.corruptRecord }
                    rows.append(.init(kind: operand.kind, accountID: operand.accountID, bytes: data))
                }
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                return (header, rows)
            }
        }
    }

    private func requireFinishingActivation(_ value: MachineUpdateActivationRecord, inventory: InstallationInventory,
        candidate: UpdateSchedulingCandidateRecord, admission: UpdateAdmissionRegistrationRecord, schema: Int64 = 23) throws {
        guard try scalar("PRAGMA user_version") == schema, !candidate.selected else { throw PreparationStoreError.corruptRecord }
        let (header, rows) = try loadInstalledReleaseRows()
        func artifact(_ kind: Int64) throws -> Data {
            guard let value = rows.first(where: { $0.kind == kind && $0.accountID == MachineUpdateInstalledReleaseEpoch.global }) else {
                throw PreparationStoreError.corruptRecord
            }
            return value.bytes
        }
        let intent = try MachineUpdateCompletionIntentRecord.decode(artifact(4))
        let historical = try UpdateSchedulingCandidateRecord.decode(artifact(106))
        try value.requireFinalizationSource(.decode(intent.activation))
        guard header.macID == macID, header.installationID == inventory.installationID,
              header.inventoryRevision == inventory.revision, header.releaseDigest == inventory.releaseDigest,
              header.activationAttempt == value.attemptID, inventory.canonicalBytes == intent.targetInventory,
              try artifact(1) == inventory.canonicalBytes, try artifact(107) == admission.encoded,
              historical.macID == candidate.macID, historical.installationID == candidate.installationID,
              historical.inventoryRevision == candidate.inventoryRevision, historical.preparation == candidate.preparation,
              historical.generation == candidate.generation, historical.updateID == value.updateID,
              try MachineUpdateActivationRecord.digest(historical.encoded) == value.candidateDigest,
              try MachineUpdateActivationRecord.digest(admission.encoded) == value.admissionDigest,
              admission.machine == value.machineAdmission else { throw PreparationStoreError.corruptRecord }
    }

    /// Reads the terminal release without granting ordinary startup or write authority.
    func stableMachineUpdateSnapshot(candidate: SignedReleaseEvidence) throws -> MachineUpdateStableReleaseSnapshot {
        try transaction(write: false) { try loadStableMachineUpdate(candidate: candidate) }
    }

    /// Captures the exact account rows and sealed release in one read transaction.
    func stableRuntimeSource(candidate: SignedReleaseEvidence) throws -> MachineUpdateStableRuntimeSource {
        try transaction(write: false) { try loadStableRuntimeSource(candidate: candidate) }
    }

    private func loadStableRuntimeSource(candidate: SignedReleaseEvidence) throws -> MachineUpdateStableRuntimeSource {
        let actual = try loadStableMachineUpdate(candidate: candidate)
        let preparations = try loadAccountPreparations()
        let initializations: [AuthorityInitializationIntent] = try statement(
            "SELECT account FROM authority_initialization_v1 ORDER BY account LIMIT 65") { row in
                var values: [AuthorityInitializationIntent] = []
                while try step(row) == SQLITE_ROW {
                    guard values.count < 64,
                          let value = try loadInitialization(accountID: blob(row, column: 0, maximum: 16)) else {
                        throw PreparationStoreError.corruptRecord
                    }
                    values.append(value)
                }
                return values
            }
        let source = try MachineUpdateStableRuntimeSource(actual: actual, preparations: preparations,
            initializations: initializations, candidate: candidate)
        try loadStableMachineUpdate(candidate: candidate).requireSame(as: actual)
        return source
    }

    func stableServiceAccountSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence) throws -> MachineUpdateStableServiceAccountSnapshot {
        try transaction(write: false) { try loadStableServiceAccountSnapshot(owner: owner, candidate: candidate) }
    }
    private func loadStableServiceAccountSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence) throws -> MachineUpdateStableServiceAccountSnapshot {
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: loadStableRuntimeSource(candidate: candidate), owner: owner)
        guard setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
        guard let preparation = setup.preparation else { throw AccountPreparationError.missing }
        return try .init(setup: setup, state: loadServiceAccountPlan(accountID: preparation.accountID), reservedNumbers: loadReservedServiceAccountNumbers())
    }

    private final class StableServiceAccountAuthorization {
        private let processID = getpid()
        private let thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private let original: MachineUpdateStableServiceAccountSnapshot
        private var expected: MachineUpdateStableServiceAccountSnapshot
        private let candidate: SignedReleaseEvidence
        private let directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease.Scope
        private var protectedDigest: Data?
        init(writer: PreparationIntentStore, expected: MachineUpdateStableServiceAccountSnapshot,
            candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease.Scope) {
            self.writer = writer; self.original = expected; self.expected = expected; self.candidate = candidate
            self.directory = directory; self.admission = admission
        }
        func capture(in owner: PreparationIntentStore) throws -> MachineUpdateStableServiceAccountSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  let writer, writer === owner, writer.active, writer.stableServiceAccountAuthorization === self,
                  let db = writer.db, sqlite3_get_autocommit(db) == 0 else { throw JournalLeaseError.invalidated }
            try writer.requireUpdateAdmissionDirectory(directory)
            try admission.validateMachineBoundary(directory: directory, expected: original.setup.source.actual.admission.machine)
            let actual = try writer.loadStableServiceAccountSnapshot(owner: original.setup.owner, candidate: candidate)
            try actual.requireSame(as: expected)
            let digest = try writer.stableServiceAccountProtectedDigest(excluding: original.preparation.accountID)
            if let protectedDigest { guard digest == protectedDigest else { throw PreparationStoreError.staleRevision } }
            else { protectedDigest = digest }
            try admission.validate(); return actual
        }
        func adopt(plan: ServiceAccountPlan, complete: Bool, in owner: PreparationIntentStore) throws {
            let actual = try owner.loadStableServiceAccountSnapshot(owner: original.setup.owner, candidate: candidate)
            try actual.requireChange(plan: plan, complete: complete, from: original)
            expected = actual; _ = try capture(in: owner)
        }
    }

    /// Retains exact numeric and UUID claims before directory work. It creates no system account.
    func retainStableServiceAccountPlan(_ plan: ServiceAccountPlan, expected: MachineUpdateStableServiceAccountSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableServiceAccountSnapshot) throws -> Void) throws -> ServiceAccountPlanStorage.State {
        try changeStableServiceAccountPlan(plan, complete: false, expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
    }
    /// The native owner verifies every directory record around this metadata transition. This marker grants no runtime authority.
    func completeStableServiceAccountPlan(_ plan: ServiceAccountPlan, expected: MachineUpdateStableServiceAccountSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableServiceAccountSnapshot) throws -> Void) throws -> ServiceAccountPlanStorage.State {
        try changeStableServiceAccountPlan(plan, complete: true, expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
    }
    private func changeStableServiceAccountPlan(_ plan: ServiceAccountPlan, complete: Bool,
        expected: MachineUpdateStableServiceAccountSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableServiceAccountSnapshot) throws -> Void) throws -> ServiceAccountPlanStorage.State {
        guard expected.setup.account?.origin == .currentRelease else { throw ServiceAccountProvisioningError.changedScope }
        try plan.validate(account: expected.preparation); try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        guard stableServiceAccountAuthorization == nil, stableAccountStorageAuthorization == nil,
              stableRuntimePreparationAuthorization == nil,
              stableAccountReservationAuthorization == nil, retainedSetupPromotionAuthorization == nil else {
            throw PreparationStoreError.transactionActive
        }
        var commitAttempted = false
        do { return try admission.withMachineAdmission { loan in
            let authorization = StableServiceAccountAuthorization(writer: self, expected: expected, candidate: candidate,
                directory: directory, admission: loan)
            stableServiceAccountAuthorization = authorization
            defer { stableServiceAccountAuthorization = nil }
            let before = try transaction(write: false) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.beforeTransaction, actual); _ = try authorization.capture(in: self); return actual
            }
            if let retained = before.state.plan {
                guard retained == plan else { throw ServiceAccountProvisioningError.conflictingRecord }
                if !complete || before.state.complete { return before.state }
            } else {
                guard !complete else { throw ServiceAccountProvisioningError.missingRecord }
                guard Set(plan.claims.map(\.number)).isDisjoint(with: before.reservedNumbers) else { throw ServiceAccountProvisioningError.conflictingRecord }
            }
            guard before.setup.account?.inInventory == false else { throw ServiceAccountProvisioningError.changedScope }
            try transaction(write: true, activationWrite: true, stableServiceAccount: authorization,
                willCommit: { commitAttempted = true }) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.inTransaction, actual); _ = try authorization.capture(in: self)
                if complete {
                    try statement("UPDATE service_accounts_v1 SET complete=1 WHERE account=? AND record=? AND complete=0") { row in
                        try bind(plan.accountID, column: 1, row: row); try bind(plan.encoded, column: 2, row: row)
                        guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw ServiceAccountProvisioningError.conflictingRecord }
                    }
                } else {
                    guard try scalar("SELECT COUNT(*) FROM service_accounts_v1") < 64 else { throw ServiceAccountProvisioningError.exhausted }
                    try statement("INSERT INTO service_accounts_v1 VALUES(?,?,?,0,?)") { row in
                        try bind(plan.accountID, column: 1, row: row)
                        try bind(Int64(serviceAccountNumber(plan, role: .transport)), column: 2, row: row)
                        try bind(Int64(serviceAccountNumber(plan, role: .gateway)), column: 3, row: row)
                        try bind(plan.encoded, column: 4, row: row)
                        guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                    }
                }
                try authorization.adopt(plan: plan, complete: complete, in: self)
                try verifyScoped(.afterMutation, authorization.capture(in: self)); _ = try authorization.capture(in: self)
            }
            do {
                return try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verifyScoped(.afterCommit, actual); _ = try authorization.capture(in: self); return actual.state
                }
            } catch { unavailable = true; shutdown(); throw error }
        } } catch {
            if commitAttempted { unavailable = true; shutdown() }
            throw error
        }
    }
    private func stableServiceAccountProtectedDigest(excluding accountID: Data) throws -> Data {
        guard accountID.count == 16 else { throw PreparationStoreError.corruptRecord }
        let tables: [String] = try statement("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 128, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                names.append(String(cString: name))
            }
            return names
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/StableServiceAccountProtectedRows/v1\0".utf8)); hash.update(data: accountID)
        hash.update(data: try machineTableDigest("sqlite_schema", maximumCellBytes: RuntimeReleaseBackendPlan.maximumBytes))
        for table in tables {
            hash.update(data: try machineTableDigest(table, excludingAccount: table == "service_accounts_v1" ? accountID : nil,
                maximumCellBytes: max(RuntimeReleaseBackendPlan.maximumBytes,
                    max(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes, MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes))))
        }
        return Data(hash.finalize())
    }

    private final class StableRuntimePreparationAuthorization {
        private let processID = getpid()
        private let thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private let original: MachineUpdateStableRuntimePreparationSnapshot
        private var expected: MachineUpdateStableRuntimePreparationSnapshot
        private let candidate: SignedReleaseEvidence
        private let directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease.Scope
        private var protectedDigest: Data?
        init(writer: PreparationIntentStore, expected: MachineUpdateStableRuntimePreparationSnapshot,
            candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease.Scope) {
            self.writer = writer; original = expected; self.expected = expected; self.candidate = candidate
            self.directory = directory; self.admission = admission
        }
        func capture(in owner: PreparationIntentStore) throws -> MachineUpdateStableRuntimePreparationSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  let writer, writer === owner, writer.active, writer.stableRuntimePreparationAuthorization === self,
                  let db = writer.db, sqlite3_get_autocommit(db) == 0 else { throw JournalLeaseError.invalidated }
            try writer.requireUpdateAdmissionDirectory(directory)
            try admission.validateMachineBoundary(directory: directory, expected: original.setup.source.actual.admission.machine)
            let actual = try writer.loadStableRuntimePreparationSnapshot(owner: original.setup.owner, candidate: candidate)
            guard actual.setup.account?.origin == .currentRelease else { throw RuntimePreparationError.changedScope }
            try actual.requireSame(as: expected)
            let digest = try writer.stableRuntimePreparationProtectedDigest(excluding: original.preparation.accountID)
            if let protectedDigest { guard digest == protectedDigest else { throw PreparationStoreError.staleRevision } }
            else { protectedDigest = digest }
            try admission.validate(); return actual
        }
        func adopt(reference: RuntimeMaterialReference, published: Bool, in owner: PreparationIntentStore) throws {
            let actual = try owner.loadStableRuntimePreparationSnapshot(owner: original.setup.owner, candidate: candidate)
            try actual.requireChange(reference: reference, published: published, from: original)
            expected = actual; _ = try capture(in: owner)
        }
    }
    /// Retains public identities after the authorized owner accepts the existing file custody disclosure.
    func retainStableRuntimeMaterial(_ reference: RuntimeMaterialReference, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        fileCustodyAccepted: Bool,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableRuntimePreparationSnapshot) throws -> Void) throws -> RuntimePreparationState {
        try changeStableRuntimePreparation(reference, published: false, expected: expected, candidate: candidate,
            directory: directory, admission: admission, fileCustodyAccepted: fileCustodyAccepted, verifyScoped: verifyScoped)
    }
    /// The native publication owner verifies actual files around this metadata transition. Completion grants no runtime admission.
    func completeStableRuntimePublication(_ reference: RuntimeMaterialReference, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        fileCustodyAccepted: Bool,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableRuntimePreparationSnapshot) throws -> Void) throws -> RuntimePreparationState {
        try changeStableRuntimePreparation(reference, published: true, expected: expected, candidate: candidate,
            directory: directory, admission: admission, fileCustodyAccepted: fileCustodyAccepted, verifyScoped: verifyScoped)
    }
    private func changeStableRuntimePreparation(_ reference: RuntimeMaterialReference, published: Bool,
        expected: MachineUpdateStableRuntimePreparationSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableRuntimePreparationSnapshot) throws -> Void) throws -> RuntimePreparationState {
        guard expected.setup.account?.origin == .currentRelease else { throw RuntimePreparationError.changedScope }
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try reference.validate(account: expected.preparation, services: expected.plan)
        try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        guard stableRuntimePreparationAuthorization == nil, stableServiceAccountAuthorization == nil,
              stableAccountStorageAuthorization == nil, stableAccountReservationAuthorization == nil,
              retainedSetupPromotionAuthorization == nil else { throw PreparationStoreError.transactionActive }
        var commitAttempted = false
        do { return try admission.withMachineAdmission { loan in
            let authorization = StableRuntimePreparationAuthorization(writer: self, expected: expected, candidate: candidate,
                directory: directory, admission: loan)
            stableRuntimePreparationAuthorization = authorization
            defer { stableRuntimePreparationAuthorization = nil }
            let before = try transaction(write: false) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.beforeTransaction, actual); _ = try authorization.capture(in: self); return actual
            }
            if let retained = before.state.reference {
                guard retained == reference else { throw RuntimePreparationError.conflictingMaterial }
                if !published || before.state.configurationPublished { return before.state }
            } else {
                guard !published else { throw RuntimePreparationError.incomplete }
            }
            guard before.setup.account?.inInventory == false else { throw RuntimePreparationError.changedScope }
            try transaction(write: true, activationWrite: true, stableRuntimePreparation: authorization,
                willCommit: { commitAttempted = true }) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.inTransaction, actual); _ = try authorization.capture(in: self)
                if published {
                    try statement("UPDATE runtime_preparation_v1 SET complete=1 WHERE account=? AND record=? AND complete=0") { row in
                        try bind(reference.services.accountID, column: 1, row: row); try bind(reference.encoded, column: 2, row: row)
                        guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw RuntimePreparationError.conflictingMaterial }
                    }
                } else {
                    guard try scalar("SELECT COUNT(*) FROM runtime_preparation_v1") < 64 else { throw RuntimePreparationError.exhausted }
                    try statement("SELECT COUNT(*) FROM runtime_preparation_v1 WHERE material=? OR pin=?") { row in
                        try bind(reference.materialID, column: 1, row: row); try bind(reference.transportPublicKeyInfo, column: 2, row: row)
                        guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 0 else { throw RuntimePreparationError.conflictingMaterial }
                    }
                    try statement("INSERT INTO runtime_preparation_v1 VALUES(?,?,?,?,0,?)") { row in
                        try bind(reference.services.accountID, column: 1, row: row); try bind(reference.materialID, column: 2, row: row)
                        try bind(reference.transportPublicKeyInfo, column: 3, row: row); try bind(reference.materialDigest, column: 4, row: row)
                        try bind(reference.encoded, column: 5, row: row)
                        guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                    }
                }
                try authorization.adopt(reference: reference, published: published, in: self)
                try verifyScoped(.afterMutation, authorization.capture(in: self)); _ = try authorization.capture(in: self)
            }
            do {
                return try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verifyScoped(.afterCommit, actual); _ = try authorization.capture(in: self); return actual.state
                }
            } catch { unavailable = true; shutdown(); throw error }
        } } catch {
            if commitAttempted { unavailable = true; shutdown() }
            throw error
        }
    }
    private func stableRuntimePreparationProtectedDigest(excluding accountID: Data?) throws -> Data {
        guard accountID == nil || accountID?.count == 16 else { throw PreparationStoreError.corruptRecord }
        let tables: [String] = try statement("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 128, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                names.append(String(cString: name))
            }
            return names
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/StableRuntimePreparationProtectedRows/v1\0".utf8)); hash.update(data: Data([accountID == nil ? 0 : 1])); if let accountID { hash.update(data: accountID) }
        hash.update(data: try machineTableDigest("sqlite_schema", maximumCellBytes: RuntimeReleaseBackendPlan.maximumBytes))
        for table in tables {
            hash.update(data: try machineTableDigest(table,
                excludingAccount: table == "runtime_preparation_v1" ? accountID : nil, maximumCellBytes: max(RuntimeReleaseBackendPlan.maximumBytes,
                    max(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes, MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes))))
        }
        return Data(hash.finalize())
    }

    /// Advances only the held import journal. Every machine row remains exact while the external source digest changes.
    func advanceStableRuntimeImport(expected: MachineUpdateStableRuntimePreparationSnapshot, previous: SharedSetupImportIntent,
        journal: SharedSetupImportJournal, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        admission: UpdateOrdinaryAdmissionLease) throws -> (intent: SharedSetupImportIntent, snapshot: MachineUpdateStableRuntimePreparationSnapshot) {
        guard expected.setup.account?.origin == .currentRelease else { throw RuntimePreparationError.changedScope }
        guard let borrowed = sharedImportReadBorrow else { throw SharedSetupImportError.wrongScope }
        try borrowed.validate(in: self, journal: journal)
        try expected.requireCurrent(machine: self, candidate: candidate)
        guard expected.state.configurationPublished, expected.state.reference != nil, previous.phase == .retained else {
            throw RuntimePreparationError.incomplete
        }
        let provisioning = try expected.setup.source.provisioningInventory(accountID: expected.preparation.accountID,
            ownerUID: expected.preparation.ownerUID, releaseDigest: expected.preparation.releaseDigest)
        guard previous.scope == (try SharedSetupImportIntent.Scope(account: expected.preparation, inventory: provisioning)) else {
            throw SharedSetupImportError.wrongScope
        }
        try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
        let before = try transaction(write: false) { try stableRuntimePreparationProtectedDigest(excluding: nil) }
        try borrowed.validate(in: self, journal: journal)
        let next = try journal.advance(previous, to: .runtimePublished)
        try borrowed.validate(in: self, journal: journal)
        let after = try transaction(write: false) { try stableRuntimePreparationProtectedDigest(excluding: nil) }
        guard before == after, try journal.current(scope: previous.scope) == next else { throw PreparationStoreError.staleRevision }
        let actual = try stableRuntimePreparationSnapshot(owner: expected.setup.owner, candidate: candidate)
        try actual.requirePublished(from: expected)
        guard actual.state == expected.state else { throw RuntimePreparationError.changedScope }
        try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
        try borrowed.validate(in: self, journal: journal)
        return (next, actual)
    }

    private enum StableAccountStorageMutation {
        case pin(Data)
        case beginInitialization(journalPath: String, continuityPath: String)
        case captureCheckpoint(JournalDatabase)
        case completeInitialization(JournalDatabase, ContinuityStore)
        case completePreparation
        var changesPreparation: Bool {
            switch self { case .pin, .completePreparation: return true; default: return false }
        }
    }
    private final class StableAccountStorageAuthorization {
        private let processID = getpid(), thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private let original: MachineUpdateStableAccountSetupSnapshot
        private var expected: MachineUpdateStableAccountSetupSnapshot
        private let candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease.Scope
        private let mutation: StableAccountStorageMutation
        private var protectedDigest: Data?
        init(writer: PreparationIntentStore, expected: MachineUpdateStableAccountSetupSnapshot, candidate: SignedReleaseEvidence,
            directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease.Scope, mutation: StableAccountStorageMutation) {
            self.writer = writer; original = expected; self.expected = expected; self.candidate = candidate
            self.directory = directory; self.admission = admission; self.mutation = mutation
        }
        func capture(in owner: PreparationIntentStore) throws -> MachineUpdateStableAccountSetupSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  let writer, writer === owner, writer.active, writer.stableAccountStorageAuthorization === self,
                  let db = writer.db, sqlite3_get_autocommit(db) == 0,
                  let preparation = original.preparation else { throw JournalLeaseError.invalidated }
            try writer.requireUpdateAdmissionDirectory(directory)
            try admission.validateMachineBoundary(directory: directory, expected: original.source.actual.admission.machine)
            let actual = try MachineUpdateStableAccountSetupSnapshot(source: writer.loadStableRuntimeSource(candidate: candidate),
                owner: original.owner)
            try actual.requireSame(as: expected)
            try writer.requireStableAccountStorageBoundary(mutation, actual: actual)
            let digest = try writer.stableAccountStorageProtectedDigest(preparation: preparation, changesPreparation: mutation.changesPreparation)
            if let protectedDigest { guard digest == protectedDigest else { throw PreparationStoreError.staleRevision } }
            else { protectedDigest = digest }
            try admission.validate(); return actual
        }
        func adopt(preparation: AccountPreparationIntent, initialization: AuthorityInitializationIntent?, in owner: PreparationIntentStore) throws {
            let actual = try MachineUpdateStableAccountSetupSnapshot(source: owner.loadStableRuntimeSource(candidate: candidate), owner: original.owner)
            try actual.requireAccountStorageState(preparation: preparation, initialization: initialization, from: original)
            expected = actual; _ = try capture(in: owner)
        }
    }

    /// Pins metadata only. The native owner separately proves possession and protected key placement.
    func pinStableAccountPreparation(publicKey: Data, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AccountPreparationIntent {
        let actual = try changeStableAccountStorage(.pin(publicKey), expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
        guard let preparation = actual.preparation else { throw AccountPreparationError.missing }; return preparation
    }
    /// Retains frozen initialization and checked paths. It creates no directories or account databases.
    func beginStableAccountInitialization(journalPath: String, continuityPath: String, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AuthorityInitializationIntent {
        let actual = try changeStableAccountStorage(.beginInitialization(journalPath: journalPath, continuityPath: continuityPath),
            expected: expected, candidate: candidate, directory: directory, admission: admission, verifyScoped: verifyScoped)
        guard let initialization = actual.account?.initialization else { throw AuthorityInitializationError.missingIntent }; return initialization
    }
    /// Captures the actual pristine journal boundary. A retained checkpoint cannot follow later journal changes.
    func captureStableAccountInitialization(journal: JournalDatabase, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AuthorityInitializationIntent {
        let actual = try changeStableAccountStorage(.captureCheckpoint(journal), expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
        guard let initial = actual.account?.initialization else { throw AuthorityInitializationError.missingIntent }; return initial
    }

    /// Requires both live stores at the exact retained checkpoint. Completion grants no runtime admission.
    func completeStableAccountInitialization(journal: JournalDatabase, continuity: ContinuityStore,
        expected: MachineUpdateStableAccountSetupSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AuthorityInitializationIntent {
        let actual = try changeStableAccountStorage(.completeInitialization(journal, continuity), expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
        guard let initial = actual.account?.initialization else { throw AuthorityInitializationError.missingIntent }; return initial
    }

    /// Records completed setup progress. It grants no current health proof and never repairs missing storage.
    func completeStableAccountPreparation(expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AccountPreparationIntent {
        let actual = try changeStableAccountStorage(.completePreparation, expected: expected, candidate: candidate,
            directory: directory, admission: admission, verifyScoped: verifyScoped)
        guard let preparation = actual.preparation else { throw AccountPreparationError.missing }; return preparation
    }

    private func requireStableAccountStorageBoundary(_ mutation: StableAccountStorageMutation,
        actual: MachineUpdateStableAccountSetupSnapshot) throws {
        switch mutation {
        case .pin, .beginInitialization: return
        default:
            guard actual.account?.origin == .currentRelease else { throw AccountPreparationError.conflict }
        }
        switch mutation {
        case .captureCheckpoint(let journal):
            guard let preparation = actual.preparation, preparation.authorityPublicKey != nil,
                  let initial = actual.account?.initialization else { throw AuthorityInitializationError.missingIntent }
            guard !initial.complete else { throw AuthorityInitializationError.completed }
            let checkpoint = try journal.initialAuthorityCheckpoint(initial: preparation.initialAuthority, databasePath: initial.journalPath)
            if let retained = initial.checkpoint, retained != checkpoint { throw AuthorityInitializationError.invalidBoundary }
        case .completeInitialization(let journal, let continuity):
            guard let preparation = actual.preparation, preparation.authorityPublicKey != nil,
                  let initial = actual.account?.initialization, let checkpoint = initial.checkpoint else {
                throw AuthorityInitializationError.invalidBoundary
            }
            try journal.requireInitializationPath(initial.journalPath)
            try continuity.requireInitializationScope(path: initial.continuityPath, mac: initial.macID, account: initial.accountID)
            guard let journalDirectory = try journal.directoryIdentities().last,
                  let continuityDirectory = try continuity.directoryIdentities().last,
                  journalDirectory != continuityDirectory,
                  !(try continuity.directoryIdentities()).contains(journalDirectory),
                  !(try journal.directoryIdentities()).contains(continuityDirectory) else { throw AuthorityInitializationError.invalidBoundary }
            let state = try continuity.read()
            guard !state.recoveryRequired, state.pending == nil, state.committed == checkpoint,
                  try journal.read({ try CheckpointedJournal.checkpoint(transaction: $0, epoch: checkpoint.journalEpoch,
                    generation: 1, authorityGeneration: 1) }) == checkpoint else { throw AuthorityInitializationError.invalidBoundary }
        case .completePreparation:
            guard let preparation = actual.preparation, let initial = actual.account?.initialization else {
                throw AccountPreparationError.incomplete
            }
            guard preparation.authorityPublicKey != nil, initial.complete,
                  initial.macID == preparation.macID, initial.accountID == preparation.accountID,
                  initial.installationID == preparation.installationID, initial.releaseDigest == preparation.releaseDigest,
                  initial.initializationBytes == preparation.initializationBytes else { throw AccountPreparationError.incomplete }
        case .pin, .beginInitialization: break
        }
    }

    private func stableAccountStorageValues(_ mutation: StableAccountStorageMutation, actual: MachineUpdateStableAccountSetupSnapshot)
        throws -> (AccountPreparationIntent, AuthorityInitializationIntent?) {
        guard let preparation = actual.preparation, let account = actual.account else { throw AccountPreparationError.missing }
        guard account.origin == .currentRelease else { throw AccountPreparationError.conflict }
        let existing = account.initialization
        switch mutation {
        case .pin(let key):
            let next = try preparation.pinning(key)
            if next != preparation {
                guard !preparation.storagePrepared, !account.inInventory, existing == nil else { throw AccountPreparationError.conflict }
            }
            return (next, existing)
        case .beginInitialization(let journal, let continuity):
            guard preparation.authorityPublicKey != nil else { throw AccountPreparationError.incomplete }
            if let existing {
                guard existing.journalPath == journal, existing.continuityPath == continuity,
                      existing.macID == preparation.macID, existing.accountID == preparation.accountID,
                      existing.installationID == preparation.installationID, existing.releaseDigest == preparation.releaseDigest,
                      existing.initializationBytes == preparation.initializationBytes else { throw AuthorityInitializationError.conflictingIntent }
                return (preparation, existing)
            }
            guard !preparation.storagePrepared, !account.inInventory, actual.source.initializations.count < 64 else {
                throw AccountPreparationError.conflict
            }
            _ = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: preparation.accountID,
                journalPath: journal, continuityPath: continuity)
            let initial = try preparation.initialAuthority
            return (preparation, try AuthorityInitializationIntent(setupID: bytes(UUID()), revision: bytes(UUID()),
                installationID: preparation.installationID, macID: preparation.macID, accountID: preparation.accountID,
                releaseDigest: preparation.releaseDigest, initializationDigest: initial.initializationDigest,
                initializationBytes: preparation.initializationBytes, journalPath: journal, continuityPath: continuity))
        case .captureCheckpoint(let journal):
            guard let existing else { throw AuthorityInitializationError.missingIntent }
            let checkpoint = try journal.initialAuthorityCheckpoint(initial: preparation.initialAuthority, databasePath: existing.journalPath)
            if let retained = existing.checkpoint {
                guard retained == checkpoint else { throw AuthorityInitializationError.invalidBoundary }; return (preparation, existing)
            }
            guard !preparation.storagePrepared, !account.inInventory else { throw AccountPreparationError.conflict }
            return (preparation, try existing.advancing(checkpoint: checkpoint, complete: false))
        case .completeInitialization:
            guard let existing, let checkpoint = existing.checkpoint else { throw AuthorityInitializationError.invalidBoundary }
            if existing.complete { return (preparation, existing) }
            guard !preparation.storagePrepared, !account.inInventory else { throw AccountPreparationError.conflict }
            return (preparation, try existing.advancing(checkpoint: checkpoint, complete: true))
        case .completePreparation:
            guard let existing else { throw AccountPreparationError.incomplete }
            let next = try preparation.prepared(initialization: existing)
            if next != preparation { guard !account.inInventory else { throw AccountPreparationError.conflict } }
            return (next, existing)
        }
    }
    private func changeStableAccountStorage(_ mutation: StableAccountStorageMutation, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> MachineUpdateStableAccountSetupSnapshot {
        try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        guard expected.preparation != nil else { throw AccountPreparationError.missing }
        guard stableAccountStorageAuthorization == nil, stableAccountReservationAuthorization == nil,
              stableRuntimePreparationAuthorization == nil,
              retainedSetupPromotionAuthorization == nil, stableServiceAccountAuthorization == nil else { throw PreparationStoreError.transactionActive }
        var commitAttempted = false
        do {
            return try admission.withMachineAdmission { loan in
                let authorization = StableAccountStorageAuthorization(writer: self, expected: expected, candidate: candidate,
                    directory: directory, admission: loan, mutation: mutation)
                stableAccountStorageAuthorization = authorization
                defer { stableAccountStorageAuthorization = nil }
                let (before, preparation, initialization) = try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verifyScoped(.beforeTransaction, actual); _ = try authorization.capture(in: self)
                    let (preparation, initialization) = try stableAccountStorageValues(mutation, actual: actual)
                    return (actual, preparation, initialization)
                }
                if before.preparation == preparation, before.account?.initialization == initialization { return before }
                try transaction(write: true, activationWrite: true, stableAccountStorage: authorization,
                    willCommit: { commitAttempted = true }) {
                    let actual = try authorization.capture(in: self)
                    try verifyScoped(.inTransaction, actual); _ = try authorization.capture(in: self)
                    if mutation.changesPreparation {
                        guard let previous = before.preparation else { throw AccountPreparationError.missing }
                        try statement("UPDATE account_preparation_v1 SET revision=?,record=? WHERE owner=? AND revision=?") { row in
                            try bind(preparation.revision, column: 1, row: row); try bind(preparation.bytes, column: 2, row: row)
                            try bind(Int64(preparation.ownerUID), column: 3, row: row); try bind(previous.revision, column: 4, row: row)
                            guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw AccountPreparationError.staleRevision }
                        }
                    } else {
                        guard let initialization else { throw AuthorityInitializationError.conflictingIntent }
                        if let previous = before.account?.initialization {
                            try saveInitialization(initialization, expected: previous)
                        } else {
                            try statement("INSERT INTO authority_initialization_v1 VALUES(?,?,?)") { row in
                                try bind(initialization.accountID, column: 1, row: row); try bind(initialization.revision, column: 2, row: row)
                                try bind(initialization.bytes, column: 3, row: row)
                                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                            }
                        }
                    }
                    try authorization.adopt(preparation: preparation, initialization: initialization, in: self)
                    try verifyScoped(.afterMutation, authorization.capture(in: self)); _ = try authorization.capture(in: self)
                }
                return try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verifyScoped(.afterCommit, actual); _ = try authorization.capture(in: self); return actual
                }
            }
        } catch {
            if commitAttempted { unavailable = true; shutdown() }
            throw error
        }
    }
    private func stableAccountStorageProtectedDigest(preparation: AccountPreparationIntent, changesPreparation: Bool) throws -> Data {
        let tables: [String] = try statement("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 128, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                names.append(String(cString: name))
            }
            return names
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/StableAccountStorageProtectedRows/v1\0".utf8))
        hash.update(data: preparation.accountID); hash.update(data: Data([changesPreparation ? 1 : 0]))
        hash.update(data: try machineTableDigest("sqlite_schema", maximumCellBytes: RuntimeReleaseBackendPlan.maximumBytes))
        for table in tables {
            hash.update(data: try machineTableDigest(table,
                excludingOwnerUID: changesPreparation && table == "account_preparation_v1" ? preparation.ownerUID : nil,
                excludingAccount: !changesPreparation && table == "authority_initialization_v1" ? preparation.accountID : nil,
                maximumCellBytes: max(RuntimeReleaseBackendPlan.maximumBytes,
                    max(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes, MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes))))
        }
        return Data(hash.finalize())
    }

    private final class StableAccountReservationAuthorization {
        private let processID = getpid()
        private let thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private let original: MachineUpdateStableAccountSetupSnapshot
        private var expected: MachineUpdateStableAccountSetupSnapshot
        private let candidate: SignedReleaseEvidence
        private let directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease.Scope
        private var protectedDigest: Data?
        init(writer: PreparationIntentStore, expected: MachineUpdateStableAccountSetupSnapshot,
            candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease.Scope) {
            self.writer = writer; self.original = expected; self.expected = expected
            self.candidate = candidate; self.directory = directory; self.admission = admission
        }
        func capture(in owner: PreparationIntentStore) throws -> MachineUpdateStableAccountSetupSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  let writer, writer === owner, writer.active, writer.stableAccountReservationAuthorization === self,
                  let db = writer.db, sqlite3_get_autocommit(db) == 0 else { throw JournalLeaseError.invalidated }
            try writer.requireUpdateAdmissionDirectory(directory)
            try admission.validateMachineBoundary(directory: directory, expected: original.source.actual.admission.machine)
            let actual = try MachineUpdateStableAccountSetupSnapshot(source: writer.loadStableRuntimeSource(candidate: candidate),
                owner: original.owner)
            try actual.requireSame(as: expected)
            let digest = try writer.stableAccountReservationProtectedDigest(excluding: original.owner.uid)
            if let protectedDigest { guard digest == protectedDigest else { throw PreparationStoreError.staleRevision } }
            else { protectedDigest = digest }
            try admission.validate(); return actual
        }
        func adopt(_ value: AccountPreparationIntent, in owner: PreparationIntentStore) throws {
            let actual = try MachineUpdateStableAccountSetupSnapshot(source: owner.loadStableRuntimeSource(candidate: candidate),
                owner: original.owner)
            try actual.requireReservation(value, from: original)
            expected = actual; _ = try capture(in: owner)
        }
    }

    /// Reserves inputs before key creation. The authenticated owner separately verifies the current account and installed code.
    func beginStableAccountPreparation(owner: LocalAccountIdentity, allowedTargetUIDs: Set<UInt32>, disclosureAccepted: Bool,
        expected: MachineUpdateStableAccountSetupSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        makeInitial: (Data, Data) throws -> AuthorityJournalInitialization,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AccountPreparationIntent {
        try expected.requireOwner(owner); try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        guard stableAccountReservationAuthorization == nil, stableAccountStorageAuthorization == nil,
              stableRuntimePreparationAuthorization == nil,
              retainedSetupPromotionAuthorization == nil, stableServiceAccountAuthorization == nil else {
            throw PreparationStoreError.transactionActive
        }
        var commitAttempted = false
        do { return try admission.withMachineAdmission { loan in
            let authorization = StableAccountReservationAuthorization(writer: self, expected: expected,
                candidate: candidate, directory: directory, admission: loan)
            stableAccountReservationAuthorization = authorization
            defer { stableAccountReservationAuthorization = nil }
            let before = try transaction(write: false) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.beforeTransaction, actual); _ = try authorization.capture(in: self)
                return actual
            }
            // Recovery returns the original grants, key pin, and initial epoch without another write or factory call.
            if let retained = before.preparation {
                guard before.account?.origin == .currentRelease, disclosureAccepted,
                      try retained.commandPolicy.allowedTargetUIDs == allowedTargetUIDs else {
                    throw AccountPreparationError.conflict
                }
                return retained
            }
            let value = try transaction(write: true, activationWrite: true, stableReservation: authorization,
                willCommit: { commitAttempted = true }) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.inTransaction, actual); _ = try authorization.capture(in: self)
                guard actual.account == nil, actual.source.preparations.count < 64 else { throw AccountPreparationError.conflict }
                var accountID = AccountPreparationIntent.randomID()
                while actual.source.accounts.contains(where: { $0.accountID == accountID }) {
                    accountID = AccountPreparationIntent.randomID()
                }
                let policy = try CommandElevationPolicy(macID: macID, accountID: accountID, callerUID: owner.uid,
                    allowedTargetUIDs: allowedTargetUIDs, independentPolicyDisclosureAccepted: disclosureAccepted)
                let initial = try makeInitial(macID, accountID)
                try ReleaseGenerationPreflight.validate(candidate, against: initial.codePolicy)
                for entry in initial.codePolicy.entries {
                    if let component = candidate.manifest.components.first(where: { $0.role == entry.role }) {
                        guard entry.installedGeneration == component.generation,
                              entry.codeDirectoryHash == candidate.codeDirectoryHashes[entry.role] else {
                            throw AccountPreparationError.conflict
                        }
                    }
                }
                let inventory = actual.source.actual.inventory
                let value = try AccountPreparationIntent(setupID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
                    macID: macID, installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, accountID: accountID,
                    ownerUID: owner.uid, directoryID: owner.directoryID, policyBytes: policy.canonicalBytes,
                    initializationBytes: initial.initializationBytes)
                try statement("INSERT INTO account_preparation_v1 VALUES(?,?,?,?)") { row in
                    try bind(Int64(owner.uid), column: 1, row: row); try bind(accountID, column: 2, row: row)
                    try bind(value.revision, column: 3, row: row); try bind(value.bytes, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                }
                try authorization.adopt(value, in: self)
                try verifyScoped(.afterMutation, authorization.capture(in: self)); _ = try authorization.capture(in: self)
                return value
            }
            return try transaction(write: false) {
                let actual = try authorization.capture(in: self)
                try verifyScoped(.afterCommit, actual); _ = try authorization.capture(in: self)
                guard actual.preparation == value else { throw PreparationStoreError.staleRevision }
                return value
            }
        } } catch {
            if commitAttempted { unavailable = true; shutdown() }
            throw error
        }
    }

    private func stableAccountReservationProtectedDigest(excluding ownerUID: UInt32) throws -> Data {
        guard ownerUID > 0, ownerUID < UInt32.max else { throw PreparationStoreError.corruptRecord }
        let tables: [String] = try statement("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 128, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                names.append(String(cString: name))
            }
            return names
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/StableAccountReservationProtectedRows/v1\0".utf8))
        hash.update(data: candidateGeneration(UInt64(ownerUID)))
        hash.update(data: try machineTableDigest("sqlite_schema", maximumCellBytes: RuntimeReleaseBackendPlan.maximumBytes))
        for table in tables {
            hash.update(data: try machineTableDigest(table,
                excludingOwnerUID: table == "account_preparation_v1" ? ownerUID : nil, maximumCellBytes: max(RuntimeReleaseBackendPlan.maximumBytes,
                    max(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes, MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes))))
        }
        return Data(hash.finalize())
    }

    func stableAccountSetupSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateStableAccountSetupSnapshot {
        try .init(source: stableRuntimeSource(candidate: candidate), owner: owner)
    }

    /// Reads the retained service claims and runtime reference under the same sealed account snapshot.
    func stableRuntimePreparationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateStableRuntimePreparationSnapshot {
        try transaction(write: false) { try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate) }
    }

    private func loadStableRuntimePreparationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateStableRuntimePreparationSnapshot {
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: loadStableRuntimeSource(candidate: candidate), owner: owner)
        guard let preparation = setup.preparation else { throw AccountPreparationError.missing }
        let account = preparation.accountID
        let result = try MachineUpdateStableRuntimePreparationSnapshot(setup: setup,
            services: loadServiceAccountPlan(accountID: account), state: loadRuntimePreparation(accountID: account),
            reservedNumbers: loadReservedServiceAccountNumbers())
        try loadStableMachineUpdate(candidate: candidate).requireSame(as: setup.source.actual)
        return result
    }

    /// Reads activation facts in one transaction. It grants no enrollment or native registration authority.
    func stableRuntimeActivationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateStableRuntimeActivationSnapshot {
        try transaction(write: false) { try loadStableRuntimeActivationSnapshot(owner: owner, candidate: candidate) }
    }

    private func loadStableRuntimeActivationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateStableRuntimeActivationSnapshot {
        let runtime = try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate)
        let state = try loadRuntimeActivation(accountID: runtime.preparation.accountID)
        let result = try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime, state: state, candidate: candidate)
        try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate).requireSame(as: runtime)
        try result.requireState(loadRuntimeActivation(accountID: runtime.preparation.accountID))
        return result
    }

    /// Reads policy operands and the activation row in one transaction.
    func retainedSetupPolicyMaterial(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPolicyMaterial {
        try transaction(write: false) { try loadRetainedSetupPolicyMaterial(owner: owner, candidate: candidate) }
    }

    private func loadRetainedSetupPolicyMaterial(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPolicyMaterial {
        let runtime = try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate)
        return try .init(runtime: runtime, activation: loadRuntimeActivation(accountID: runtime.preparation.accountID))
    }

    /// Reads policy metadata and activation facts in one transaction. It grants no journal write or publication authority.
    func retainedSetupPolicySnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPolicySnapshot {
        try transaction(write: false) {
            let runtime = try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate)
            let state = try loadRuntimeActivation(accountID: runtime.preparation.accountID)
            let activation = try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: runtime, state: state, candidate: candidate)
            let actual = runtime.setup.source.actual
            let intent: MachineUpdateRetainedSetupPolicyIntentRecord?
            if actual.schemaVersion >= MachineUpdateRetainedSetupPolicyStorage.schemaVersion {
                intent = try loadRetainedSetupPolicyIntents(installationID: actual.inventory.installationID)
                    .first { $0.accountID == runtime.preparation.accountID }
            } else { intent = nil }
            let result = try MachineUpdateRetainedSetupPolicySnapshot(activation: activation, intent: intent, candidate: candidate)
            try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate).requireSame(as: runtime)
            try activation.requireState(loadRuntimeActivation(accountID: runtime.preparation.accountID))
            return result
        }
    }

    /// Reads retained activation and its exact startup receipt in one transaction. It grants no write authority.
    func retainedSetupActivationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupActivationSnapshot {
        try transaction(write: false) { try loadRetainedSetupActivationSnapshot(owner: owner, candidate: candidate) }
    }

    private func loadRetainedSetupActivationSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupActivationSnapshot {
        let runtime = try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate)
        let actual = runtime.setup.source.actual, account = runtime.preparation.accountID
        guard (25...28).contains(actual.schemaVersion),
              let intent = try loadRetainedSetupPolicyIntents(installationID: actual.inventory.installationID)
                .first(where: { $0.accountID == account }) else { throw RuntimeActivationError.incomplete }
        let state = try loadRetainedSetupActivation(accountID: account)
        let result = try MachineUpdateRetainedSetupActivationSnapshot(runtime: runtime, state: state,
            intent: intent, candidate: candidate)
        try loadStableRuntimePreparationSnapshot(owner: owner, candidate: candidate).requireSame(as: runtime)
        try state.requireSame(as: loadRetainedSetupActivation(accountID: account))
        guard try loadRetainedSetupPolicyIntents(installationID: actual.inventory.installationID)
            .first(where: { $0.accountID == account }) == intent else { throw PreparationStoreError.staleRevision }
        return result
    }

    /// Joins the actual retained activation and completion rows in one read transaction.
    func retainedSetupCompletionSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupCompletionSnapshot {
        try transaction(write: false) { try loadRetainedSetupCompletionSnapshot(owner: owner, candidate: candidate) }
    }

    private func loadRetainedSetupCompletionSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupCompletionSnapshot {
        let activation = try loadRetainedSetupActivationSnapshot(owner: owner, candidate: candidate)
        let account = activation.runtime.preparation.accountID
        let frame = try loadStableMachineUpdateFrame(candidate: candidate)
        try frame.snapshot.requireSame(as: activation.runtime.setup.source.actual)
        let intent = frame.completionIntents.first { $0.binding.accountID == account }
        let result = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: intent, candidate: candidate)
        try loadRetainedSetupActivationSnapshot(owner: owner, candidate: candidate).requireSame(as: activation)
        let current = try loadStableMachineUpdateFrame(candidate: candidate)
        try current.snapshot.requireSame(as: frame.snapshot)
        guard current.completionIntents.first(where: { $0.binding.accountID == account }) == intent else {
            throw PreparationStoreError.staleRevision
        }
        return result
    }

    /// Captures promotion and its exact completion chain in one read transaction. It grants no writer authority.
    func retainedSetupPromotionSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPromotionSnapshot {
        try transaction(write: false) { try loadRetainedSetupPromotionSnapshot(owner: owner, candidate: candidate) }
    }

    private func loadRetainedSetupPromotionSnapshot(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPromotionSnapshot {
        let completion = try loadRetainedSetupCompletionSnapshot(owner: owner, candidate: candidate)
        let actual = completion.activation.runtime.setup.source.actual, account = completion.activation.runtime.preparation.accountID
        let frame = try loadStableMachineUpdateFrame(candidate: candidate)
        try frame.snapshot.requireSame(as: actual)
        let intent = try frame.promotionIntents.first { try $0.publication().configuration.archive.binding.startupBinding.accountID == account }
        let result = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: intent, candidate: candidate)
        try loadRetainedSetupCompletionSnapshot(owner: owner, candidate: candidate).requireSame(as: completion)
        let current = try loadStableMachineUpdateFrame(candidate: candidate)
        try current.snapshot.requireSame(as: frame.snapshot)
        guard try current.promotionIntents.first(where: { try $0.publication().configuration.archive.binding.startupBinding.accountID == account }) == intent else {
            throw PreparationStoreError.staleRevision
        }
        return result
    }

    /// A synchronous loan of this writer's actual private frame. Other files cannot construct it.
    final class RetainedSetupPromotionFrameLoan {
        private let process = getpid(), thread = pthread_self(), lock = NSRecursiveLock()
        private var read: ((MachineUpdateRetainedSetupCompletionSnapshot) throws -> Void)?
        private var executing = false
        fileprivate init(_ read: @escaping (MachineUpdateRetainedSetupCompletionSnapshot) throws -> Void) { self.read = read }
        func verify(_ expected: MachineUpdateRetainedSetupCompletionSnapshot) throws {
            guard getpid() == process, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            try lock.withLock {
                guard !executing, let read else { throw JournalLeaseError.invalidated }
                executing = true; defer { executing = false }
                try read(expected)
                guard self.read != nil else { throw JournalLeaseError.invalidated }
            }
        }
        fileprivate func expire() { lock.withLock { read = nil } }
    }

    private final class RetainedSetupPromotionAuthorization {
        private let process = getpid(), thread = pthread_self()
        private weak var writer: PreparationIntentStore?
        private let original: MachineUpdateRetainedSetupPromotionSnapshot
        private var expected: MachineUpdateRetainedSetupPromotionSnapshot
        private let candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease.Scope
        private let owners: [LocalAccountIdentity]
        private let retaining: Bool
        private var protectedDigest: Data?
        private var catalog: MachineUpdateRetainedSetupPromotionCatalog.Frame?
        init(writer: PreparationIntentStore, expected: MachineUpdateRetainedSetupPromotionSnapshot,
            candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease.Scope,
            owners: [LocalAccountIdentity], retaining: Bool) {
            self.writer = writer; original = expected; self.expected = expected; self.candidate = candidate
            self.directory = directory; self.admission = admission; self.owners = owners; self.retaining = retaining
        }
        private func requireScope(_ owner: PreparationIntentStore) throws {
            guard getpid() == process, pthread_equal(pthread_self(), thread) != 0, let writer, writer === owner,
                  writer.active, writer.retainedSetupPromotionAuthorization === self, let db = writer.db,
                  sqlite3_get_autocommit(db) == 0 else { throw JournalLeaseError.invalidated }
            try writer.requireUpdateAdmissionDirectory(directory)
            try admission.validateMachineBoundary(directory: directory,
                expected: original.completion.activation.runtime.setup.source.actual.admission.machine)
        }
        func capture(in owner: PreparationIntentStore) throws -> MachineUpdateRetainedSetupPromotionSnapshot {
            try requireScope(owner)
            let actual = try owner.loadRetainedSetupPromotionSnapshot(owner: original.completion.activation.runtime.setup.owner, candidate: candidate)
            try actual.requireSame(as: expected)
            let digest = try owner.retainedSetupPromotionProtectedDigest(excluding: original.completion.activation.runtime.preparation.accountID, candidate: candidate)
            if let protectedDigest { guard digest == protectedDigest else { throw PreparationStoreError.staleRevision } }
            else { protectedDigest = digest }
            let current = try MachineUpdateRetainedSetupPromotionCatalog.capture(owner.db!)
            if let catalog { try current.requireSame(as: catalog) } else { catalog = current }
            try owner.captureRetainedSetupPromotionCompatibility(expected: actual.completion.activation.runtime.setup.source,
                owners: owners, candidate: candidate)
            try owner.loadRetainedSetupPromotionSnapshot(owner: original.completion.activation.runtime.setup.owner,
                candidate: candidate).requireSame(as: actual)
            try admission.validate(); return actual
        }
        func adopt(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord, in owner: PreparationIntentStore) throws {
            try requireScope(owner)
            let actual = try owner.loadRetainedSetupPromotionSnapshot(owner: original.completion.activation.runtime.setup.owner, candidate: candidate)
            if retaining { try actual.requireRetention(intent, from: original) } else { try actual.requireTransition(intent, from: original) }
            try intent.requireSnapshot(actual.completion, candidate: candidate)
            guard let catalog else { throw JournalLeaseError.invalidated }
            let current = try MachineUpdateRetainedSetupPromotionCatalog.capture(owner.db!)
            if retaining { try current.requireRetention(from: catalog) } else { try current.requireSame(as: catalog) }
            self.catalog = current; expected = actual; _ = try capture(in: owner)
        }
    }

    private func captureRetainedSetupPromotionCompatibility(expected: MachineUpdateStableRuntimeSource,
        owners: [LocalAccountIdentity], candidate: SignedReleaseEvidence) throws {
        try loadStableRuntimeSource(candidate: candidate).requireSame(as: expected)
        let retained = try owners.map { owner in
            let value = try loadRetainedSetupActivationSnapshot(owner: owner, candidate: candidate)
            try value.runtime.setup.source.requireSame(as: expected); return value
        }
        guard Set(retained.map { $0.runtime.preparation.accountID }).count == retained.count else {
            throw RuntimeActivationCompatibilityError.unexpectedRetainedSnapshot
        }
        let context = StableCompatibilityRead(source: expected, retained: retained)
        let inputs = try loadRetainedRuntimeCompatibilityInputs(stable: context)
        _ = try RuntimeReleaseCompatibilitySnapshot.describe(inputs: inputs)
        guard try loadRetainedRuntimeCompatibilityInputs(stable: context) == inputs else { throw PreparationStoreError.staleRevision }
    }

    /// Retains one prepared intent. Only G4 can supply native custody proof.
    func retainRetainedSetupPromotionIntent(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord,
        boundary: AuthorityJournal.MachineUpdatePolicyBoundary, expected: MachineUpdateRetainedSetupPromotionSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        native: MachineUpdateRetainedSetupPromotionNativeContext.NativeContext,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateRetainedSetupPromotionSnapshot) throws -> Void) throws
        -> MachineUpdateRetainedSetupPromotionSnapshot {
        guard intent.phase == .prepared else { throw PreparationStoreError.invalidTransition }
        return try writeRetainedSetupPromotionIntent(intent, boundary: boundary, expected: expected, candidate: candidate,
            directory: directory, admission: admission, native: native, retaining: true, observation: nil, verifyScoped: verifyScoped)
    }
    /// Changes one adjacent phase. The file marker requires a fresh read-only observation.
    func changeRetainedSetupPromotionIntent(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord,
        boundary: AuthorityJournal.MachineUpdatePolicyBoundary, expected: MachineUpdateRetainedSetupPromotionSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        native: MachineUpdateRetainedSetupPromotionNativeContext.NativeContext,
        observation: RuntimeRetainedSetupCompletionPublication.Observation? = nil,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateRetainedSetupPromotionSnapshot) throws -> Void) throws
        -> MachineUpdateRetainedSetupPromotionSnapshot {
        guard let previous = expected.intent, intent.phase != .prepared else { throw PreparationStoreError.invalidTransition }
        if previous != intent { try intent.requireTransition(from: previous) }
        return try writeRetainedSetupPromotionIntent(intent, boundary: boundary, expected: expected, candidate: candidate,
            directory: directory, admission: admission, native: native, retaining: false, observation: observation, verifyScoped: verifyScoped)
    }
    func requireRetainedSetupPromotionWriterAvailable() throws {
        guard retainedSetupPromotionAuthorization == nil, stableServiceAccountAuthorization == nil,
              stableRuntimePreparationAuthorization == nil,
              stableAccountReservationAuthorization == nil, stableAccountStorageAuthorization == nil else {
            throw PreparationStoreError.transactionActive
        }
    }
    private func writeRetainedSetupPromotionIntent(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord,
        boundary: AuthorityJournal.MachineUpdatePolicyBoundary, expected: MachineUpdateRetainedSetupPromotionSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        native: MachineUpdateRetainedSetupPromotionNativeContext.NativeContext, retaining: Bool,
        observation: RuntimeRetainedSetupCompletionPublication.Observation?,
        verifyScoped: (CompletionIntentStorageStage, MachineUpdateRetainedSetupPromotionSnapshot) throws -> Void) throws
        -> MachineUpdateRetainedSetupPromotionSnapshot {
        let schema = expected.completion.activation.runtime.setup.source.actual.schemaVersion
        try MachineUpdateRetainedSetupPromotionStorage.requireWriteFormats(candidate, sourceSchema: schema,
            operation: retaining ? .retainPrepared : .changePhase)
        try intent.requireSource(expected.completion, current: boundary, candidate: candidate)
        _ = try intent.encoded
        try native.requireActive()
        try requireRetainedSetupPromotionWriterAvailable()
        let claims = try retainedSetupCompatibilityOwners(expected: expected.completion.activation.runtime.setup.source, candidate: candidate)
        let owners = try claims.map { claim in
            let owner: LocalAccountIdentity
            do { owner = try LocalAccountDirectory.lookup(uid: claim.ownerUID) }
            catch { throw RuntimeActivationCompatibilityError.ownerUnavailable(claim.ownerUID) }
            do { try LocalAccountDirectory.validateOwnership(owner, uid: claim.ownerUID, directoryID: claim.directoryID) }
            catch { throw RuntimeActivationCompatibilityError.ownerIdentityChanged(claim.ownerUID) }
            return owner
        }
        var committed = false
        do {
            return try admission.withMachineAdmission { scope in
                let authorization = RetainedSetupPromotionAuthorization(writer: self, expected: expected, candidate: candidate,
                    directory: directory, admission: scope, owners: owners, retaining: retaining)
                try requireRetainedSetupPromotionWriterAvailable()
                retainedSetupPromotionAuthorization = authorization
                defer { retainedSetupPromotionAuthorization = nil }
                func verify(_ stage: CompletionIntentStorageStage, _ actual: MachineUpdateRetainedSetupPromotionSnapshot) throws {
                    let loan = RetainedSetupPromotionFrameLoan { approved in
                        try authorization.capture(in: self).completion.requireSame(as: approved)
                    }
                    defer { loan.expire() }
                    try native.withWriterFrame(loan) {
                        let completion = actual.completion
                        guard let initial = completion.activation.runtime.setup.account?.initialization else { throw RuntimeActivationError.incomplete }
                        let paths = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: initial.accountID,
                            journalPath: initial.journalPath, continuityPath: initial.continuityPath)
                        try MachineUpdateRetainedSetupPromotionNativeSupport.withReadOnlyPair(initial: initial,
                            verifyCurrent: { try native.verify(completion) }, openStorage: {
                                try MachineUpdateRetainedSetupPromotionNativeSupport.openExistingStorage(initial: initial,
                                    openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                                    openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory,
                                        excludingDirectory: $0) })
                            }) { journal, current in
                                try MachineUpdateRetainedSetupPromotionSourceValidation.withPinnedPair(completion: completion,
                                    readPolicyBoundary: { try journal.captureRetainedSetupPolicyBoundary(expected: initial) },
                                    verifyCurrent: current) { pair, kind, pinned in
                                        guard pair == boundary, kind == .recorded else { throw PreparationStoreError.staleRevision }
                                        try verifyScoped(stage, actual); try pinned()
                                        try intent.requireSource(completion, current: pair, candidate: candidate)
                                        if intent.phase == .filesPublished {
                                            guard let observation else { throw RuntimeActivationError.incomplete }
                                            let checked = RuntimeRetainedSetupCompletionPublication.Observation(verify: {
                                                try pinned(); try observation.verify(); try pinned()
                                            }, read: { artifact in
                                                try pinned(); let bytes = try observation.read(artifact); try pinned(); return bytes
                                            })
                                            guard try intent.publication().progress(observation: checked) == .selected else {
                                                throw RuntimeActivationError.incomplete
                                            }
                                        }
                                        try pinned()
                                    }
                            }
                    }
                }
                let before = try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verify(.beforeTransaction, actual); _ = try authorization.capture(in: self); return actual
                }
                if before.intent == intent { return before }
                try transaction(write: true, activationWrite: true, retainedSetupPromotion: authorization) {
                    let actual = try authorization.capture(in: self)
                    try verify(.inTransaction, actual); _ = try authorization.capture(in: self)
                    guard retaining ? actual.intent == nil : actual.intent != nil else { throw PreparationStoreError.staleRevision }
                    try writeRetainedSetupPromotionRow(intent, replacing: actual.intent)
                    try authorization.adopt(intent, in: self)
                    try verify(.afterMutation, authorization.capture(in: self)); _ = try authorization.capture(in: self)
                }
                committed = true
                return try transaction(write: false) {
                    let actual = try authorization.capture(in: self)
                    try verify(.afterCommit, actual); _ = try authorization.capture(in: self)
                    guard actual.intent == intent else { throw PreparationStoreError.staleRevision }; return actual
                }
            }
        } catch { if committed { unavailable = true; shutdown() }; throw error }
    }
    // Only the native driver and the owned DEBUG fixture call this primitive. It grants no custody proof.
    private func writeRetainedSetupPromotionRow(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord,
        replacing previous: MachineUpdateRetainedSetupPromotionIntentRecord?) throws {
        let accountID = try intent.publication().configuration.archive.binding.startupBinding.accountID
        let encoded = try intent.encoded, schema = try scalar("PRAGMA user_version")
        guard previous == nil && [Int64(26), 27, 28].contains(schema) || previous != nil && [Int64(27), 28].contains(schema) else {
            throw PreparationStoreError.invalidTransition
        }
        try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
            if previous == nil {
                guard intent.phase == .prepared else { throw PreparationStoreError.invalidTransition }
                if schema == 26 { try exec(MachineUpdateRetainedSetupPromotionStorage.createSQL) }
                guard try scalar("SELECT COUNT(*) FROM retained_setup_promotion_intents_v1") < 64 else { throw PreparationStoreError.capacity }
                try statement("SELECT COUNT(*) FROM retained_setup_promotion_intents_v1 WHERE id=?") { row in
                    try bind(bytes(intent.id), column: 1, row: row)
                    guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 0 else { throw PreparationStoreError.staleRevision }
                }
                try statement("INSERT INTO retained_setup_promotion_intents_v1 VALUES(?,?,?,?)") { row in
                    try bind(accountID, column: 1, row: row)
                    try bind(bytes(intent.id), column: 2, row: row); try bind(bytes(intent.revision), column: 3, row: row)
                    try bind(encoded, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
                if schema == 26 { try exec("PRAGMA user_version=27") }
            } else {
                guard let previous else { throw PreparationStoreError.staleRevision }
                try intent.requireTransition(from: previous)
                try statement("UPDATE retained_setup_promotion_intents_v1 SET revision=?,record=? WHERE account=? AND id=? AND revision=?") { row in
                    try bind(bytes(intent.revision), column: 1, row: row); try bind(encoded, column: 2, row: row)
                    try bind(accountID, column: 3, row: row)
                    try bind(bytes(previous.id), column: 4, row: row); try bind(bytes(previous.revision), column: 5, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            }
        }
    }

    #if DEBUG
    /// Runs only the private SQL primitive on an ordinary owned lease. It never supplies native custody proof.
    final class OwnedRetainedSetupPromotionSQLFixture {
        private weak var owner: PreparationIntentStore?
        private let process = getpid(), thread = pthread_self()
        fileprivate init(_ owner: PreparationIntentStore) { self.owner = owner }
        fileprivate func expire() { owner = nil }
        private func current() throws -> PreparationIntentStore {
            guard getpid() == process, pthread_equal(pthread_self(), thread) != 0, getuid() != 0,
                  let owner, owner.active else { throw JournalLeaseError.invalidated }
            try owner.lease.validate(); return owner
        }
        func write(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord,
            replacing previous: MachineUpdateRetainedSetupPromotionIntentRecord? = nil) throws {
            try current().writeRetainedSetupPromotionRow(intent, replacing: previous)
        }
        func replaceSyntheticBytesForBoundsTest(_ bytes: Data, accountID: Data) throws {
            let owner = try current()
            try owner.withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
                try owner.statement("UPDATE retained_setup_promotion_intents_v1 SET record=? WHERE account=?") { row in
                    try owner.bind(bytes, column: 1, row: row); try owner.bind(accountID, column: 2, row: row)
                    guard try owner.step(row) == SQLITE_DONE, sqlite3_changes(owner.db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            }
        }
        func limit() throws -> Int32 { sqlite3_limit(try current().db, SQLITE_LIMIT_LENGTH, -1) }
        func read(accountID: Data) throws -> MachineUpdateRetainedSetupPromotionIntentRecord? {
            let owner = try current()
            return try owner.withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
                try owner.statement("SELECT record FROM retained_setup_promotion_intents_v1 WHERE account=?") { row in
                    try owner.bind(accountID, column: 1, row: row)
                    if try owner.step(row) == SQLITE_DONE { return nil }
                    return try .decode(owner.blob(row, column: 0, maximum: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes))
                }
            }
        }
    }
    private enum RetainedSetupPromotionFixtureRollback: Error { case done }
    /// Always rolls back. Root cannot use this fixture entry, including with an existing native connection.
    /// Catch expected corruptRecord and JournalLeaseError refusals inside the body with XCTAssertThrowsError.
    /// If either error escapes, the transaction quarantines this store.
    func withOwnedRetainedSetupPromotionSQLFixture<Value>(_ body: (OwnedRetainedSetupPromotionSQLFixture) throws -> Value) throws -> Value {
        guard getuid() != 0 else { throw JournalLeaseError.unsafeMetadata }
        try requireRetainedSetupPromotionWriterAvailable()
        try lease.validate()
        var output: Value?
        do {
            try transaction(write: false) {
                let fixture = OwnedRetainedSetupPromotionSQLFixture(self)
                defer { fixture.expire() }
                output = try body(fixture)
                throw RetainedSetupPromotionFixtureRollback.done
            }
        } catch RetainedSetupPromotionFixtureRollback.done {}
        guard let output else { throw PreparationStoreError.invalidTransition }; return output
    }
    #endif

    private func retainedSetupPromotionProtectedDigest(excluding accountID: Data, candidate: SignedReleaseEvidence) throws -> Data {
        guard accountID.count == 16 else { throw PreparationStoreError.corruptRecord }
        let tables: [String] = try statement("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name") { row in
            var values: [String] = []
            while try step(row) == SQLITE_ROW {
                guard values.count < 128, let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                values.append(String(cString: name))
            }
            return values
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/RetainedSetupPromotionProtectedRows/v1\0".utf8)); hash.update(data: accountID)
        for table in tables where table != MachineUpdateRetainedSetupPromotionStorage.tableName {
            hash.update(data: try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
                try machineTableDigest(table, maximumCellBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes)
            })
        }
        hash.update(data: Data("Remozio/RetainedSetupPromotionOtherIntents/v1\0".utf8))
        if try scalar("PRAGMA user_version") >= 27 {
            let frame = try loadStableMachineUpdateFrame(candidate: candidate)
            for value in frame.promotionIntents where try value.publication().configuration.archive.binding.startupBinding.accountID != accountID {
                let bytes = try value.encoded
                hash.update(data: candidateGeneration(UInt64(bytes.count))); hash.update(data: bytes)
            }
        }
        return Data(hash.finalize())
    }

    private func loadRetainedSetupActivation(accountID: Data) throws -> RuntimeRetainedSetupActivationState {
        try withRetainedSetupRecordLimit(maximumBytes: RuntimeRetainedSetupActivationPlan.maximumBytes) {
            try statement("SELECT material,digest,registered,record FROM runtime_activation_v1 WHERE account=?") { row in
                try bind(accountID, column: 1, row: row)
                if try step(row) == SQLITE_DONE { return try .init(plan: nil, jobsRegistered: false) }
                let data = try blob(row, column: 3, maximum: RuntimeRetainedSetupActivationPlan.maximumBytes)
                let plan: RuntimeRetainedSetupActivationPlan
                do { plan = try .decode(data) } catch { throw PreparationStoreError.corruptRecord }
                guard plan.accountID == accountID, plan.reference.services.macID == macID,
                      try blob(row, column: 0, maximum: 16) == plan.reference.materialID,
                      try blob(row, column: 1, maximum: 32) == MachineUpdateActivationRecord.digest(data),
                      sqlite3_column_type(row, 2) == SQLITE_INTEGER,
                      [0, 1].contains(sqlite3_column_int64(row, 2)) else { throw PreparationStoreError.corruptRecord }
                let registered = sqlite3_column_int64(row, 2) == 1
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                return try .init(plan: plan, jobsRegistered: registered)
            }
        }
    }

    /// Reads a durable intent for the exact owner and machine state. The paired journal still needs its own observation.
    func retainedSetupPolicyIntent(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPolicyIntentRecord? {
        try transaction(write: false) {
            let material = try loadRetainedSetupPolicyMaterial(owner: owner, candidate: candidate)
            let stable = material.runtime.setup.source.actual
            guard stable.schemaVersion >= MachineUpdateRetainedSetupPolicyStorage.schemaVersion else { return nil }
            let records = try loadRetainedSetupPolicyIntents(installationID: stable.inventory.installationID)
            guard let record = records.first(where: { $0.accountID == material.runtime.preparation.accountID }) else { return nil }
            try record.requireMaterial(material, candidate: candidate)
            try loadRetainedSetupPolicyMaterial(owner: owner, candidate: candidate).requireSame(as: material)
            return record
        }
    }

    private func loadRetainedSetupPolicyIntents(installationID: Data) throws -> [MachineUpdateRetainedSetupPolicyIntentRecord] {
        try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPolicyIntentRecord.maximumBytes) {
            try statement("SELECT account,id,revision,record FROM retained_setup_policy_intents_v1 ORDER BY account LIMIT 65") { row in
                var records: [MachineUpdateRetainedSetupPolicyIntentRecord] = []
                var accounts = Set<Data>()
                while try step(row) == SQLITE_ROW {
                    guard records.count < 64 else { throw PreparationStoreError.corruptRecord }
                    let record = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(blob(row, column: 3,
                        maximum: MachineUpdateRetainedSetupPolicyIntentRecord.maximumBytes))
                    guard try blob(row, column: 0, maximum: 16) == record.accountID,
                          try blob(row, column: 1, maximum: 16) == bytes(record.id),
                          try blob(row, column: 2, maximum: 16) == bytes(record.revision),
                          record.macID == macID, record.installationID == installationID,
                          accounts.insert(record.accountID).inserted else { throw PreparationStoreError.corruptRecord }
                    records.append(record)
                }
                return records
            }
        }
    }

    private func withRetainedSetupRecordLimit<Value>(maximumBytes: Int, _ body: () throws -> Value) throws -> Value {
        guard let db else { throw PreparationStoreError.closed }
        let previous = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, -1)
        let required = Int32(maximumBytes + 4096)
        guard previous < required else { return try body() }
        _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, required)
        defer { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, previous) }
        return try body()
    }

    /// Reads archived completion metadata. The live activation plan and journal need separate validation.
    func retainedSetupCompletionIntent(accountID: Data, ownerUID: UInt32, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupCompletionIntentRecord? {
        try transaction(write: false) {
            let frame = try loadStableMachineUpdateFrame(candidate: candidate)
            guard let record = frame.completionIntents.first(where: { $0.binding.accountID == accountID }) else { return nil }
            guard record.binding.ownerUID == ownerUID else { throw PreparationStoreError.staleRevision }
            return record
        }
    }

    private func loadRetainedSetupCompletionIntents(installationID: Data, policies: [MachineUpdateRetainedSetupPolicyIntentRecord])
        throws -> [MachineUpdateRetainedSetupCompletionIntentRecord] {
        let startup = Dictionary(uniqueKeysWithValues: policies.map { ($0.accountID, $0) })
        return try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupCompletionIntentRecord.maximumBytes) {
            try statement("SELECT account,id,revision,record FROM retained_setup_completion_intents_v1 ORDER BY account LIMIT 65") { row in
                var records: [MachineUpdateRetainedSetupCompletionIntentRecord] = []
                var accounts = Set<Data>()
                while try step(row) == SQLITE_ROW {
                    guard records.count < 64 else { throw PreparationStoreError.corruptRecord }
                    let record = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(blob(row, column: 3,
                        maximum: MachineUpdateRetainedSetupCompletionIntentRecord.maximumBytes))
                    let account = record.binding.accountID
                    guard try blob(row, column: 0, maximum: 16) == account,
                          try blob(row, column: 1, maximum: 16) == bytes(record.id),
                          try blob(row, column: 2, maximum: 16) == bytes(record.revision),
                          record.binding.macID == macID, record.binding.installationID == installationID,
                          accounts.insert(account).inserted, startup[account] == record.startupIntent else {
                        throw PreparationStoreError.corruptRecord
                    }
                    records.append(record)
                }
                return records
            }
        }
    }

    /// Reads archived promotion metadata. It grants no file, startup, or writer authority.
    func retainedSetupPromotionIntent(accountID: Data, ownerUID: UInt32, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPromotionIntentRecord? {
        try transaction(write: false) {
            let frame = try loadStableMachineUpdateFrame(candidate: candidate)
            for record in frame.promotionIntents {
                let binding = try record.publication().configuration.archive.binding.startupBinding
                if binding.accountID == accountID {
                    guard binding.ownerUID == ownerUID else { throw PreparationStoreError.staleRevision }
                    return record
                }
            }
            return nil
        }
    }

    private func loadRetainedSetupPromotionIntents(installationID: Data,
        completion: [MachineUpdateRetainedSetupCompletionIntentRecord]) throws -> [MachineUpdateRetainedSetupPromotionIntentRecord] {
        let completions = Dictionary(uniqueKeysWithValues: completion.map { ($0.binding.accountID, $0) })
        return try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
            try statement("SELECT account,id,revision,record FROM retained_setup_promotion_intents_v1 ORDER BY account LIMIT 65") { row in
                var records: [MachineUpdateRetainedSetupPromotionIntentRecord] = []
                var accounts = Set<Data>(), ids = Set<UUID>()
                while try step(row) == SQLITE_ROW {
                    guard records.count < 64 else { throw PreparationStoreError.corruptRecord }
                    let record = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(blob(row, column: 3,
                        maximum: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes))
                    let archive = try record.publication().configuration.archive
                    let binding = archive.binding.startupBinding
                    guard try blob(row, column: 0, maximum: 16) == binding.accountID,
                          try blob(row, column: 1, maximum: 16) == bytes(record.id),
                          try blob(row, column: 2, maximum: 16) == bytes(record.revision),
                          binding.macID == macID, binding.installationID == installationID,
                          accounts.insert(binding.accountID).inserted, ids.insert(record.id).inserted,
                          let actual = completions[binding.accountID],
                          try actual.encoded == archive.completionIntentBytes else {
                        throw PreparationStoreError.corruptRecord
                    }
                    records.append(record)
                }
                return records
            }
        }
    }

    /// Reads signed historical metadata only. It grants no live readiness, startup, or writer authority.
    func retainedSetupPromotionReady(accountID: Data, ownerUID: UInt32, candidate: SignedReleaseEvidence)
        throws -> MachineUpdateRetainedSetupPromotionReadyRecord? {
        try transaction(write: false) {
            let frame = try loadStableMachineUpdateFrame(candidate: candidate)
            for record in frame.readyRecords {
                let binding = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(record.request).binding
                if binding.accountID == accountID {
                    guard binding.ownerUID == ownerUID else { throw PreparationStoreError.staleRevision }
                    return record
                }
            }
            return nil
        }
    }

    private func loadRetainedSetupPromotionReadyRecords(installationID: Data,
        promotions: [MachineUpdateRetainedSetupPromotionIntentRecord]) throws -> [MachineUpdateRetainedSetupPromotionReadyRecord] {
        try statement("SELECT account,id,revision,record FROM retained_setup_promotion_ready_v1 ORDER BY account LIMIT 65") { row in
            var records: [MachineUpdateRetainedSetupPromotionReadyRecord] = []
            var accounts = Set<Data>(), ids = Set<UUID>()
            while try step(row) == SQLITE_ROW {
                guard records.count < 64 else { throw PreparationStoreError.corruptRecord }
                let record = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(blob(row, column: 3,
                    maximum: MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes))
                let binding = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(record.request).binding
                guard try blob(row, column: 0, maximum: 16) == binding.accountID,
                      try blob(row, column: 1, maximum: 16) == bytes(record.id),
                      try blob(row, column: 2, maximum: 16) == bytes(record.revision),
                      binding.macID == macID, binding.installationID == installationID,
                      accounts.insert(binding.accountID).inserted, ids.insert(record.id).inserted,
                      let published = promotions.first(where: { $0.id == record.promotionID }) else {
                    throw PreparationStoreError.corruptRecord
                }
                try record.requirePublishedIntent(published)
                let selected = try published.publication().configuration.archive.binding.startupBinding
                guard selected.accountID == binding.accountID, selected.ownerUID == binding.ownerUID else {
                    throw PreparationStoreError.corruptRecord
                }
                records.append(record)
            }
            return records
        }
    }

    private func loadStableReleaseRecord() throws -> MachineUpdateStableReleaseRecord {
        try statement("SELECT id,epoch,revision,record FROM stable_release_state_v1 ORDER BY id") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
            let seal = try MachineUpdateStableReleaseRecord.decode(blob(row, column: 3, maximum: MachineUpdateStableReleaseRecord.maximumBytes))
            guard try blob(row, column: 1, maximum: 16) == bytes(seal.id),
                  try blob(row, column: 2, maximum: 16) == bytes(seal.revision),
                  try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            return seal
        }
    }

    private func loadStableMachineUpdate(candidate: SignedReleaseEvidence) throws -> MachineUpdateStableReleaseSnapshot {
        try loadStableMachineUpdateFrame(candidate: candidate).snapshot
    }

    private func loadStableMachineUpdateFrame(candidate release: SignedReleaseEvidence)
        throws -> (snapshot: MachineUpdateStableReleaseSnapshot, completionIntents: [MachineUpdateRetainedSetupCompletionIntentRecord],
            promotionIntents: [MachineUpdateRetainedSetupPromotionIntentRecord], readyRecords: [MachineUpdateRetainedSetupPromotionReadyRecord]) {
        try identity(macID)
        let schema = try scalar("PRAGMA user_version")
        guard (24...MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion).contains(schema) else {
            throw PreparationStoreError.invalidTransition
        }
        let hasRetainedPolicy = schema >= MachineUpdateRetainedSetupPolicyStorage.schemaVersion
        let hasRetainedCompletion = schema >= MachineUpdateRetainedSetupCompletionStorage.schemaVersion
        let hasRetainedPromotion = schema >= MachineUpdateRetainedSetupPromotionStorage.schemaVersion
        let hasRetainedReady = schema >= MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion
        try MachineUpdateStableReleaseRecord.requireFormats(release)
        if hasRetainedPolicy { try MachineUpdateRetainedSetupPolicyStorage.requireReaderFormats(release) }
        if hasRetainedCompletion { try MachineUpdateRetainedSetupCompletionStorage.requireReaderFormats(release) }
        if hasRetainedPromotion { try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(release) }
        if hasRetainedReady { try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(release) }
        guard let inventory = try loadInventoryRecord(), let candidate = try loadUpdateCandidate(),
              let activation = try loadMachineUpdateActivationRecord(), let admission = try loadUpdateAdmissionRegistration(),
              try loadAll().first(where: { $0.id == candidate.preparation.id }) == candidate.preparation else {
            throw PreparationStoreError.corruptRecord
        }
        for table in Self.completionRetirementTables {
            guard try scalar("SELECT COUNT(*) FROM \(table)") == 0 else { throw PreparationStoreError.corruptRecord }
        }
        let seal = try loadStableReleaseRecord()
        guard activation == seal.completed else { throw PreparationStoreError.corruptRecord }
        try requireFinishingActivation(seal.finishing, inventory: inventory, candidate: candidate, admission: admission, schema: schema)
        let (header, rows) = try loadInstalledReleaseRows()
        let installed = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: header.encoded, artifacts: rows, candidate: release)
        guard try installed.inventory() == inventory else { throw PreparationStoreError.corruptRecord }
        try seal.requireCurrentInventory(inventory, epoch: installed, candidate: release)
        let policies = hasRetainedPolicy ? try loadRetainedSetupPolicyIntents(installationID: inventory.installationID) : []
        let completion = hasRetainedCompletion
            ? try loadRetainedSetupCompletionIntents(installationID: inventory.installationID, policies: policies) : []
        let promotions = hasRetainedPromotion
            ? try loadRetainedSetupPromotionIntents(installationID: inventory.installationID, completion: completion) : []
        let ready = hasRetainedReady
            ? try loadRetainedSetupPromotionReadyRecords(installationID: inventory.installationID, promotions: promotions) : []
        let current = try installedCurrentSourceProjection(inventory: inventory, installed: installed, schema: schema)
        let snapshot = MachineUpdateStableReleaseSnapshot(schemaVersion: schema, inventory: inventory, activation: activation,
            admission: admission, candidate: candidate, installed: installed, seal: seal, currentRowsDigest: current.digest)
        return (snapshot, completion, promotions, ready)
    }

    private func loadMachineUpdateFinalization(candidate release: SignedReleaseEvidence) throws -> MachineUpdateFinalizationSnapshot {
        try identity(macID)
        let schema = try scalar("PRAGMA user_version")
        guard schema < 24 else { throw PreparationStoreError.invalidTransition }
        try requireInstalledReleaseFormats(release)
        guard schema == 23, let inventory = try loadInventoryRecord(),
              let candidate = try loadUpdateCandidate(), let activation = try loadMachineUpdateActivation(),
              let admission = try loadUpdateAdmissionRegistration(), activation.phase == .finishing,
              try loadAll().first(where: { $0.id == candidate.preparation.id }) == candidate.preparation else {
            throw PreparationStoreError.staleRevision
        }
        for table in Self.completionRetirementTables {
            guard try scalar("SELECT COUNT(*) FROM \(table)") == 0 else { throw PreparationStoreError.corruptRecord }
        }
        let (header, rows) = try loadInstalledReleaseRows()
        let archive = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: header.encoded, artifacts: rows, candidate: release)
        guard try archive.inventory() == inventory else { throw PreparationStoreError.staleRevision }
        let intent = try archive.completionIntent()
        var preparations: [AccountPreparationIntent] = []
        for account in intent.record.accounts {
            if let preparation = try loadAccountPreparation(ownerUID: account.ownerUID) {
                guard preparation.accountID == account.accountID, preparation.macID == macID,
                      preparation.installationID == inventory.installationID else { throw PreparationStoreError.staleRevision }
                preparations.append(preparation)
            }
        }
        var initializations: [AuthorityInitializationIntent] = []
        for policy in intent.policies {
            guard let initial = try loadInitialization(accountID: policy.binding.accountID), initial.complete,
                  initial.installationID == inventory.installationID,
                  let preparation = preparations.first(where: { $0.accountID == initial.accountID }),
                  initial.releaseDigest == preparation.releaseDigest, initial.initializationBytes == preparation.initializationBytes,
                  let account = intent.record.accounts.first(where: { $0.accountID == initial.accountID }),
                  account.inInventory == inventory.accounts.contains(where: { $0.accountID == initial.accountID }),
                  !account.inInventory || inventory.accounts.contains(where: { $0.accountID == initial.accountID && $0.ownerUID == account.ownerUID }) else {
                throw PreparationStoreError.staleRevision
            }
            initializations.append(initial)
        }
        return .init(schemaVersion: 23, inventory: inventory, candidate: candidate, activation: activation,
            admission: admission, installed: archive, preparations: preparations, initializations: initializations)
    }

    /// Lends one exact publication frame. This loan grants no native file writer or metadata retirement authority.
    final class CompletionPublicationScope: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private let snapshot: MachineUpdateCompletionPublicationSnapshot
        private var verifyCurrent: (() throws -> Void)?
        private var active = true
        fileprivate init(snapshot: MachineUpdateCompletionPublicationSnapshot, verifyCurrent: @escaping () throws -> Void) {
            self.snapshot = snapshot; self.verifyCurrent = verifyCurrent
        }
        func read() throws -> MachineUpdateCompletionPublicationSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard active, let verifyCurrent else { throw JournalLeaseError.invalidated }
                do { try verifyCurrent(); guard active else { throw JournalLeaseError.invalidated }; return snapshot }
                catch { expire(); throw error }
            }
        }
        fileprivate func expire() { lock.withLock { active = false; verifyCurrent = nil } }
    }
    enum CompletionPublicationOperation {
        case prepare(Data, MachineUpdateCompletionPublicationPlan.File)
        case complete(Data, MachineUpdateCompletionPublicationPlan.File)
    }
    func machineUpdateCompletionPublication() throws -> MachineUpdateCompletionPublicationRecord? {
        try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") == 22 else { return nil }
            return try loadCompletionPublication()
        }
    }
    func withCurrentMachineUpdateCompletionPublication<Value>(expected: MachineUpdateCompletionIntentArchive,
        publication: MachineUpdateCompletionPublicationRecord?, plan: MachineUpdateCompletionPublicationPlan,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionPublicationScope) throws -> Value) throws -> Value {
        try restart.withClosedAdmission {
            try transaction(write: false) {
                try withCompletionPublicationScope(expected: expected, publication: publication, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart, body)
            }
        }
    }
    private func completionPublicationSnapshot(expected: MachineUpdateCompletionIntentArchive,
        publication: MachineUpdateCompletionPublicationRecord?, plan: MachineUpdateCompletionPublicationPlan,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease) throws -> MachineUpdateCompletionPublicationSnapshot {
        try requireCompletionPublicationFormats(candidate)
        try restart.validate()
        let completion = try loadCompletionRecoverySnapshot(candidate: candidate, directory: directory, allowPublication: true)
        try completion.requireSame(as: .init(restart: restartSnapshot, intent: expected))
        try restart.validateMachineBoundary(directory: directory, expected: restartSnapshot.source.replacement.admission.machine)
        guard expected.policyMarkersRecorded else { throw PreparationStoreError.invalidTransition }
        let version = try scalar("PRAGMA user_version")
        if let publication {
            guard version == 22, try loadCompletionPublication() == publication else { throw PreparationStoreError.staleRevision }
            try publication.requirePlan(plan)
        } else {
            guard version == 21 else { throw PreparationStoreError.staleRevision }
            let retainedPlan = try MachineUpdateCompletionPublicationPlan(retainedConfiguration: completion.restart.configuration,
                retainedBackend: completion.restart.backend, intent: completion.intent, candidate: candidate)
            guard try retainedPlan.fingerprint == plan.fingerprint else { throw PreparationStoreError.staleRevision }
        }
        return try .init(completion: completion, publication: publication, candidate: candidate)
    }
    private func withCompletionPublicationScope<Value>(expected: MachineUpdateCompletionIntentArchive,
        publication: MachineUpdateCompletionPublicationRecord?, plan: MachineUpdateCompletionPublicationPlan,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionPublicationScope) throws -> Value) throws -> Value {
        let value = try completionPublicationSnapshot(expected: expected, publication: publication, plan: plan,
            restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart)
        let scope = CompletionPublicationScope(snapshot: value, verifyCurrent: { [weak self] in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            try self.completionPublicationSnapshot(expected: expected, publication: publication, plan: plan,
                restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart).requireSame(as: value)
        })
        defer { scope.expire() }
        _ = try scope.read(); let result = try body(scope); _ = try scope.read(); return result
    }
    /// Retains the first publication intent in one explicit schema transition. It changes no policy or external file.
    func retainMachineUpdateCompletionPublication(_ publication: MachineUpdateCompletionPublicationRecord,
        plan: MachineUpdateCompletionPublicationPlan, expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionPublicationScope) throws -> Void) throws -> MachineUpdateCompletionPublicationRecord {
        try publication.requirePlan(plan)
        guard publication.inventoryState == .pending, publication.entries.allSatisfy({ $0.state == .pending }) else {
            throw PreparationStoreError.invalidTransition
        }
        return try restart.withClosedAdmission {
            let previous: MachineUpdateCompletionPublicationRecord? = try transaction(write: false) {
                let version = try scalar("PRAGMA user_version")
                let retained = try version == 22 ? loadCompletionPublication() : nil
                guard retained == nil || retained == publication else { throw PreparationStoreError.staleRevision }
                try withCompletionPublicationScope(expected: expected, publication: retained, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.beforeTransaction, $0)
                }
                return retained
            }
            let result = try transaction(write: previous == nil, activationWrite: true) {
                try withCompletionPublicationScope(expected: expected, publication: previous, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.inTransaction, $0)
                }
                if previous != nil { return publication }
                try exec("CREATE TABLE machine_update_completion_publication_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 524288)) STRICT")
                try exec("PRAGMA user_version=22"); try identity(macID)
                try writeCompletionPublication(publication, replacing: nil)
                try withCompletionPublicationScope(expected: expected, publication: publication, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.afterMutation, $0)
                }
                return publication
            }
            return try finishCompletionPublication(result, plan: plan, expected: expected, restartSnapshot: restartSnapshot,
                candidate: candidate, directory: directory, restart: restart, verifyScoped: verifyScoped)
        }
    }
    func advanceMachineUpdateCompletionPublication(_ publication: MachineUpdateCompletionPublicationRecord,
        operation: CompletionPublicationOperation, plan: MachineUpdateCompletionPublicationPlan,
        expected: MachineUpdateCompletionIntentArchive, restartSnapshot: MachineUpdateRestartSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionPublicationScope) throws -> Void) throws -> MachineUpdateCompletionPublicationRecord {
        let next: MachineUpdateCompletionPublicationRecord
        switch operation {
        case .prepare(let account, let file): next = try publication.advancing(accountID: account, file: file, to: .writing)
        case .complete(let account, let file): next = try publication.advancing(accountID: account, file: file, to: .published)
        }
        try next.requirePlan(plan)
        return try restart.withClosedAdmission {
            try transaction(write: false) {
                try withCompletionPublicationScope(expected: expected, publication: publication, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.beforeTransaction, $0)
                }
            }
            let result = try transaction(write: true, activationWrite: true) {
                try withCompletionPublicationScope(expected: expected, publication: publication, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.inTransaction, $0)
                }
                try writeCompletionPublication(next, replacing: publication)
                try withCompletionPublicationScope(expected: expected, publication: next, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.afterMutation, $0)
                }
                return next
            }
            return try finishCompletionPublication(result, plan: plan, expected: expected, restartSnapshot: restartSnapshot,
                candidate: candidate, directory: directory, restart: restart, verifyScoped: verifyScoped)
        }
    }
    private func finishCompletionPublication(_ publication: MachineUpdateCompletionPublicationRecord,
        plan: MachineUpdateCompletionPublicationPlan, expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionPublicationScope) throws -> Void) throws -> MachineUpdateCompletionPublicationRecord {
        do {
            return try transaction(write: false) {
                try withCompletionPublicationScope(expected: expected, publication: publication, plan: plan,
                    restartSnapshot: restartSnapshot, candidate: candidate, directory: directory, restart: restart) {
                    try verifyScoped(.afterCommit, $0)
                }
                return publication
            }
        } catch { unavailable = true; shutdown(); throw error }
    }
    /// Reads the publication frame without claiming file publication or admission authority.
    func machineUpdateCompletionPublicationRecoverySnapshot(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease) throws -> MachineUpdateCompletionPublicationSnapshot {
        try transaction(write: false) {
            try requireCompletionPublicationFormats(candidate)
            guard try scalar("PRAGMA user_version") == 22 else { throw PreparationStoreError.invalidTransition }
            let completion = try loadCompletionRecoverySnapshot(candidate: candidate, directory: directory, allowPublication: true)
            return try .init(completion: completion, publication: loadCompletionPublication(), candidate: candidate)
        }
    }

    private func requireCompletionPublicationFormats(_ candidate: SignedReleaseEvidence) throws {
        try requireCompletionIntentFormats(candidate)
        for requirement in try MachineUpdateCompletionPublicationRecord.requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
    private func writeCompletionPublication(_ publication: MachineUpdateCompletionPublicationRecord,
        replacing previous: MachineUpdateCompletionPublicationRecord?) throws {
        if let previous { guard try loadCompletionPublication() == previous else { throw PreparationStoreError.staleRevision } }
        let sql = previous == nil ? "INSERT INTO machine_update_completion_publication_v1 VALUES(1,?,?,?)" :
            "UPDATE machine_update_completion_publication_v1 SET id=?,revision=?,record=? WHERE singleton=1"
        try withCompletionPublicationRecordLimit {
            try statement(sql) { row in
                try bind(bytes(publication.id), column: 1, row: row); try bind(bytes(publication.revision), column: 2, row: row)
                try bind(publication.encoded, column: 3, row: row)
                guard try step(row) == SQLITE_DONE, let db, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
            }
        }
        guard try loadCompletionPublication() == publication else { throw PreparationStoreError.staleRevision }
    }
    private func loadCompletionPublication() throws -> MachineUpdateCompletionPublicationRecord {
        let value: MachineUpdateCompletionPublicationRecord = try withCompletionPublicationRecordLimit {
            try statement("SELECT singleton,id,revision,record FROM machine_update_completion_publication_v1 ORDER BY singleton") { row in
                guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                      sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
                let id = try blob(row, column: 1, maximum: 16), revision = try blob(row, column: 2, maximum: 16)
                let record = try blob(row, column: 3, maximum: MachineUpdateCompletionPublicationRecord.maximumBytes)
                let value = try MachineUpdateCompletionPublicationRecord.decode(record)
                guard id == bytes(value.id), revision == bytes(value.revision), try step(row) == SQLITE_DONE else {
                    throw PreparationStoreError.corruptRecord
                }
                return value
            }
        }
        let intent = try loadMachineUpdateCompletionIntent()
        let activation = try MachineUpdateActivationRecord.decode(intent.record.activation)
        guard intent.policyMarkersRecorded, try value.intentDigest == MachineUpdateActivationRecord.digest(intent.record.encoded),
              value.sourceInventoryDigest == activation.inventoryDigest,
              value.targetInventoryDigest == MachineUpdateActivationRecord.digest(intent.record.targetInventory) else {
            throw PreparationStoreError.corruptRecord
        }
        return value
    }
    private func withCompletionPublicationRecordLimit<Value>(_ body: () throws -> Value) throws -> Value {
        guard let db else { throw PreparationStoreError.closed }
        let previous = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, Int32(MachineUpdateCompletionPublicationRecord.maximumBytes + 4096))
        defer { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, previous) }
        return try body()
    }

    /// A synchronous loan of one verified completion read. The loan expires before a later machine write can start.
    final class CompletionSnapshotScope: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private let snapshot: MachineUpdateCompletionSnapshot
        private var verifyCurrent: (() throws -> Void)?
        private var active = true
        fileprivate init(snapshot: MachineUpdateCompletionSnapshot, verifyCurrent: @escaping () throws -> Void) {
            self.snapshot = snapshot; self.verifyCurrent = verifyCurrent
        }
        func read() throws -> MachineUpdateCompletionSnapshot {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard active, let verifyCurrent else { throw JournalLeaseError.invalidated }
                do {
                    try verifyCurrent()
                    guard active else { throw JournalLeaseError.invalidated }
                    return snapshot
                } catch { active = false; throw error }
            }
        }
        fileprivate func expire() { lock.withLock { active = false; verifyCurrent = nil } }
    }

    func withCurrentMachineUpdateCompletionSnapshot<Value>(expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionSnapshotScope) throws -> Value) throws -> Value {
        try restart.withClosedAdmission {
            try transaction(write: false) {
                try withCompletionSnapshotInTransaction(expected: expected, restartSnapshot: restartSnapshot,
                    candidate: candidate, directory: directory, restart: restart, body)
            }
        }
    }

    private func withCompletionSnapshotInTransaction<Value>(expected: MachineUpdateCompletionIntentArchive,
        restartSnapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        _ body: (CompletionSnapshotScope) throws -> Value) throws -> Value {
        func readCurrent(_ store: PreparationIntentStore) throws -> MachineUpdateCompletionSnapshot {
            try restart.validate()
            let current = try store.loadCompletionRecoverySnapshot(candidate: candidate, directory: directory)
            try current.requireSame(as: .init(restart: restartSnapshot, intent: expected))
            try restart.validateMachineBoundary(directory: directory, expected: current.restart.source.replacement.admission.machine)
            return current
        }
        let snapshot = try readCurrent(self)
        let scope = CompletionSnapshotScope(snapshot: snapshot, verifyCurrent: { [weak self] in
            guard let self, self.active else { throw JournalLeaseError.invalidated }
            _ = try readCurrent(self)
        })
        defer { scope.expire() }
        _ = try scope.read()
        let value = try body(scope)
        _ = try scope.read()
        return value
    }

    /// Acknowledges one new durable marker. It cannot be decoded, renewed or used for a second attempt.
    final class PolicyWritePermit: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        private let lock = NSLock()
        private let processID = getpid()
        private let thread = pthread_self()
        private var used = false
        let archive: MachineUpdateCompletionIntentArchive
        let accountID: Data
        fileprivate init(archive: MachineUpdateCompletionIntentArchive, accountID: Data) {
            self.archive = archive; self.accountID = accountID
        }
        var description: String { "PolicyWritePermit(redacted)" }
        var debugDescription: String { description }
        func consume(in scope: CompletionSnapshotScope) throws -> MachineUpdatePolicyIntentRecord {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            return try lock.withLock {
                guard !used else { throw JournalLeaseError.invalidated }
                used = true
                let current = try scope.read()
                guard current.intent == archive,
                      let record = archive.policies.first(where: { $0.binding.accountID == accountID }),
                      record.phase == .writing else { throw PreparationStoreError.staleRevision }
                return record
            }
        }
    }

    struct AuthorizedPolicyWrite {
        let archive: MachineUpdateCompletionIntentArchive
        let permit: PolicyWritePermit
        fileprivate init(archive: MachineUpdateCompletionIntentArchive, accountID: Data) {
            self.archive = archive; permit = PolicyWritePermit(archive: archive, accountID: accountID)
        }
    }

    /// Issues a permit only after this new marker receives its final acknowledgment.
    func authorizeMachineUpdatePolicyWrite(expected: MachineUpdateCompletionIntentArchive, accountID: Data,
        boundary: AuthorityJournal.MachineUpdatePolicyBoundary, snapshot: MachineUpdateRestartSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        readBoundary: (CompletionSnapshotScope) throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyScoped: (CompletionIntentStorageStage, CompletionSnapshotScope) throws -> Void) throws -> AuthorizedPolicyWrite {
        guard !expected.policies.contains(where: { $0.phase == .writing }) else {
            throw PreparationStoreError.invalidTransition
        }
        let next = try mutateCompletionIntent(expected: expected, snapshot: snapshot, candidate: candidate,
            directory: directory, restart: restart, verifyScoped: { stage, scope in
                try verifyScoped(stage, scope)
                guard try readBoundary(scope) == boundary else { throw PreparationStoreError.staleRevision }
                try verifyScoped(stage, scope)
            }) {
            try $0.preparingWrite(accountID: accountID, expected: boundary)
        }
        try restart.validate()
        return AuthorizedPolicyWrite(archive: next, accountID: accountID)
    }

    func recordMachineUpdatePolicyReceipt(_ receipt: AuthorityJournal.MachineUpdatePolicyCommitReceipt,
        expected: MachineUpdateCompletionIntentArchive, snapshot: MachineUpdateRestartSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionSnapshotScope) throws -> Void) throws -> MachineUpdateCompletionIntentArchive {
        try mutateCompletionIntent(expected: expected, snapshot: snapshot, candidate: candidate, directory: directory,
            restart: restart, verifyScoped: verifyScoped) { try $0.recording(receipt) }
    }

    func recordRecoveredMachineUpdatePolicyBoundary(_ boundary: AuthorityJournal.MachineUpdatePolicyBoundary,
        expected: MachineUpdateCompletionIntentArchive, snapshot: MachineUpdateRestartSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionSnapshotScope) throws -> Void) throws -> MachineUpdateCompletionIntentArchive {
        try mutateCompletionIntent(expected: expected, snapshot: snapshot, candidate: candidate, directory: directory,
            restart: restart, verifyScoped: verifyScoped) { try $0.recordingRecoveredBoundary(boundary) }
    }

    private func mutateCompletionIntent(expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verifyScoped: (CompletionIntentStorageStage, CompletionSnapshotScope) throws -> Void,
        mutation: (MachineUpdateCompletionIntentArchive) throws -> MachineUpdateCompletionIntentArchive) throws -> MachineUpdateCompletionIntentArchive {
        try restart.withClosedAdmission {
            try transaction(write: false) {
                try withCompletionSnapshotInTransaction(expected: expected, restartSnapshot: snapshot, candidate: candidate,
                    directory: directory, restart: restart) { try verifyScoped(.beforeTransaction, $0) }
            }
            try restart.validate()
            let value = try transaction(write: true, activationWrite: true) {
                try withCompletionSnapshotInTransaction(expected: expected, restartSnapshot: snapshot, candidate: candidate,
                    directory: directory, restart: restart) { try verifyScoped(.inTransaction, $0) }
                let next = try mutation(expected)
                try writeCompletionIntent(next)
                try withCompletionSnapshotInTransaction(expected: next, restartSnapshot: snapshot, candidate: candidate,
                    directory: directory, restart: restart) { try verifyScoped(.afterMutation, $0) }
                return next
            }
            do {
                return try transaction(write: false) {
                    try withCompletionSnapshotInTransaction(expected: value, restartSnapshot: snapshot, candidate: candidate,
                        directory: directory, restart: restart) { try verifyScoped(.afterCommit, $0) }
                    return value
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    /// Reads the retained intent and the verified historical restart frame in one transaction.
    func machineUpdateCompletionRecoverySnapshot(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease) throws -> MachineUpdateCompletionSnapshot {
        try transaction(write: false) {
            try loadCompletionRecoverySnapshot(candidate: candidate, directory: directory)
        }
    }

    private func loadCompletionRecoverySnapshot(candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, allowPublication: Bool = false) throws -> MachineUpdateCompletionSnapshot {
        try identity(macID); try requireUpdateAdmissionDirectory(directory)
        let schema = try scalar("PRAGMA user_version")
        guard schema == 21 || (allowPublication && schema == 22),
              let activation = try loadMachineUpdateActivation(), activation.phase == .restartChecking,
              let configuration = try loadMachineUpdateConfigurationEpoch(), configuration.record.publication?.complete == true,
              let backend = try loadMachineUpdateBackendEpoch(epoch: configuration),
              backend.record.accounts != nil, backend.record.publication?.complete == true else {
            throw PreparationStoreError.invalidTransition
        }
        try requireCompletionIntentFormats(candidate)
        let current = try requireCurrentConfigurationEpoch(configuration.record, directory: directory, allowCompletionSchema: true)
        let actual = current.replacement
        guard actual.runtime.schemaVersion == schema, actual.runtime.completionIntent != nil else {
            throw PreparationStoreError.staleRevision
        }
        let historical = MachineUpdateReplacementContext(activation: actual.activation, inventory: actual.inventory,
            candidate: actual.candidate, admission: actual.admission, replacement: actual.replacement,
            runtime: actual.runtime.completionSourceInputs())
        let source = MachineUpdateRestartSource(replacement: historical, accounts: current.accounts,
            provisioningHistory: current.provisioningHistory)
        let snapshot = MachineUpdateRestartSnapshot(source: source, configuration: configuration, backend: backend)
        let intent = try loadMachineUpdateCompletionIntent()
        try intent.requireSnapshot(snapshot, candidate: candidate, currentSourceDigest: machineEpochSourceDigest(normalizedSchema: 20))
        return .init(restart: snapshot, intent: intent)
    }

    private func requireCompletionIntentFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try MachineUpdateCompletionIntentRecord.requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }

    private func writeCompletionIntent(_ value: MachineUpdateCompletionIntentArchive) throws {
        try value.validate()
        try exec("DELETE FROM machine_update_completion_intent_v1")
        func write(kind: Int64, account: Data, id: UUID, revision: UUID, record: Data) throws {
            try statement("INSERT INTO machine_update_completion_intent_v1 VALUES(?,?,?,?,?)") { row in
                guard sqlite3_bind_int64(row, 1, kind) == SQLITE_OK else { throw PreparationStoreError.corruptRecord }
                try bind(account, column: 2, row: row); try bind(bytes(id), column: 3, row: row)
                try bind(bytes(revision), column: 4, row: row); try bind(record, column: 5, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
        }
        try write(kind: 0, account: Data([0]), id: value.record.id, revision: value.record.revision, record: value.record.encoded)
        for policy in value.policies {
            try write(kind: 1, account: policy.binding.accountID, id: policy.id, revision: policy.revision, record: policy.encoded)
        }
    }

    private func loadMachineUpdateCompletionIntent() throws -> MachineUpdateCompletionIntentArchive {
        try statement("SELECT kind,account,id,revision,record FROM machine_update_completion_intent_v1 ORDER BY kind,account") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == 0, try blob(row, column: 1, maximum: 1) == Data([0]) else {
                throw PreparationStoreError.corruptRecord
            }
            let header = try MachineUpdateCompletionIntentRecord.decode(blob(row, column: 4, maximum: MachineUpdateCompletionIntentRecord.maximumBytes))
            guard try blob(row, column: 2, maximum: 16) == bytes(header.id),
                  try blob(row, column: 3, maximum: 16) == bytes(header.revision) else { throw PreparationStoreError.corruptRecord }
            var policies: [MachineUpdatePolicyIntentRecord] = []
            while try step(row) == SQLITE_ROW {
                guard policies.count < 128, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                      sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
                let policy = try MachineUpdatePolicyIntentRecord.decode(blob(row, column: 4, maximum: MachineUpdatePolicyIntentRecord.maximumBytes))
                guard try blob(row, column: 1, maximum: 16) == policy.binding.accountID,
                      try blob(row, column: 2, maximum: 16) == bytes(policy.id),
                      try blob(row, column: 3, maximum: 16) == bytes(policy.revision) else { throw PreparationStoreError.corruptRecord }
                policies.append(policy)
            }
            let archive = try MachineUpdateCompletionIntentArchive(record: header, policies: policies)
            guard try MachineUpdateActivationRecord.decode(header.activation).macID == macID else { throw PreparationStoreError.wrongMac }
            return archive
        }
    }

    private func completionIntentFingerprint() throws -> Data {
        _ = try loadMachineUpdateCompletionIntent()
        return try machineTableDigest("machine_update_completion_intent_v1")
    }

    func machineUpdateBackendEpoch() throws -> MachineUpdateBackendEpoch.Archive? {
        try transaction(write: false) {
            try identity(macID)
            guard try scalar("PRAGMA user_version") >= 20 else { return nil }
            guard let epoch = try loadMachineUpdateConfigurationEpoch(), let archive = try loadMachineUpdateBackendEpoch(epoch: epoch) else {
                throw PreparationStoreError.corruptRecord
            }
            return archive
        }
    }

    /// The protected verifier checks actual backend files before, during and after the durable write.
    func retainMachineUpdateBackendEpoch(_ expected: MachineUpdateBackendEpochRecord,
        captures: [MachineUpdateBackendEpoch.Capture], candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        verifyCurrent: () throws -> Void) throws -> MachineUpdateBackendEpochRecord {
        try quiescence.withExclusiveActivity { _ in
            let value = try transaction(write: true, activationWrite: true) {
                guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                try MachineUpdateBackendEpoch.requireFormats(candidate, epoch: epoch)
                try requireCurrentBackendEpoch(expected, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent()
                guard let inventory = try loadInventoryRecord() else { throw PreparationStoreError.corruptRecord }
                for capture in captures {
                    let state = try loadGatewayRuntimeActivation(accountID: capture.accountID)
                    if let activation = state.plan, state.filesPublished {
                        guard let foreground = try loadRuntimeActivation(accountID: capture.accountID).plan,
                              let source = capture.source else { throw PreparationStoreError.staleRevision }
                        let actual = try RuntimeReleaseBackendSource(foreground: foreground, activation: activation,
                            journal: loadGatewayJournalPreparation(accountID: capture.accountID),
                            settings: loadGatewaySettingsTransition(accountID: capture.accountID), inventory: inventory)
                        guard try actual.encoded == source.encoded else { throw PreparationStoreError.staleRevision }
                    } else {
                        guard capture.source == nil, capture.startup == nil, capture.completion == nil else { throw PreparationStoreError.staleRevision }
                    }
                }
                let next = try expected.retaining(captures, epoch: epoch)
                if next == expected { try verifyCurrent(); return expected }
                let artifacts = try MachineUpdateBackendEpoch.artifacts(captures, epoch: epoch)
                for artifact in artifacts {
                    try writeBackendEpochRow(kind: artifact.kind, account: artifact.accountID, bytes: artifact.bytes, record: next)
                }
                try statement("UPDATE machine_update_backend_epoch_v1 SET revision=?,record=? WHERE kind=0 AND epoch=? AND revision=?") { row in
                    try bind(bytes(next.revision), column: 1, row: row); try bind(next.encoded, column: 2, row: row)
                    try bind(bytes(next.id), column: 3, row: row); try bind(bytes(expected.revision), column: 4, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
                try requireCurrentBackendEpoch(next, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent(); return next
            }
            do {
                return try transaction(write: false) {
                    guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                    try requireCurrentBackendEpoch(value, epoch: epoch, directory: directory, quiescence: quiescence)
                    try verifyCurrent(); return value
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    func advanceMachineUpdateBackendPublication(_ expected: MachineUpdateBackendEpochRecord,
        operation: MachineUpdateBackendPublicationOperation, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verifyCurrent: (MachineUpdateBackendEpochRecord) throws -> Void) throws -> MachineUpdateBackendEpochRecord {
        let next = try expected.applying(operation)
        return try quiescence.withExclusiveActivity { _ in
            let value = try transaction(write: true, activationWrite: true) {
                guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                try MachineUpdateBackendEpoch.requirePublicationFormats(candidate, epoch: epoch)
                try requireCurrentBackendEpoch(expected, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent(expected); try verifyCurrent(next)
                try withBackendRecordLimit {
                    try statement("UPDATE machine_update_backend_epoch_v1 SET revision=? WHERE epoch=? AND revision=?") { row in
                        try bind(bytes(next.revision), column: 1, row: row); try bind(bytes(next.id), column: 2, row: row)
                        try bind(bytes(expected.revision), column: 3, row: row)
                        guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == Int32(next.operands.count + 1) else { throw PreparationStoreError.staleRevision }
                    }
                    try statement("UPDATE machine_update_backend_epoch_v1 SET record=? WHERE kind=0 AND epoch=? AND revision=?") { row in
                        try bind(next.encoded, column: 1, row: row); try bind(bytes(next.id), column: 2, row: row)
                        try bind(bytes(next.revision), column: 3, row: row)
                        guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                    }
                }
                try requireCurrentBackendEpoch(next, epoch: epoch, directory: directory, quiescence: quiescence)
                try verifyCurrent(next); return next
            }
            do {
                return try transaction(write: false) {
                    guard let epoch = try loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                    try requireCurrentBackendEpoch(value, epoch: epoch, directory: directory, quiescence: quiescence)
                    try verifyCurrent(value); return value
                }
            } catch { unavailable = true; shutdown(); throw error }
        }
    }

    /// This verifier expires when the callback returns. It grants no native identity, file writer or admission.
    func withCurrentMachineUpdateBackendEpoch<Value>(_ expected: MachineUpdateBackendEpochRecord,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try quiescence.withExclusiveActivity { _ in
            try transaction(write: false) {
                let processID = getpid()
                var scopeActive = true; defer { scopeActive = false }
                let validate: () throws -> Void = { [weak self] in
                    guard scopeActive, getpid() == processID, let self else { throw JournalLeaseError.invalidated }
                    guard let epoch = try self.loadMachineUpdateConfigurationEpoch() else { throw PreparationStoreError.corruptRecord }
                    try self.requireCurrentBackendEpoch(expected, epoch: epoch, directory: directory, quiescence: quiescence)
                }
                try validate(); let value = try body(validate); try validate(); return value
            }
        }
    }

    private func withBackendRecordLimit<Value>(_ body: () throws -> Value) throws -> Value {
        guard let db else { throw PreparationStoreError.closed }
        let previous = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 2150000)
        defer { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, previous) }
        return try body()
    }
    private func writeBackendEpochRow(kind: Int64, account: Data, bytes recordBytes: Data,
        record: MachineUpdateBackendEpochRecord) throws {
        try withBackendRecordLimit {
            try statement("INSERT INTO machine_update_backend_epoch_v1 VALUES(?,?,?,?,?)") { row in
                try bind(kind, column: 1, row: row); try bind(account, column: 2, row: row)
                try bind(bytes(record.id), column: 3, row: row); try bind(bytes(record.revision), column: 4, row: row)
                try bind(recordBytes, column: 5, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        }
    }
    private func requireCurrentBackendEpoch(_ expected: MachineUpdateBackendEpochRecord,
        epoch: MachineUpdateConfigurationEpoch.Archive, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease) throws {
        try requireCurrentConfigurationEpoch(epoch.record, directory: directory, quiescence: quiescence)
        guard try loadMachineUpdateBackendEpoch(epoch: epoch)?.record == expected,
              try expected.currentSourceDigest == machineEpochSourceDigest() else { throw PreparationStoreError.staleRevision }
    }
    private func loadMachineUpdateBackendEpoch(epoch: MachineUpdateConfigurationEpoch.Archive) throws -> MachineUpdateBackendEpoch.Archive? {
        try withBackendRecordLimit {
            let rows: [(Int64, Data, Data, Data, Data)] = try statement("SELECT kind,account,epoch,revision,record FROM machine_update_backend_epoch_v1 ORDER BY kind,account") { row in
                var values: [(Int64, Data, Data, Data, Data)] = []
                while try step(row) == SQLITE_ROW {
                    guard values.count < 385, sqlite3_column_type(row, 0) == SQLITE_INTEGER else { throw PreparationStoreError.corruptRecord }
                    let kind = sqlite3_column_int64(row, 0)
                    guard (0...3).contains(kind) else { throw PreparationStoreError.corruptRecord }
                    let maximum = kind == 0 ? MachineUpdateBackendEpochRecord.maximumBytes : kind == 1 ? RuntimeReleaseBackendSource.maximumBytes : RuntimeReleaseBackendPlan.maximumBytes
                    values.append(try (kind, blob(row, column: 1, maximum: 16), blob(row, column: 2, maximum: 16),
                        blob(row, column: 3, maximum: 16), blob(row, column: 4, maximum: maximum)))
                }
                return values
            }
            guard let first = rows.first else { return nil }
            guard first.0 == 0, first.1 == MachineUpdateBackendEpoch.global else { throw PreparationStoreError.corruptRecord }
            let header = try MachineUpdateBackendEpochRecord.decode(first.4)
            guard header.macID == macID, rows.allSatisfy({ $0.2 == bytes(header.id) && $0.3 == bytes(header.revision) }) else {
                throw PreparationStoreError.corruptRecord
            }
            let archive = MachineUpdateBackendEpoch.Archive(record: header,
                artifacts: rows.dropFirst().map { .init(kind: $0.0, accountID: $0.1, bytes: $0.4) })
            try archive.validate(epoch: epoch)
            return archive
        }
    }
    private func loadRequiredMachineUpdateBackendEpochHeader() throws -> Data {
        guard let epoch = try loadMachineUpdateConfigurationEpoch(),
              let archive = try loadMachineUpdateBackendEpoch(epoch: epoch) else {
            throw PreparationStoreError.corruptRecord
        }
        return try archive.record.encoded
    }

    private func machineEpochSourceDigest(normalizedSchema: Int64? = nil) throws -> Data {
        try identity(macID)
        let schema = try scalar("PRAGMA user_version")
        let digestSchema = normalizedSchema ?? schema
        guard [Int64(19), 20, 21, 22].contains(schema), [Int64(19), 20].contains(digestSchema),
              digestSchema <= schema else {
            throw PreparationStoreError.incompatibleStore
        }
        return try machineEpochSourceDigest(schema: schema, digestSchema: digestSchema,
            installationID: loadInventoryRecord()?.installationID)
    }

    private func machineEpochSourceDigest(schema: Int64, digestSchema: Int64, installationID: Data?,
        historicalTables: [String: Data] = [:]) throws -> Data {
        let tables: [String] = try statement("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            var values: [String] = []
            while try step(row) == SQLITE_ROW {
                guard values.count < 21 + Int(schema - 19), let name = sqlite3_column_text(row, 0) else { throw PreparationStoreError.corruptRecord }
                values.append(String(cString: name))
            }
            return values
        }
        var hash = SHA256(); hash.update(data: Data("Remozio/MachineEpochSource/v1\0".utf8))
        hash.update(data: candidateGeneration(UInt64(digestSchema)))
        let sharedImport = try sharedImportCompatibilitySnapshot(installationID: installationID)
        hash.update(data: try RuntimeReleaseCompatibilitySnapshot.externalSourceDigest(sharedImport: sharedImport))
        for table in tables where table != "machine_update_configuration_epoch_v1" &&
            table != "machine_update_activation_v1" && table != "machine_update_backend_epoch_v1" &&
            table != "machine_update_completion_intent_v1" && table != "machine_update_completion_publication_v1" &&
            table != "installed_release_state_v1" && table != "stable_release_state_v1" {
            if table == MachineUpdateRetainedSetupPolicyStorage.tableName {
                hash.update(data: try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPolicyIntentRecord.maximumBytes) {
                    try machineTableDigest(table)
                })
            } else if table == MachineUpdateRetainedSetupCompletionStorage.tableName {
                hash.update(data: try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupCompletionIntentRecord.maximumBytes) {
                    try machineTableDigest(table)
                })
            } else if table == MachineUpdateRetainedSetupPromotionStorage.tableName {
                hash.update(data: try withRetainedSetupRecordLimit(maximumBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes) {
                    try machineTableDigest(table)
                })
            } else {
                hash.update(data: try historicalTables[table] ?? machineTableDigest(table))
            }
        }
        return Data(hash.finalize())
    }

    private func machineTableDigest(_ table: String, excludingOwnerUID: UInt32? = nil, excludingAccount: Data? = nil,
        maximumCellBytes: Int? = nil) throws -> Data {
        guard excludingAccount == nil || ["authority_initialization_v1", "service_accounts_v1", "runtime_preparation_v1"].contains(table) && excludingAccount?.count == 16
            && excludingOwnerUID == nil else { throw PreparationStoreError.corruptRecord }
        guard excludingOwnerUID == nil || table == "account_preparation_v1" && excludingOwnerUID! > 0
            && excludingOwnerUID! < UInt32.max else { throw PreparationStoreError.corruptRecord }
        guard !table.isEmpty, table.utf8.allSatisfy({ ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 95 }) else {
            throw PreparationStoreError.corruptRecord
        }
        let cellLimit = maximumCellBytes ?? (table == MachineUpdateRetainedSetupPromotionReadyStorage.tableName
            ? MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes
            : table == MachineUpdateRetainedSetupPromotionStorage.tableName
                ? MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes : 278528)
        let selection = excludingAccount != nil ? " WHERE account<>?" : excludingOwnerUID == nil ? "" : " WHERE owner<>?"
        let rows: [Data] = try statement("SELECT * FROM \(table)\(selection)") { row in
            if let excludingOwnerUID { try bind(Int64(excludingOwnerUID), column: 1, row: row) }
            if let excludingAccount { try bind(excludingAccount, column: 1, row: row) }
            var rows: [Data] = []
            while try step(row) == SQLITE_ROW {
                guard rows.count < 1_048_576 else { throw PreparationStoreError.capacity }
                var hash = SHA256(); hash.update(data: Data("Remozio/MachineEpochRow/v1\0".utf8))
                let count = sqlite3_column_count(row); hash.update(data: candidateGeneration(UInt64(count)))
                for column in 0..<count {
                    let type = sqlite3_column_type(row, column); hash.update(data: Data([UInt8(type)]))
                    switch type {
                    case SQLITE_NULL: break
                    case SQLITE_INTEGER: hash.update(data: candidateGeneration(UInt64(bitPattern: sqlite3_column_int64(row, column))))
                    case SQLITE_TEXT, SQLITE_BLOB:
                        let size = sqlite3_column_bytes(row, column)
                        guard size >= 0, size <= cellLimit else { throw PreparationStoreError.corruptRecord }
                        hash.update(data: candidateGeneration(UInt64(size)))
                        if size > 0 {
                            guard let data = sqlite3_column_blob(row, column) else { throw PreparationStoreError.corruptRecord }
                            hash.update(data: Data(bytes: data, count: Int(size)))
                        }
                    default: throw PreparationStoreError.corruptRecord
                    }
                }
                rows.append(Data(hash.finalize()))
            }
            return rows.sorted { $0.lexicographicallyPrecedes($1) }
        }
        return machineEpochTableDigest(table, rows: rows)
    }

    private func machineEpochTableDigest(_ table: String, rows: [Data]) -> Data {
        var hash = SHA256(); hash.update(data: Data("Remozio/MachineEpochTable/v1\0".utf8))
        hash.update(data: candidateGeneration(UInt64(table.utf8.count))); hash.update(data: Data(table.utf8))
        hash.update(data: candidateGeneration(UInt64(rows.count)))
        for row in rows { hash.update(data: row) }
        return Data(hash.finalize())
    }

    func machineUpdateReplacement() throws -> MachineUpdateReplacementRecord? {
        try transaction(write: false) {
            try identity(macID)
            return try scalar("PRAGMA user_version") >= 18 ? loadMachineUpdateReplacement() : nil
        }
    }

    func machineUpdateReplacementContext(_ activation: MachineUpdateActivationRecord) throws -> MachineUpdateReplacementContext {
        try transaction(write: false) { try loadMachineUpdateReplacementContext(activation) }
    }

    func withCurrentMachineUpdateReplacement<Value>(_ expected: MachineUpdateReplacementContext,
        directory: ReleaseDestinationLease,
        _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try transaction(write: false) {
            guard expected.replacement != nil else { throw PreparationStoreError.staleRevision }
            let processID = getpid()
            var scopeActive = true
            defer { scopeActive = false }
            let validate: () throws -> Void = { [weak self] in
                guard scopeActive, getpid() == processID, let self else { throw JournalLeaseError.invalidated }
                guard try self.loadMachineUpdateReplacementContext(expected.activation) == expected else {
                    throw PreparationStoreError.staleRevision
                }
                try self.requireUpdateAdmissionDirectory(directory)
            }
            try validate(); let value = try body(validate); try validate(); return value
        }
    }

    func machineUpdateRestartSource(_ activation: MachineUpdateActivationRecord,
                                    directory: ReleaseDestinationLease) throws -> MachineUpdateRestartSource {
        try transaction(write: false) {
            try requireUpdateAdmissionDirectory(directory)
            return try loadMachineUpdateRestartSource(activation)
        }
    }

    func withCurrentMachineUpdateRestartSource<Value>(_ expected: MachineUpdateRestartSource,
        directory: ReleaseDestinationLease,
        _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try transaction(write: false) {
            let processID = getpid()
            var scopeActive = true
            defer { scopeActive = false }
            let validate: () throws -> Void = { [weak self] in
                guard scopeActive, getpid() == processID, let self else { throw JournalLeaseError.invalidated }
                try self.requireUpdateAdmissionDirectory(directory)
                guard try self.loadMachineUpdateRestartSource(expected.replacement.activation) == expected else {
                    throw PreparationStoreError.staleRevision
                }
            }
            try validate(); let value = try body(validate); try validate(); return value
        }
    }

    func retainMachineUpdateReplacement(_ value: MachineUpdateReplacementRecord, activation: MachineUpdateActivationRecord,
        runtime: RuntimeReleaseCompatibilitySnapshot.Inputs, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease, verify: () throws -> Void) throws -> MachineUpdateReplacementRecord {
        try transaction(write: true, activationWrite: true) {
            let context = try loadMachineUpdateReplacementContext(activation)
            guard activation.phase == .activationStarted, context.runtime == runtime, context.replacement == nil,
                  value.phase == .prepared else { throw PreparationStoreError.staleRevision }
            try value.requireScope(activation: activation, inventory: context.inventory, candidate: context.candidate)
            try requireUpdateAdmissionDirectory(directory)
            try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
            try verify(); try writeMachineUpdateReplacement(value, replacing: nil); try verify()
            try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
        }
        return try finishMachineUpdateReplacement(value, activation: activation, verify: {
            try self.requireUpdateAdmissionDirectory(directory)
            try quiescence.validateMachineBoundary(directory: directory, expected: self.loadMachineUpdateReplacementContext(activation).admission.machine)
            try verify()
        })
    }

    func withBoundMachineUpdateReplacement<Value>(_ expected: MachineUpdateReplacementRecord,
        activation: MachineUpdateActivationRecord, runtime: RuntimeReleaseCompatibilitySnapshot.Inputs,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        _ body: (_ validate: @escaping () throws -> Void) throws -> Value) throws -> Value {
        try transaction(write: false) {
            let context = try loadMachineUpdateReplacementContext(activation)
            guard context.replacement == expected, context.runtime == runtime else { throw PreparationStoreError.staleRevision }
            try requireUpdateAdmissionDirectory(directory)
            try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
            let processID = getpid()
            var scopeActive = true
            defer { scopeActive = false }
            let validate: () throws -> Void = { [weak self] in
                guard scopeActive, getpid() == processID, let self else { throw JournalLeaseError.invalidated }
                guard try self.loadMachineUpdateReplacementContext(activation) == context else { throw PreparationStoreError.staleRevision }
                try self.requireUpdateAdmissionDirectory(directory)
                try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
            }
            try validate(); let value = try body(validate); try validate(); return value
        }
    }

    func observeMachineUpdateReplacement(_ expected: MachineUpdateReplacementRecord,
        activation: MachineUpdateActivationRecord, directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        verify: () throws -> Void) throws -> MachineUpdateReplacementRecord {
        let next = try expected.observingSwap()
        try transaction(write: true, activationWrite: true) {
            let context = try loadMachineUpdateReplacementContext(activation)
            guard context.replacement == expected else { throw PreparationStoreError.staleRevision }
            try requireUpdateAdmissionDirectory(directory)
            try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
            try verify(); try writeMachineUpdateReplacement(next, replacing: expected); try verify()
            try quiescence.validateMachineBoundary(directory: directory, expected: context.admission.machine)
        }
        return try finishMachineUpdateReplacement(next, activation: activation, verify: {
            try self.requireUpdateAdmissionDirectory(directory)
            try quiescence.validateMachineBoundary(directory: directory, expected: self.loadMachineUpdateReplacementContext(activation).admission.machine)
            try verify()
        })
    }

    private func finishMachineUpdateReplacement(_ expected: MachineUpdateReplacementRecord,
        activation: MachineUpdateActivationRecord, verify: () throws -> Void) throws -> MachineUpdateReplacementRecord {
        do {
            return try transaction(write: false) {
                guard try loadMachineUpdateReplacementContext(activation).replacement == expected else { throw PreparationStoreError.staleRevision }
                try verify(); return expected
            }
        } catch { unavailable = true; shutdown(); throw error }
    }

    private func loadMachineUpdateReplacementContext(_ expected: MachineUpdateActivationRecord) throws -> MachineUpdateReplacementContext {
        try identity(macID)
        guard try scalar("PRAGMA user_version") >= 18, expected.phase.irreversible,
              try loadMachineUpdateActivation() == expected,
              let inventory = try loadInventoryRecord(), let candidate = try loadUpdateCandidate(),
              let admission = try loadUpdateAdmissionRegistration() else { throw PreparationStoreError.staleRevision }
        try expected.requireScope(candidate: candidate, inventory: inventory, admission: admission)
        return try .init(activation: expected, inventory: inventory, candidate: candidate, admission: admission,
            replacement: loadMachineUpdateReplacement(), runtime: loadRetainedRuntimeCompatibilityInputs())
    }

    private func loadMachineUpdateReplacement() throws -> MachineUpdateReplacementRecord? {
        try statement("SELECT id,revision,record FROM machine_update_replacement_v1 ORDER BY id") { row in
            if try step(row) == SQLITE_DONE { return nil }
            guard sqlite3_column_type(row, 0) == SQLITE_INTEGER, sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
            let record = try blob(row, column: 2, maximum: MachineUpdateReplacementRecord.maximumBytes)
            let value = try MachineUpdateReplacementRecord.decode(record)
            guard try blob(row, column: 1, maximum: 16) == bytes(value.revision), try step(row) == SQLITE_DONE,
                  let activation = try loadMachineUpdateActivation(), let inventory = try loadInventoryRecord(),
                  let candidate = try loadUpdateCandidate() else { throw PreparationStoreError.corruptRecord }
            do { try value.requireScope(activation: activation, inventory: inventory, candidate: candidate) }
            catch { throw PreparationStoreError.corruptRecord }
            return value
        }
    }

    private func writeMachineUpdateReplacement(_ value: MachineUpdateReplacementRecord,
        replacing previous: MachineUpdateReplacementRecord?) throws {
        if let previous {
            try statement("UPDATE machine_update_replacement_v1 SET revision=?,record=? WHERE id=1 AND revision=?") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                try bind(bytes(previous.revision), column: 3, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        } else {
            try statement("INSERT INTO machine_update_replacement_v1 VALUES(1,?,?)") { row in
                try bind(bytes(value.revision), column: 1, row: row); try bind(value.encoded, column: 2, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
        }
    }

    private func loadMachineUpdateRestartSource(_ activation: MachineUpdateActivationRecord) throws -> MachineUpdateRestartSource {
        let context = try loadMachineUpdateReplacementContext(activation)
        guard context.replacement != nil else { throw MachineUpdateReplacementError.changedBinding }
        let accounts = try loadMachineUpdateAccounts(context)
        guard try [Int64(17), 18, 19, 20, 21, 22].contains(scalar("PRAGMA user_version")) else { throw PreparationStoreError.incompatibleStore }
        let history: MachineUpdateProvisioningHistory? = nil
        return .init(replacement: context, accounts: accounts, provisioningHistory: history)
    }

    private func identity(_ macID: Data) throws {
        let version = try scalar("PRAGMA user_version")
        var expected = ["installation_identity_v1", "preparation_intents_v1"]
        if version >= 2 { expected.append("installation_inventory_v1") }
        if version >= 3 { expected.append("authority_initialization_v1") }
        if version >= 4 { expected.append("account_preparation_v1") }
        if version >= 5 { expected.append("service_accounts_v1") }
        if version >= 6 { expected.append("runtime_preparation_v1") }
        if version >= 7 { expected.append("runtime_activation_v1") }
        if version >= 8 { expected.append("gateway_preparation_v1") }
        if version >= 9 { expected.append("gateway_journal_preparation_v1") }
        if version >= 10 { expected.append("gateway_runtime_activation_v1") }
        if version >= 11 { expected.append("gateway_settings_transition_v1") }
        if version >= 12 { expected.append("runtime_audit_upgrade_v1") }
        if version >= 13 { expected += ["runtime_audit_graph_v1", "runtime_audit_graph_chunks_v1"] }
        if version >= 14 { expected.append("runtime_audit_cutover_v1") }
        if version >= 15 { expected.append("update_scheduling_candidate_v1") }
        if version >= 16 { expected.append("update_admission_registration_v1") }
        if version >= 17 { expected.append("machine_update_activation_v1") }
        if version >= 18 { expected.append("machine_update_replacement_v1") }
        if version >= 19 { expected.append("machine_update_configuration_epoch_v1") }
        if version >= 20 { expected.append("machine_update_backend_epoch_v1") }
        if version >= 21 { expected.append("machine_update_completion_intent_v1") }
        if version >= 22 { expected.append("machine_update_completion_publication_v1") }
        if version >= 23 { expected.append("installed_release_state_v1") }
        if version >= 24 { expected.append("stable_release_state_v1") }
        if version >= MachineUpdateRetainedSetupPolicyStorage.schemaVersion {
            expected.append(MachineUpdateRetainedSetupPolicyStorage.tableName)
        }
        if version >= MachineUpdateRetainedSetupCompletionStorage.schemaVersion {
            expected.append(MachineUpdateRetainedSetupCompletionStorage.tableName)
        }
        if version >= MachineUpdateRetainedSetupPromotionStorage.schemaVersion {
            expected.append(MachineUpdateRetainedSetupPromotionStorage.tableName)
        }
        if version >= MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion {
            expected.append(MachineUpdateRetainedSetupPromotionReadyStorage.tableName)
        }
        expected.sort()
        guard try scalar("PRAGMA application_id") == Self.applicationID, Self.supportedSchemaVersions.contains(version),
              try scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'") == Int64(expected.count) else {
            throw PreparationStoreError.incompatibleStore
        }
        let names = try statement("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < expected.count, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0), let type = sqlite3_column_text(row, 1),
                      String(cString: type) == "table" else { throw PreparationStoreError.incompatibleStore }
                names.append(String(cString: name))
            }
            return names
        }
        guard names == expected else { throw PreparationStoreError.incompatibleStore }
        if version >= MachineUpdateRetainedSetupPromotionStorage.schemaVersion {
            try statement("SELECT sql FROM sqlite_schema WHERE name='retained_setup_promotion_intents_v1' AND type='table'") { row in
                guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let sql = sqlite3_column_text(row, 0),
                      String(cString: sql) == MachineUpdateRetainedSetupPromotionStorage.createSQL,
                      try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
            }
        }
        if version >= MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion {
            try statement("SELECT sql FROM sqlite_schema WHERE name='retained_setup_promotion_ready_v1' AND type='table'") { row in
                guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let sql = sqlite3_column_text(row, 0),
                      String(cString: sql) == MachineUpdateRetainedSetupPromotionReadyStorage.createSQL,
                      try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
            }
        }
        try statement("SELECT id,mac FROM installation_identity_v1") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.incompatibleStore }
            guard try blob(row, column: 1, maximum: 16) == macID else { throw PreparationStoreError.wrongMac }
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
        }
    }
    private func loadAll() throws -> [PreparationIntentRecord] {
        try statement("SELECT id,revision,record FROM preparation_intents_v1 ORDER BY id LIMIT 4097") { row in
            var result: [PreparationIntentRecord] = []
            while try step(row) == SQLITE_ROW {
                guard result.count < 4096 else { throw PreparationStoreError.corruptRecord }
                let value: PreparationIntentRecord
                do { value = try .decode(blob(row, column: 2, maximum: PreparationIntentRecord.maximumBytes)) }
                catch { throw PreparationStoreError.corruptRecord }
                guard try blob(row, column: 0, maximum: 16) == bytes(value.id),
                      try blob(row, column: 1, maximum: 16) == bytes(value.revision) else { throw PreparationStoreError.corruptRecord }
                result.append(value)
            }
            return result
        }
    }
    private func transaction<T>(write: Bool, activationWrite: Bool = false,
        retainedSetupPromotion: RetainedSetupPromotionAuthorization? = nil,
        stableReservation: StableAccountReservationAuthorization? = nil,
        stableAccountStorage: StableAccountStorageAuthorization? = nil,
        stableRuntimePreparation: StableRuntimePreparationAuthorization? = nil,
        stableServiceAccount: StableServiceAccountAuthorization? = nil, willCommit: () -> Void = {},
        _ body: () throws -> T) throws -> T {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        do { try lease.validate() } catch { unavailable = true; shutdown(); throw error }
        do { try exec(write ? "BEGIN IMMEDIATE" : "BEGIN") }
        catch {
            if Self.isSQLiteCorruption(error) { unavailable = true; shutdown() }
            throw error
        }
        active = true; defer { active = false }
        do {
            // Stable startup and retained setup use separate owners. Ordinary callers cannot change the settled rows.
            if let stableRuntimePreparation {
                guard stableServiceAccount == nil, stableAccountStorage == nil, stableReservation == nil,
                      retainedSetupPromotion == nil, write, activationWrite,
                      stableRuntimePreparationAuthorization === stableRuntimePreparation,
                      (24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }
                _ = try stableRuntimePreparation.capture(in: self)
            } else if let stableServiceAccount {
                guard stableAccountStorage == nil, stableReservation == nil, retainedSetupPromotion == nil, write, activationWrite,
                      stableServiceAccountAuthorization === stableServiceAccount,
                      (24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }
                _ = try stableServiceAccount.capture(in: self)
            } else if let stableAccountStorage {
                guard stableReservation == nil, retainedSetupPromotion == nil, write, activationWrite,
                      stableAccountStorageAuthorization === stableAccountStorage,
                      (24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }
                _ = try stableAccountStorage.capture(in: self)
            } else if let stableReservation {
                guard retainedSetupPromotion == nil, write, activationWrite,
                      stableAccountReservationAuthorization === stableReservation,
                      (24...28).contains(try scalar("PRAGMA user_version")) else {
                    throw PreparationStoreError.invalidTransition
                }
                _ = try stableReservation.capture(in: self)
            } else if let retainedSetupPromotion {
                guard write, activationWrite, retainedSetupPromotionAuthorization === retainedSetupPromotion,
                      [Int64(26), 27, 28].contains(try scalar("PRAGMA user_version")) else {
                    throw PreparationStoreError.invalidTransition
                }
                _ = try retainedSetupPromotion.capture(in: self)
            } else if write, try scalar("PRAGMA user_version") >= 24 { throw PreparationStoreError.invalidTransition }
            if write && !activationWrite, try scalar("PRAGMA user_version") >= 17,
               try loadMachineUpdateActivation()?.phase.blocksMachineWrites == true {
                throw PreparationStoreError.invalidTransition
            }
            let value = try body()
            if let retainedSetupPromotion { _ = try retainedSetupPromotion.capture(in: self) }
            if let stableReservation { _ = try stableReservation.capture(in: self) }
            if let stableAccountStorage { _ = try stableAccountStorage.capture(in: self) }
            if let stableServiceAccount { _ = try stableServiceAccount.capture(in: self) }
            if let stableRuntimePreparation { _ = try stableRuntimePreparation.capture(in: self) }
            try lease.validate()
            do {
                if write { willCommit() }
                if let retainedSetupPromotion { _ = try retainedSetupPromotion.capture(in: self) }
                if let stableReservation { _ = try stableReservation.capture(in: self) }
                if let stableAccountStorage { _ = try stableAccountStorage.capture(in: self) }
                if let stableServiceAccount { _ = try stableServiceAccount.capture(in: self) }
                if let stableRuntimePreparation { _ = try stableRuntimePreparation.capture(in: self) }
                try exec("COMMIT")
                if write { try didCommit?() }
            } catch { unavailable = true; throw error }
            try lease.validate()
            return value
        } catch {
            if error as? PreparationStoreError == .corruptRecord || error as? PreparationStoreError == .incompatibleStore || error is JournalLeaseError || Self.isSQLiteCorruption(error) {
                unavailable = true
            }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            if unavailable { shutdown() }
            throw error
        }
    }
    private static func isSQLiteCorruption(_ error: any Error) -> Bool {
        guard case PreparationStoreError.storage(let code) = error else { return false }
        let primary = code & 0xff
        return primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB
    }
    private func bytes(_ id: UUID) -> Data {
        var value = id.uuid
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    private func bind(_ number: Int64, column: Int32, row: OpaquePointer) throws {
        let result = sqlite3_bind_int64(row, column, number)
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }
    private func bind(_ data: Data, column: Int32, row: OpaquePointer) throws {
        let result = data.withUnsafeBytes {
            sqlite3_bind_blob(row, column, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }
    private func blob(_ row: OpaquePointer, column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(row, column))
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(row, column) else { throw PreparationStoreError.corruptRecord }
        return Data(bytes: pointer, count: count)
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER else { throw PreparationStoreError.incompatibleStore }
            let result = sqlite3_column_int64(row, 0)
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
            return result
        }
    }
    private func exec(_ sql: String) throws {
        guard let db else { throw PreparationStoreError.closed }
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
        return result
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        guard let db else { throw PreparationStoreError.closed }
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw PreparationStoreError.storage(result) }
        defer { sqlite3_finalize(row) }
        return try body(row)
    }
    private func shutdown() {
        if let db { _ = sqlite3_close_v2(db) }
        db = nil; lease.close()
    }
}
