import CryptoKit
import Foundation
import Darwin
import SQLite3

enum PreparationStoreError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongMac, closed, unavailable, transactionActive
    case capacity, notFound, staleRevision, invalidTransition, corruptRecord, inventoryNotEnabled, wrongInstallation
    case storage(Int32)
}

/// Serialized machine-scoped bookkeeping. Stored copy metadata grants no activation authority.
public final class PreparationIntentStore {
    public static let supportedSchemaVersions: Set<Int64> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    private let lease: InstallationStorageLease
    private var db: OpaquePointer?
    private let maximumRecords: Int
    private let macID: Data
    private let didCommit: (() throws -> Void)?
    private var active = false
    private var unavailable = false
    private static let applicationID: Int64 = 0x524D4953

    public static func open(directoryPath: String, macID: Data, maximumRecords: Int = 64,
                     initialize: Bool = false) throws -> PreparationIntentStore {
        try .init(lease: InstallationStorageLease.acquire(directoryPath: directoryPath),
                  macID: macID, maximumRecords: maximumRecords, initialize: initialize)
    }
    // Internal fixture seam. The connection owns the lease even when initialization fails.
    init(lease: InstallationStorageLease, macID: Data, maximumRecords: Int, initialize: Bool,
         didCommit: (() throws -> Void)? = nil) throws {
        self.lease = lease; self.maximumRecords = maximumRecords; self.macID = macID; self.didCommit = didCommit
        do {
            guard macID.count == 16, (1...4096).contains(maximumRecords) else { throw PreparationStoreError.invalidConfiguration }
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
        try transaction(write: false) {
            try identity(macID)
            let schema = try scalar("PRAGMA user_version")
            let inventory = try schema >= 2 ? loadInventoryRecord() : nil
            let sharedImport = try lease.sharedImportCompatibilitySnapshot(macID: macID, installationID: inventory?.installationID)
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
            var values: [RuntimeReleaseCompatibilitySnapshot.Runtime] = []
            for id in ids {
                let state = try loadRuntimePreparation(accountID: id)
                guard let reference = state.reference else { throw PreparationStoreError.corruptRecord }
                try requireRuntimeMaterialScope(reference)
                var record: Data?, registered = false
                if activated.contains(id) {
                    let activation = try loadRuntimeActivation(accountID: id)
                    guard let plan = activation.plan, plan.reference == reference else { throw PreparationStoreError.corruptRecord }
                    try requireRuntimeActivationScope(plan)
                    if activation.jobsRegistered {
                        guard let inventory, try plan.enrolledInventory(inventory) == inventory else { throw PreparationStoreError.corruptRecord }
                    }
                    record = try plan.encoded; registered = activation.jobsRegistered
                }
                values.append(.init(reference: reference, configurationPublished: state.configurationPublished,
                    activationRecord: record, jobsRegistered: registered))
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
                let scope = try requireGatewayRuntimeActivationScope(plan)
                if state.jobRegistered {
                    let proposal = try plan.proposal(journal: scope.journal, foreground: scope.foreground, inventory: scope.inventory)
                    guard try proposal.enrolledInventory(scope.inventory) == scope.inventory else { throw PreparationStoreError.corruptRecord }
                }
                let settings = try schema >= 11 ? loadGatewaySettingsTransition(accountID: id) : .empty
                if let revision = settings.pending ?? settings.active { _ = try requireGatewaySettingsScope(revision) }
                gateways.append(.init(accountID: id, activationRecord: try plan.encoded,
                    configurationPublished: state.filesPublished, jobRegistered: state.jobRegistered,
                    activeSettings: try settings.active?.encoded, pendingSettings: try settings.pending?.encoded,
                    settingsPhase: settings.phase?.rawValue))
            }
            try identity(macID)
            return .init(schemaVersion: schema, macID: macID, inventory: inventory?.canonicalBytes, runtimes: values, gateways: gateways, sharedImport: sharedImport)
        }
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
    private func requireRuntimeActivationScope(_ plan: RuntimeActivationPlan) throws {
        guard try scalar("PRAGMA user_version") >= 6 else { throw RuntimeActivationError.incomplete }
        try requireRuntimeMaterialScope(plan.reference)
        let runtime = try loadRuntimePreparation(accountID: plan.accountID)
        guard runtime.configurationPublished, runtime.reference == plan.reference,
              let account = try loadAccountPreparation(ownerUID: plan.reference.services.ownerUID),
              let inventory = try loadInventoryRecord() else { throw RuntimeActivationError.incomplete }
        try plan.validate(account: account, reference: plan.reference)
        _ = try plan.enrolledInventory(inventory)
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
    private func requireGatewaySettingsScope(_ revision: GatewayRuntimeSettingsRevision) throws -> GatewayRuntimeActivationPlan {
        guard revision.sequence <= UInt64(Int64.max) else { throw GatewayPreparationError.exhausted }
        guard try scalar("PRAGMA user_version") >= 10 else { throw GatewayPreparationError.incomplete }
        let state = try loadGatewayRuntimeActivation(accountID: revision.accountID)
        guard state.filesPublished, state.jobRegistered, let activation = state.plan else { throw GatewayPreparationError.incomplete }
        let scope = try requireGatewayRuntimeActivationScope(activation)
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
    private func requireGatewayRuntimeActivationScope(_ plan: GatewayRuntimeActivationPlan) throws
        -> (journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory) {
        guard try scalar("PRAGMA user_version") >= 9 else { throw GatewayPreparationError.incomplete }
        let journal = try loadGatewayJournalPreparation(accountID: plan.accountID)
        let activation = try loadRuntimeActivation(accountID: plan.accountID)
        guard journal.initialized, let intent = journal.intent, activation.jobsRegistered, let foreground = activation.plan,
              let inventory = try loadInventoryRecord(), intent.id == plan.journalIntentID,
              try intent.digest == plan.journalIntentDigest else { throw GatewayPreparationError.incomplete }
        try requireGatewayJournalScope(intent)
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
    private func requireGatewayJournalScope(_ intent: GatewayJournalSetupIntent) throws {
        guard try scalar("PRAGMA user_version") >= 8 else { throw GatewayPreparationError.incomplete }
        try requireGatewayMaterialScope(intent.material)
        guard try loadGatewayPreparation(accountID: intent.accountID).reference == intent.material,
              let foreground = try loadRuntimeActivation(accountID: intent.accountID).plan,
              let inventory = try loadInventoryRecord() else { throw GatewayPreparationError.incomplete }
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
    private func requireGatewayMaterialScope(_ reference: GatewayMaterialReference) throws {
        try requireRuntimeMaterialScope(reference.runtime)
        guard try scalar("PRAGMA user_version") >= 7 else { throw GatewayPreparationError.incomplete }
        let runtime = try loadRuntimePreparation(accountID: reference.runtime.services.accountID)
        let activation = try loadRuntimeActivation(accountID: reference.runtime.services.accountID)
        guard runtime.configurationPublished, runtime.reference == reference.runtime, activation.jobsRegistered,
              let plan = activation.plan, plan.reference == reference.runtime,
              let inventory = try loadInventoryRecord(), try plan.enrolledInventory(inventory) == inventory else {
            throw GatewayPreparationError.incomplete
        }
        try requireRuntimeActivationScope(plan)
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
    private func requireRuntimeMaterialScope(_ reference: RuntimeMaterialReference) throws {
        try requireServiceAccountScope(reference.services)
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
            return try statement("SELECT account FROM service_accounts_v1 ORDER BY account LIMIT 65") { row in
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
    private func requireServiceAccountScope(_ plan: ServiceAccountPlan) throws {
        guard plan.macID == macID, try scalar("PRAGMA user_version") >= 4,
              let account = try loadAccountPreparation(ownerUID: plan.ownerUID),
              let inventory = try loadInventoryRecord(), inventory.installationID == plan.installationID,
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
        if let db { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 278_528) }
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
    private func identity(_ macID: Data) throws {
        let version = try scalar("PRAGMA user_version")
        guard try scalar("PRAGMA application_id") == Self.applicationID, Self.supportedSchemaVersions.contains(version),
              try scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'") == version + 1 else {
            throw PreparationStoreError.incompatibleStore
        }
        let names = try statement("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 12, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0), let type = sqlite3_column_text(row, 1),
                      String(cString: type) == "table" else { throw PreparationStoreError.incompatibleStore }
                names.append(String(cString: name))
            }
            return names
        }
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
        expected.sort()
        guard names == expected else { throw PreparationStoreError.incompatibleStore }
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
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
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
            let value = try body()
            try lease.validate()
            do { try exec("COMMIT"); if write { try didCommit?() } } catch { unavailable = true; throw error }
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
