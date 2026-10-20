import Foundation
import RemozioProtocol
import SQLite3

public enum JournalDatabaseError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongScope, closed, unavailable, transactionActive, expiredTransaction, readOnly, transactionFailed
    case storage(Int32)
}

/// One Mac/account's journal connection. The root authority owns this object and serializes its calls.
/// This storage layer has no admission, checkpoint or dispatch authority.
public final class JournalDatabase {
    private static let applicationID: Int64 = 0x524D5A4F
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        try lease.directoryIdentities()
    }
    private let lease: ProtectedJournalLease
    private var db: OpaquePointer?
    private var tables: AuditJournalTables?
    private var consumption: ConsumptionJournal?
    private var commandReplay: CommandSubmissionReplayJournal?
    private var gateway: GatewayAuthorityJournal?
    private var configuredGatewayPolicy: GatewayAuthorityPolicy?
    private var enrollment: EnrollmentJournal?
    private var routing: RoutingJournal?
    private let recordLimits: CBORLimits
    private let descriptorLimits: CBORLimits
    private var active: UUID?
    private var unavailable = false

    /// Inspect only under owner serialization. A retired connection cannot resume; this grants no storage authority.
    var retired: Bool { db == nil || unavailable }

    /// `initialize` is an explicit setup operation on an empty, already provisioned file. Never use it as recovery.
    public static func open(directoryPath: String, macID: Data, accountID: Data,
                            recordLimits: CBORLimits, descriptorLimits: CBORLimits, decisionLimits: CBORLimits,
                            maximumConsumptions: Int, busyMilliseconds: UInt32, initialize: Bool = false, migrateFromVersion: Int64? = nil, gatewayPolicy: GatewayAuthorityPolicy? = nil, routingPolicy: RoutingJournalPolicy? = nil,
                            maximumCommandSubmissions: Int = 1_000_000,
                            initialAuthority: AuthorityJournalInitialization? = nil) throws -> JournalDatabase {
        if initialAuthority != nil {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        }
        return try JournalDatabase(lease: ProtectedJournalLease.acquire(directoryPath: directoryPath), macID: macID, accountID: accountID,
                            recordLimits: recordLimits, descriptorLimits: descriptorLimits, decisionLimits: decisionLimits,
                            maximumConsumptions: maximumConsumptions, busyMilliseconds: busyMilliseconds,
                            initialize: initialize, migrateFromVersion: migrateFromVersion, gatewayPolicy: gatewayPolicy, routingPolicy: routingPolicy,
                            maximumCommandSubmissions: maximumCommandSubmissions, initialAuthority: initialAuthority)
    }

    /// Internal fixture entry point. Ownership of the lease transfers to this connection, including on failure.
    init(lease: ProtectedJournalLease, macID: Data, accountID: Data,
         recordLimits: CBORLimits, descriptorLimits: CBORLimits, decisionLimits: CBORLimits,
         maximumConsumptions: Int, busyMilliseconds: UInt32, initialize: Bool, migrateFromVersion: Int64? = nil, gatewayPolicy: GatewayAuthorityPolicy? = nil, routingPolicy: RoutingJournalPolicy? = nil,
         maximumCommandSubmissions: Int = 1_000_000, initialAuthority: AuthorityJournalInitialization? = nil,
         didInitializeAuthority: (AuthorityJournalInitialization.Stage) throws -> Void = { _ in }) throws {
        self.lease = lease
        self.recordLimits = recordLimits
        self.descriptorLimits = descriptorLimits
        do {
            guard macID.count == 16, accountID.count == 16, busyMilliseconds <= 60_000,
                  maximumConsumptions > 0, maximumConsumptions <= Int(Int32.max),
                  maximumCommandSubmissions > 0, maximumCommandSubmissions <= Int(Int32.max), !(initialize && migrateFromVersion != nil),
                  migrateFromVersion == nil || migrateFromVersion == 1 || migrateFromVersion == 2 || migrateFromVersion == 3 || migrateFromVersion == 4 || migrateFromVersion == 5 || migrateFromVersion == 6 || migrateFromVersion == 7 || migrateFromVersion == 8 || migrateFromVersion == 9 || migrateFromVersion == 10 || migrateFromVersion == 11,
                  max(recordLimits.maxBytes, descriptorLimits.maxBytes) <= Int(Int32.max) - 4096,
                  decisionLimits.maxBytes <= Int(Int32.max) - 4096 - recordLimits.maxBytes else {
                throw JournalDatabaseError.invalidConfiguration
            }
            if let initialAuthority {
                guard initialize, initialAuthority.descriptor.macID == macID, initialAuthority.descriptor.accountID == accountID else {
                    throw JournalDatabaseError.invalidConfiguration
                }
            }
            try lease.validate()
            var connection: OpaquePointer?
            let rc = sqlite3_open_v2(lease.databasePath, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard rc == SQLITE_OK, let connection else { throw JournalDatabaseError.storage(rc) }
            try lease.validate()
            guard sqlite3_busy_timeout(connection, Int32(busyMilliseconds)) == SQLITE_OK,
                  sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1 else { throw JournalDatabaseError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, Int32(max(max(recordLimits.maxBytes + decisionLimits.maxBytes, descriptorLimits.maxBytes) + 4096, max((gatewayPolicy?.payloadLimits.maxBytes ?? 0) + 32768, 136096))))
            try exec("PRAGMA trusted_schema=OFF")
            try exec("PRAGMA foreign_keys=ON")
            if initialize { try requireEmptyStore() }
            else { try validateIdentity(macID: macID, accountID: accountID, version: migrateFromVersion) }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try text("PRAGMA journal_mode") == "delete", try integer("PRAGMA synchronous") == 3,
                  try integer("PRAGMA fullfsync") == 1, try integer("PRAGMA foreign_keys") == 1,
                  try integer("PRAGMA trusted_schema") == 0 else { throw JournalDatabaseError.invalidConfiguration }
            let tables = try AuditJournalTables(connection: connection, macID: macID, accountID: accountID,
                                                 recordLimits: recordLimits, descriptorLimits: descriptorLimits)
            self.tables = tables
            let consumption = try ConsumptionJournal(connection: connection, macID: macID, accountID: accountID,
                decisionLimits: decisionLimits, recordLimits: recordLimits, maximumRows: maximumConsumptions)
            self.consumption = consumption
            commandReplay = try CommandSubmissionReplayJournal(connection: connection, macID: macID, accountID: accountID, maximumRows: maximumCommandSubmissions)
            enrollment = EnrollmentJournal(connection: connection, macID: macID, accountID: accountID)
            if let routingPolicy { routing = RoutingJournal(connection: connection, macID: macID, accountID: accountID, policy: routingPolicy) }
            if let gatewayPolicy { gateway = GatewayAuthorityJournal(connection: connection, macID: macID, accountID: accountID, policy: gatewayPolicy); configuredGatewayPolicy = gatewayPolicy }
            if initialize {
                try create(macID: macID, accountID: accountID, tables: tables, consumption: consumption,
                    initialAuthority: initialAuthority, didInitializeAuthority: didInitializeAuthority)
            }
            else if let migrateFromVersion { try migrate(macID: macID, accountID: accountID, consumption: consumption, from: migrateFromVersion) }
            try validateIdentity(macID: macID, accountID: accountID)
            try lease.validate()
        } catch {
            shutdown()
            throw error
        }
    }

    deinit { shutdown() }

    /// In-memory capability only. The trusted host must authenticate setup before installing any provider.
    /// Existing schema12 tables and the current writer stay in place. This does not configure a registration.
    @discardableResult
    func enableGatewayPolicy(_ policy: GatewayAuthorityPolicy, macID: Data, accountID: Data) throws -> Bool {
        guard let connection = db else { throw JournalDatabaseError.closed }
        guard !unavailable else { throw JournalDatabaseError.unavailable }
        guard active == nil else { throw JournalDatabaseError.transactionActive }
        guard macID.count == 16, accountID.count == 16 else { throw JournalDatabaseError.wrongScope }
        try validateLease(); try validateIdentity(macID: macID, accountID: accountID)
        if let current = configuredGatewayPolicy {
            guard current.sameConfiguration(as: policy) else { throw GatewayAuthorityError.invalidConfiguration }
            return false
        }
        gateway = GatewayAuthorityJournal(connection: connection, macID: macID, accountID: accountID, policy: policy)
        configuredGatewayPolicy = policy
        return true
    }

    public func read<T>(_ body: (JournalTransaction) throws -> T) throws -> T { try transaction(write: false, body) }
    public func write<T>(_ body: (JournalTransaction) throws -> T) throws -> T { try transaction(write: true, body) }

    public func close() throws {
        guard active == nil else { throw JournalDatabaseError.transactionActive }
        shutdown()
    }

    private func transaction<T>(write: Bool, _ body: (JournalTransaction) throws -> T) throws -> T {
        guard db != nil else { throw JournalDatabaseError.closed }
        guard !unavailable else { throw JournalDatabaseError.unavailable }
        guard active == nil else { throw JournalDatabaseError.transactionActive }
        try validateLease()
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        let token = UUID()
        active = token
        defer { active = nil }
        let scope = JournalTransaction(owner: self, token: token, writable: write)
        do {
            let value = try body(scope)
            guard !scope.failed else { throw JournalDatabaseError.transactionFailed }
            try validateLease()
            do { try exec("COMMIT") }
            catch { unavailable = true; throw error }
            try validateLease()
            return value
        } catch {
            if scope.createdEpoch || scope.headMismatch { unavailable = true }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }

    fileprivate func access(_ token: UUID) throws -> AuditJournalTables {
        guard db != nil, active == token, !unavailable, let tables else { throw JournalDatabaseError.expiredTransaction }
        try validateLease()
        return tables
    }

    fileprivate func storageSchemaVersion(_ token: UUID) throws -> UInt64 {
        _ = try access(token)
        let version = try integer("PRAGMA user_version")
        guard (12...16).contains(version) else {
            unavailable = true
            throw JournalDatabaseError.incompatibleStore
        }
        return UInt64(version)
    }

    func requireInitializationPath(_ path: String) throws {
        try validateLease()
        guard lease.databasePath == path else { throw AuthorityInitializationError.conflictingIntent }
    }
    func initialAuthorityCheckpoint(initial: AuthorityJournalInitialization, databasePath: String) throws -> ContinuityCheckpoint {
        try requireInitializationPath(databasePath)
        return try read { transaction in
            guard try transaction.storageSchemaVersion == (initial.installCommandReplay ? 15 : 13),
                  let boundary = try transaction.epoch(initial.descriptor.epoch), boundary.head == 0, boundary.retainedAfter == 0,
                  try boundary.descriptor.encode(limits: self.descriptorLimits) == initial.descriptor.encode(limits: self.descriptorLimits),
                  try transaction.codePolicy()?.policy == initial.codePolicy else { throw AuthorityInitializationError.invalidBoundary }
            let trust = try transaction.approvalTrustSnapshot()
            guard trust.macID == initial.descriptor.macID, trust.accountID == initial.descriptor.accountID,
                  trust.authorityCapabilities.contracts == initial.capabilities.contracts,
                  trust.allowedContracts == initial.allowedContracts, trust.enrollments.isEmpty else {
                throw AuthorityInitializationError.invalidBoundary
            }
            // Count every table in the catalog. Inactive enrollment and old outcome rows also prevent bootstrap recovery.
            let populated: Set<String> = ["journal_identity_v1", "audit_epochs_v1", "approval_authority_v1", "authority_code_policy_v1", "routing_state_v1"]
            guard try self.integer("SELECT count(*) FROM main.routing_state_v1 WHERE id=1 AND mode=0 AND revision=zeroblob(8)") == 1 else {
                throw AuthorityInitializationError.invalidBoundary
            }
            var names = [String]()
            try self.statement("SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'") { row in
                while true {
                    let result = sqlite3_step(row)
                    if result == SQLITE_DONE { break }
                    guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
                    guard let name = sqlite3_column_text(row, 0) else { throw JournalDatabaseError.incompatibleStore }
                    names.append(String(cString: name))
                }
            }
            _ = try transaction.continuityDigests()
            for name in names {
                guard name.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
                      try self.integer("SELECT count(*) FROM main.\(name)") == (populated.contains(name) ? 1 : 0) else {
                    throw AuthorityInitializationError.invalidBoundary
                }
            }
            return try CheckpointedJournal.checkpoint(transaction: transaction, epoch: initial.descriptor.epoch,
                generation: 1, authorityGeneration: 1)
        }
    }

    fileprivate func continuityDigests(_ token: UUID) throws -> JournalContinuityDigests {
        _ = try access(token)
        guard let db else { throw JournalDatabaseError.expiredTransaction }
        return try JournalContinuityDigest.read(db)
    }

    fileprivate func ledger(_ token: UUID) throws -> ConsumptionJournal {
        _ = try access(token)
        guard let consumption else { throw JournalDatabaseError.expiredTransaction }
        return consumption
    }

    fileprivate func commandReplayLedger(_ token: UUID) throws -> CommandSubmissionReplayJournal {
        _ = try access(token)
        guard let commandReplay else { throw JournalDatabaseError.expiredTransaction }
        return commandReplay
    }

    fileprivate func gatewayLedger(_ token: UUID) throws -> GatewayAuthorityJournal {
        _ = try access(token)
        guard let gateway else { throw GatewayAuthorityError.disabled }
        return gateway
    }

    fileprivate func appendEnrollmentEvent(_ event: AuditEventMetadata, token: UUID, writer: AuditEpochWriter, expectedHead: UInt64) throws {
        try access(token).append(event.encode(limits: recordLimits), writer: writer, expectedHead: expectedHead)
    }

    fileprivate func enrollmentLedger(_ token: UUID) throws -> EnrollmentJournal {
        _ = try access(token)
        guard let enrollment else { throw JournalDatabaseError.expiredTransaction }
        return enrollment
    }

    fileprivate func historyRecoveryLedger(_ token: UUID) throws -> HistoryRecoveryJournal {
        _ = try access(token)
        guard let db else { throw JournalDatabaseError.expiredTransaction }
        return HistoryRecoveryJournal(connection: db)
    }

    fileprivate func codePolicyLedger(_ token: UUID) throws -> CodePolicyJournal {
        _ = try access(token)
        guard let db else { throw JournalDatabaseError.expiredTransaction }
        return CodePolicyJournal(connection: db)
    }

    fileprivate func routingLedger(_ token: UUID) throws -> RoutingJournal {
        _ = try access(token)
        guard let routing else { throw RoutingJournalError.disabled }
        return routing
    }

    private func validateLease() throws {
        do { try lease.validate() }
        catch { unavailable = true; throw error }
    }

    private func create(macID: Data, accountID: Data, tables: AuditJournalTables, consumption: ConsumptionJournal,
                        initialAuthority: AuthorityJournalInitialization?,
                        didInitializeAuthority: (AuthorityJournalInitialization.Stage) throws -> Void) throws {
        try exec("BEGIN IMMEDIATE")
        do {
            try requireEmptyStore()
            try exec("CREATE TABLE main.journal_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1), mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16)) STRICT")
            try statement("INSERT INTO main.journal_identity_v1 VALUES(1,?,?)") { stmt in
                for (index, value) in [macID, accountID].enumerated() {
                    let rc = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
                    guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
                }
                guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            }
            try tables.createSchema()
            try consumption.createSchema()
            try consumption.createOutcomeSchema()
            try GatewayAuthorityJournal.createSchema(db!)
            try GatewayAuthorityJournal.createRevocationSchema(db!)
            try EnrollmentJournal.createSchema(db!)
            try RoutingJournal.createSchema(db!)
            try GatewayAuthorityJournal.createAcknowledgmentSchema(db!)
            try GatewayAuthorityJournal.createReconciledSchema(db!)
            try GatewayAuthorityJournal.createRecoveredRevocationsSchema(db!)
            try GatewayAuthorityJournal.createTrustRestrictionsSchema(db!)
            try EnrollmentJournal.createPairingSchema(db!)
            try exec("PRAGMA application_id=\(Self.applicationID)")
            try exec("PRAGMA user_version=12")
            if let initialAuthority {
                let token = UUID(); active = token
                defer { active = nil }
                let transaction = JournalTransaction(owner: self, token: token, writable: true)
                try initialAuthority.apply(transaction, didStage: didInitializeAuthority)
                guard !transaction.failed else { throw JournalDatabaseError.transactionFailed }
            }
            try lease.validate()
            try exec("COMMIT")
        } catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    private func migrate(macID: Data, accountID: Data, consumption: ConsumptionJournal, from version: Int64) throws {
        try exec("BEGIN IMMEDIATE")
        do {
            try validateIdentity(macID: macID, accountID: accountID, version: version)
            if version == 1 { try consumption.createSchema() }
            if version < 3 { try consumption.createOutcomeSchema() }
            if version < 4 { try GatewayAuthorityJournal.createSchema(db!) }
            if version < 5 { try GatewayAuthorityJournal.createRevocationSchema(db!) }
            if version < 6 { try EnrollmentJournal.createSchema(db!) }
            if version < 7 { try RoutingJournal.createSchema(db!) }
            if version < 8 { try GatewayAuthorityJournal.createAcknowledgmentSchema(db!) }
            if version < 9 { try GatewayAuthorityJournal.createReconciledSchema(db!) }
            if version < 10 { try GatewayAuthorityJournal.createRecoveredRevocationsSchema(db!) }
            if version < 11 { try GatewayAuthorityJournal.createTrustRestrictionsSchema(db!) }
            try EnrollmentJournal.createPairingSchema(db!)
            try exec("PRAGMA user_version=12")
            try lease.validate()
            try exec("COMMIT")
        } catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    private func requireEmptyStore() throws {
        guard try integer("PRAGMA application_id") == 0, try integer("PRAGMA user_version") == 0,
              try integer("SELECT count(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else {
            throw JournalDatabaseError.incompatibleStore
        }
    }

    private func validateIdentity(macID: Data, accountID: Data, version expectedVersion: Int64? = nil) throws {
        let version = try integer("PRAGMA user_version")
        guard try integer("PRAGMA application_id") == Self.applicationID,
              expectedVersion.map({ version == $0 }) ?? (12...16).contains(version) else {
            throw JournalDatabaseError.incompatibleStore
        }
        try statement("SELECT id,mac,account FROM main.journal_identity_v1") { stmt in
            guard sqlite3_step(stmt) == SQLITE_ROW, sqlite3_column_int64(stmt, 0) == 1 else { throw JournalDatabaseError.incompatibleStore }
            for (column, value) in [(Int32(1), macID), (Int32(2), accountID)] {
                guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, sqlite3_column_bytes(stmt, column) == 16,
                      let pointer = sqlite3_column_blob(stmt, column) else { throw JournalDatabaseError.incompatibleStore }
                guard Data(bytes: pointer, count: 16) == value else { throw JournalDatabaseError.wrongScope }
            }
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
        }
        var queries = ["SELECT mac,account,epoch,descriptor,head,retained FROM main.audit_epochs_v1 LIMIT 0",
                       "SELECT mac,account,epoch,sequence,event,body FROM main.audit_records_v1 LIMIT 0"]
        if version >= 2 { queries.append("SELECT mac,account,request,decision,event FROM main.consumptions_v1 LIMIT 0") }
        if version >= 3 { queries.append("SELECT mac,account,request,revision,event FROM main.consumption_outcomes_v1 LIMIT 0") }
        if version >= 4 {
            queries += ["SELECT id,identity,head FROM main.gateway_authority_v1 LIMIT 0",
                        "SELECT operation,revision,kind,candidate,payload,signature,token FROM main.gateway_outbox_v1 LIMIT 0",
                        "SELECT candidate,phone,enrollment,operation,run,started,deadline,consumed FROM main.gateway_root_candidates_v1 LIMIT 0",
                        "SELECT phone,candidate FROM main.gateway_desired_tokens_v1 LIMIT 0"]
        }
        if version >= 5 { queries.append("SELECT operation,revision,phone,enrollment,payload,signature,run,started,deadline FROM main.gateway_revocations_v1 LIMIT 0") }
        if version >= 6 {
            queries += ["SELECT id,policy,revision FROM main.approval_authority_v1 LIMIT 0",
                        "SELECT phone,epoch,active,body FROM main.approval_enrollments_v1 LIMIT 0"]
        }
        if version >= 7 {
            queries += ["SELECT id,mode,revision FROM main.routing_state_v1 LIMIT 0",
                        "SELECT operation,payload,run,started,deadline,consumed FROM main.routing_operations_v1 LIMIT 0"]
        }
        if version >= 8 { queries.append("SELECT id,revision,operation FROM main.gateway_acknowledgment_v1 LIMIT 0") }
        if version >= 9 { queries.append("SELECT operation,revision,kind,candidate,payload,signature FROM main.gateway_reconciled_controls_v1 LIMIT 0") }
        if version >= 10 { queries.append("SELECT phone,enrollment,operation,payload,signature FROM main.gateway_recovered_revocations_v1 LIMIT 0") }
        if version >= 11 { queries.append("SELECT phone,kind,operation,payload,signature FROM main.gateway_trust_restrictions_v1 LIMIT 0") }
        if version >= 12 { queries.append("SELECT setup,phone,epoch,transcript,proof FROM main.pairing_commits_v1 LIMIT 0") }
        if version >= 14 { queries.append("SELECT epoch,evidence FROM main.history_recoveries_v1 LIMIT 0") }
        if version >= 13 { queries.append("SELECT id,revision,policy FROM main.authority_code_policy_v1 LIMIT 0") }
        if version >= 15 { queries.append("SELECT mac,account,submission,nonce,caller,capture FROM main.command_submissions_v1 LIMIT 0") }
        if version >= 16 { queries.append("SELECT operation,revision,kind,credential,payload,signature,run,started,deadline FROM main.gateway_submission_outbox_v1 LIMIT 0") }
        for query in queries {
            try statement(query) { guard sqlite3_step($0) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore } }
        }
    }

    private func shutdown() {
        tables = nil
        consumption = nil
        commandReplay = nil
        gateway = nil
        enrollment = nil
        routing = nil
        if let db {
            // No statement, blob handle or raw connection can escape this owner.
            precondition(sqlite3_close(db) == SQLITE_OK, "Journal connection retained a private SQLite resource")
            self.db = nil
        }
        lease.close()
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var value: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &value, nil)
        guard rc == SQLITE_OK, let value else { throw JournalDatabaseError.storage(rc) }
        defer { sqlite3_finalize(value) }
        return try body(value)
    }
    private func integer(_ sql: String) throws -> Int64 {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            return sqlite3_column_int64($0, 0)
        }
    }
    private func text(_ sql: String) throws -> String {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW, let text = sqlite3_column_text($0, 0) else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            return String(cString: text)
        }
    }
}

/// Valid only inside its owner's synchronous callback. Escaping this object does not retain connection access.
public final class JournalTransaction {
    private weak var owner: JournalDatabase?
    private let token: UUID
    private let writable: Bool
    fileprivate var failed = false
    fileprivate var headMismatch = false
    fileprivate var createdEpoch = false
    fileprivate init(owner: JournalDatabase, token: UUID, writable: Bool) {
        self.owner = owner; self.token = token; self.writable = writable
    }
    private func tables(write: Bool = false) throws -> AuditJournalTables {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        guard !write || writable else { throw JournalDatabaseError.readOnly }
        return try owner.access(token)
    }
    /// Observes the current protected schema under the live transaction. This does not authorize installation or migration.
    public var storageSchemaVersion: UInt64 {
        get throws {
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            do { return try owner.storageSchemaVersion(token) }
            catch { failed = true; throw error }
        }
    }

    /// Includes uncommitted writes in this transaction. Publish only after both durable stores commit.
    public func continuityDigests() throws -> JournalContinuityDigests {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.continuityDigests(token)
    }

    /// Explicit protected installation. Commit the schema change through CheckpointedJournal before accepting commands.
    public func installCommandSubmissionReplay() throws {
        try withCommandReplay(write: true) { try $0.install() }
    }

    /// Reserve the ID and nonce together. The host supplies verified capture metadata and separate admission gates.
    /// Publish this historical result only after both durable stores commit. It grants no action authority.
    public func reserveCommandSubmission(_ value: CommandSubmissionReservation) throws -> CommandSubmissionReservation {
        try withCommandReplay(write: true) { try $0.reserve(value) }
    }

    public func commandSubmissionReservation(submissionID: Data) throws -> CommandSubmissionReservation? {
        try withCommandReplay(write: false) { try $0.read(submissionID: submissionID) }
    }

    /// Internal observation through the current protected transaction. The admission owner must validate continuity and scope.
    func commandSubmissionReserved(_ submission: CapturedSubmission) throws -> Bool {
        try withCommandReplay(write: false) { try $0.contains(submission) }
    }

    private func withCommandReplay<T>(write: Bool, _ body: (CommandSubmissionReplayJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.commandReplayLedger(token))
        } catch {
            failed = true
            if error as? CommandSubmissionReplayError == .corruptData || error as? AuthorityCodePolicyError == .corruptData { headMismatch = true }
            throw error
        }
    }

    func historyRecovery(epoch: Data) throws -> HistoryRecoveryIntent? {
        try withHistoryRecovery(write: false) { try $0.read(epoch: epoch) }
    }

    /// Retain recovery evidence in the same transaction as its new epoch and gap event.
    func recordHistoryRecovery(_ intent: HistoryRecoveryIntent) throws {
        try withHistoryRecovery(write: true) { try $0.insert(intent) }
    }

    private func withHistoryRecovery<T>(write: Bool, _ body: (HistoryRecoveryJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.historyRecoveryLedger(token))
        } catch {
            failed = true
            throw error
        }
    }

    public func codePolicy() throws -> AuthorityCodePolicySnapshot? {
        try withCodePolicy(write: false) { try $0.read() }
    }

    /// Protected installer input, after signature, placement, compatibility and quiescence checks.
    /// Commit through CheckpointedJournal before activating code. This storage call cannot perform those checks.
    public func installCodePolicy(_ policy: AuthorityCodePolicy, expectedRevision: UUID?) throws -> AuthorityCodePolicySnapshot {
        try withCodePolicy(write: true) { try $0.install(policy, expectedRevision: expectedRevision) }
    }

    private func withCodePolicy<T>(write: Bool, _ body: (CodePolicyJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.codePolicyLedger(token))
        } catch {
            failed = true
            if error as? AuthorityCodePolicyError == .corruptData { headMismatch = true }
            throw error
        }
    }

    public func epoch(_ id: Data) throws -> AuditEpochRead? { try tables().epoch(id) }
    public func page(epoch: Data, after: UInt64, maximumRecords: Int, maximumBytes: Int) throws -> AuditJournalPage {
        try tables().page(epoch: epoch, after: after, maximumRecords: maximumRecords, maximumBytes: maximumBytes)
    }
    private func mutate<T>(_ body: (AuditJournalTables) throws -> T) throws -> T {
        do { return try body(tables(write: true)) }
        catch {
            failed = true
            if error as? AuditJournalError == .headMismatch { headMismatch = true }
            throw error
        }
    }
    /// Internal verification path. Public callers must use the overload that reads durable trust.
    func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                        trust: ApprovalTrustSnapshot, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                        writer: AuditEpochWriter, expectedHead: UInt64, requestLimits: CBORLimits,
                        signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        try mutate { audit in
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try owner.ledger(token).consume(canonicalDecision: canonicalDecision, signature: signature,
                retained: retained, trust: trust, now: now, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedHead, audit: audit, requestLimits: requestLimits, signingLimits: signingLimits)
        }
    }

    private func withEnrollment<T>(write: Bool, _ body: (EnrollmentJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.enrollmentLedger(token))
        } catch {
            failed = true
            if error as? EnrollmentJournalError == .corruptData || error as? AuditJournalError == .headMismatch { headMismatch = true }
            throw error
        }
    }

    /// Protected administrator setup. This stores policy only; it cannot infer trust from audit records or incoming decisions.
    public func configureApprovalAuthority(capabilities: ContractCapabilities, allowedContracts: Set<RequestContract>) throws -> UUID {
        try withEnrollment(write: true) { try $0.configure(capabilities: capabilities, allowed: allowedContracts) }
    }
    public func approvalTrustSnapshot() throws -> ApprovalTrustSnapshot {
        try withEnrollment(write: false) { try $0.snapshot() }
    }
    public func requestDeliveryTrust() throws -> RequestDeliveryTrust {
        try withEnrollment(write: false) { ledger in
            try RequestDeliveryTrust(approval: ledger.snapshot(), enrollments: ledger.all())
        }
    }
    /// One protected read for a listener incarnation. The host supplies current local protocol policy and resource limits.
    public func directApprovalTrust(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64 = 1,
                                    auditVersions: Set<UInt64> = []) throws -> DirectApprovalTrust {
        guard (1...16_777_216).contains(maximumPayloadBytes), minimumEnvelopeVersion > 0,
              auditVersions.count <= 16, !auditVersions.contains(0) else { throw DirectListenerError.invalidConfiguration }
        return try withEnrollment(write: false) {
            try $0.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes,
                minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions)
        }
    }
    /// Rechecks the protected revision and peer binding. It grants no approval or execution authority.
    public func requireDirectApprovalPeer(_ peer: DirectApprovalPeer, expectedTrustRevision: UUID) throws {
        try withEnrollment(write: false) { try $0.requireDirectPeer(peer, revision: expectedTrustRevision) }
    }
    /// Validate a decoded IPC binding against current protected enrollment state in this transaction.
    public func requireDirectApprovalBinding(_ binding: AuthorityPeerBinding) throws {
        try withEnrollment(write: false) { try $0.requireDirectBinding(binding) }
    }
    public func approvalEnrollments() throws -> [StoredApprovalEnrollment] {
        try withEnrollment(write: false) { ledger in _ = try ledger.snapshot(); return try ledger.all() }
    }

    /// Returns receipt material only for an active enrollment on an authenticated phone channel.
    public func committedPairing(setupID: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data) throws -> PairingTranscript? {
        try withEnrollment(write: false) { try $0.committedPairing(setupID: setupID, phoneID: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch) }
    }

    func retainPairing(_ transcript: PairingTranscript, biometricProof: Data, enrollment: StoredApprovalEnrollment) throws {
        try withEnrollment(write: true) { try $0.retainPairing(transcript, biometricProof: biometricProof, enrollment: enrollment) }
    }

    /// The host verifies administrator authorization and the biometric enrollment proof before calling this method.
    public func addApprovalEnrollment(_ enrollment: StoredApprovalEnrollment, expectedTrustRevision: UUID,
                                      eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> UUID {
        try withEnrollment(write: true) { ledger in
            let next = try ledger.add(enrollment, expected: expectedTrustRevision)
            try enrollmentEvent(phone: enrollment.approval.phoneID, added: true, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedAuditHead, snapshot: ledger.snapshot())
            return next
        }
    }

    /// Removal and its audit event share the transaction with the signed gateway control when a gateway is configured.
    public func revokeApprovalEnrollment(phoneID: Data, epoch: Data, expectedTrustRevision: UUID,
                                         eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64,
                                         gateway: EnrollmentGatewayRemoval? = nil) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        try withEnrollment(write: true) { ledger in
            if try ledger.hasGateway(), gateway == nil { throw EnrollmentJournalError.gatewayRequired }
            let (old, next) = try ledger.revoke(phone: phoneID, epoch: epoch, expected: expectedTrustRevision)
            var control: GatewayAuthorityEnvelope?
            if let gateway {
                let enrollment = try GatewayPhoneEnrollment(phoneID: phoneID, epoch: epoch, tag: old.notificationTag, active: false)
                control = try revokeGatewayEnrollment(trust: GatewayAuthorityTrust(registration: gateway.registration, enrollment: enrollment, active: true),
                    expectedHead: gateway.expectedHead, nowUnixMillis: gateway.nowUnixMillis, now: gateway.now, sign: gateway.sign)
            }
            try enrollmentEvent(phone: phoneID, added: false, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedAuditHead, snapshot: ledger.snapshot())
            return (next, control)
        }
    }

    /// Root-signed revocation evidence can only restrict authority. Expired delivery envelopes remain valid evidence.
    /// The host closes affected admission until this transaction and its continuity checkpoint have committed.
    /// A changed return revision means that a system recovery event was appended at expectedAuditHead + 1.
    public func recoverGatewayRevocation(canonicalPayload: Data, signature: Data, registration: GatewayRegistrationIdentity,
                                         expectedTrustRevision: UUID, eventID: Data, receiptTimeMs: UInt64?,
                                         writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> UUID {
        try withEnrollment(write: true) { ledger in
            let snapshot = try ledger.snapshot()
            guard snapshot.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            guard snapshot.macID == registration.macID, snapshot.accountID == registration.accountID else { throw GatewayAuthorityError.wrongScope }
            let (revocation, changed) = try withGateway(write: true) {
                try $0.recoverRevocation(payload: canonicalPayload, signature: signature, identity: registration)
            }
            let next = try ledger.restrictRecovered(phone: revocation.binding.phoneID, epoch: revocation.binding.enrollmentEpoch,
                expected: expectedTrustRevision, evidenceChanged: changed)
            if next != expectedTrustRevision {
                guard expectedAuditHead < UInt64.max else { throw AuditJournalError.headMismatch }
                let event = try AuditEventMetadata(eventID: eventID, macID: snapshot.macID, accountID: snapshot.accountID,
                    journalEpoch: writer.epoch, sequence: expectedAuditHead + 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
                    kind: .recovery, category: .enrollment, action: nil, decisionPhoneID: nil, authentication: .system,
                    outcome: .accepted, reason: .revoked, droppedEventCount: nil, peerDeviceID: revocation.binding.phoneID)
                guard let owner else { throw JournalDatabaseError.expiredTransaction }
                try owner.appendEnrollmentEvent(event, token: token, writer: writer, expectedHead: expectedAuditHead)
            }
            return next
        }
    }

    /// Root-signed unknown trust history restricts this phone without deleting pairing or enrollment records.
    /// The host closes affected admission until this transaction and its independent checkpoint commit.
    public func restrictUnknownGatewayTrust(kind: GatewayTrustEvidenceKind, canonicalPayload: Data, signature: Data,
                                           registration: GatewayRegistrationIdentity, expectedTrustRevision: UUID,
                                           eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter,
                                           expectedAuditHead: UInt64) throws -> GatewayTrustRestrictionResult {
        try withEnrollment(write: true) { ledger in
            let snapshot = try ledger.snapshot()
            guard snapshot.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            guard snapshot.macID == registration.macID, snapshot.accountID == registration.accountID else { throw GatewayAuthorityError.wrongScope }
            let (phone, disposition) = try withGateway(write: true) {
                try $0.restrictUnknownTrust(kind: kind, payload: canonicalPayload, signature: signature,
                    identity: registration, enrollments: ledger.all())
            }
            var revision = expectedTrustRevision
            if disposition == .restricted {
                revision = try ledger.advanceForRestriction(expected: expectedTrustRevision)
                guard expectedAuditHead < UInt64.max else { throw AuditJournalError.headMismatch }
                let event = try AuditEventMetadata(eventID: eventID, macID: snapshot.macID, accountID: snapshot.accountID,
                    journalEpoch: writer.epoch, sequence: expectedAuditHead + 1, requestID: nil, eventTimeMs: nil,
                    authorityReceiptTimeMs: receiptTimeMs, kind: .recovery, category: .enrollment, action: nil,
                    decisionPhoneID: nil, authentication: .system, outcome: .unresolved, reason: .bindingMismatch,
                    droppedEventCount: nil, peerDeviceID: phone)
                guard let owner else { throw JournalDatabaseError.expiredTransaction }
                try owner.appendEnrollmentEvent(event, token: token, writer: writer, expectedHead: expectedAuditHead)
            }
            return GatewayTrustRestrictionResult(phoneID: phone, disposition: disposition, trustRevision: revision)
        }
    }

    /// Apply the head receipt before collecting history. Missing history cannot cancel restrictive evidence.
    public func recoverGatewayTrust(from head: VerifiedGatewayHead, expectedTrustRevision: UUID,
                                    receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> GatewayTrustEvidenceRecovery {
        try recoverGatewayTrust(records: head.evidence.receipt.map { [$0] } ?? [], registration: head.evidence.registration,
            expectedTrustRevision: expectedTrustRevision, receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: expectedAuditHead)
    }

    /// Apply each verified page before contiguity checks. A page with gaps still contains valid restrictive evidence.
    /// Keep affected admission closed until the write and independent continuity checkpoint complete.
    public func recoverGatewayTrust(from history: VerifiedGatewayControlHistory, expectedTrustRevision: UUID,
                                    receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> GatewayTrustEvidenceRecovery {
        try recoverGatewayTrust(records: history.page.records, registration: history.page.registration,
            expectedTrustRevision: expectedTrustRevision, receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: expectedAuditHead)
    }

    private func recoverGatewayTrust(records: [GatewayControlReceipt], registration: GatewayRegistrationIdentity,
                                     expectedTrustRevision: UUID, receiptTimeMs: UInt64?, writer: AuditEpochWriter,
                                     expectedAuditHead: UInt64) throws -> GatewayTrustEvidenceRecovery {
        try withEnrollment(write: true) { ledger in
            guard records.count <= 16 else { throw GatewayAuthorityError.capacityExceeded }
            let snapshot = try ledger.snapshot()
            guard snapshot.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            _ = try gatewayAuthorityHead(registration)
            guard try epoch(writer.epoch)?.head == expectedAuditHead else { throw AuditJournalError.headMismatch }
            var revision = expectedTrustRevision, auditHead = expectedAuditHead
            var changed: Set<Data> = []
            for record in records {
                var eventUUID = UUID().uuid
                let eventID = withUnsafeBytes(of: &eventUUID) { Data($0) }
                let next: UUID, phone: Data
                switch record {
                case .submission:
                    guard try withGateway(write: false, { try $0.submissionHistoryInstalled() }) else {
                        throw GatewayAuthorityError.unsupportedSubmissionControl
                    }
                    // Credential history belongs to reconciliation. It must not change a phone enrollment or restore a private key.
                    continue
                case .candidate(let receipt):
                    phone = receipt.candidate.binding.phoneID
                    next = try restrictUnknownGatewayTrust(kind: .candidate, canonicalPayload: record.canonicalPayload,
                        signature: record.signature, registration: registration, expectedTrustRevision: revision,
                        eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: auditHead).trustRevision
                case .recipient(let receipt):
                    switch receipt.control {
                    case .activation(let value):
                        phone = value.binding.phoneID
                        next = try restrictUnknownGatewayTrust(kind: .activation, canonicalPayload: record.canonicalPayload,
                            signature: record.signature, registration: registration, expectedTrustRevision: revision,
                            eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: auditHead).trustRevision
                    case .revocation(let value):
                        phone = value.binding.phoneID
                        next = try recoverGatewayRevocation(canonicalPayload: record.canonicalPayload, signature: record.signature,
                            registration: registration, expectedTrustRevision: revision, eventID: eventID,
                            receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: auditHead)
                    }
                }
                if next != revision { changed.insert(phone); auditHead += 1; revision = next }
            }
            return GatewayTrustEvidenceRecovery(trustRevision: revision, auditHead: auditHead,
                changedPhoneIDs: changed, restrictedPhoneIDs: try ledger.restrictedPhones())
        }
    }

    /// Phones awaiting independent administrator repair. Retained pairing rows do not grant these phones authority.
    public func approvalTrustRestrictions() throws -> Set<Data> {
        try withEnrollment(write: false) { ledger in _ = try ledger.snapshot(); return try ledger.restrictedPhones() }
    }

    private func enrollmentEvent(phone: Data, added: Bool, eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter,
                                 expectedHead: UInt64, snapshot: ApprovalTrustSnapshot) throws {
        guard expectedHead < UInt64.max else { throw AuditJournalError.headMismatch }
        let event = try AuditEventMetadata(eventID: eventID, macID: snapshot.macID, accountID: snapshot.accountID,
            journalEpoch: writer.epoch, sequence: expectedHead + 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
            kind: added ? .enrollmentAdded : .enrollmentRevoked, category: .enrollment, action: nil, decisionPhoneID: nil,
            authentication: .localAdministrator, outcome: .accepted, reason: added ? .none : .revoked, droppedEventCount: nil, peerDeviceID: phone)
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        try owner.appendEnrollmentEvent(event, token: token, writer: writer, expectedHead: expectedHead)
    }

    /// Reads current enrolled keys in this write transaction. No caller-supplied enrollment snapshot can authorize consumption.
    public func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                        expectedTrustRevision: UUID, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                        writer: AuditEpochWriter, expectedHead: UInt64, requestLimits: CBORLimits,
                        signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        try withEnrollment(write: true) { ledger in
            let trust = try ledger.snapshot()
            guard trust.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            return try consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained, trust: trust,
                now: now, eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: expectedHead,
                requestLimits: requestLimits, signingLimits: signingLimits)
        }
    }

    public func consumption(requestID: Data) throws -> ConsumptionReceipt? {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.ledger(token).receipt(requestID: requestID)
    }

    /// Record a controller-verified observation. No transition grants permission to execute or retry an action.
    public func transitionConsumption(requestID: Data, expectedRevision: UInt64, event: RequestEvent, eventID: Data,
                                      receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedHead: UInt64) throws -> ConsumptionOutcome {
        try mutate { audit in
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try owner.ledger(token).transition(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: expectedHead, audit: audit)
        }
    }

    /// Enumerate retained observations under the authority's recovery lock. Never restore requests from this page.
    public func consumptionOutcomes(afterRequestID: Data? = nil, maximumRecords: Int, maximumBytes: Int) throws -> ConsumptionOutcomePage {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.ledger(token).outcomePage(after: afterRequestID, maximumRecords: maximumRecords, maximumBytes: maximumBytes)
    }

    /// Startup only, after authority continuity checks and fresh epoch creation. Never use for live requests.
    func reconcileInterruptedConsumptions(afterRequestID: Data? = nil, maximumRecords: Int, maximumBytes: Int,
                                          writer: AuditEpochWriter, expectedHead: UInt64) throws -> ConsumptionRecoveryBatch {
        try mutate { audit in
            guard try audit.epoch(writer.epoch)?.head == expectedHead else { throw AuditJournalError.headMismatch }
            let page = try consumptionOutcomes(afterRequestID: afterRequestID, maximumRecords: maximumRecords, maximumBytes: maximumBytes)
            let unresolved = page.outcomes.filter { $0.phase == .authorized || $0.phase == .executing }
            guard unresolved.allSatisfy({ $0.event.journalEpoch != writer.epoch }) else {
                throw ConsumptionJournalError.invalidConfiguration
            }
            var head = expectedHead
            for outcome in unresolved {
                var eventID = UUID().uuid
                _ = try transitionConsumption(requestID: outcome.receipt.decision.requestID, expectedRevision: outcome.revision,
                    event: .restartAuthority, eventID: withUnsafeBytes(of: &eventID) { Data($0) }, receiptTimeMs: nil,
                    writer: writer, expectedHead: head)
                head += 1 // transitionConsumption rejects overflow before appending.
            }
            return ConsumptionRecoveryBatch(nextRequestID: page.nextRequestID, changedCount: unresolved.count, journalHead: head)
        }
    }

    public func consumptionOutcome(requestID: Data) throws -> ConsumptionOutcome? {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.ledger(token).outcome(requestID: requestID)
    }

    private func withRouting<T>(write: Bool, _ body: (RoutingJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.routingLedger(token))
        } catch {
            failed = true
            if error as? RoutingJournalError == .corruptData || error as? RoutingJournalError == .invalidClock ||
                error as? AuditJournalError == .headMismatch { headMismatch = true }
            throw error
        }
    }

    public func routingState() throws -> RoutingState { try withRouting(write: false) { try $0.state() } }

    /// The host authenticates the local Mac control surface. Never expose this API to phone or transport callers.
    public func setLocalRoutingMode(_ mode: RoutingMode, expectedRevision: UInt64, eventID: Data, receiptTimeMs: UInt64?,
                                    writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> RoutingState {
        try withRouting(write: true) { routing in
            let state = try routing.setLocal(mode, expected: expectedRevision)
            try routingEvent(phone: nil, eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer,
                expectedHead: expectedAuditHead, scope: routing.scope)
            return state
        }
    }

    private func routingEnrollment(phone: Data, epoch: Data, revision: UUID) throws -> StoredApprovalEnrollment {
        try withEnrollment(write: false) { ledger in
            let trust = try ledger.snapshot()
            guard trust.revision == revision else { throw EnrollmentJournalError.staleRevision }
            guard try !ledger.restrictedPhones().contains(phone) else { throw EnrollmentJournalError.recoveryRequired }
            guard let enrollment = try ledger.all().first(where: {
                $0.approval.phoneID == phone && $0.epoch == epoch && $0.approval.active
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            return enrollment
        }
    }

    /// Supply the separately authenticated phone identity. Publish the challenge only after this transaction commits.
    public func issueRoutingChallenge(authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data, expectedTrustRevision: UUID,
                                      expectedRoutingRevision: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> RoutingAwayControl {
        try withRouting(write: true) { routing in
            let enrollment = try routingEnrollment(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, revision: expectedTrustRevision)
            return try routing.issue(enrollment: enrollment, expected: expectedRoutingRevision, wall: nowUnixMillis, now: now)
        }
    }

    /// Rechecks stored enrollment and commits the mode, operation result and audit event together. Retries never reapply a mode.
    public func applyRoutingAway(canonicalPayload: Data, signature: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                 expectedTrustRevision: UUID, nowUnixMillis: UInt64, now: AuthorityMoment,
                                 eventID: Data, writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> RoutingChange {
        try withRouting(write: true) { routing in
            let enrollment = try routingEnrollment(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, revision: expectedTrustRevision)
            let result = try routing.apply(payload: canonicalPayload, signature: signature, enrollment: enrollment, wall: nowUnixMillis, now: now)
            if result.inserted {
                try routingEvent(phone: authenticatedPhoneID, eventID: eventID, receiptTimeMs: nowUnixMillis,
                    writer: writer, expectedHead: expectedAuditHead, scope: routing.scope)
            }
            return result
        }
    }

    private func routingEvent(phone: Data?, eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter,
                               expectedHead: UInt64, scope: (macID: Data, accountID: Data)) throws {
        guard expectedHead < UInt64.max else { throw AuditJournalError.headMismatch }
        let event = try AuditEventMetadata(eventID: eventID, macID: scope.macID, accountID: scope.accountID, journalEpoch: writer.epoch,
            sequence: expectedHead + 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
            kind: .routingChanged, category: .authority, action: nil, decisionPhoneID: phone,
            authentication: phone == nil ? .localUser : .decisionKey, outcome: .accepted, reason: .none, droppedEventCount: nil, peerDeviceID: nil)
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        try owner.appendEnrollmentEvent(event, token: token, writer: writer, expectedHead: expectedHead)
    }

    private func withGateway<T>(write: Bool, _ body: (GatewayAuthorityJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.gatewayLedger(token))
        } catch {
            failed = true
            if let error = error as? GatewayAuthorityError, [.headMismatch, .invalidClock, .corruptData].contains(error) { headMismatch = true }
            throw error
        }
    }

    /// Protected administrator setup only. This method cannot replace an existing gateway registration.
    public func configureGatewayAuthority(_ identity: GatewayRegistrationIdentity) throws {
        try withGateway(write: true) { try $0.configure(identity) }
    }

    /// Protected setup only. Update the continuity checkpoint for the new authority digest before runtime activation.
    public func installGatewaySubmissionHistory(_ registration: GatewayRegistrationIdentity) throws {
        try withGateway(write: true) { try $0.installSubmissionHistory(identity: registration) }
    }

    public func rotateGatewaySubmission(publicKey: Data, registration: GatewayRegistrationIdentity, registrationActive: Bool,
                                        expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.rotateSubmission(publicKey: publicKey, identity: registration, active: registrationActive,
            expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    public func revokeGatewaySubmission(credentialID: Data, registration: GatewayRegistrationIdentity, registrationActive: Bool,
                                        expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.revokeSubmission(credentialID: credentialID, identity: registration, active: registrationActive,
            expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    /// Retained Root intent only. This does not prove current gateway state or grant possession of a private credential.
    public func desiredGatewaySubmission(_ registration: GatewayRegistrationIdentity) throws -> GatewaySubmissionReceipt? {
        try withGateway(write: false) { try $0.desiredSubmission(identity: registration) }
    }

    public func pendingGatewaySubmission(operationID: Data, registration: GatewayRegistrationIdentity, registrationActive: Bool,
                                         nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try withGateway(write: false) { try $0.pendingSubmission(operationID: operationID, identity: registration, active: registrationActive,
            wall: nowUnixMillis, now: now) }
    }

    public func renewGatewaySubmission(operationID: Data, registration: GatewayRegistrationIdentity, registrationActive: Bool,
                                       expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                       sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.renewSubmission(operationID: operationID, identity: registration, active: registrationActive,
            expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    public func gatewayAuthorityHead(_ identity: GatewayRegistrationIdentity) throws -> UInt64 {
        try withGateway(write: false) { try $0.head(identity) }
    }

    func firstGatewayNonRegistrationControl(after revision: UInt64, registration: GatewayRegistrationIdentity) throws -> UInt64? {
        try withGateway(write: false) { try $0.firstNonRegistrationControl(after: revision, identity: registration) }
    }

    /// Historical metadata only. It cannot establish current gateway availability or restore authority.
    public func gatewayAcknowledgment(_ identity: GatewayRegistrationIdentity) throws -> GatewayAcknowledgment? {
        try withGateway(write: false) { try $0.acknowledgment(identity) }
    }

    /// Root host only: use its protected query owner and serialize this transaction with local trust changes.
    /// Missing or conflicting history requires reconciliation before publishing mappings or enabling affected authority.
    public func acknowledgeGatewayHead(_ verified: VerifiedGatewayHead) throws -> GatewayAcknowledgmentResult {
        try withGateway(write: true) { try $0.acknowledge(verified) }
    }

    /// Inspect the proposed acknowledgment without writing. A recorded disposition still requires the owner to commit it.
    func inspectGatewayHead(_ verified: VerifiedGatewayHead) throws -> GatewayAcknowledgmentResult {
        try withGateway(write: false) { try $0.acknowledge(verified, record: false) }
    }

    /// Protected root recovery after independent continuity checks. Serialize with trust and registration changes.
    /// Apply recovered revocations before reconciliation. Unknown trust history still requires host recovery.
    /// Collection includes the shared boundary receipt when expectedLocalRevision is nonzero.
    /// Success retires old delivery attempts; renew only current desired tokens after commit.
    public func reconcileGatewayDeliveryHistory(_ history: VerifiedGatewayHistory, registrationActive: Bool,
                                               expectedTrustRevision: UUID, expectedLocalRevision: UInt64, now: AuthorityMoment) throws -> GatewayHistoryRecoveryResult {
        guard registrationActive else { throw GatewayAuthorityError.unavailableRegistration }
        let enrollments = try withEnrollment(write: false) { ledger in
            let snapshot = try ledger.snapshot(), identity = history.head.evidence.registration
            guard snapshot.macID == identity.macID, snapshot.accountID == identity.accountID else { throw GatewayAuthorityError.wrongScope }
            guard snapshot.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            return try ledger.all()
        }
        return try withGateway(write: true) { try $0.reconcile(history, expectedLocalRevision: expectedLocalRevision, enrollments: enrollments, now: now) }
    }

    /// Internal verification path. Public token APIs derive phone trust from durable enrollment.
    /// Keep the signer local to the root authority. Publish only after commit and continuity checks.
    func prepareGatewayCandidate(registrationToken: String, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                        trust: GatewayAuthorityTrust, expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) {
            try $0.prepare(token: registrationToken, authenticatedPhoneID: authenticatedPhoneID, authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch,
                trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign)
        }
    }

    /// The root host establishes continuity and current enrollment before automatic recovery. No new phone prompt is needed.
    func renewDesiredGatewayCandidate(trust: GatewayAuthorityTrust, expectedHead: UInt64,
                                             nowUnixMillis: UInt64, now: AuthorityMoment,
                                             sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.renewDesired(trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    /// Proof consumption and the signed activation outbox share this transaction. No biometric is required for routine token rotation.
    func consumeGatewayProof(canonicalProof: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                    trust: GatewayAuthorityTrust, expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                    sign: (GatewayMappingActivation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) {
            try $0.consume(proofBytes: canonicalProof, authenticatedPhoneID: authenticatedPhoneID, authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch,
                trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign)
        }
    }

    func pendingGatewayControl(operationID: Data, trust: GatewayAuthorityTrust,
                                      nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try withGateway(write: false) { try $0.pending(operationID: operationID, trust: trust, wall: nowUnixMillis, now: now) }
    }

    private func storedGatewayTrust(phoneID: Data, epoch: Data, registration: GatewayRegistrationIdentity,
                                    registrationActive: Bool, expectedTrustRevision: UUID) throws -> GatewayAuthorityTrust {
        try withEnrollment(write: false) { ledger in
            let snapshot = try ledger.snapshot()
            guard snapshot.macID == registration.macID, snapshot.accountID == registration.accountID else { throw GatewayAuthorityError.wrongScope }
            guard snapshot.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            guard try !ledger.restrictedPhones().contains(phoneID) else { throw EnrollmentJournalError.recoveryRequired }
            guard let enrolled = try ledger.all().first(where: {
                $0.approval.phoneID == phoneID && $0.epoch == epoch && $0.approval.active
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            return try GatewayAuthorityTrust(registration: registration,
                enrollment: GatewayPhoneEnrollment(phoneID: phoneID, epoch: epoch, tag: enrolled.notificationTag, active: true),
                active: registrationActive)
        }
    }

    /// The host authenticates the phone channel. The journal supplies its current epoch and notification tag.
    /// Registration activity remains protected host state. Neither it nor the signer may come from a phone message.
    public func prepareGatewayCandidate(registrationToken: String, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                        registration: GatewayRegistrationIdentity, registrationActive: Bool, expectedTrustRevision: UUID,
                                        expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        let trust = try storedGatewayTrust(phoneID: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch,
            registration: registration, registrationActive: registrationActive, expectedTrustRevision: expectedTrustRevision)
        return try prepareGatewayCandidate(registrationToken: registrationToken, authenticatedPhoneID: authenticatedPhoneID,
            authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch, trust: trust, expectedHead: expectedHead,
            nowUnixMillis: nowUnixMillis, now: now, sign: sign)
    }

    /// Automatic recovery reads only this enrolled epoch's current desired token. It requires no new phone prompt.
    public func renewDesiredGatewayCandidate(phoneID: Data, enrollmentEpoch: Data,
                                             registration: GatewayRegistrationIdentity, registrationActive: Bool, expectedTrustRevision: UUID,
                                             expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                             sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        let trust = try storedGatewayTrust(phoneID: phoneID, epoch: enrollmentEpoch,
            registration: registration, registrationActive: registrationActive, expectedTrustRevision: expectedTrustRevision)
        return try renewDesiredGatewayCandidate(trust: trust, expectedHead: expectedHead, nowUnixMillis: nowUnixMillis, now: now, sign: sign)
    }

    /// Current durable enrollment is checked in the proof-consumption transaction, before any activation is signed.
    public func consumeGatewayProof(canonicalProof: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                    registration: GatewayRegistrationIdentity, registrationActive: Bool, expectedTrustRevision: UUID,
                                    expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                    sign: (GatewayMappingActivation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        let trust = try storedGatewayTrust(phoneID: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch,
            registration: registration, registrationActive: registrationActive, expectedTrustRevision: expectedTrustRevision)
        return try consumeGatewayProof(canonicalProof: canonicalProof, authenticatedPhoneID: authenticatedPhoneID,
            authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch, trust: trust, expectedHead: expectedHead,
            nowUnixMillis: nowUnixMillis, now: now, sign: sign)
    }

    /// Root-only operational state. Derive current phone trust from protected enrollment, never caller-supplied metadata.
    func currentGatewayTokenState(phoneID: Data, enrollmentEpoch: Data,
                                  registration: GatewayRegistrationIdentity, registrationActive: Bool,
                                  expectedTrustRevision: UUID, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayCurrentTokenState? {
        let trust = try storedGatewayTrust(phoneID: phoneID, epoch: enrollmentEpoch, registration: registration,
            registrationActive: registrationActive, expectedTrustRevision: expectedTrustRevision)
        return try withGateway(write: false) { try $0.currentTokenState(trust: trust, wall: nowUnixMillis, now: now) }
    }

    public func pendingGatewayControl(operationID: Data, phoneID: Data, enrollmentEpoch: Data,
                                      registration: GatewayRegistrationIdentity, registrationActive: Bool, expectedTrustRevision: UUID,
                                      nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        let trust = try storedGatewayTrust(phoneID: phoneID, epoch: enrollmentEpoch,
            registration: registration, registrationActive: registrationActive, expectedTrustRevision: expectedTrustRevision)
        return try pendingGatewayControl(operationID: operationID, trust: trust, nowUnixMillis: nowUnixMillis, now: now)
    }

    /// Protected enrollment removal only. Append the enrollment audit event in this same transaction.
    /// Repeating this operation refreshes the delivery control; it never removes the retained revocation.
    public func revokeGatewayEnrollment(trust: GatewayAuthorityTrust, expectedHead: UInt64,
                                        nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewayPhoneRevocation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.revoke(trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    /// Historical revocation survives control expiry and process restart. It does not prove a gateway acknowledgment.
    public func gatewayEnrollmentRevoked(trust: GatewayAuthorityTrust) throws -> Bool {
        try withGateway(write: false) { try $0.revoked(trust: trust) }
    }

    /// This path accepts inactive enrollment state so a removal can still reach the gateway.
    public func pendingGatewayRevocation(operationID: Data, trust: GatewayAuthorityTrust,
                                         nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try withGateway(write: false) { try $0.pendingRevocation(operationID: operationID, trust: trust, wall: nowUnixMillis, now: now) }
    }

    public func createEpoch(_ descriptor: AuditEpochDescriptor) throws -> AuditEpochWriter {
        try mutate {
            let writer = try $0.createEpoch(descriptor)
            createdEpoch = true
            return writer
        }
    }
    public func append(_ canonicalRecord: Data, writer: AuditEpochWriter, expectedHead: UInt64) throws {
        try mutate { try $0.append(canonicalRecord, writer: writer, expectedHead: expectedHead) }
    }
    public func prune(epoch: Data, through: UInt64, expectedHead: UInt64) throws {
        try mutate { try $0.prune(epoch: epoch, through: through, expectedHead: expectedHead) }
    }
}
