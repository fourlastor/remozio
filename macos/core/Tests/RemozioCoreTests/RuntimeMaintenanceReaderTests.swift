import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Owns synthetic records and a real SQLite file. It proves no installed peer, native hold or service recovery.
struct RuntimeMaintenanceReaderFixture {
    let machine: () -> PreparationIntentStore
    let candidate: SignedReleaseEvidence
    let account: AccountPreparationIntent
    let authority: RuntimeMaintenanceWindowRecord.Account
    let databasePath: String
    let reopen: () throws -> Void
    let edit: ([String]) throws -> Void
    func mutate(_ sql: String) throws { try edit([sql]) }
}

final class RuntimeMaintenanceReaderTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Storage = RuntimeMaintenanceWindowStorage
    private func fixture(_ body: (RuntimeMaintenanceReaderFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(body)
    }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func data(_ byte: UInt8, _ count: Int = 16) -> Data { Data(repeating: byte, count: count) }
    private func account(_ f: RuntimeMaintenanceReaderFixture, changed: Bool = false) throws -> Record.Account {
        try .init(accountID: f.authority.accountID, ownerUID: f.authority.ownerUID + (changed ? 1 : 0),
            directoryID: f.authority.directoryID)
    }
    private func owner(_ f: RuntimeMaintenanceReaderFixture) -> LocalAccountIdentity {
        .init(uid: f.account.ownerUID, primaryGroupID: getgid(), directoryID: f.account.directoryID)
    }
    private func record(_ f: RuntimeMaintenanceReaderFixture, changed: Bool = false,
                        phase: Record.Phase = .authorized) throws -> Record {
        let stable = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        let scope = try Record.Scope(macID: stable.inventory.macID, installationID: stable.inventory.installationID,
            authority: account(f, changed: changed), target: .init(accountID: data(92), ownerUID: 65001, directoryID: data(93)),
            releaseDigest: data(1, 32), candidateDigest: data(2, 32), authorityPolicyDigest: data(3, 32),
            operationDigest: data(4, 32), restorationDigest: data(5, 32), mutationFootprintDigest: data(6, 32),
            authorityGrantDigest: data(7, 32), targetConsentDigest: data(8, 32), administratorIntentDigest: data(9, 32))
        return try .init(id: data(90), revision: data(91), purpose: .retainedRuntime, scope: scope, phase: phase,
            operation: .notStarted, service: .unknown, failure: phase == .needsOwnerRecovery ? .healthFailed : nil, gate: nil)
    }
    private func enable(_ f: RuntimeMaintenanceReaderFixture) throws {
        try f.edit([Storage.createSQL, "PRAGMA user_version=29"])
    }
    private func insert(_ value: Record, _ f: RuntimeMaintenanceReaderFixture) throws {
        try f.mutate("INSERT INTO \(Storage.tableName) VALUES(X'\(hex(value.scope.authority.accountID))',X'\(hex(value.id))',X'\(hex(value.revision))',\(value.phase.rawValue),X'\(try hex(value.encoded))')")
    }
    /// Reads every cell with its SQLite type. The catalog and rows are compared without using the production digest.
    private func rows(_ f: RuntimeMaintenanceReaderFixture, omitMaintenance: Bool = false) throws -> [String: [Data]] {
        var connection: OpaquePointer?
        guard sqlite3_open_v2(f.databasePath, &connection, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK,
              let db = connection else { throw PreparationStoreError.invalidConfiguration }
        defer { sqlite3_close(db) }
        func query(_ sql: String) throws -> [Data] {
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let row = statement else {
                throw PreparationStoreError.corruptRecord
            }
            defer { sqlite3_finalize(row) }
            var values: [Data] = []
            while true {
                let result = sqlite3_step(row)
                if result == SQLITE_DONE { return values.sorted { $0.lexicographicallyPrecedes($1) } }
                guard result == SQLITE_ROW else { throw PreparationStoreError.storage(result) }
                var value = Data()
                for column in 0..<sqlite3_column_count(row) {
                    value.append(UInt8(sqlite3_column_type(row, column)))
                    let count = Int(sqlite3_column_bytes(row, column))
                    var size = UInt64(count).bigEndian
                    withUnsafeBytes(of: &size) { value.append(contentsOf: $0) }
                    if count > 0, let bytes = sqlite3_column_blob(row, column) { value.append(Data(bytes: bytes, count: count)) }
                }
                values.append(value)
            }
        }
        var names: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'", -1, &names, nil) == SQLITE_OK,
              let names else { throw PreparationStoreError.corruptRecord }
        defer { sqlite3_finalize(names) }
        var result: [String: [Data]] = [:]
        while sqlite3_step(names) == SQLITE_ROW {
            let table = String(cString: sqlite3_column_text(names, 0))
            if omitMaintenance && table == Storage.tableName { continue }
            result[table] = try query("SELECT * FROM \(table)")
        }
        let exclusion = omitMaintenance ? " WHERE name NOT LIKE '%runtime_maintenance_windows_v1%'" : ""
        result["catalog"] = try query("SELECT type,name,tbl_name,sql FROM sqlite_schema\(exclusion)")
        return result
    }
    func testOpeningSchema28DoesNotMigrateOrChangeAnyRow() throws {
        try fixture { f in
            let before = try rows(f), stable = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(stable.schemaVersion, 28)
            try f.reopen()
            try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: stable)
            XCTAssertEqual(try rows(f), before)
            let projection = try f.machine().runtimeMaintenanceStartupProjection(account: account(f), candidate: f.candidate)
            XCTAssertFalse(projection.requiresLocalHold); XCTAssertFalse(projection.needsOwnerRecovery)
            XCTAssertEqual(try rows(f), before)
        }
    }
    func testSchema29RetainsEveryOtherRowAndReadsTheStableCompletionChain() throws {
        try fixture { f in
            let before = try rows(f, omitMaintenance: true)
            try enable(f)
            XCTAssertEqual(try rows(f, omitMaintenance: true), before)
            let stable = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(stable.schemaVersion, 29)
            let current = try f.machine().stableRuntimeSource(candidate: f.candidate)
            XCTAssertEqual(current.actual.schemaVersion, 29)
            XCTAssertNotNil(try f.machine().retainedSetupCompletionIntent(accountID: f.account.accountID,
                ownerUID: f.account.ownerUID, candidate: f.candidate))
            XCTAssertNotNil(try f.machine().retainedSetupPromotionIntent(accountID: f.account.accountID,
                ownerUID: f.account.ownerUID, candidate: f.candidate))
            XCTAssertNotNil(try f.machine().retainedSetupPromotionReady(accountID: f.account.accountID,
                ownerUID: f.account.ownerUID, candidate: f.candidate))
            try f.reopen()
            try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: stable)
            XCTAssertEqual(try rows(f, omitMaintenance: true), before)
        }
    }
    func testSchema29CompatibilityUsesAnActualRetainedActivationPlan() throws {
        try MachineUpdateReplacementTests.withMaintenanceRuntimeCompatibilityFixture { f in
            let retained = try f.capture(), compatibility = try f.read(retained)
            XCTAssertEqual(compatibility.inputs.schemaVersion, 29)
            XCTAssertEqual(retained.runtime.setup.source.actual.schemaVersion, 29)
            for role in [AuthorityCodeRole.authority, .setupController] {
                XCTAssertTrue(compatibility.requirements.formats.contains {
                    $0.role == role && $0.name == Record.formatName && $0.readVersions.contains(1)
                })
            }
        }
    }
    func testWindowRowsParticipateInTheStableDigestAndHoldOnlyTheirAccount() throws {
        try fixture { f in
            try enable(f)
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let value = try record(f)
            try insert(value, f)
            let current = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertNotEqual(before.currentRowsDigest, current.currentRowsDigest)
            XCTAssertThrowsError(try current.requireSame(as: before))
            let a = try f.machine().runtimeMaintenanceStartupProjection(account: account(f), candidate: f.candidate)
            XCTAssertTrue(a.requiresLocalHold); XCTAssertFalse(a.needsOwnerRecovery)
            XCTAssertEqual(a.attemptID, value.id); XCTAssertEqual(a.revision, value.revision)
            let other = try Record.Account(accountID: data(94), ownerUID: 65002, directoryID: data(95))
            let b = f.machine().runtimeMaintenanceStartupProjection(account: other, candidate: f.candidate)
            XCTAssertFalse(b.requiresLocalHold); XCTAssertNil(b.attemptID)
            try f.reopen()
            XCTAssertEqual(try f.machine().runtimeMaintenanceStartupProjection(account: account(f), candidate: f.candidate), a)
        }
    }
    func testStartupChangedScopeKeepsAHeldAndReportsOwnerRecovery() throws {
        try fixture { f in
            try enable(f)
            try insert(record(f, changed: true), f)
            try f.reopen()
            let a = try f.machine().runtimeMaintenanceStartupProjection(account: account(f), candidate: f.candidate)
            XCTAssertTrue(a.requiresLocalHold); XCTAssertTrue(a.needsOwnerRecovery)
            XCTAssertNil(a.attemptID); XCTAssertNil(a.revision)
            XCTAssertNoThrow(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate))
        }
    }
    func testOldReadersAndExistingWritersRefuseSchema29() throws {
        try fixture { f in
            try enable(f)
            let before = try rows(f)
            let components = try f.candidate.manifest.components.map { component in
                try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter { $0.name != Record.formatName }, requests: component.requests)
            }
            let old = try SignedReleaseEvidence(manifest: .init(release: f.candidate.manifest.release, build: f.candidate.manifest.build,
                components: components, dependencies: f.candidate.manifest.dependencies), codeDirectoryHashes: f.candidate.codeDirectoryHashes,
                dependencyCodeDirectoryHashes: f.candidate.dependencyCodeDirectoryHashes)
            XCTAssertThrowsError(try f.machine().stableMachineUpdateSnapshot(candidate: old)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            try f.reopen()
            XCTAssertFalse(MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(29))
            XCTAssertFalse(MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(29))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPolicyStorage.requireSchema(29, candidate: f.candidate))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionStorage.requireWriteFormats(f.candidate,
                sourceSchema: 29, operation: .retainPrepared))
            let stable = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertThrowsError(try f.machine().writeInventory(stable.inventory, expectedRevision: stable.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertEqual(try rows(f), before)
        }
    }
    func testIndexedCorruptionAndNoncanonicalTableDeclarationsRefuse() throws {
        try fixture { f in
            try enable(f); try insert(record(f), f)
            try f.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=randomblob(16)")
            XCTAssertThrowsError(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
        try fixture { f in
            try enable(f)
            try f.machine().close()
            var connection: OpaquePointer?
            XCTAssertEqual(sqlite3_open(f.databasePath, &connection), SQLITE_OK)
            let db = try XCTUnwrap(connection)
            defer { sqlite3_close(db) }
            XCTAssertEqual(sqlite3_exec(db, "DROP TABLE runtime_maintenance_windows_v1", nil, nil, nil), SQLITE_OK)
            XCTAssertEqual(sqlite3_exec(db, "CREATE TABLE runtime_maintenance_windows_v1(account BLOB PRIMARY KEY,attempt BLOB,revision BLOB,phase INTEGER,record BLOB) STRICT", nil, nil, nil), SQLITE_OK)
            XCTAssertThrowsError(try f.reopen()) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
        }
    }
}
