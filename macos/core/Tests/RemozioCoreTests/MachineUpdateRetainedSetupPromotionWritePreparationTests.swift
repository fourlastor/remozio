import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class MachineUpdateRetainedSetupPromotionWritePreparationTests: XCTestCase {
    private typealias Storage = MachineUpdateRetainedSetupPromotionStorage
    private typealias Catalog = MachineUpdateRetainedSetupPromotionCatalog

    private func exec(_ db: OpaquePointer, _ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }

    private func database(schema: Int64 = 26, promotion: Bool = false,
        _ body: (OpaquePointer) throws -> Void) throws {
        var connection: OpaquePointer?
        guard sqlite3_open(":memory:", &connection) == SQLITE_OK, let connection else {
            if let connection { sqlite3_close(connection) }
            throw PreparationStoreError.invalidConfiguration
        }
        defer { XCTAssertEqual(sqlite3_close(connection), SQLITE_OK) }
        try exec(connection, "CREATE TABLE protected_rows(id INTEGER PRIMARY KEY,value BLOB NOT NULL) STRICT")
        if promotion { try exec(connection, Storage.createSQL) }
        try exec(connection, "PRAGMA user_version=\(schema)")
        try body(connection)
    }

    private func editing(_ candidate: SignedReleaseEvidence,
        _ edit: (AuthorityCodeRole, ReleaseFormat) throws -> ReleaseFormat) throws -> SignedReleaseEvidence {
        let components = try candidate.manifest.components.map { component in
            try ReleaseComponent(role: component.role, identifier: component.identifier,
                generation: component.generation, relativePath: component.relativePath,
                codeDirectoryHash: component.codeDirectoryHash, build: component.build, teamID: component.teamID,
                formats: component.formats.map { try edit(component.role, $0) }, requests: component.requests)
        }
        return try .init(manifest: .init(release: candidate.manifest.release, build: candidate.manifest.build,
            components: components, dependencies: candidate.manifest.dependencies),
            codeDirectoryHashes: candidate.codeDirectoryHashes, dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
    }

    private func migration(_ candidate: SignedReleaseEvidence, roles: Set<AuthorityCodeRole>) throws -> SignedReleaseEvidence {
        try editing(candidate) { role, format in
            guard [AuthorityCodeRole.authority, .setupController].contains(role),
                  format.name == "authority.installation-preparation" else { return format }
            var migrations = format.migrations
            migrations[26] = roles.contains(role) ? 27 : nil
            return try .init(name: format.name, readers: format.readers, writers: format.writers, migrations: migrations)
        }
    }

    func testMigrationRequiresBothRolesAndLeavesTheActualStoreUsable() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionNativeContextFixture { f in
            let before = try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            try Storage.requireProposalFormats(f.candidate)
            let roleSets: [Set<AuthorityCodeRole>] = [[], [.authority], [.setupController]]
            for roles in roleSets {
                let candidate = try migration(f.candidate, roles: roles)
                XCTAssertThrowsError(try Storage.requireWriteFormats(candidate, sourceSchema: 26, operation: .retainPrepared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
                try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
            }
            let declared = try migration(f.candidate, roles: [.authority, .setupController])
            try Storage.requireWriteFormats(declared, sourceSchema: 26, operation: .retainPrepared)
            try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
        }
    }

    func testEveryProducerWriterIsRequiredEvenWhenNoMigrationIsNeeded() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionNativeContextFixture { f in
            let before = try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            var writers: [(AuthorityCodeRole, String, UInt64)] = []
            for role in [AuthorityCodeRole.authority, .setupController] {
                for version in [UInt64(25), 26, 27] { writers.append((role, "authority.installation-preparation", version)) }
                writers.append((role, MachineUpdateRetainedSetupPolicyIntentRecord.formatName, 2))
                writers.append((role, MachineUpdateRetainedSetupCompletionIntentRecord.formatName, 1))
            }
            writers.append((.setupController, MachineUpdateRetainedSetupPromotionIntentRecord.formatName, 1))
            for requirement in try RuntimeRetainedSetupCompletionBinding.completedHostRequirements {
                for version in requirement.writeVersions { writers.append((requirement.role, requirement.name, version)) }
            }
            for (missingRole, missingName, missingVersion) in writers {
                let candidate = try editing(f.candidate) { role, format in
                    guard role == missingRole, format.name == missingName else { return format }
                    let writers = format.writers.subtracting([missingVersion])
                    return try .init(name: format.name, readers: format.readers, writers: writers,
                        migrations: format.migrations.filter { writers.contains($0.value) })
                }
                try Storage.requireReaderFormats(candidate)
                for schema in [Int64(27), 28] {
                    XCTAssertThrowsError(try Storage.requireWriteFormats(candidate, sourceSchema: schema, operation: .changePhase)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                    }
                }
                try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
            }
        }
    }

    func testSchemaAndOperationRemainSeparateFromDeclarations() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionNativeContextFixture { f in
            for schema in [Int64(27), 28] {
                try Storage.requireWriteFormats(f.candidate, sourceSchema: schema, operation: .retainPrepared)
                try Storage.requireWriteFormats(f.candidate, sourceSchema: schema, operation: .changePhase)
            }
            for schema in [Int64(24), 25, 29] {
                XCTAssertThrowsError(try Storage.requireWriteFormats(f.candidate, sourceSchema: schema, operation: .retainPrepared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            }
            let declared = try migration(f.candidate, roles: [.authority, .setupController])
            XCTAssertThrowsError(try Storage.requireWriteFormats(declared, sourceSchema: 26, operation: .changePhase)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testCatalogAllowsOnlyTheCanonical26To27Addition() throws {
        try database { db in
            try exec(db, "BEGIN IMMEDIATE")
            let before = try Catalog.capture(db)
            try exec(db, Storage.createSQL)
            try exec(db, "PRAGMA user_version=27")
            let after = try Catalog.capture(db)
            try after.requireRetention(from: before)
            XCTAssertEqual(before.protectedDigest, after.protectedDigest)
            XCTAssertNil(before.promotionDigest)
            XCTAssertNotNil(after.promotionDigest)
            XCTAssertThrowsError(try after.requireSame(as: before))
            try after.requireSame(as: Catalog.capture(db))
            try exec(db, "COMMIT")
        }
    }

    func testCatalogPinsOtherTablesIndexesViewsAndTriggers() throws {
        for change in [
            "ALTER TABLE protected_rows ADD COLUMN extra INTEGER",
            "CREATE TABLE other_rows(value INTEGER)",
            "CREATE INDEX other_index ON protected_rows(value)",
            "CREATE VIEW other_view AS SELECT value FROM protected_rows",
            "CREATE TRIGGER other_trigger AFTER INSERT ON protected_rows BEGIN SELECT 1; END",
            "CREATE INDEX promotion_index ON retained_setup_promotion_intents_v1(revision)"
        ] {
            try database { db in
                try exec(db, "BEGIN IMMEDIATE")
                let before = try Catalog.capture(db)
                try exec(db, Storage.createSQL)
                try exec(db, "PRAGMA user_version=27")
                try exec(db, change)
                let after = try Catalog.capture(db)
                XCTAssertThrowsError(try after.requireRetention(from: before)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                try exec(db, "ROLLBACK")
            }
        }
    }

    func testCatalogRequiresTheExactPromotionTableAndItsIndex() throws {
        let declarations: [String?] = [nil,
            Storage.createSQL.replacingOccurrences(of: "3149824", with: "3149823"),
            Storage.createSQL.replacingOccurrences(of: "PRIMARY KEY", with: "NOT NULL")
        ]
        for declaration in declarations {
            try database(schema: 27) { db in
                if let declaration { try exec(db, declaration) }
                try exec(db, "BEGIN")
                XCTAssertThrowsError(try Catalog.capture(db)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
                XCTAssertNil(sqlite3_next_stmt(db, nil))
                try exec(db, "ROLLBACK")
            }
        }
        try database(schema: 26, promotion: true) { db in
            try exec(db, "BEGIN")
            XCTAssertThrowsError(try Catalog.capture(db)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            try exec(db, "ROLLBACK")
        }
    }

    func testExistingPromotionCatalogAndSchema28StayPinned() throws {
        try database(schema: 27, promotion: true) { db in
            try exec(db, "BEGIN IMMEDIATE")
            let before = try Catalog.capture(db)
            try exec(db, "PRAGMA user_version=28")
            let ready = try Catalog.capture(db)
            XCTAssertNotEqual(before.protectedDigest, ready.protectedDigest)
            XCTAssertThrowsError(try ready.requireRetention(from: before))
            try ready.requireSame(as: Catalog.capture(db))
            try exec(db, "PRAGMA user_version=27")
            try exec(db, "CREATE INDEX extra_promotion_index ON retained_setup_promotion_intents_v1(record)")
            XCTAssertThrowsError(try Catalog.capture(db).requireRetention(from: before))
            try exec(db, "ROLLBACK")
        }
        for schema in [Int64(0), 25, 29] {
            try database(schema: schema) { db in
                try exec(db, "BEGIN")
                XCTAssertThrowsError(try Catalog.capture(db)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
                try exec(db, "ROLLBACK")
            }
        }
    }

    func testRollbackRestoresSchemaTableAbsenceAndTheOriginalCatalog() throws {
        try database { db in
            XCTAssertThrowsError(try Catalog.capture(db)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try exec(db, "BEGIN IMMEDIATE")
            let before = try Catalog.capture(db)
            try exec(db, Storage.createSQL)
            try exec(db, "PRAGMA user_version=27")
            try Catalog.capture(db).requireRetention(from: before)
            try exec(db, "ROLLBACK")
            XCTAssertEqual(sqlite3_get_autocommit(db), 1)
            XCTAssertNil(sqlite3_next_stmt(db, nil))
            try exec(db, "BEGIN IMMEDIATE")
            try Catalog.capture(db).requireSame(as: before)
            try exec(db, "INSERT INTO protected_rows VALUES(1,X'01')")
            try exec(db, "ROLLBACK")
        }
    }

    func testCatalogBoundsEntryCountAndDeclarationBytes() throws {
        try database { db in
            for index in 0..<128 { try exec(db, "CREATE TABLE extra_\(index)(value INTEGER)") }
            try exec(db, "BEGIN")
            XCTAssertThrowsError(try Catalog.capture(db)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertNil(sqlite3_next_stmt(db, nil))
            try exec(db, "ROLLBACK")
        }
        try database { db in
            try exec(db, "CREATE VIEW oversized AS SELECT '" + String(repeating: "a", count: 8192) + "'")
            try exec(db, "BEGIN")
            XCTAssertThrowsError(try Catalog.capture(db)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertNil(sqlite3_next_stmt(db, nil))
            try exec(db, "ROLLBACK")
        }
    }

    func testCatalogDoesNotReplaceTheSeparateProtectedRowDigest() throws {
        try database { db in
            try exec(db, "BEGIN IMMEDIATE")
            let before = try Catalog.capture(db)
            try exec(db, "INSERT INTO protected_rows VALUES(1,X'0102')")
            try Catalog.capture(db).requireSame(as: before)
            try exec(db, "ROLLBACK")
        }
    }
}
