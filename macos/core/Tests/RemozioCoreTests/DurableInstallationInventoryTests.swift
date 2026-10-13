import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class DurableInstallationInventoryTests: XCTestCase {
    private struct Fixture {
        let root: URL
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-inventory-unit-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            for name in ["State", "Target"] {
                let folder = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
                guard chmod(folder.path, name == "State" ? 0o700 : 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            }
            for name in ["writer.lock", "installation.sqlite"] {
                let file = root.appendingPathComponent("State/" + name)
                try Data().write(to: file); guard chmod(file.path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            }
        }
        func store(initialize: Bool = false, mac: Data = Data(repeating: 1, count: 16),
                   didCommit: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
            try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "State", owner: geteuid()),
                      macID: mac, maximumRecords: 2, initialize: initialize, didCommit: didCommit)
        }
        func sql(_ sql: String) throws -> Int64 {
            var db: OpaquePointer?
            guard sqlite3_open_v2(root.appendingPathComponent("State/installation.sqlite").path, &db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK, let db else { throw JournalLeaseError.unsafeMetadata }
            defer { sqlite3_close(db) }
            var row: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &row, nil) == SQLITE_OK, let row else { throw JournalLeaseError.unsafeMetadata }
            defer { sqlite3_finalize(row) }
            let status = sqlite3_step(row)
            guard status == SQLITE_ROW || status == SQLITE_DONE else { throw JournalLeaseError.unsafeMetadata }
            return status == SQLITE_ROW ? sqlite3_column_int64(row, 0) : 0
        }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let f = try Fixture(); defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: f.root)) }
        try body(f)
    }
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func value(_ revision: UInt8 = 4, mac: UInt8 = 1, installation: UInt8 = 2) throws -> InstallationInventory {
        try .init(macID: id(mac), installationID: id(installation), revision: id(revision),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: 9, count: 32),
            accounts: [.init(accountID: id(3), ownerUID: getuid())],
            services: [.init(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: "dev.remozio.fixture.authority", plistName: "dev.remozio.fixture.authority.plist", accountID: id(3))])
    }
    private func intent(_ f: Fixture, _ store: PreparationIntentStore) throws -> PreparationIntentRecord {
        let target = try ReleaseDestinationLease(anchor: f.root.path, relativeDirectory: "Target", owner: geteuid())
        defer { target.close() }
        return try store.begin(parent: target.path, ancestry: target.preparationAncestry())
    }

    func testOpenRetainsSchemaOneWithoutImplicitUpgrade() throws {
        try fixture { f in
            let store = try f.store(initialize: true)
            XCTAssertThrowsError(try store.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .inventoryNotEnabled) }
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 1)
            XCTAssertEqual(try f.sql("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"), 2)
            try store.close()
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertThrowsError(try reopened.inventory())
            XCTAssertEqual(try reopened.records(), [])
        }
    }
    func testExplicitUpgradePreservesPreparationAndSurvivesReopen() throws {
        try fixture { f in
            let store = try f.store(initialize: true), retained = try intent(f, store)
            try store.upgradeInventoryStorage(); try store.upgradeInventoryStorage()
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 2)
            XCTAssertEqual(try f.sql("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"), 3)
            XCTAssertEqual(try store.records(), [retained]); XCTAssertNil(try store.inventory())
            try store.close()
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.records(), [retained]); XCTAssertNil(try reopened.inventory())
        }
    }
    func testInventoryAndPreparationKeepOneExclusiveWriter() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage(); let saved = try store.writeInventory(value(), expectedRevision: nil)
            XCTAssertThrowsError(try f.store()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            _ = try intent(f, store)
            XCTAssertEqual(try store.inventory(), saved)
        }
    }
    func testInitializationRefusesExistingInventoryAndReplacementRequiresRevision() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage(); let first = try store.writeInventory(value(), expectedRevision: nil)
            XCTAssertThrowsError(try store.writeInventory(value(5), expectedRevision: nil)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try store.writeInventory(value(5), expectedRevision: id(9))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(try store.inventory(), first)
            let second = try store.writeInventory(value(5), expectedRevision: first.revision)
            XCTAssertEqual(try store.inventory(), second)
            XCTAssertNotEqual(second.revision, first.revision)
        }
    }

    func testMissingMalformedAndStaleExpectedRevisionsAreRejected() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage()
            XCTAssertThrowsError(try store.writeInventory(value(), expectedRevision: id(4))) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            let first = try store.writeInventory(value(), expectedRevision: nil)
            XCTAssertThrowsError(try store.writeInventory(value(5), expectedRevision: Data()))
            XCTAssertEqual(try store.inventory(), first)
            let second = try store.writeInventory(first, expectedRevision: first.revision)
            XCTAssertNotEqual(second.revision, first.revision)
            XCTAssertThrowsError(try store.writeInventory(value(5), expectedRevision: first.revision))
            XCTAssertEqual(try store.inventory(), second)
        }
    }

    func testCrossMacAndInstallationReplacementCannotChangeRetainedRecord() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage(); let saved = try store.writeInventory(value(), expectedRevision: nil)
            XCTAssertThrowsError(try store.writeInventory(value(5, mac: 9), expectedRevision: saved.revision))
            XCTAssertThrowsError(try store.writeInventory(value(5, installation: 9), expectedRevision: saved.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .wrongInstallation)
            }
            XCTAssertEqual(try store.inventory(), saved)
        }
    }

    func testReopenKeepsScopeAndRejectsWrongMac() throws {
        try fixture { f in
            let store = try f.store(initialize: true)
            try store.upgradeInventoryStorage(); let saved = try store.writeInventory(value(), expectedRevision: nil); try store.close()
            XCTAssertThrowsError(try f.store(mac: id(9))) { XCTAssertEqual($0 as? PreparationStoreError, .wrongMac) }
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.inventory(), saved)
        }
    }

    func testCorruptRowBindingsRetireInventoryAndPreparationAccess() throws {
        for column in ["installation", "revision"] {
            try fixture { f in
                let store = try f.store(initialize: true); defer { try? store.close() }
                try store.upgradeInventoryStorage(); try store.writeInventory(value(), expectedRevision: nil)
                _ = try f.sql("UPDATE installation_inventory_v1 SET \(column)=zeroblob(16)")
                XCTAssertThrowsError(try store.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
                XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            }
        }
    }
    func testMalformedInventoryPayloadRetiresConnectionWithoutDeletingState() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage(); try store.writeInventory(value(), expectedRevision: nil)
            _ = try f.sql("UPDATE installation_inventory_v1 SET record=x'80'")
            XCTAssertThrowsError(try store.inventory())
            XCTAssertThrowsError(try store.records())
            XCTAssertEqual(try f.sql("SELECT count(*) FROM installation_inventory_v1"), 1)
        }
    }
    func testUnknownStorageVersionRetiresTheSharedConnection() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage(); _ = try f.sql("PRAGMA user_version=99")
            XCTAssertThrowsError(try store.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
            XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        }
    }
    func testPublicOperationsRejectOrdinaryUserBeforeMutatingFixture() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            for operation in [{ try store.enableInventoryStorage() }, { _ = try store.loadInventory() },
                              { _ = try store.initializeInventory(self.value()) }, { _ = try store.replaceInventory(self.value(5), expectedRevision: self.id(4)) }] {
                XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            }
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 1)
        }
    }
    func testUncertainCommitRetiresStoreAndReopenObservesCommittedRevision() throws {
        struct LostAcknowledgment: Error {}
        try fixture { f in
            var armed = false
            let store = try f.store(initialize: true, didCommit: { if armed { throw LostAcknowledgment() } })
            try store.upgradeInventoryStorage(); let retained = try intent(f, store)
            let first = try store.writeInventory(value(), expectedRevision: nil); armed = true
            XCTAssertThrowsError(try store.writeInventory(value(5), expectedRevision: first.revision)) { XCTAssertTrue($0 is LostAcknowledgment) }
            XCTAssertThrowsError(try store.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            let reopened = try f.store(); defer { try? reopened.close() }
            let saved = try XCTUnwrap(reopened.inventory())
            XCTAssertNotEqual(saved.revision, first.revision); XCTAssertNotEqual(saved.revision, id(5))
            XCTAssertEqual(saved.installationID, first.installationID); XCTAssertEqual(saved.accounts, first.accounts)
            XCTAssertEqual(try reopened.records(), [retained])
        }
    }

    func testUncertainMigrationReopenUsesVersionTwoWithoutRepeatingInitialization() throws {
        struct LostAcknowledgment: Error {}
        try fixture { f in
            var armed = false
            let store = try f.store(initialize: true, didCommit: { if armed { throw LostAcknowledgment() } })
            let retained = try intent(f, store); armed = true
            XCTAssertThrowsError(try store.upgradeInventoryStorage())
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 2)
            XCTAssertEqual(try reopened.records(), [retained]); XCTAssertNil(try reopened.inventory())
        }
    }
    func testInventoryLargerThanLegacySQLiteLimitSurvivesReopen() throws {
        try fixture { f in
            let accounts = try (1...64).map { try InstallationAccount(accountID: id(UInt8($0)), ownerUID: uid_t(600 + $0)) }
            let appLabel = "dev.remozio.app." + String(repeating: "a", count: 225)
            let guiLabel = "dev.remozio.gui." + String(repeating: "g", count: 225)
            var services = [try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: accounts[0].accountID)]
            for account in accounts {
                services.append(try .init(role: .app, kind: .mainApp, domainUID: account.ownerUID, executionUID: account.ownerUID,
                    label: appLabel, plistName: nil, accountID: account.accountID))
                services.append(try .init(role: .guiAgent, kind: .agent, domainUID: account.ownerUID, executionUID: account.ownerUID,
                    label: guiLabel, plistName: guiLabel + ".plist", accountID: account.accountID))
            }
            let large = try InstallationInventory(macID: id(1), installationID: id(2), revision: id(4),
                bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: 9, count: 32), accounts: accounts, services: services)
            XCTAssertGreaterThan(large.canonicalBytes.count, 32768)
            let store = try f.store(initialize: true)
            try store.upgradeInventoryStorage(); let saved = try store.writeInventory(large, expectedRevision: nil); try store.close()
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.inventory(), saved)
        }
    }
    func testCallerCannotReuseHistoricalRevisionToReviveAStaleWriter() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            try store.upgradeInventoryStorage()
            let proposed = try value()
            let first = try store.writeInventory(proposed, expectedRevision: nil)
            XCTAssertNotEqual(first.revision, proposed.revision)
            let second = try store.writeInventory(value(5), expectedRevision: first.revision)
            let third = try store.writeInventory(first, expectedRevision: second.revision)
            XCTAssertNotEqual(third.revision, first.revision)
            XCTAssertNotEqual(third.revision, second.revision)
            XCTAssertThrowsError(try store.writeInventory(value(6), expectedRevision: first.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(try store.inventory(), third)
        }
    }

}
