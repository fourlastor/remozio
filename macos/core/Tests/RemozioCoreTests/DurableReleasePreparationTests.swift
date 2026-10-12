import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class DurableReleasePreparationTests: XCTestCase {
    private struct Fixture {
        let root: URL
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-durable-unit-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            for name in ["State", "Target"] {
                let directory = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
                guard chmod(directory.path, name == "State" ? 0o700 : 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            }
            for name in ["writer.lock", "installation.sqlite"] {
                let file = root.appendingPathComponent("State/" + name)
                try Data().write(to: file)
                guard chmod(file.path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            }
        }
        func store(initialize: Bool = false, macID: Data = Data(repeating: 1, count: 16), maximum: Int = 2) throws -> PreparationIntentStore {
            try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "State", owner: geteuid()),
                      macID: macID, maximumRecords: maximum, initialize: initialize)
        }
        func destination() throws -> ReleaseDestinationLease {
            try .init(anchor: root.path, relativeDirectory: "Target", owner: geteuid())
        }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let value = try Fixture()
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: value.root)) }
        try body(value)
    }
    private func signature(hash: UInt8 = 1) throws -> SignedReleaseEvidence {
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.fixture", generation: 4,
            relativePath: "Contents/MacOS/App", codeDirectoryHash: nil, build: "4", teamID: "ABCDEFGHIJ", formats: [])
        return .init(manifest: try .init(release: "0.1.0", build: "4", components: [app]),
                     codeDirectoryHashes: [.app: Data(repeating: hash, count: 20)])
    }
    private func policy(generation: UInt64 = 4) throws -> AuthorityCodePolicy {
        try .init(entries: [.init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.fixture",
            installedGeneration: generation, minimumGeneration: generation, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)])
    }
    private func recordedCopy(_ store: PreparationIntentStore, _ destination: ReleaseDestinationLease,
                              signature: SignedReleaseEvidence) throws -> PreparationIntentRecord {
        let intent = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
        let copy = URL(fileURLWithPath: destination.path).appendingPathComponent(intent.bundleName)
        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(copy.path, 0o755), 0)
        let file = copy.appendingPathComponent("file")
        try Data("data".utf8).write(to: file); XCTAssertEqual(chmod(file.path, 0o644), 0)
        return try store.recordCopy(id: intent.id, expectedRevision: intent.revision,
            identity: destination.preparationCopyIdentity(name: intent.bundleName), digest: DurableReleasePreparation.digest(signature))
    }
    func testIntentSurvivesReopenWithoutBecomingCopyEvidence() throws {
        try fixture { f in
            let first = try f.store(initialize: true), destination = try f.destination()
            defer { destination.close() }
            let intent = try first.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            try first.close()
            let second = try f.store(); defer { try? second.close() }
            XCTAssertEqual(try second.records(), [intent])
            XCTAssertThrowsError(try DurableReleasePreparation.recoverInLease(attemptID: intent.id, destination: destination,
                store: second, readPolicy: { try self.policy() }, inspect: { _, _, _ in XCTFail("Intent reached inspection"); return try self.signature() })) {
                guard case DurablePreparationError.incompleteRecord = $0 else { return XCTFail("Wrong error: \($0)") }
            }
        }
    }
    func testRecordedCopyRequiresFreshInspectionAfterReopen() throws {
        try fixture { f in
            let first = try f.store(initialize: true), destination = try f.destination(); defer { destination.close() }
            let signed = try signature(), record = try recordedCopy(first, destination, signature: signed)
            try first.close()
            let second = try f.store(); defer { try? second.close() }
            var inspections = 0, reads = 0
            let recovered = try DurableReleasePreparation.recoverInLease(attemptID: record.id, destination: destination,
                store: second, readPolicy: { reads += 1; return try self.policy() }, inspect: { _, team, identifier in
                    inspections += 1; XCTAssertEqual(team, "ABCDEFGHIJ"); XCTAssertEqual(identifier, "dev.remozio.fixture"); return signed
                })
            XCTAssertEqual(recovered.attemptID, record.id); XCTAssertEqual(recovered.copy.counts.files, 1)
            XCTAssertEqual(inspections, 1); XCTAssertEqual(reads, 2)
        }
    }
    func testFreshSigningFailureRejectsStoredMetadata() throws {
        struct InspectionFailure: Error {}
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let record = try recordedCopy(store, destination, signature: signature())
            XCTAssertThrowsError(try DurableReleasePreparation.recoverInLease(attemptID: record.id, destination: destination,
                store: store, readPolicy: { try self.policy() }, inspect: { _, _, _ in throw InspectionFailure() })) {
                XCTAssertTrue($0 is InspectionFailure)
            }
        }
    }
    func testDifferentSigningDigestRejectsRecovery() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let record = try recordedCopy(store, destination, signature: signature())
            XCTAssertThrowsError(try DurableReleasePreparation.recoverInLease(attemptID: record.id, destination: destination,
                store: store, readPolicy: { try self.policy() }, inspect: { _, _, _ in try self.signature(hash: 2) })) {
                guard case DurablePreparationError.signingMetadataChanged = $0 else { return XCTFail("Wrong error: \($0)") }
            }
        }
    }
    func testReplacementCopyInodeRejectsBeforeInspection() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let record = try recordedCopy(store, destination, signature: signature())
            let copy = URL(fileURLWithPath: destination.path).appendingPathComponent(record.bundleName)
            try FileManager.default.moveItem(at: copy, to: copy.appendingPathExtension("saved"))
            try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
            XCTAssertThrowsError(try DurableReleasePreparation.recoverInLease(attemptID: record.id, destination: destination,
                store: store, readPolicy: { XCTFail("Replacement reached policy"); return try self.policy() },
                inspect: { _, _, _ in XCTFail("Replacement reached inspection"); return try self.signature() })) {
                guard case DurablePreparationError.destinationChanged = $0 else { return XCTFail("Wrong error: \($0)") }
            }
        }
    }
    func testAdvancingFloorDuringRecoveryRejectsWithoutChangingTheRecord() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let signed = try signature(), record = try recordedCopy(store, destination, signature: signed)
            var reads = 0
            XCTAssertThrowsError(try DurableReleasePreparation.recoverInLease(attemptID: record.id, destination: destination,
                store: store, readPolicy: { reads += 1; return try self.policy(generation: reads == 1 ? 4 : 5) },
                inspect: { _, _, _ in signed })) {
                XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.app))
            }
            XCTAssertEqual(reads, 2); XCTAssertEqual(try store.records(), [record])
        }
    }
    func testStaleRevisionAndAbandonedAttemptCannotRevive() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let intent = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            let abandoned = try store.abandon(id: intent.id, expectedRevision: intent.revision)
            XCTAssertThrowsError(try store.abandon(id: intent.id, expectedRevision: intent.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try store.recordCopy(id: abandoned.id, expectedRevision: abandoned.revision,
                identity: .init(device: 1, inode: 2), digest: Data(repeating: 1, count: 32))) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertEqual(try store.records(), [abandoned])
        }
    }
    func testWrongMacAndReinitializationRejectWithoutErasingState() throws {
        try fixture { f in
            let first = try f.store(initialize: true), destination = try f.destination(); defer { destination.close() }
            let intent = try first.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            try first.close()
            XCTAssertThrowsError(try f.store(macID: Data(repeating: 2, count: 16))) { XCTAssertEqual($0 as? PreparationStoreError, .wrongMac) }
            XCTAssertThrowsError(try f.store(initialize: true)) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
            let second = try f.store(); defer { try? second.close() }
            XCTAssertEqual(try second.records(), [intent])
        }
    }
    func testReducedCapacityPreservesExistingRecords() throws {
        try fixture { f in
            let first = try f.store(initialize: true), destination = try f.destination(); defer { destination.close() }
            for _ in 0..<2 { _ = try first.begin(parent: destination.path, ancestry: destination.preparationAncestry()) }
            try first.close()
            let second = try f.store(maximum: 1); defer { try? second.close() }
            XCTAssertEqual(try second.records().count, 2)
            XCTAssertThrowsError(try second.begin(parent: destination.path, ancestry: destination.preparationAncestry())) {
                XCTAssertEqual($0 as? PreparationStoreError, .capacity)
            }
        }
    }
    func testPublicEntriesRefuseOrdinaryIdentityBeforeSourcePolicyAndRecordAccess() throws {
        try fixture { f in
            XCTAssertThrowsError(try PreparationIntentStore.open(directoryPath: "/missing", macID: Data(repeating: 1, count: 16))) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            var reads = 0
            XCTAssertThrowsError(try DurableReleasePreparation.prepare(source: URL(fileURLWithPath: "/missing"),
                destination: destination, store: store, readPolicy: { reads += 1; return try self.policy() })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try DurableReleasePreparation.recover(attemptID: UUID(), destination: destination,
                store: store, readPolicy: { reads += 1; return try self.policy() })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try DurableReleasePreparation.reconcileAbandoned(destination: destination, store: store)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(reads, 0); XCTAssertTrue(try store.records().isEmpty)
        }
    }

    func testCodecRejectsUnknownFieldsAndOversizedRecords() throws {
        let record = try PreparationIntentRecord(id: UUID(), revision: UUID(), parent: "/Fixture/Release",
            ancestry: [.init(device: 1, inode: 2)], phase: .intent)
        XCTAssertEqual(try PreparationIntentRecord.decode(record.encoded), record)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: record.encoded) as? [String: Any])
        object["unknown"] = 1
        let unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        for bytes in [unknown, try record.encoded + Data([10]), Data(repeating: 1, count: PreparationIntentRecord.maximumBytes + 1)] {
            XCTAssertThrowsError(try PreparationIntentRecord.decode(bytes)) {
                XCTAssertEqual($0 as? PreparationRecordError, .corruptRecord)
            }
        }
    }
    func testInvalidTargetRollsBackWithoutRetiringHealthyStore() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            for path in ["relative", "/Fixture/../Release", "/Fixture//Release", "/Fixture/Release/"] {
                XCTAssertThrowsError(try store.begin(parent: path, ancestry: [.init(device: 1, inode: 2)])) {
                    XCTAssertEqual($0 as? PreparationRecordError, .invalidRecord)
                }
                XCTAssertTrue(try store.records().isEmpty)
            }
        }
    }
    func testExclusiveWriterPreventsConcurrentStoreOwnership() throws {
        try fixture { f in
            let first = try f.store(initialize: true)
            XCTAssertThrowsError(try f.store()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            try first.close()
            let second = try f.store(); defer { try? second.close() }
            XCTAssertTrue(try second.records().isEmpty)
        }
    }
    func testDatabaseReplacementPermanentlyRetiresConnection() throws {
        try fixture { f in
            let store = try f.store(initialize: true); defer { try? store.close() }
            let path = f.root.appendingPathComponent("State/installation.sqlite")
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("saved"))
            try Data().write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
            XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        }
    }
    func testCorruptStoredRecordPermanentlyRetiresConnection() throws {
        try fixture { f in
            let first = try f.store(initialize: true), destination = try f.destination(); defer { destination.close() }
            _ = try first.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            try first.close()
            var database: OpaquePointer?
            XCTAssertEqual(sqlite3_open_v2(f.root.appendingPathComponent("State/installation.sqlite").path, &database,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
            let opened = try XCTUnwrap(database)
            XCTAssertEqual(sqlite3_exec(opened, "UPDATE preparation_intents_v1 SET record=x'01'", nil, nil, nil), SQLITE_OK)
            XCTAssertEqual(sqlite3_close(opened), SQLITE_OK)
            let second = try f.store(); defer { try? second.close() }
            XCTAssertThrowsError(try second.records()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            XCTAssertThrowsError(try second.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        }
    }

    func testSQLiteBtreeCorruptionPermanentlyRetiresConnection() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            _ = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            var database: OpaquePointer?
            XCTAssertEqual(sqlite3_open_v2(f.root.appendingPathComponent("State/installation.sqlite").path, &database,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
            let opened = try XCTUnwrap(database)
            var statement: OpaquePointer?
            XCTAssertEqual(sqlite3_prepare_v2(opened, "SELECT rootpage FROM sqlite_master WHERE name='preparation_intents_v1'", -1, &statement, nil), SQLITE_OK)
            let query = try XCTUnwrap(statement)
            XCTAssertEqual(sqlite3_step(query), SQLITE_ROW)
            let rootPage = sqlite3_column_int64(query, 0)
            XCTAssertGreaterThan(rootPage, 1)
            XCTAssertEqual(sqlite3_finalize(query), SQLITE_OK)
            XCTAssertEqual(sqlite3_prepare_v2(opened, "PRAGMA page_size", -1, &statement, nil), SQLITE_OK)
            let pageQuery = try XCTUnwrap(statement)
            XCTAssertEqual(sqlite3_step(pageQuery), SQLITE_ROW)
            let pageSize = sqlite3_column_int64(pageQuery, 0)
            XCTAssertGreaterThanOrEqual(pageSize, 512)
            XCTAssertEqual(sqlite3_finalize(pageQuery), SQLITE_OK)
            XCTAssertEqual(sqlite3_close(opened), SQLITE_OK)
            let fd = open(f.root.appendingPathComponent("State/installation.sqlite").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { close(fd) }
            var invalidPage: UInt8 = 0xff
            XCTAssertEqual(pwrite(fd, &invalidPage, 1, off_t((rootPage - 1) * pageSize)), 1)
            var counter = UInt32(9999).bigEndian
            XCTAssertEqual(pwrite(fd, &counter, 4, 24), 4)
            XCTAssertEqual(fsync(fd), 0)
            XCTAssertThrowsError(try store.records()) {
                guard case PreparationStoreError.storage(let code) = $0 else { return XCTFail("Wrong error: \($0)") }
                XCTAssertTrue([SQLITE_CORRUPT, SQLITE_NOTADB].contains(code & 0xff))
            }
            XCTAssertThrowsError(try store.records()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        }
    }

    func testRepeatedFailedPreparationsReclaimOnlyAbsentAbandonedRecords() throws {
        try fixture { f in
            let store = try f.store(initialize: true, maximum: 1), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            for _ in 0..<65 {
                XCTAssertThrowsError(try DurableReleasePreparation.prepareInLease(source: f.root.appendingPathComponent("missing.app"),
                    destination: destination, store: store, readPolicy: { try self.policy() })) {
                    XCTAssertNotEqual($0 as? PreparationStoreError, .capacity)
                }
                let records = try store.records()
                XCTAssertEqual(records.count, 1); XCTAssertEqual(records.first?.phase, .abandoned)
                XCTAssertFalse(try destination.preparationCopyExists(name: XCTUnwrap(records.first).bundleName))
            }
            try DurableReleasePreparation.reconcileAbandonedInLease(destination: destination, store: store)
            XCTAssertTrue(try store.records().isEmpty)
            XCTAssertNoThrow(try store.begin(parent: destination.path, ancestry: destination.preparationAncestry()))
        }
    }
    func testReconciliationRetainsAbandonedRecordAndExistingCopy() throws {
        try fixture { f in
            let store = try f.store(initialize: true, maximum: 1), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let record = try recordedCopy(store, destination, signature: signature())
            let abandoned = try store.abandon(id: record.id, expectedRevision: record.revision)
            try DurableReleasePreparation.reconcileAbandonedInLease(destination: destination, store: store)
            XCTAssertEqual(try store.records(), [abandoned])
            XCTAssertTrue(try destination.preparationCopyExists(name: record.bundleName))
        }
    }
    func testReconciliationRetainsMismatchedAncestryAndTarget() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let original = try destination.preparationAncestry()
            var changed = original
            changed[changed.count - 1] = .init(device: original.last!.device, inode: UInt64.max)
            let first = try store.begin(parent: destination.path, ancestry: changed)
            _ = try store.abandon(id: first.id, expectedRevision: first.revision)
            let second = try store.begin(parent: destination.path + "-other", ancestry: original)
            _ = try store.abandon(id: second.id, expectedRevision: second.revision)
            let before = try store.records()
            try DurableReleasePreparation.reconcileAbandonedInLease(destination: destination, store: store)
            XCTAssertEqual(try store.records(), before)
        }
    }
    func testReconciliationCannotForgetLiveOrStaleRecords() throws {
        try fixture { f in
            let store = try f.store(initialize: true), destination = try f.destination()
            defer { try? store.close(); destination.close() }
            let record = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
            XCTAssertThrowsError(try store.forgetAbsentAbandoned(id: record.id, expectedRevision: record.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            let abandoned = try store.abandon(id: record.id, expectedRevision: record.revision)
            XCTAssertThrowsError(try store.forgetAbsentAbandoned(id: record.id, expectedRevision: record.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(try store.records(), [abandoned])
        }
    }
}
