import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

/// The stable frame cache lives for one read transaction on one connection. These tests pin its premise and its limits.
final class PreparationStoreFrameCacheTests: XCTestCase {
    private typealias Event = PreparationIntentStore.StableFrameCacheEvent
    private enum Sentinel: Error { case rollback }

    private func fixture(_ body: (RetainedMaterialWriterFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(body)
    }

    /// A second connection, as another process or `readFresh`'s peer would open it. It never waits for a lock.
    private func withSecondConnection<T>(_ path: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var connection: OpaquePointer?
        guard sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let db = connection else {
            if let connection { sqlite3_close(connection) }
            throw PreparationStoreError.invalidConfiguration
        }
        defer { XCTAssertEqual(sqlite3_close(db), SQLITE_OK) }
        XCTAssertEqual(sqlite3_busy_timeout(db, 0), SQLITE_OK)
        return try body(db)
    }

    private func events(_ machine: PreparationIntentStore, _ body: () throws -> Void) rethrows -> [Event] {
        var seen: [Event] = []
        machine.observeStableFrameCache = { seen.append($0) }
        defer { machine.observeStableFrameCache = nil }
        try body()
        return seen
    }

    private func otherKey(_ candidate: SignedReleaseEvidence) -> SignedReleaseEvidence {
        var dependencies = candidate.dependencyCodeDirectoryHashes
        dependencies["remozio.frame-cache-test"] = Data(repeating: 0x5A, count: 32)
        return .init(manifest: candidate.manifest, codeDirectoryHashes: candidate.codeDirectoryHashes,
            dependencyCodeDirectoryHashes: dependencies)
    }

    /// A copy of the current committed database, taken through SQLite so no torn file is ever read.
    private func copyCommittedDatabase(_ f: RetainedMaterialWriterFixture, to path: String) throws {
        try withSecondConnection(f.databasePath) { db in
            sqlite3_busy_timeout(db, 1000)
            let quoted = path.replacingOccurrences(of: "'", with: "''")
            XCTAssertEqual(sqlite3_exec(db, "VACUUM INTO '\(quoted)'", nil, nil, nil), SQLITE_OK)
        }
    }

    private func names(_ db: OpaquePointer, _ sql: String) throws -> [String] {
        var row: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &row, nil) == SQLITE_OK, let row else { throw PreparationStoreError.corruptRecord }
        defer { sqlite3_finalize(row) }
        var values: [String] = []
        while sqlite3_step(row) == SQLITE_ROW { values.append(String(cString: sqlite3_column_text(row, 0))) }
        return values
    }

    /// Stages, on connection `db`, the rows of every table that differs from the earlier committed copy. Every staged
    /// row is a byte-identical row the store itself committed before, so the result is a valid store state.
    /// Returns the restored table names. The caller commits.
    private func stageRestore(_ db: OpaquePointer, from copy: String) throws -> [String] {
        let quoted = copy.replacingOccurrences(of: "'", with: "''")
        XCTAssertEqual(sqlite3_exec(db, "ATTACH DATABASE '\(quoted)' AS earlier", nil, nil, nil), SQLITE_OK)
        XCTAssertEqual(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil), SQLITE_OK)
        var restored: [String] = []
        for table in try names(db, "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name") {
            let differs = try names(db, """
                SELECT 1 FROM (SELECT * FROM main.\(table) EXCEPT SELECT * FROM earlier.\(table)) UNION ALL
                SELECT 1 FROM (SELECT * FROM earlier.\(table) EXCEPT SELECT * FROM main.\(table)) LIMIT 1
                """)
            guard !differs.isEmpty else { continue }
            XCTAssertEqual(sqlite3_exec(db, "DELETE FROM main.\(table)", nil, nil, nil), SQLITE_OK)
            XCTAssertEqual(sqlite3_exec(db, "INSERT INTO main.\(table) SELECT * FROM earlier.\(table)", nil, nil, nil), SQLITE_OK)
            restored.append(table)
        }
        return restored
    }

    /// Commits a real writer's change on the store's own connection, keeping a copy of the state before it. Afterwards
    /// the database holds state B and the copy holds state A; both are states the store committed itself.
    private func retainWithEarlierCopy(_ f: RetainedMaterialWriterFixture, _ machine: PreparationIntentStore,
        _ body: (_ copy: String, _ before: MachineUpdateStableReleaseSnapshot) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("frame-cache-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let copy = directory.appendingPathComponent("earlier.sqlite").path
        let before = try machine.stableMachineUpdateSnapshot(candidate: f.candidate)
        try copyCommittedDatabase(f, to: copy)
        let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        _ = try machine.retainRetainedSetupRuntimeMaterial(f.material.reference,
            expected: .init(runtime: entry.runtime, activation: entry.activation), candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
        XCTAssertThrowsError(try machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before),
            "The retained-material writer no longer changes a row the stable frame covers") {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
        try body(copy, before)
    }

    /// The premise, proven: while this connection holds a read transaction with the frame cached, another connection's
    /// valid commit gets SQLITE_BUSY after its busy timeout. The same commit succeeds once the read transaction ends.
    /// If the store left journal_mode=DELETE (for example for WAL without the snapshot reasoning being re-checked), this
    /// test fails.
    func testReadTransactionLockBlocksAnotherConnectionsCommitWhileTheCacheIsActive() throws {
        try fixture { f in
            let machine = try f.machine()
            try retainWithEarlierCopy(f, machine) { copy, before in
                try withSecondConnection(f.databasePath) { db in
                    XCTAssertEqual(sqlite3_busy_timeout(db, 50), SQLITE_OK)
                    let seen = try events(machine) {
                        try machine.withStableFrameCacheProbe { probe in
                            XCTAssertEqual(try probe.journalMode().lowercased(), "delete")
                            let first = try probe.load(f.candidate)
                            try probe.load(f.candidate).requireSame(as: first)
                            XCTAssertFalse(try stageRestore(db, from: copy).isEmpty)
                            let started = Date()
                            XCTAssertEqual(sqlite3_exec(db, "COMMIT", nil, nil, nil) & 0xff, SQLITE_BUSY)
                            XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started), 0.04, "B did not wait for its busy timeout")
                            XCTAssertEqual(sqlite3_get_autocommit(db), 0, "B's transaction must stay open for the retry")
                            try probe.load(f.candidate).requireSame(as: first)
                        }
                    }
                    XCTAssertEqual(seen, [.miss, .hit, .hit])
                    XCTAssertEqual(sqlite3_exec(db, "COMMIT", nil, nil, nil), SQLITE_OK)
                    XCTAssertEqual(sqlite3_exec(db, "DETACH DATABASE earlier", nil, nil, nil), SQLITE_OK)
                }
                try machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
            }
        }
    }

    /// readFresh shape: two read transactions on one connection with a valid commit from another connection between
    /// them. The second transaction misses, reads the committed rows, and the comparison reports a stale revision.
    func testRacingCommitBetweenTwoReadTransactionsIsStillDetected() throws {
        try fixture { f in
            let machine = try f.machine()
            try retainWithEarlierCopy(f, machine) { copy, before in
                var first: MachineUpdateStableReleaseSnapshot?, second: MachineUpdateStableReleaseSnapshot?
                let seen = try events(machine) {
                    first = try machine.stableMachineUpdateSnapshot(candidate: f.candidate)
                    try withSecondConnection(f.databasePath) { db in
                        XCTAssertFalse(try stageRestore(db, from: copy).isEmpty)
                        XCTAssertEqual(sqlite3_exec(db, "COMMIT", nil, nil, nil), SQLITE_OK)
                        XCTAssertEqual(sqlite3_exec(db, "DETACH DATABASE earlier", nil, nil, nil), SQLITE_OK)
                    }
                    second = try machine.stableMachineUpdateSnapshot(candidate: f.candidate)
                }
                XCTAssertEqual(seen, [.miss, .miss])
                let read = try XCTUnwrap(second), cached = try XCTUnwrap(first)
                XCTAssertThrowsError(try read.requireSame(as: cached)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                try read.requireSame(as: before)
            }
        }
    }

    func testNothingCarriesOverBetweenTwoTransactions() throws {
        try fixture { f in
            let machine = try f.machine()
            var frames: [PreparationIntentStore.InitialRuntimeRead: Int] = [:]
            machine.observeStoreRead = { frames[$0, default: 0] += 1 }
            defer { machine.observeStoreRead = nil }
            let seen = try events(machine) {
                let first = try machine.stableMachineUpdateSnapshot(candidate: f.candidate)
                try machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: first)
                try machine.withStableFrameCacheProbe { probe in
                    try probe.load(f.candidate).requireSame(as: first); try probe.load(f.candidate).requireSame(as: first)
                }
            }
            XCTAssertEqual(seen, [.miss, .miss, .miss, .hit])
            XCTAssertEqual(frames[.frame], 3); XCTAssertEqual(frames[.readTransaction], 3)
        }
    }

    func testOneReadTransactionLoadsTheFrameOnceForTheNestedEntryReaders() throws {
        try fixture { f in
            let machine = try f.machine()
            let seen = try events(machine) { _ = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate) }
            XCTAssertEqual(seen, [.miss] + Array(repeating: .hit, count: 5))
        }
    }

    func testWriteTransactionsNeverHit() throws {
        try fixture { f in
            let machine = try f.machine()
            let before = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
            var writing = false, writeEvents: [Event] = []
            machine.observeStoreRead = { kind in
                if kind == .writeTransaction { writing = true } else if kind == .readTransaction { writing = false }
            }
            machine.observeStableFrameCache = { if writing { writeEvents.append($0) } }
            defer { machine.observeStoreRead = nil; machine.observeStableFrameCache = nil }
            _ = try machine.retainRetainedSetupRuntimeMaterial(f.material.reference,
                expected: .init(runtime: before.runtime, activation: before.activation), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            XCTAssertFalse(writeEvents.isEmpty, "The writer's captures no longer load the stable frame")
            XCTAssertFalse(writeEvents.contains(.hit))
        }
    }

    /// A write on the cache's own connection inside a read transaction must miss and see the change.
    func testOwnConnectionWriteInvalidatesTheCache() throws {
        try fixture { f in
            let machine = try f.machine()
            let seen = try events(machine) {
                XCTAssertThrowsError(try machine.withStableFrameCacheProbe { probe in
                    _ = try probe.load(f.candidate)
                    try probe.execute("DELETE FROM update_scheduling_candidate_v1")
                    XCTAssertThrowsError(try probe.load(f.candidate)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                    }
                    throw Sentinel.rollback
                }) { XCTAssertTrue($0 is Sentinel) }
            }
            XCTAssertEqual(seen, [.miss, .miss])
            XCTAssertNoThrow(try machine.stableMachineUpdateSnapshot(candidate: f.candidate))
        }
    }

    /// `PRAGMA user_version =` and DDL leave total_changes64 unchanged, but they move the transaction to WRITE. Even a
    /// rewrite of the same user_version must miss.
    func testOwnConnectionSchemaWriteWithoutRowChangesMisses() throws {
        for statement in ["PRAGMA user_version = %d", "CREATE TABLE main.frame_cache_probe_v1(value INTEGER)"] {
            try fixture { f in
                let machine = try f.machine()
                let version = try f.scalar("PRAGMA user_version")
                let seen = try events(machine) {
                    XCTAssertThrowsError(try machine.withStableFrameCacheProbe { probe in
                        let first = try probe.load(f.candidate)
                        try probe.execute(statement.replacingOccurrences(of: "%d", with: String(version)))
                        if statement.hasPrefix("PRAGMA") {
                            try probe.load(f.candidate).requireSame(as: first)
                        } else {
                            _ = try? probe.load(f.candidate)
                        }
                        throw Sentinel.rollback
                    }) { XCTAssertTrue($0 is Sentinel) }
                }
                XCTAssertEqual(seen, [.miss, .miss], statement)
                XCTAssertNoThrow(try machine.stableMachineUpdateSnapshot(candidate: f.candidate))
            }
        }
    }

    func testErrorsAreNeverCached() throws {
        try fixture { f in
            let machine = try f.machine()
            let seen = try events(machine) {
                XCTAssertThrowsError(try machine.withStableFrameCacheProbe { probe in
                    try probe.execute("DELETE FROM update_scheduling_candidate_v1")
                    for _ in 0..<2 {
                        XCTAssertThrowsError(try probe.load(f.candidate)) {
                            XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                        }
                    }
                    throw Sentinel.rollback
                }) { XCTAssertTrue($0 is Sentinel) }
            }
            XCTAssertEqual(seen, [.miss, .miss])
            XCTAssertNoThrow(try machine.stableMachineUpdateSnapshot(candidate: f.candidate))
        }
    }

    /// A different candidate key misses and gives exactly the outcome it gives in its own transaction.
    func testADifferentCandidateMissesAndKeepsItsOwnOutcome() throws {
        try fixture { f in
            let other = otherKey(f.candidate)
            enum Outcome { case value(MachineUpdateStableReleaseSnapshot), failure(String) }
            func outcome(_ load: () throws -> MachineUpdateStableReleaseSnapshot) -> Outcome {
                do { return .value(try load()) } catch { return .failure(String(reflecting: error)) }
            }
            let alone = outcome { try f.machine().stableMachineUpdateSnapshot(candidate: other) }
            // A `.corruptRecord` or `.incompatibleStore` thrown out of `transaction` marks the connection unavailable and
            // shuts it down, so the probe below would fail with `.unavailable`. Reopen to give the probe a fresh connection.
            try f.reopen(nil)
            let machine = try f.machine()
            var shared: Outcome?
            let seen = try events(machine) {
                try machine.withStableFrameCacheProbe { probe in
                    _ = try probe.load(f.candidate)
                    shared = outcome { try probe.load(other) }
                }
            }
            XCTAssertEqual(seen, [.miss, .miss])
            switch (alone, shared) {
            case (.value(let a), .value(let b)?): try b.requireSame(as: a)
            case (.failure(let a), .failure(let b)?): XCTAssertEqual(a, b)
            default: XCTFail("The candidate outcome changed inside a shared read transaction")
            }
        }
    }
    /// The machine directory that holds `installation.sqlite`; the store's shared-import journal lives under it.
    private func machineDirectory(_ f: RetainedMaterialWriterFixture) -> URL {
        URL(fileURLWithPath: f.databasePath).deletingLastPathComponent()
    }

    /// The frame pins the shared-import journal and relay directory through `currentRowsDigest`. The SQLite lock does not
    /// cover them, so a change there while the frame is cached must miss and be seen.
    func testSharedImportChangeInsideTheReadTransactionMisses() throws {
        try fixture { f in
            let machine = try f.machine(), folder = machineDirectory(f)
            let sharedImport = folder.appendingPathComponent("SharedSetupImport")
            defer { try? FileManager.default.removeItem(at: sharedImport) }
            var reads = 0
            machine.observeStoreRead = { if $0 == .sharedImport { reads += 1 } }
            defer { machine.observeStoreRead = nil }
            let seen = try events(machine) {
                try machine.withStableFrameCacheProbe { probe in
                    let first = try probe.load(f.candidate)
                    try probe.load(f.candidate).requireSame(as: first)
                    XCTAssertEqual(reads, 2, "A hit must recapture the shared import")
                    // Same steps as StableRuntimeImportTests.journal(initialize: true): a real, empty journal.
                    let anchor = folder.deletingLastPathComponent().path
                    let relative = folder.lastPathComponent + "/SharedSetupImport"
                    let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
                    _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
                    directory.close()
                    let journal = try SharedSetupImportJournal(lease: .init(anchor: anchor, relativeDirectory: relative,
                        owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                        macID: first.inventory.macID, installationID: first.inventory.installationID, initialize: true)
                    try journal.close()
                    let changed = try probe.load(f.candidate)
                    XCTAssertThrowsError(try changed.requireSame(as: first), "The cache hid a shared-import change") {
                        XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                    }
                    try probe.load(f.candidate).requireSame(as: changed)
                }
            }
            XCTAssertEqual(seen, [.miss, .hit, .miss, .hit])
        }
    }

    /// When the shared-import capture fails on a hit, the load throws what an uncached load throws. The cached frame is
    /// never returned.
    func testSharedImportFailureOnAHitThrowsLikeAnUncachedLoad() throws {
        try fixture { f in
            let machine = try f.machine()
            let blocker = machineDirectory(f).appendingPathComponent("SharedSetupImport")
            defer { try? FileManager.default.removeItem(at: blocker) }
            var onHit: String?
            let seen = try events(machine) {
                try machine.withStableFrameCacheProbe { probe in
                    _ = try probe.load(f.candidate)
                    // A regular file where the shared-import directory belongs: the capture cannot open it.
                    XCTAssertTrue(FileManager.default.createFile(atPath: blocker.path, contents: Data("x".utf8)))
                    XCTAssertThrowsError(try probe.load(f.candidate), "A failed capture returned the cached frame") {
                        onHit = String(reflecting: $0)
                    }
                }
            }
            XCTAssertEqual(seen, [.miss])
            // Last, because the uncached failure may leave the connection unavailable.
            XCTAssertThrowsError(try machine.stableMachineUpdateSnapshot(candidate: f.candidate)) {
                XCTAssertNotNil(onHit); XCTAssertEqual(String(reflecting: $0), onHit)
            }
        }
    }
}
