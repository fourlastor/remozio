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

    /// The premise: while this connection holds a read transaction, another connection cannot commit. If the store left
    /// journal_mode=DELETE (for example for WAL without the snapshot reasoning being re-checked), this test fails.
    func testReadTransactionLockBlocksAnotherConnectionsCommitWhileTheCacheIsActive() throws {
        try fixture { f in
            let machine = try f.machine()
            let seen = try events(machine) {
                try machine.withStableFrameCacheProbe { probe in
                    XCTAssertEqual(try probe.journalMode().lowercased(), "delete")
                    let first = try probe.load(f.candidate)
                    try withSecondConnection(f.databasePath) { db in
                        XCTAssertEqual(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil), SQLITE_OK)
                        XCTAssertEqual(sqlite3_exec(db, "DELETE FROM update_scheduling_candidate_v1", nil, nil, nil), SQLITE_OK)
                        XCTAssertEqual(sqlite3_exec(db, "COMMIT", nil, nil, nil) & 0xff, SQLITE_BUSY)
                        XCTAssertEqual(sqlite3_exec(db, "ROLLBACK", nil, nil, nil), SQLITE_OK)
                    }
                    try probe.load(f.candidate).requireSame(as: first)
                }
            }
            XCTAssertEqual(seen, [.miss, .hit])
            XCTAssertNoThrow(try machine.stableMachineUpdateSnapshot(candidate: f.candidate))
        }
    }

    /// readFresh shape: two read transactions on one connection with a commit from another connection between them.
    func testRacingCommitBetweenTwoReadTransactionsIsStillDetected() throws {
        try fixture { f in
            let machine = try f.machine()
            let seen = try events(machine) {
                _ = try machine.stableMachineUpdateSnapshot(candidate: f.candidate)
                try withSecondConnection(f.databasePath) { db in
                    XCTAssertEqual(sqlite3_exec(db, "DELETE FROM update_scheduling_candidate_v1", nil, nil, nil), SQLITE_OK)
                }
                XCTAssertThrowsError(try machine.stableMachineUpdateSnapshot(candidate: f.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            XCTAssertEqual(seen, [.miss, .miss])
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
            let machine = try f.machine(), other = otherKey(f.candidate)
            enum Outcome { case value(MachineUpdateStableReleaseSnapshot), failure(String) }
            func outcome(_ load: () throws -> MachineUpdateStableReleaseSnapshot) -> Outcome {
                do { return .value(try load()) } catch { return .failure(String(reflecting: error)) }
            }
            let alone = outcome { try machine.stableMachineUpdateSnapshot(candidate: other) }
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
}
