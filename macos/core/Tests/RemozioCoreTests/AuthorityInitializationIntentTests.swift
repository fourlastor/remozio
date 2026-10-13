import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityInitializationIntentTests: XCTestCase {
    private struct LostAcknowledgment: Error {}
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), epoch = Data(repeating: 3, count: 16)
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func initial(replay: Bool = true, feature: UInt64? = nil) throws -> AuthorityJournalInitialization {
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1),
            5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
        return .init(descriptor: descriptor, codePolicy: policy, capabilities: .init(contracts: [contract: feature.map { [$0] } ?? []]),
            allowedContracts: [contract], installCommandReplay: replay)
    }
    private func fixture(_ body: (URL) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let root = URL(fileURLWithPath: "/private/tmp/remozio-initialization-intent-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, kind): (String, SetupDatabaseKind) in [("machine", .installation), ("journal", .journal), ("continuity", .continuity)] {
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
        }
        try body(root)
    }
    private func store(_ root: URL, initialize: Bool = false, hook: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
        try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "machine", owner: getuid()),
            macID: mac, maximumRecords: 10, initialize: initialize, didCommit: hook)
    }
    private func inventory(_ store: PreparationIntentStore, release: UInt8 = 8) throws -> InstallationInventory {
        let value = try InstallationInventory(macID: mac, installationID: Data(repeating: 5, count: 16), revision: Data(repeating: 6, count: 16),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: release, count: 32),
            accounts: [.init(accountID: account, ownerUID: getuid())], services: [.init(role: .authority, kind: .daemon,
                domainUID: nil, executionUID: 0, label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: account)])
        try store.upgradeInventoryStorage()
        return try store.writeInventory(value, expectedRevision: nil)
    }
    private func begin(_ root: URL, _ store: PreparationIntentStore, _ inventory: InstallationInventory,
                       seed: AuthorityJournalInitialization? = nil) throws -> AuthorityInitializationIntent {
        try store.beginInitialization(initial: seed ?? initial(), journalPath: root.path + "/journal/journal.sqlite",
            continuityPath: root.path + "/continuity/continuity.sqlite", expectedInventoryRevision: inventory.revision)
    }
    private func journal(_ root: URL, seed: AuthorityJournalInitialization? = nil, recordByteLimit: Int = 16384) throws -> JournalDatabase {
        try .init(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
            macID: mac, accountID: account, recordLimits: .init(maxBytes: recordByteLimit, maxDepth: 8, maxItems: 512), descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: seed != nil, initialAuthority: seed)
    }
    private func continuity(_ root: URL, checkpoint: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try .init(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
            macID: mac, accountID: account, initialize: checkpoint)
    }
    private func sql(_ root: URL, file: String = "machine/installation.sqlite", query: String) throws -> Int64 {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(root.path + "/" + file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
        let connection = try XCTUnwrap(db); defer { sqlite3_close(connection) }
        var statement: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, query, -1, &statement, nil), SQLITE_OK)
        let row = try XCTUnwrap(statement); defer { sqlite3_finalize(row) }
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
        return result == SQLITE_ROW ? sqlite3_column_int64(row, 0) : 0
    }
    func testReadDoesNotUpgradeAndExplicitBeginPersistsBeforeJournalInitialization() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            XCTAssertNil(try machine.initialization(accountID: account)); XCTAssertEqual(try sql(root, query: "PRAGMA user_version"), 2)
            let intent = try begin(root, machine, inventory)
            XCTAssertNil(intent.checkpoint); XCTAssertFalse(intent.complete)
            XCTAssertEqual(try intent.initialAuthority.initializationBytes, try initial().initializationBytes)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
            XCTAssertEqual(try sql(root, query: "PRAGMA user_version"), 3)
            try machine.close()
            let restored = try store(root); defer { try? restored.close() }
            XCTAssertEqual(try restored.initialization(accountID: account), intent)
            XCTAssertEqual(try restored.inventory(), inventory)
        }
    }
    func testJournalCommitGapAndCheckpointCommitGapResumeWithoutInitialization() throws {
        try fixture { root in
            let seed = try initial(), machine = try store(root, initialize: true), inventory = try inventory(machine)
            let intent = try begin(root, machine, inventory, seed: seed)
            let firstJournal = try journal(root, seed: seed); try firstJournal.close(); try machine.close()
            let journalBytes = try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite"))
            let restored = try store(root), retained = try XCTUnwrap(restored.initialization(accountID: account))
            XCTAssertEqual(retained, intent)
            let liveJournal = try journal(root); defer { try? liveJournal.close() }
            let captured = try restored.captureInitialization(expected: retained, initial: seed, journal: liveJournal)
            let checkpoint = try XCTUnwrap(captured.checkpoint)
            let firstContinuity = try continuity(root, checkpoint: checkpoint); firstContinuity.close(); try restored.close()
            let last = try store(root); defer { try? last.close() }
            let liveContinuity = try continuity(root); defer { liveContinuity.close() }
            let completed = try last.completeInitialization(expected: captured, journal: liveJournal, continuity: liveContinuity)
            XCTAssertTrue(completed.complete); XCTAssertEqual(completed.checkpoint, checkpoint)
            XCTAssertEqual(try last.completeInitialization(expected: completed, journal: liveJournal, continuity: liveContinuity), completed)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), journalBytes)
            XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: liveJournal, continuity: liveContinuity), .unchanged(checkpoint))
            XCTAssertEqual(try liveJournal.read { try $0.approvalTrustSnapshot().enrollments.count }, 0)
        }
    }
    func testLostAcknowledgmentsRetainIntentCandidateAndCompletionAcrossReopen() throws {
        for phase in 0...2 {
            try fixture { root in
                var armed = false
                let machine = try store(root, initialize: true, hook: { if armed { throw LostAcknowledgment() } })
                let inventory = try inventory(machine), seed = try initial()
                if phase == 0 {
                    armed = true
                    XCTAssertThrowsError(try begin(root, machine, inventory, seed: seed)) { XCTAssertTrue($0 is LostAcknowledgment) }
                    let reopened = try store(root); defer { try? reopened.close() }
                    let retained = try XCTUnwrap(reopened.initialization(accountID: account))
                    XCTAssertNil(retained.checkpoint)
                    XCTAssertThrowsError(try begin(root, reopened, inventory, seed: seed))
                } else {
                    let intent = try begin(root, machine, inventory, seed: seed)
                    let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
                    if phase == 1 {
                        armed = true
                        XCTAssertThrowsError(try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal))
                        let reopened = try store(root); defer { try? reopened.close() }
                        let retained = try XCTUnwrap(reopened.initialization(accountID: account))
                        XCTAssertNotNil(retained.checkpoint); XCTAssertFalse(retained.complete)
                        XCTAssertEqual(try reopened.captureInitialization(expected: retained, initial: seed, journal: liveJournal), retained)
                    } else {
                        let captured = try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal)
                        let liveContinuity = try continuity(root, checkpoint: XCTUnwrap(captured.checkpoint)); defer { liveContinuity.close() }
                        armed = true
                        XCTAssertThrowsError(try machine.completeInitialization(expected: captured, journal: liveJournal, continuity: liveContinuity))
                        let reopened = try store(root); defer { try? reopened.close() }
                        let retained = try XCTUnwrap(reopened.initialization(accountID: account))
                        XCTAssertTrue(retained.complete)
                        XCTAssertEqual(try reopened.completeInitialization(expected: retained, journal: liveJournal, continuity: liveContinuity), retained)
                    }
                }
            }
        }
    }
    func testChangedInputsDuplicateIntentAndStaleRevisionCannotReplaceRetainedState() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            XCTAssertThrowsError(try begin(root, machine, inventory))
            let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
            XCTAssertThrowsError(try machine.captureInitialization(expected: intent, initial: initial(feature: 9), journal: liveJournal))
            let captured = try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal)
            XCTAssertThrowsError(try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal))
            XCTAssertEqual(try machine.initialization(accountID: account), captured)
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
                bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 9, count: 32), accounts: inventory.accounts, services: inventory.services)
            _ = try machine.writeInventory(changed, expectedRevision: inventory.revision)
            XCTAssertThrowsError(try machine.captureInitialization(expected: captured, initial: seed, journal: liveJournal))
            XCTAssertEqual(try machine.initialization(accountID: account), captured)
        }
    }
    func testCaptureRefusesJournalWithOtherRetainedHistoryAndKeepsIntent() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
            let other = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 7, count: 16)),
                4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            _ = try liveJournal.write { try $0.createEpoch(other) }
            XCTAssertThrowsError(try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal))
            XCTAssertEqual(try machine.initialization(accountID: account), intent)
            XCTAssertNotNil(try liveJournal.read { try $0.epoch(other.epoch) })
        }
    }
    func testCapturedBoundaryCannotFollowChangedJournalAndCompletionDoesNotRepairIt() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
            let captured = try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal)
            let liveContinuity = try continuity(root, checkpoint: XCTUnwrap(captured.checkpoint)); defer { liveContinuity.close() }
            _ = try sql(root, file: "journal/journal.sqlite", query: "UPDATE approval_authority_v1 SET revision=zeroblob(16)")
            XCTAssertThrowsError(try machine.captureInitialization(expected: captured, initial: seed, journal: liveJournal))
            XCTAssertThrowsError(try machine.completeInitialization(expected: captured, journal: liveJournal, continuity: liveContinuity))
            XCTAssertEqual(try machine.initialization(accountID: account), captured)
            XCTAssertFalse(try liveContinuity.read().recoveryRequired)
        }
    }
    func testUncapturedIntentCannotCompleteAndMalformedRowRetiresStore() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
            let checkpoint = try liveJournal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: 1, authorityGeneration: 1) }
            let liveContinuity = try continuity(root, checkpoint: checkpoint); defer { liveContinuity.close() }
            XCTAssertThrowsError(try machine.completeInitialization(expected: intent, journal: liveJournal, continuity: liveContinuity))
            _ = try sql(root, query: "UPDATE authority_initialization_v1 SET record=x'80'")
            XCTAssertThrowsError(try machine.initialization(accountID: account)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            XCTAssertThrowsError(try machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertEqual(try sql(root, query: "SELECT count(*) FROM authority_initialization_v1"), 1)
        }
    }
    func testInvalidPathsAndWrongInventoryRevisionRollBackSchemaUpgrade() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial()
            for (journal, continuity) in [("/bad/../journal.sqlite", root.path + "/continuity/continuity.sqlite"),
                                         (root.path + "/journal/journal.sqlite", root.path + "/journal/continuity.sqlite"),
                                         (root.path + "/journal/journal.sqlite", root.path + "/journal/nested/continuity.sqlite")] {
                XCTAssertThrowsError(try machine.beginInitialization(initial: seed, journalPath: journal, continuityPath: continuity,
                    expectedInventoryRevision: inventory.revision))
                XCTAssertEqual(try sql(root, query: "PRAGMA user_version"), 2)
            }
            XCTAssertThrowsError(try machine.beginInitialization(initial: seed, journalPath: root.path + "/journal/journal.sqlite",
                continuityPath: root.path + "/continuity/continuity.sqlite", expectedInventoryRevision: Data(repeating: 9, count: 16)))
            XCTAssertEqual(try sql(root, query: "PRAGMA user_version"), 2)
        }
    }
    func testValidDescriptorLargerThanRecordLimitCanCaptureAndComplete() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            XCTAssertGreaterThan(try seed.descriptor.encode(limits: limits).count, 64)
            let liveJournal = try journal(root, seed: seed, recordByteLimit: 64); defer { try? liveJournal.close() }
            let captured = try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal)
            let liveContinuity = try continuity(root, checkpoint: XCTUnwrap(captured.checkpoint)); defer { liveContinuity.close() }
            XCTAssertTrue(try machine.completeInitialization(expected: captured, journal: liveJournal, continuity: liveContinuity).complete)
        }
    }
    func testJournalNestedWithinContinuityCannotBeginSetupEvenWithProvisionedFiles() throws {
        try fixture { root in
            let nested = try ProtectedSetupDirectory(anchor: root.path, relativePath: "continuity/nested", owner: getuid())
            defer { nested.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: nested, kind: .journal, owner: getuid())
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine)
            XCTAssertThrowsError(try machine.beginInitialization(initial: initial(),
                journalPath: root.path + "/continuity/nested/journal.sqlite", continuityPath: root.path + "/continuity/continuity.sqlite",
                expectedInventoryRevision: inventory.revision)) { XCTAssertEqual($0 as? AuthorityInitializationError, .invalidIntent) }
            XCTAssertNil(try machine.initialization(accountID: account))
            XCTAssertEqual(try sql(root, query: "PRAGMA user_version"), 2)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("continuity/nested/journal.sqlite")), Data())
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("continuity/continuity.sqlite")), Data())
        }
    }
    func testPublicOperationsRequireBothRootIdentitiesBeforeAccess() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), intent = try begin(root, machine, inventory, seed: seed)
            let liveJournal = try journal(root, seed: seed); defer { try? liveJournal.close() }
            let captured = try machine.captureInitialization(expected: intent, initial: seed, journal: liveJournal)
            let liveContinuity = try continuity(root, checkpoint: XCTUnwrap(captured.checkpoint)); defer { liveContinuity.close() }
            for operation in [{ _ = try machine.beginAuthorityInitialization(initial: seed, journalPath: intent.journalPath,
                                  continuityPath: intent.continuityPath, expectedInventoryRevision: inventory.revision) },
                              { _ = try machine.loadAuthorityInitialization(accountID: self.account) },
                              { _ = try machine.captureAuthorityInitialization(expected: captured, initial: seed, journal: liveJournal) },
                              { _ = try machine.completeAuthorityInitialization(expected: captured, journal: liveJournal, continuity: liveContinuity) }] {
                XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            }
            XCTAssertEqual(try machine.initialization(accountID: account), captured)
        }
    }
}
