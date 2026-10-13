import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityJournalInitializationTests: XCTestCase {
    private enum Fault: Error { case interrupted }
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), epoch = Data(repeating: 3, count: 16)
    private var bounds: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 3) } }
    private func seed(macID: Data? = nil, replay: Bool = true, validPolicy: Bool = true) throws -> AuthorityJournalInitialization {
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID ?? mac), 2: .bytes(account), 3: .bytes(epoch),
            4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: bounds), limits: bounds)
        let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
        return AuthorityJournalInitialization(descriptor: descriptor, codePolicy: policy,
            capabilities: ContractCapabilities(contracts: [try contract: []]), allowedContracts: validPolicy ? [try contract] : [],
            installCommandReplay: replay)
    }
    private func fixture(_ body: (URL) throws -> Void) throws {
        guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
        defer { free(canonical) }
        let root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent("remozio-initial-authority-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, kind): (String, SetupDatabaseKind) in [("journal", .journal), ("continuity", .continuity)] {
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
        }
        try body(root)
    }
    private func open(_ root: URL, initialize: Bool, initial: AuthorityJournalInitialization? = nil,
                      hook: (AuthorityJournalInitialization.Stage) throws -> Void = { _ in }) throws -> JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
            macID: mac, accountID: account, recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize,
            initialAuthority: initial, didInitializeAuthority: hook)
    }
    private func scalar(_ root: URL, query: String) throws -> Int64 {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(root.path + "/journal/journal.sqlite", &db, SQLITE_OPEN_READONLY, nil), SQLITE_OK)
        let opened = try XCTUnwrap(db); defer { sqlite3_close(opened) }
        var statement: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(opened, query, -1, &statement, nil), SQLITE_OK)
        let prepared = try XCTUnwrap(statement); defer { sqlite3_finalize(prepared) }
        XCTAssertEqual(sqlite3_step(prepared), SQLITE_ROW); return sqlite3_column_int64(prepared, 0)
    }
    func testCompleteInitialAuthorityCommitsAndReopensWithoutPhoneTrust() throws {
        try fixture { root in
            let initial = try seed(), database = try open(root, initialize: true, initial: initial)
            let policyRevision = try database.read { transaction in
                XCTAssertEqual(try transaction.storageSchemaVersion, 15)
                XCTAssertEqual(try transaction.epoch(epoch)?.descriptor.encode(limits: bounds), try initial.descriptor.encode(limits: bounds))
                let trust = try transaction.approvalTrustSnapshot()
                XCTAssertEqual(trust.macID, mac); XCTAssertEqual(trust.accountID, account)
                XCTAssertTrue(trust.enrollments.isEmpty); XCTAssertEqual(trust.allowedContracts, initial.allowedContracts)
                XCTAssertNil(try transaction.commandSubmissionReservation(submissionID: Data(repeating: 7, count: 16)))
                let policy = try XCTUnwrap(transaction.codePolicy()); XCTAssertEqual(policy.policy, initial.codePolicy)
                return policy.revision
            }
            try database.close()
            let restored = try open(root, initialize: false); defer { try? restored.close() }
            XCTAssertEqual(try restored.read { try $0.codePolicy()?.revision }, policyRevision)
            XCTAssertNotNil(try restored.read { try $0.epoch(epoch) })
        }
    }
    func testEveryBootstrapStageFailureRollsBackTheEntireSchemaAndAllowsExplicitRetry() throws {
        for stage: AuthorityJournalInitialization.Stage in [.epoch, .approvalPolicy, .codePolicy, .commandReplay] {
            try fixture { root in
                let initial = try seed()
                XCTAssertThrowsError(try open(root, initialize: true, initial: initial) { if $0 == stage { throw Fault.interrupted } })
                XCTAssertEqual(try scalar(root, query: "PRAGMA application_id"), 0)
                XCTAssertEqual(try scalar(root, query: "PRAGMA user_version"), 0)
                XCTAssertEqual(try scalar(root, query: "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"), 0)
                let retried = try open(root, initialize: true, initial: initial); defer { try? retried.close() }
                XCTAssertEqual(try retried.read { try $0.storageSchemaVersion }, 15)
            }
        }
    }
    func testInvalidApprovalPolicyCannotLeaveAnEpochOrSchema() throws {
        try fixture { root in
            XCTAssertThrowsError(try open(root, initialize: true, initial: seed(validPolicy: false)))
            XCTAssertEqual(try scalar(root, query: "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"), 0)
            let retried = try open(root, initialize: true, initial: seed()); defer { try? retried.close() }
            XCTAssertNotNil(try retried.read { try $0.epoch(epoch) })
        }
    }
    func testRetainedStateCannotBeReinitializedAndKeepsItsIdentity() throws {
        try fixture { root in
            let initial = try seed(), first = try open(root, initialize: true, initial: initial)
            let before = try first.read { try $0.continuityDigests() }; try first.close()
            let bytes = try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite"))
            XCTAssertThrowsError(try open(root, initialize: true, initial: initial))
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), bytes)
            let restored = try open(root, initialize: false); defer { try? restored.close() }
            XCTAssertEqual(try restored.read { try $0.continuityDigests() }, before)
        }
    }
    func testBootstrapRequiresExplicitInitializationAndMatchingScopeBeforeSQLite() throws {
        try fixture { root in
            for (initialize, initial) in [(false, try seed()), (true, try seed(macID: Data(repeating: 8, count: 16)))] {
                XCTAssertThrowsError(try open(root, initialize: initialize, initial: initial)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .invalidConfiguration)
                }
                XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
            }
        }
    }
    func testStorageOnlyInitializationAndOptionalReplayKeepTheirExistingProfiles() throws {
        for initialized in [false, true] {
            try fixture { root in
                let database = try open(root, initialize: true, initial: initialized ? seed(replay: false) : nil)
                defer { try? database.close() }
                XCTAssertEqual(try database.read { try $0.storageSchemaVersion }, initialized ? 13 : 12)
                if initialized { XCTAssertNotNil(try database.read { try $0.codePolicy() }) }
                else { XCTAssertNil(try database.read { try $0.codePolicy() }) }
                XCTAssertThrowsError(try database.read { try $0.commandSubmissionReservation(submissionID: Data(repeating: 7, count: 16)) })
            }
        }
    }
    func testCommittedInitialStateBuildsAndReconcilesTheIndependentCheckpoint() throws {
        try fixture { root in
            let database = try open(root, initialize: true, initial: seed())
            let checkpoint = try database.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: 1, authorityGeneration: 1) }
            let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: mac, accountID: account, initialize: checkpoint)
            XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: database, continuity: store), .unchanged(checkpoint))
            store.close(); try database.close()
            let restored = try open(root, initialize: false); defer { try? restored.close() }
            let retained = try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: mac, accountID: account, initialize: nil)
            defer { retained.close() }
            XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: restored, continuity: retained), .unchanged(checkpoint))
        }
    }
}
