import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Real owned import journals and relay records prove value selection only. No consumer file or native identity is supplied.
final class RetainedSetupInitialSelectionTests: XCTestCase {
    private typealias Selection = MachineUpdateRetainedSetupInitialSelection
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private enum Fault: Error { case stopped }
    private struct Seed { let intent: SharedSetupImportIntent; let relay: SharedSetupImportRelayPlan?; let path: String }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func fixture(seed: (Fixture) throws -> Void = { _ in },
        body: (Fixture, Snapshot, Boundary) throws -> Void) throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture(seed: seed, body: body)
    }
    private func journal(_ f: Fixture, initialize: Bool) throws -> SharedSetupImportJournal {
        let machine = URL(fileURLWithPath: f.directory.path), anchor = machine.deletingLastPathComponent().path
        let relative = machine.lastPathComponent + "/SharedSetupImport"
        if initialize {
            let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
            defer { directory.close() }; _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
        }
        return try .init(lease: .init(anchor: anchor, relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(),
            databaseName: "setup-import.sqlite"), owner: getuid(), macID: f.source.runtime.preparation.macID,
            installationID: f.source.runtime.preparation.installationID, initialize: initialize)
    }
    private func seed(_ f: Fixture, relay: Bool = true) throws -> Seed {
        let runtime = f.source.runtime, account = runtime.preparation
        let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        let presence = try PresenceConfiguration(idleMilliseconds: 540000, observationLifetimeMilliseconds: 7000,
            unavailableGraceMilliseconds: 45000)
        let cloud = try relay ? SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
            zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only") : nil
        let proposal = PortableSetup(defaults: try .init(presence: presence, gateway: GatewaySetupForm().settingsSelection()), cloudflare: cloud)
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal)
        let store = try journal(f, initialize: true); defer { try? store.close() }; try store.begin(intent)
        let directory = try ProtectedSetupDirectory(anchor: f.directory.path, relativePath: "SharedSetupImport", owner: getuid(), createIfMissing: false)
        defer { directory.close() }
        let plan = try relay ? SharedSetupImportRelayPlan(expected: intent, port: 51001) : nil
        if let plan {
            _ = try AdministrativeSetupPublication.publish(plan.bytes, file: .importRelayPlan(accountID: account.accountID),
                directory: directory, owner: getuid())
        }
        return Seed(intent: intent, relay: plan, path: directory.path)
    }
    private func withSelection<Result>(_ f: Fixture, _ expected: Snapshot, _ pair: Boundary,
        policy: AuthorityCodePolicy? = nil, body: (Selection, Selection.Scope) throws -> Result) throws -> Result {
        try Selection.withCurrent(machine: f.machine(), expected: expected, candidate: f.candidate,
            recordedStartupPolicy: policy ?? pair.policy.policy, readPolicyBoundary: {
                let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(expected.activation.runtime.setup.account?.initialization))
            }, verifyCurrent: { _ in }, body: body)
    }
    private func replaceOwnedImport(_ record: SharedSetupImportIntent, at path: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path + "/setup-import.sqlite", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK else {
            if let db { sqlite3_close(db) }; throw Fault.stopped
        }
        defer { sqlite3_close(db) }
        let sql = "UPDATE shared_setup_import_v2 SET operation=x'\(hex(record.operationID))',revision=x'\(hex(record.revision))',digest=x'\(hex(record.proposalDigest))',phase=\(record.phase.rawValue),record=x'\(try hex(record.bytes))' WHERE account=x'\(hex(record.scope.accountID))'"
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK, sqlite3_changes(db) == 1 else { throw Fault.stopped }
    }
    private func replaceOwnedRelay(_ bytes: Data, at path: String) throws {
        let fd = Darwin.open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }; defer { Darwin.close(fd) }
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw Fault.stopped }; offset += count
        }
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
    }

    func testActualJournalAbsenceSelectsDefaultsWithoutCreatingStorageAndRepeatsExactBytes() throws {
        try fixture { f, snapshot, pair in
            let path = f.directory.path + "/SharedSetupImport"
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            let first = try withSelection(f, snapshot, pair) { selected, scope in
                XCTAssertFalse(selected.inputs.journalPresent); XCTAssertNil(selected.importDigest); XCTAssertNil(selected.relayDigest)
                try scope.verify(); return selected
            }
            let second = try withSelection(f, snapshot, pair) { selected, _ in selected }
            try first.requireSame(as: second); XCTAssertEqual(first.digest, second.digest)
            XCTAssertEqual(try first.configuration.digest, try second.configuration.digest)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.idleMilliseconds, 120000)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }

    func testNondefaultActualImportAndRelaySupplyEveryValueAndBothDigestPins() throws {
        var seeded: Seed?
        try fixture(seed: { seeded = try self.seed($0) }) { f, snapshot, pair in
            let source = try XCTUnwrap(seeded)
            let first = try withSelection(f, snapshot, pair) { selected, scope in
                XCTAssertTrue(selected.inputs.journalPresent); XCTAssertEqual(selected.inputs.intent, source.intent)
                XCTAssertEqual(selected.importDigest, try Data(SHA256.hash(data: source.intent.bytes)))
                XCTAssertEqual(selected.relayDigest, Data(SHA256.hash(data: try XCTUnwrap(source.relay).bytes)))
                try scope.read().requireSame(as: selected); return selected
            }
            let second = try withSelection(f, snapshot, pair) { selected, _ in selected }
            try first.requireSame(as: second)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.idleMilliseconds, 540000)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.observationLifetimeMilliseconds, 7000)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.unavailableGraceMilliseconds, 45000)
            XCTAssertEqual(first.configuration.bundle.transport.relayPort, 51001)
            let a = try RuntimePublishedArtifactValidation.artifacts(bundle: first.configuration.bundle, material: f.material)
            let b = try RuntimePublishedArtifactValidation.artifacts(bundle: second.configuration.bundle, material: f.material)
            XCTAssertEqual(a.map(\.path), b.map(\.path)); XCTAssertEqual(a.map(\.bytes), b.map(\.bytes))
            XCTAssertFalse(try f.machine().retainedSetupPolicySnapshot(owner: snapshot.activation.runtime.setup.owner,
                candidate: f.candidate).activation.runtime.state.configurationPublished)
        }
    }

    func testAnActualEmptyJournalIsNotCallerSuppliedAbsence() throws {
        try fixture(seed: { f in let store = try self.journal(f, initialize: true); try store.close() }) { f, snapshot, pair in
            try withSelection(f, snapshot, pair) { selected, scope in
                XCTAssertTrue(selected.inputs.journalPresent); XCTAssertNil(selected.inputs.intent)
                XCTAssertNil(selected.importDigest); XCTAssertNil(selected.relayDigest)
                XCTAssertEqual(selected.configuration.bundle.command.presence.presence.policy.idleMilliseconds, 120000)
                try scope.verify()
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: f.directory.path + "/SharedSetupImport/setup-import.sqlite"))
        }
    }

    func testTheCurrentAuthorityPolicyCannotReplaceTheRecordedTargetStartupPolicy() throws {
        try fixture { f, snapshot, pair in
            let account = f.currentAuthorityAccountID
            let initial = try XCTUnwrap(f.source.runtime.setup.source.accounts.first { $0.accountID == account }?.initialization)
            let openJournal = f.openJournalLease, openContinuity = f.openContinuityLease
            let journal = try MachineUpdateRetainedSetupPolicyNativeEntry.openJournal(access: .readOnly, initial: initial,
                openJournalLease: { try openJournal(account) }, openContinuityLease: { try openContinuity(account, $0) },
                verifySelf: { _ in })
            defer { try? journal.close() }
            let authority = try journal.captureRetainedSetupPolicyBoundary(expected: initial).policy.policy
            try journal.close()
            XCTAssertNotEqual(try pair.policy.policy.bytes, try authority.bytes)
            var called = false
            XCTAssertThrowsError(try withSelection(f, snapshot, pair, policy: authority) { _, _ in called = true }) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertFalse(called); XCTAssertFalse(FileManager.default.fileExists(atPath: f.directory.path + "/SharedSetupImport"))
        }
    }

    func testARealImportRecordChangeInsideTheScopeRefusesAndDoesNotAcknowledgeTheValue() throws {
        var seeded: Seed?
        try fixture(seed: { seeded = try self.seed($0, relay: false) }) { f, snapshot, pair in
            let source = try XCTUnwrap(seeded)
            let changed = try SharedSetupImportIntent(scope: source.intent.scope, proposal: source.intent.recipe.settings)
            // Restore only the fixture's injected external change. The selection owner has no repair path.
            defer { XCTAssertNoThrow(try replaceOwnedImport(source.intent, at: source.path)) }
            XCTAssertThrowsError(try withSelection(f, snapshot, pair) { _, scope in
                try self.replaceOwnedImport(changed, at: source.path)
                XCTAssertThrowsError(try scope.verify())
            })
        }
    }

    func testARealRelayRecordChangeInsideTheScopeRefusesWithoutSelectingANewPort() throws {
        var seeded: Seed?
        try fixture(seed: { seeded = try self.seed($0) }) { f, snapshot, pair in
            let source = try XCTUnwrap(seeded), original = try XCTUnwrap(source.relay)
            let changed = try SharedSetupImportRelayPlan(expected: source.intent, port: 51002)
            let path = source.path + "/" + AdministrativeSetupPublication.File.importRelayPlan(accountID: source.intent.scope.accountID).name
            defer { XCTAssertNoThrow(try replaceOwnedRelay(original.bytes, at: path)) }
            XCTAssertThrowsError(try withSelection(f, snapshot, pair) { selected, scope in
                XCTAssertEqual(selected.configuration.bundle.transport.relayPort, 51001)
                try self.replaceOwnedRelay(changed.bytes, at: path)
                XCTAssertThrowsError(try scope.verify())
            })
        }
    }

    func testTheValueScopeExpiresOnReturnAndOnBodyFailure() throws {
        try fixture { f, snapshot, pair in
            var escaped: Selection.Scope?
            _ = try withSelection(f, snapshot, pair) { selected, scope in escaped = scope; try scope.verify(); return selected }
            XCTAssertThrowsError(try XCTUnwrap(escaped).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try withSelection(f, snapshot, pair) { _, scope in escaped = scope; throw Fault.stopped }) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testPreparedWritingAndMissingPolicyRecordsCannotSelectAnyValue() throws {
        try fixture { f, snapshot, pair in
            let original = try XCTUnwrap(snapshot.intent)
            var records: [MachineUpdateRetainedSetupPolicyIntentRecord?] = [nil]
            for phase in [MachineUpdateRetainedSetupPolicyIntentRecord.Phase.prepared, .writing] {
                var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded) as? [String: Any])
                fields["phase"] = phase.rawValue; fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
                records.append(try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])))
            }
            for record in records {
                let proposed = try Snapshot(activation: snapshot.activation, intent: record, candidate: f.candidate); var called = false
                XCTAssertThrowsError(try withSelection(f, proposed, pair) { _, _ in called = true }) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
                XCTAssertFalse(called)
            }
        }
    }

    func testEachBorrowedFrameReadsTheActualSnapshotAndPairAtMostTwice() throws {
        try fixture { f, snapshot, pair in
            var snapshots = 0, pairs = 0
            try Selection.withCurrent(machine: f.machine(), expected: snapshot, candidate: f.candidate,
                recordedStartupPolicy: pair.policy.policy, readPolicyBoundary: {
                    pairs += 1
                    let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                    return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(snapshot.activation.runtime.setup.account?.initialization))
                }, verifyCurrent: { _ in snapshots += 1 }) { selected, scope in
                    let oldSnapshots = snapshots, oldPairs = pairs
                    let frame = try scope.readFrame()
                    XCTAssertEqual(snapshots - oldSnapshots, 2); XCTAssertLessThanOrEqual(snapshots - oldSnapshots, 2)
                    XCTAssertEqual(pairs - oldPairs, 2); XCTAssertLessThanOrEqual(pairs - oldPairs, 2)
                    try frame.snapshot.requireSame(as: snapshot); XCTAssertEqual(frame.current, pair)
                    try frame.selection.requireSame(as: selected)
                    XCTAssertEqual(String(describing: frame), "RetainedSetupInitialSelectionFrame(redacted)")
                }
        }
    }
}
