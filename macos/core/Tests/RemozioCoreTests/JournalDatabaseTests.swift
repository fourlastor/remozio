import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class JournalDatabaseTests: XCTestCase {
    private enum Failure: Error { case injected }
    private var bounds: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func descriptor(_ epoch: UInt8 = 3) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bounds), limits: bounds)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3) throws -> Data {
        try AuditEventMetadata(eventID: id(UInt8(sequence)), macID: id(1), accountID: id(2), journalEpoch: id(epoch),
            sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .consumed,
            category: .command, action: nil, decisionPhoneID: nil, authentication: .system, outcome: .accepted,
            reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bounds)
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, mac: UInt8 = 1, account: UInt8 = 2,
                      busy: UInt32 = 100, maximumSubmissions: Int = 1_000_000) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(mac), accountID: id(account),
                            recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: 10, busyMilliseconds: busy, initialize: initialize, maximumCommandSubmissions: maximumSubmissions)
    }

    private func submissionReservation(_ value: UInt8 = 7, nonce: UInt8? = nil, mac: UInt8 = 1, account: UInt8 = 2) throws -> CommandSubmissionReservation {
        try CommandSubmissionReservation(macID: id(mac), accountID: id(account),
            submission: CapturedSubmission(id: id(value), nonce: Data(repeating: nonce ?? value, count: 32), callerBinding: id(8)),
            captureDigest: Data(repeating: 9, count: 32))
    }

    func testStorageSchemaObservationTracksProtectedMigrationWithoutChangingContinuity() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        var expired: JournalTransaction?
        let before = try database.read { try $0.continuityDigests() }
        XCTAssertEqual(try database.read { tx in
            expired = tx
            return try tx.storageSchemaVersion
        }, UInt64(12))
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
        XCTAssertThrowsError(try expired!.storageSchemaVersion) {
            XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction)
        }
        _ = try installRecoveryPolicy(database)
        XCTAssertEqual(try database.read { try $0.storageSchemaVersion }, UInt64(13))
        XCTAssertThrowsError(try database.write { tx in
            try tx.installCommandSubmissionReplay()
            XCTAssertEqual(try tx.storageSchemaVersion, UInt64(15))
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.storageSchemaVersion }, UInt64(13))
        try database.write { try $0.installCommandSubmissionReplay() }
        XCTAssertEqual(try database.read { try $0.storageSchemaVersion }, UInt64(15))
    }

    func testUnsupportedObservedStorageSchemaRetiresTheConnection() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        try fixture.sql("PRAGMA user_version=99")
        XCTAssertThrowsError(try database.read { try $0.storageSchemaVersion }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .incompatibleStore)
        }
        XCTAssertTrue(database.retired)
        XCTAssertThrowsError(try database.read { try $0.storageSchemaVersion }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .unavailable)
        }
    }

    func testCommandReplayMigrationAndReservationSurviveReopenWithoutChangingCodePolicy() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let policy = try installRecoveryPolicy(database), before = try database.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try database.read { try $0.commandSubmissionReservation(submissionID: id(7)) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .unavailable)
        }
        try database.write { try $0.installCommandSubmissionReplay() }
        let installed = try database.read { try $0.continuityDigests() }
        XCTAssertNotEqual(before.authority, installed.authority)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "15")
        XCTAssertEqual(try database.read { try $0.codePolicy() }, policy)
        XCTAssertNil(try database.read { try $0.historyRecovery(epoch: id(9)) })
        let value = try submissionReservation()
        XCTAssertEqual(try database.write { try $0.reserveCommandSubmission(value) }, value)
        let reserved = try database.read { try $0.continuityDigests() }
        XCTAssertNotEqual(installed.authority, reserved.authority)
        XCTAssertEqual(installed.ledger, reserved.ledger)
        try database.close()
        let reopened = try open(fixture)
        defer { try? reopened.close() }
        XCTAssertEqual(try reopened.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }, value)
        XCTAssertEqual(try reopened.read { try $0.codePolicy() }, policy)
        XCTAssertEqual(try reopened.read { try $0.continuityDigests() }, reserved)
        XCTAssertNil(try reopened.read { try $0.commandSubmissionReservation(submissionID: id(10)) })
        for duplicate in [try submissionReservation(7, nonce: 10), try submissionReservation(10, nonce: 7), value] {
            XCTAssertThrowsError(try reopened.write { try $0.reserveCommandSubmission(duplicate) }) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
            }
        }
        XCTAssertEqual(try reopened.read { try $0.continuityDigests() }, reserved)
    }

    func testCommandReplayMigrationPreservesExistingHistoryRecoveryEvidence() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        let policy = try installRecoveryPolicy(database)
        let intent = try recoveryIntent(database.read { try $0.continuityDigests() })
        try database.write { try $0.recordHistoryRecovery(intent) }
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "14")
        let before = try database.read { try $0.continuityDigests() }
        try database.write { try $0.installCommandSubmissionReplay() }
        let after = try database.read { try $0.continuityDigests() }
        XCTAssertNotEqual(before.authority, after.authority)
        XCTAssertEqual(before.ledger, after.ledger)
        XCTAssertEqual(try database.read { try $0.historyRecovery(epoch: intent.recoveryEpoch) }, intent)
        XCTAssertEqual(try database.write { try $0.installCodePolicy(policy.policy, expectedRevision: policy.revision) }, policy)
        try database.write { try $0.installCommandSubmissionReplay() }
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, after)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "15")
    }

    func testCommandReplayInstallationRequiresPolicyAndRollsBackItsEntireCatalog() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        let empty = try database.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try database.write { try $0.installCommandSubmissionReplay() }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .unavailable)
        }
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, empty)
        _ = try installRecoveryPolicy(database)
        let before = try database.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try database.write { tx in
            try tx.installCommandSubmissionReplay()
            _ = try tx.reserveCommandSubmission(submissionReservation())
            throw Failure.injected
        })
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "13")
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
        XCTAssertNil(try database.read { try $0.historyRecovery(epoch: id(9)) })
        try database.write { try $0.installCommandSubmissionReplay() }
        XCTAssertNil(try database.read { try $0.commandSubmissionReservation(submissionID: id(7)) })
    }

    func testCommandReplayCaughtFailureCannotCommitEarlierTentativeReservations() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        _ = try installRecoveryPolicy(database)
        try database.write { try $0.installCommandSubmissionReplay() }
        let before = try database.read { try $0.continuityDigests() }, value = try submissionReservation()
        XCTAssertThrowsError(try database.write { tx in
            _ = try tx.reserveCommandSubmission(value)
            do { _ = try tx.reserveCommandSubmission(value); XCTFail("duplicate accepted") }
            catch { XCTAssertEqual(error as? CommandSubmissionReplayError, .alreadyReserved) }
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertNil(try database.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) })
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
        XCTAssertEqual(try database.write { try $0.reserveCommandSubmission(value) }, value)
    }

    func testCommandReplayCapacityDoesNotEvictAndCanBeRaisedAfterReopen() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true, maximumSubmissions: 1)
        _ = try installRecoveryPolicy(database)
        try database.write { try $0.installCommandSubmissionReplay() }
        let first = try submissionReservation(), second = try submissionReservation(10)
        _ = try database.write { try $0.reserveCommandSubmission(first) }
        let before = try database.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try database.write { try $0.reserveCommandSubmission(second) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .capacityExceeded)
        }
        XCTAssertThrowsError(try database.write { try $0.reserveCommandSubmission(first) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
        }
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
        try database.close()
        let reopened = try open(fixture, maximumSubmissions: 2)
        defer { try? reopened.close() }
        _ = try reopened.write { try $0.reserveCommandSubmission(second) }
        for value in [first, second] {
            XCTAssertEqual(try reopened.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }, value)
        }
    }

    func testCommandReplayRejectsWrongScopeReadOnlyAndEscapedTransactions() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        _ = try installRecoveryPolicy(database)
        try database.write { try $0.installCommandSubmissionReplay() }
        let before = try database.read { try $0.continuityDigests() }, value = try submissionReservation()
        for wrong in [try submissionReservation(mac: 3), try submissionReservation(account: 3)] {
            XCTAssertThrowsError(try database.write { try $0.reserveCommandSubmission(wrong) }) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .wrongScope)
            }
        }
        XCTAssertThrowsError(try database.read { try $0.reserveCommandSubmission(value) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        XCTAssertThrowsError(try database.read { try $0.installCommandSubmissionReplay() }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let escaped = try database.write { $0 }
        XCTAssertThrowsError(try escaped.reserveCommandSubmission(value)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction)
        }
        XCTAssertThrowsError(try escaped.commandSubmissionReservation(submissionID: value.submission.id)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction)
        }
        XCTAssertThrowsError(try escaped.installCommandSubmissionReplay()) {
            XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction)
        }
        XCTAssertThrowsError(try database.read { try $0.commandSubmissionReservation(submissionID: Data([1])) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .invalidConfiguration)
        }
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
    }

    func testCommandReplayCorruptStoredBindingRetiresTheJournal() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        _ = try installRecoveryPolicy(database)
        try database.write { try $0.installCommandSubmissionReplay() }
        let value = try submissionReservation()
        _ = try database.write { try $0.reserveCommandSubmission(value) }
        // A disposable malformed table models corruption that bypassed write-time CHECK constraints.
        try fixture.sql("ALTER TABLE command_submissions_v1 RENAME TO saved_replay")
        try fixture.sql("CREATE TABLE command_submissions_v1 AS SELECT mac,account,submission,x'00' AS nonce,caller,capture FROM saved_replay")
        XCTAssertThrowsError(try database.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .corruptData)
        }
        XCTAssertTrue(database.retired)
        XCTAssertThrowsError(try database.read { _ in XCTFail("corrupt storage remained usable") }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .unavailable)
        }
    }

    func testCommandReplayRejectsInvalidConfigurationAndRecordSizes() throws {
        for maximum in [0, -1, Int(Int32.max) + 1] {
            let fixture = try Fixture()
            XCTAssertThrowsError(try open(fixture, initialize: true, maximumSubmissions: maximum)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .invalidConfiguration)
            }
            let database = try open(fixture, initialize: true)
            try database.close()
        }
        let binding = try submissionReservation().submission
        for invalid in [(Data([1]), id(2), Data(repeating: 9, count: 32)),
                        (id(1), Data([2]), Data(repeating: 9, count: 32)), (id(1), id(2), Data([9]))] {
            XCTAssertThrowsError(try CommandSubmissionReservation(macID: invalid.0, accountID: invalid.1,
                submission: binding, captureDigest: invalid.2)) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .invalidConfiguration)
            }
        }
    }

    private func installRecoveryPolicy(_ database: JournalDatabase) throws -> AuthorityCodePolicySnapshot {
        let entry = try AuthorityCodeEntry(role: .authority, teamID: "ABCDEF1234", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 7, count: 20), active: true)
        return try database.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: nil) }
    }

    private func recoveryIntent(_ digests: JournalContinuityDigests) throws -> HistoryRecoveryIntent {
        let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: digests.authority,
            ledgerDigest: digests.ledger, journalEpoch: id(3), journalHead: 0, authorityGeneration: 1)
        return try HistoryRecoveryIntent(previous: ContinuityState(committed: checkpoint, pending: nil, recoveryRequired: false),
            authorityDigest: digests.authority, ledgerDigest: digests.ledger, recoveryEpoch: id(9))
    }

    func testHistoryEvidenceChangesOnlyLedgerAndSurvivesReopen() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let policy = try installRecoveryPolicy(database)
        let before = try database.read { try $0.continuityDigests() }
        let intent = try recoveryIntent(before)
        XCTAssertNil(try database.read { try $0.historyRecovery(epoch: id(9)) })
        try database.write { try $0.recordHistoryRecovery(intent) }
        let after = try database.read { try $0.continuityDigests() }
        XCTAssertEqual(before.authority, after.authority)
        XCTAssertNotEqual(before.ledger, after.ledger)
        XCTAssertEqual(try database.read { try $0.historyRecovery(epoch: id(9)) }, intent)
        XCTAssertEqual(try database.read { try $0.codePolicy() }, policy)
        try database.close()
        let reopened = try open(fixture)
        defer { try? reopened.close() }
        XCTAssertEqual(try reopened.read { try $0.historyRecovery(epoch: id(9)) }, intent)
        XCTAssertEqual(try reopened.read { try $0.continuityDigests() }, after)
        XCTAssertEqual(try reopened.read { try $0.codePolicy() }, policy)
        try fixture.sql("UPDATE history_recoveries_v1 SET evidence=x'00'")
        XCTAssertNotEqual(try reopened.read { try $0.continuityDigests().ledger }, after.ledger)
        XCTAssertEqual(try reopened.read { try $0.continuityDigests().authority }, after.authority)
        XCTAssertThrowsError(try reopened.read { try $0.historyRecovery(epoch: id(9)) })
    }

    func testHistoryEvidenceMigrationRollsBackAndRejectsDuplicateAndReadOnlyWrites() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        defer { try? database.close() }
        _ = try installRecoveryPolicy(database)
        let before = try database.read { try $0.continuityDigests() }, intent = try recoveryIntent(before)
        XCTAssertThrowsError(try database.write { tx in
            try tx.recordHistoryRecovery(intent)
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, before)
        XCTAssertNil(try database.read { try $0.historyRecovery(epoch: id(9)) })
        XCTAssertThrowsError(try database.read { try $0.recordHistoryRecovery(intent) })
        try database.write { try $0.recordHistoryRecovery(intent) }
        let after = try database.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try database.write { try $0.recordHistoryRecovery(intent) })
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, after)
        let escaped = try database.read { $0 }
        XCTAssertThrowsError(try escaped.historyRecovery(epoch: id(9)))
    }

    func testContinuityDigestsSeparateHistoryAndSurviveReopen() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let initial = try database.read { try $0.continuityDigests() }
        XCTAssertEqual(initial.authority.count, 32)
        XCTAssertEqual(initial.ledger.count, 32)
        XCTAssertNotEqual(initial.authority, initial.ledger)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let epoch = try database.read { try $0.continuityDigests() }
        XCTAssertEqual(initial.authority, epoch.authority)
        XCTAssertNotEqual(initial.ledger, epoch.ledger)
        try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) }
        let appended = try database.read { try $0.continuityDigests() }
        XCTAssertEqual(initial.authority, appended.authority)
        XCTAssertNotEqual(epoch.ledger, appended.ledger)
        XCTAssertThrowsError(try database.write { tx in
            try tx.append(record(2), writer: writer, expectedHead: 1)
            XCTAssertNotEqual(try tx.continuityDigests().ledger, appended.ledger)
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.continuityDigests() }, appended)
        let escaped = try database.read { $0 }
        XCTAssertThrowsError(try escaped.continuityDigests())
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.continuityDigests() }, appended)
    }

    func testContinuityDigestsBindTrustConsumptionAndOutcomesIndependentOfInsertionOrder() throws {
        let first = try Fixture(), second = try Fixture()
        let a = try open(first, initialize: true), b = try open(second, initialize: true)
        let empty = try a.read { try $0.continuityDigests() }
        // Synthetic storage bytes test hash coverage, not semantic enrollment or decision validation.
        let one = "INSERT INTO approval_enrollments_v1 VALUES(zeroblob(16),zeroblob(16),0,x'01')"
        let two = "INSERT INTO approval_enrollments_v1 VALUES(zeroblob(16),x'01010101010101010101010101010101',0,x'02')"
        try first.sql(one)
        try first.sql(two)
        try second.sql(two)
        try second.sql(one)
        let enrolled = try a.read { try $0.continuityDigests() }
        XCTAssertEqual(enrolled, try b.read { try $0.continuityDigests() })
        XCTAssertNotEqual(empty.authority, enrolled.authority)
        XCTAssertEqual(empty.ledger, enrolled.ledger)
        try first.sql("UPDATE approval_enrollments_v1 SET active=1 WHERE body=x'01'")
        XCTAssertNotEqual(enrolled.authority, try a.read { try $0.continuityDigests().authority })
        let trust = try a.read { try $0.continuityDigests() }
        try first.sql("INSERT INTO consumptions_v1 VALUES(zeroblob(16),zeroblob(16),zeroblob(16),x'01',x'02')")
        let consumed = try a.read { try $0.continuityDigests() }
        XCTAssertEqual(trust.authority, consumed.authority)
        XCTAssertNotEqual(trust.ledger, consumed.ledger)
        try first.sql("INSERT INTO consumption_outcomes_v1 VALUES(zeroblob(16),zeroblob(16),zeroblob(16),1,x'03')")
        let outcome = try a.read { try $0.continuityDigests() }
        XCTAssertNotEqual(consumed.ledger, outcome.ledger)
        try first.sql("UPDATE consumption_outcomes_v1 SET revision=2,event=x'04'")
        XCTAssertNotEqual(outcome.ledger, try a.read { try $0.continuityDigests().ledger })
    }

    func testContinuityDigestRejectsUncoveredTables() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try fixture.sql("CREATE TABLE future_authority(value BLOB) STRICT")
        XCTAssertThrowsError(try database.read { try $0.continuityDigests() }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .incompatibleStore)
        }
    }

    func testExplicitSetupPersistenceAndWriterRetirementAcrossReopen() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture))
        let database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }, try [record(1)])
        XCTAssertThrowsError(try reopened.write { try $0.append(record(2), writer: writer, expectedHead: 1) })
        XCTAssertThrowsError(try reopened.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try reopened.close()
        let recovered = try open(fixture)
        let fresh = try recovered.write { try $0.createEpoch(descriptor(4)) }
        try recovered.write { try $0.append(record(1, epoch: 4), writer: fresh, expectedHead: 0) }
        XCTAssertEqual(try recovered.read { try $0.epoch(id(4))?.head }, 1)
    }

    func testWrongScopeVersionAndReinitializeDoNotReplaceExistingData() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        _ = try database.write { try $0.createEpoch(descriptor()) }
        try database.close()
        for operation in [{ try self.open(fixture, mac: 9) }, { try self.open(fixture, account: 9) },
                          { try self.open(fixture, initialize: true) }] {
            XCTAssertThrowsError(try operation())
        }
        try fixture.sql("PRAGMA user_version=99")
        XCTAssertThrowsError(try open(fixture))
        try fixture.sql("PRAGMA user_version=12")
        let reopened = try open(fixture)
        XCTAssertNotNil(try reopened.read { try $0.epoch(id(3)) })
        try reopened.close()
        try fixture.sql("PRAGMA journal_mode=WAL")
        XCTAssertThrowsError(try open(fixture, mac: 9))
        XCTAssertEqual(try fixture.scalar("PRAGMA journal_mode"), "wal")
    }

    func testMalformedStoreAndMissingTableFailWithoutReset() throws {
        let malformed = try Fixture(), data = Data("not a SQLite database".utf8)
        try data.write(to: URL(fileURLWithPath: malformed.path))
        XCTAssertEqual(chmod(malformed.path, 0o600), 0)
        XCTAssertThrowsError(try open(malformed, initialize: true))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: malformed.path)), data)
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try database.close()
        try fixture.sql("DROP TABLE audit_records_v1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, initialize: true))
    }

    func testEscapedTransactionCannotAccessLaterTransactionOrClosedOwner() throws {
        let fixture = try Fixture()
        var database: JournalDatabase? = try open(fixture, initialize: true)
        let escaped = try database!.read { $0 }
        XCTAssertThrowsError(try escaped.epoch(id(3)))
        try database!.read { current in
            XCTAssertThrowsError(try escaped.epoch(id(3)))
            XCTAssertNil(try current.epoch(id(3)))
        }
        try database!.close()
        XCTAssertThrowsError(try escaped.epoch(id(3)))
        database = nil
        XCTAssertThrowsError(try escaped.epoch(id(3)))
    }

    func testReadOnlyAndNestedOperationsCannotAlterOuterTransaction() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        XCTAssertThrowsError(try database.read { try $0.createEpoch(descriptor()) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        try database.write { transaction in
            XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            XCTAssertThrowsError(try database.write { _ in })
            XCTAssertThrowsError(try database.close())
            _ = try transaction.createEpoch(descriptor())
        }
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testCallbackFailureRollsBackAndSwallowedMutationErrorCannotCommit() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertThrowsError(try $0.append(record(1), writer: writer, expectedHead: 1))
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) }
    }

    func testCaughtHeadMismatchRollsBackAndRetiresOwner() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertThrowsError(try $0.append(record(1), writer: writer, expectedHead: 0)) { XCTAssertEqual($0 as? AuditJournalError, .headMismatch) }
        })
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testEpochCreationRollbackRetiresOwnerAndUncommittedWriter() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        var escaped: AuditEpochWriter?
        XCTAssertThrowsError(try database.write {
            escaped = try $0.createEpoch(descriptor())
            throw Failure.injected
        })
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertNil(try reopened.read { try $0.epoch(id(3)) })
        _ = try reopened.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try reopened.write { try $0.append(record(1), writer: XCTUnwrap(escaped), expectedHead: 0) })
    }

    func testSQLiteAutomaticRollbackRetiresOwnerButStatementAbortAllowsRetry() throws {
        for action in ["ABORT", "ROLLBACK"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            try fixture.sql("CREATE TRIGGER fail_insert BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(\(action),'injected'); END")
            XCTAssertThrowsError(try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) })
            if action == "ABORT" { XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0) }
            else { XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) } }
            try database.close()
            try fixture.sql("DROP TRIGGER fail_insert")
            let reopened = try open(fixture)
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testLeaseFailureBeforeCommitRetiresOwnerEvenAfterPermissionsRestored() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertEqual(chmod(fixture.path, 0o644), 0)
        })
        XCTAssertEqual(chmod(fixture.path, 0o600), 0)
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testFailedOpenAndCloseReleaseLeaseAndProductionRequiresRoot() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture, initialize: true, busy: 60_001))
        let database = try open(fixture, initialize: true)
        XCTAssertThrowsError(try open(fixture)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try database.close(); try database.close()
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
        let next = try open(fixture)
        try next.close()
        if geteuid() != 0 {
            XCTAssertThrowsError(try JournalDatabase.open(directoryPath: fixture.directory, macID: id(1), accountID: id(2),
                recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: 10, busyMilliseconds: 100)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ query: String) throws { _ = try scalar(query) }
        func scalar(_ query: String) throws -> String? {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
            defer { sqlite3_finalize(stmt) }
            let rc = sqlite3_step(stmt)
            guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw Failure.injected }
            return rc == SQLITE_ROW ? sqlite3_column_text(stmt, 0).map { String(cString: $0) } : nil
        }
    }
}
