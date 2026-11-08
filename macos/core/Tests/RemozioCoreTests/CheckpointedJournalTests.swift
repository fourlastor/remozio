import Darwin
import Foundation
import SQLite3
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class CheckpointedJournalTests: XCTestCase {
    private enum Fault: Error { case injected }

    private func commandReservation() throws -> CommandSubmissionReservation {
        try CommandSubmissionReservation(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            submission: CapturedSubmission(id: Data(repeating: 8, count: 16), nonce: Data(repeating: 9, count: 32),
                callerBinding: Data(repeating: 10, count: 16)), captureDigest: Data(repeating: 11, count: 32))
    }
    private func installCommandReplay(_ fixture: Fixture) throws -> CheckpointedJournal {
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        try commits.write(epoch: fixture.epoch) { try $0.installCommandSubmissionReplay() }
        return commits
    }

    func testCommandReplayCheckpointAndReservationSurviveRestartWithoutCreatingAnAuditEvent() throws {
        let fixture = try Fixture(), commits = try installCommandReplay(fixture), value = try commandReservation()
        let before = try fixture.store.read().committed
        XCTAssertEqual(try commits.write(epoch: fixture.epoch) { try $0.reserveCommandSubmission(value) }, value)
        let after = try fixture.store.read().committed
        XCTAssertNotEqual(before.authorityDigest, after.authorityDigest)
        XCTAssertEqual(before.ledgerDigest, after.ledgerDigest)
        XCTAssertEqual(after.journalHead, 0)
        XCTAssertEqual(after.generation, before.generation + 1)
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(after))
        let restarted = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertEqual(try restarted.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }, value)
        XCTAssertThrowsError(try restarted.write(epoch: fixture.epoch, recoverRejectedBody: true) { try $0.reserveCommandSubmission(value) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
        }
        XCTAssertFalse(restarted.retired)
        XCTAssertEqual(try fixture.store.read().committed, after)
    }

    func testCommandReplayMalformedSubmissionFieldsAreRejectedBeforeCheckpointWork() throws {
        let fixture = try Fixture(), commits = try installCommandReplay(fixture), value = try commandReservation()
        let before = try fixture.store.read()
        for (field, expected) in [(0, 16), (1, 32), (2, 16)] {
            for length in [0, expected - 1, expected + 1] {
                let wrong = Data(repeating: 7, count: length)
                let binding = CapturedSubmission(id: field == 0 ? wrong : value.submission.id,
                    nonce: field == 1 ? wrong : value.submission.nonce,
                    callerBinding: field == 2 ? wrong : value.submission.callerBinding)
                XCTAssertThrowsError(try CommandSubmissionReservation(macID: value.macID, accountID: value.accountID,
                    submission: binding, captureDigest: value.captureDigest)) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .invalidConfiguration)
                }
            }
        }
        XCTAssertFalse(commits.retired)
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try commits.read { try $0.continuityDigests().authority }, before.committed.authorityDigest)
        XCTAssertEqual(try commits.write(epoch: fixture.epoch) { try $0.reserveCommandSubmission(value) }, value)
    }

    func testCommandReplayCommitFailuresNeverReleaseAResultAndReconcileTheReservation() throws {
        for finalize in [false, true] {
            let fixture = try Fixture(), commits = try installCommandReplay(fixture), value = try commandReservation()
            let before = try fixture.store.read().committed
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try fixture.sql("CREATE TRIGGER fail_replay BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try commits.write(epoch: fixture.epoch, recoverRejectedBody: true) { try $0.reserveCommandSubmission(value) })
            XCTAssertTrue(commits.retired)
            let pending = try fixture.store.read().pending
            XCTAssertEqual(pending != nil, finalize)
            try fixture.sql("DROP TRIGGER fail_replay")
            try fixture.reopen()
            let result = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
            if finalize { XCTAssertEqual(result, .finalized(try XCTUnwrap(pending))) }
            else { XCTAssertEqual(result, .unchanged(before)) }
            XCTAssertEqual(try fixture.journal.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }, finalize ? value : nil)
        }
    }

    func testCommandReplaySchemaMigrationReconcilesAfterPrepareOrFinalizeFailure() throws {
        for finalize in [false, true] {
            let fixture = try Fixture(), commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
            let before = try fixture.store.read().committed
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try fixture.sql("CREATE TRIGGER fail_replay_schema BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) { try $0.installCommandSubmissionReplay() })
            XCTAssertTrue(commits.retired)
            let pending = try fixture.store.read().pending
            try fixture.sql("DROP TRIGGER fail_replay_schema")
            try fixture.reopen()
            let result = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
            if finalize {
                XCTAssertEqual(result, .finalized(try XCTUnwrap(pending)))
                XCTAssertNil(try fixture.journal.read { try $0.commandSubmissionReservation(submissionID: Data(repeating: 8, count: 16)) })
            } else {
                XCTAssertEqual(result, .unchanged(before))
                XCTAssertThrowsError(try fixture.journal.read { try $0.commandSubmissionReservation(submissionID: Data(repeating: 8, count: 16)) }) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .unavailable)
                }
            }
            XCTAssertEqual(try fixture.journal.read { try $0.codePolicy()?.policy }, try codePolicy())
        }
    }

    func testMissingCommandReplayReservationRequiresRepairInsteadOfHistoryRecovery() throws {
        let fixture = try Fixture(), commits = try installCommandReplay(fixture), value = try commandReservation()
        _ = try commits.write(epoch: fixture.epoch) { try $0.reserveCommandSubmission(value) }
        try fixture.sql("DELETE FROM command_submissions_v1", journal: true)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .repairRequired)
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
        XCTAssertThrowsError(try recoverHistory(fixture)) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
        XCTAssertThrowsError(try fixture.store.historyRecovery()) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
    }

    func testAuditHistoryRecoveryPreservesCommandReplayReservationsAndSchema() throws {
        let fixture = try Fixture(), commits = try installCommandReplay(fixture), value = try commandReservation()
        _ = try commits.write(epoch: fixture.epoch) { try $0.reserveCommandSubmission(value) }
        let before = try fixture.store.read().committed
        try fixture.journal.write { try fixture.append($0) }
        let recovered = try recoverHistory(fixture)
        XCTAssertNotEqual(before.journalEpoch, recovered.journalEpoch)
        XCTAssertEqual(before.authorityDigest, recovered.authorityDigest)
        XCTAssertEqual(try fixture.journal.read { try $0.commandSubmissionReservation(submissionID: value.submission.id) }, value)
        XCTAssertNotNil(try fixture.journal.read { try $0.historyRecovery(epoch: recovered.journalEpoch) })
        try fixture.reopen()
        XCTAssertEqual(try recoverHistory(fixture), recovered)
        let restarted = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try restarted.write(epoch: recovered.journalEpoch, recoverRejectedBody: true) { try $0.reserveCommandSubmission(value) }) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
        }
        XCTAssertFalse(restarted.retired)
        XCTAssertEqual(try restarted.read { try $0.codePolicy()?.policy }, try codePolicy())
    }

    func testRejectedBodyCanContinueOnlyAfterVerifiedRollback() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch, recoverRejectedBody: true) { transaction in
            try fixture.append(transaction)
            throw Fault.injected
        })
        XCTAssertFalse(commits.retired)
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try commits.read { try $0.epoch(fixture.epoch)?.head }, 0)
        try commits.write(epoch: fixture.epoch, recoverRejectedBody: true) { try fixture.append($0) }
        XCTAssertEqual(try fixture.store.read().committed.journalHead, 1)
    }

    func testRequestModeDoesNotRecoverAfterCheckpointPreparationOrFinalizationFailure() throws {
        for finalize in [false, true] {
            let fixture = try Fixture()
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try fixture.sql("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            XCTAssertThrowsError(try commits.write(epoch: fixture.epoch, recoverRejectedBody: true) { try fixture.append($0) })
            XCTAssertTrue(commits.retired)
            XCTAssertThrowsError(try commits.read { _ in XCTFail("retired read ran") })
        }
    }

    func testCheckpointReadRejectsChangedBoundaryBeforeCallingReader() throws {
        let fixture = try Fixture(), commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        try fixture.journal.write { try fixture.append($0) }
        XCTAssertThrowsError(try commits.read { _ in XCTFail("mismatched read ran") })
        XCTAssertTrue(commits.retired)
    }

    func testResultReturnsAfterBothStoresCommitAndSurvivesReopen() throws {
        let fixture = try Fixture()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let result = try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            return "committed"
        }
        XCTAssertEqual(result, "committed")
        let state = try fixture.store.read()
        XCTAssertNil(state.pending)
        XCTAssertEqual(state.committed.generation, 2)
        XCTAssertEqual(state.committed.journalHead, 1)
        XCTAssertEqual(state.committed, try fixture.observed(generation: 2))
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), state)
        XCTAssertEqual(state.committed, try fixture.observed(generation: 2))
    }

    func testPreparationFailureRollsBackJournalAndRetiresCoordinator() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.sql("CREATE TRIGGER fail_prepare BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0); return "must not escape" })
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { _ in XCTFail("retired callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .retired)
        }
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
    }

    func testFinalizationFailureRetainsCommittedCandidateAndBothBoundaries() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0); return "must not escape" })
        let prepared = try fixture.store.read()
        XCTAssertEqual(prepared.committed, before.committed)
        XCTAssertEqual(prepared.pending, try fixture.observed(generation: 2))
        XCTAssertFalse(prepared.recoveryRequired)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), prepared)
        XCTAssertEqual(prepared.pending, try fixture.observed(generation: 2))
        let restarted = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try restarted.write(epoch: fixture.epoch) { _ in XCTFail("unresolved callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .unresolvedPreparation)
        }
    }

    func testCallbackFailureLeavesOldBoundaryAndMismatchDoesNotRunCallback() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            throw Fault.injected
        })
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
        try fixture.journal.write { try fixture.append($0) }
        let mismatched = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try mismatched.write(epoch: fixture.epoch) { _ in XCTFail("mismatched callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .boundaryMismatch)
        }
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testJournalRollbackAfterPreparationRetainsOldBoundaryForRecovery() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            // A swallowed mutation error still poisons the enclosing journal transaction.
            XCTAssertThrowsError(try transaction.append(Data([0]), writer: fixture.writer, expectedHead: 1))
            return "must not escape"
        })
        let prepared = try fixture.store.read()
        XCTAssertNotNil(prepared.pending)
        XCTAssertEqual(prepared.pending?.journalHead, 1)
        XCTAssertEqual(prepared.committed, before.committed)
        XCTAssertFalse(prepared.recoveryRequired)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), prepared)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
    }

    func testRecoveryFinalizesCommittedCandidateAndIsIdempotent() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0) })
        try fixture.reopen()
        let candidate = try XCTUnwrap(fixture.store.read().pending)
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .finalized(candidate))
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(candidate))
        XCTAssertNil(try fixture.store.read().pending)
        XCTAssertEqual(try fixture.observed(generation: 2), candidate)
    }

    func testRecoveryDiscardsPreparationWhenJournalRolledBack() throws {
        let fixture = try Fixture(), before = try fixture.store.read().committed
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            XCTAssertThrowsError(try transaction.append(Data([0]), writer: fixture.writer, expectedHead: 1))
        })
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .discarded(before))
        XCTAssertEqual(try fixture.observed(generation: 1), before)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(before))
    }

    func testRecoveryPreservesHistoryMismatchWithoutRequiringAdministratorRepair() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.journal.write { try fixture.append($0) }
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .historyDiscontinuity(before))
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.head }, 1)
    }

    func testRecoveryFailurePreservesPreparationAndAllowsStorageRetry() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0) })
        let before = try fixture.store.read()
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store))
        XCTAssertEqual(try fixture.store.read(), before)
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store),
                       .finalized(try XCTUnwrap(before.pending)))
    }

    func testRecoveryPersistsTrustMismatchAndMarkerFailureDoesNotHideIt() throws {
        let fixture = try Fixture()
        try fixture.sql("INSERT INTO approval_enrollments_v1 VALUES(zeroblob(16),zeroblob(16),0,x'01')", journal: true)
        try fixture.sql("CREATE TRIGGER fail_marker BEFORE UPDATE ON continuity_v1 WHEN NEW.repair=1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store))
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_marker")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .repairRequired)
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
        try fixture.sql("DELETE FROM approval_enrollments_v1", journal: true)
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .repairRequired)
    }

    func testRecoveryDoesNotTurnClosedJournalIntoRepairMarker() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.journal.close()
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
        XCTAssertEqual(try fixture.store.read(), before)
    }

    func testStartupWithholdsWriterUntilCheckpointedRecoveryCompletes() throws {
        let fixture = try Fixture()
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        XCTAssertThrowsError(try startup.completedWriter())
        let next = Data(repeating: 9, count: 16)
        guard case .recovering = try startup.start(descriptor: fixture.descriptor(next)) else { return XCTFail("startup did not begin") }
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertEqual(try fixture.store.read().committed.journalEpoch, next)
        guard case .complete = try startup.advance() else { return XCTFail("empty recovery did not finish") }
        XCTAssertEqual(try startup.completedWriter().epoch, next)
        XCTAssertThrowsError(try startup.start(descriptor: fixture.descriptor(Data(repeating: 10, count: 16))))
        try fixture.reopen()
        XCTAssertNil(try fixture.store.read().pending)
        XCTAssertEqual(try fixture.store.read().committed.journalEpoch, next)
    }

    func testStartupFailureNeverReleasesWriterAndCanRecoverAfterReopen() throws {
        let fixture = try Fixture()
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try startup.start(descriptor: fixture.descriptor(Data(repeating: 9, count: 16))))
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertThrowsError(try startup.advance())
        try fixture.sql("DROP TRIGGER fail_finalize")
        try fixture.reopen()
        let retry = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        let next = Data(repeating: 10, count: 16)
        guard case .recovering = try retry.start(descriptor: fixture.descriptor(next)) else { return XCTFail("retry did not begin") }
        guard case .complete = try retry.advance() else { return XCTFail("retry did not complete") }
        XCTAssertEqual(try retry.completedWriter().epoch, next)
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testStartupPreservesHistoryDiscontinuityWithoutCreatingEpoch() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        let next = Data(repeating: 9, count: 16)
        guard case .historyDiscontinuity = try startup.start(descriptor: fixture.descriptor(next)) else {
            return XCTFail("history loss was not surfaced")
        }
        XCTAssertNil(try fixture.journal.read { try $0.epoch(next) })
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testStorageOwnerHoldsAndReleasesBothLeases() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        var storage: AuthorityStorage? = try AuthorityStorage(openJournal: { try fixture.openJournal() },
            openContinuity: { try fixture.openStore(excludingDirectory: $0) })
        XCTAssertNotNil(storage)
        XCTAssertThrowsError(try fixture.openJournal())
        XCTAssertThrowsError(try fixture.openStore())
        storage = nil
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    func testStorageRejectsNestedDirectoryIdentitiesAndReleasesBothLeases() throws {
        for useCaseAlias in [false, true] {
            let fixture = try Fixture()
            try fixture.journal.close(); fixture.store.close()
            try FileManager.default.moveItem(at: fixture.root.appendingPathComponent("continuity"),
                to: fixture.root.appendingPathComponent("journal/continuity"))
            let directory = useCaseAlias ? "JOURNAL/continuity" : "journal/continuity"
            if useCaseAlias && !FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent(directory).path) {
                continue // The non-alias case still exercises containment on case-sensitive volumes.
            }
            XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
                openContinuity: { try fixture.openStore(directory: directory, excludingDirectory: $0) })) {
                XCTAssertTrue($0 is AuthorityServiceConfigurationError)
            }
            let journal = try fixture.openJournal(), continuity = try fixture.openStore(directory: directory)
            try journal.close(); continuity.close()
        }
    }

    func testAliasedStoreIsConfigurationFailureBeforeLockContention() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        for directory in ["journal", "JOURNAL"] {
            if !FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent(directory).path) { continue }
            XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
                openContinuity: { try fixture.openStore(directory: directory, excludingDirectory: $0) })) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
                XCTAssertEqual(AuthorityStartupFailure(error: $0), .configurationFailure)
            }
            let reopened = try fixture.openJournal()
            try reopened.close()
        }
        let competing = try fixture.openStore()
        defer { competing.close() }
        XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
            openContinuity: { try fixture.openStore(excludingDirectory: $0) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
            XCTAssertEqual(AuthorityStartupFailure(error: $0), .temporaryStorageFailure)
        }
        let reopened = try fixture.openJournal()
        try reopened.close()
    }

    func testFailedContinuityOpenReleasesJournalAndPreservesError() throws {
        let fixture = try Fixture()
        try fixture.journal.close()
        XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() }, openContinuity: { _ in
            throw Fault.injected
        })) { XCTAssertTrue($0 is Fault) }
        fixture.journal = try fixture.openJournal()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    private func requestStartupOwner(_ fixture: Fixture) throws -> AuthorityJournal {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        }
        try fixture.journal.close(); fixture.store.close()
        return try AuthorityJournal(storage: fixture.openTransferredStorage())
    }

    func testStartupCreatesFreshEpochAndEnablesCheckpointedRequestsOnlyAfterRecovery() throws {
        let fixture = try Fixture(), owner = try requestStartupOwner(fixture), clock = try AuthorityClock()
        XCTAssertThrowsError(try owner.withRequests { _ in true })
        try owner.prepareRequests(clockEpoch: clock.epoch, maximumPayloadBytes: 16384)
        XCTAssertThrowsError(try owner.prepareRequests(clockEpoch: clock.epoch, maximumPayloadBytes: 16384))
        let now = try clock.now()
        let draft = try ApprovalRequestDraft(contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            requiredFeatures: [], capture: Data([0xa0]), actions: [CapturedAction(choice: .execute, scope: .currentRequest)],
            firstObservedAt: now, deadlineMilliseconds: now.milliseconds + 10000, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 11000)
        _ = try owner.withRequests { try $0.admitFixture(draft, now: now, receiptTimeMs: nil) }
        XCTAssertThrowsError(try fixture.openJournal())
        XCTAssertThrowsError(try fixture.openStore())
        try owner.close()
        try fixture.reopen()
        let checkpoint = try fixture.store.read().committed
        XCTAssertNotEqual(checkpoint.journalEpoch, fixture.epoch)
        let epoch = try XCTUnwrap(fixture.journal.read { try $0.epoch(checkpoint.journalEpoch) })
        XCTAssertEqual(epoch.descriptor.cause, .restart)
        XCTAssertEqual(epoch.descriptor.previousEpoch, fixture.epoch)
        XCTAssertEqual(epoch.descriptor.previousSequence, 0)
        XCTAssertEqual(epoch.descriptor.generation, checkpoint.currentAuthorityGeneration)
        XCTAssertEqual(epoch.head, 1)
        XCTAssertNil(try fixture.store.read().pending)
    }

    func testRequestAdmissionReservesCarrierSpaceWithinConfiguredPayloadBudget() throws {
        let fixture = try Fixture(), owner = try requestStartupOwner(fixture), clock = try AuthorityClock()
        let maximum = 1024, bodyMaximum = maximum - ApprovalMessage.overheadBytes
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 32, maxItems: 262_144)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let actions = [CapturedAction(choice: .execute, scope: .currentRequest)]
        func captureForBody(_ size: Int) throws -> Data {
            for padding in 0..<size {
                let capture = try DeterministicCBOR.encode(.map([0: .bytes(Data(count: padding))]), limits: limits)
                let payload = try IssuedRequestPayload(contract: contract, macID: Data(repeating: 1, count: 16),
                    accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16),
                    challenge: Data(repeating: 4, count: 32), requiredFeatures: [], createdUnixMilliseconds: 1000,
                    expiresUnixMilliseconds: 11000, canonicalCapture: capture, permittedActions: actions,
                    bodyLimits: limits, captureLimits: limits)
                if try payload.encode(limits: limits).count == size { return capture }
            }
            throw Fault.injected
        }
        let tooLarge = try captureForBody(maximum), accepted = try captureForBody(bodyMaximum)
        try owner.prepareRequests(clockEpoch: clock.epoch, maximumPayloadBytes: maximum)
        let now = try clock.now()
        func draft(_ capture: Data) throws -> ApprovalRequestDraft {
            try ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: capture, actions: actions,
                firstObservedAt: now, deadlineMilliseconds: now.milliseconds + 10000,
                createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 11000)
        }
        let oversized = try draft(tooLarge), fitting = try draft(accepted)
        XCTAssertThrowsError(try owner.withRequests { try $0.admitFixture(oversized, now: now, receiptTimeMs: nil) })
        let payload = try owner.withRequests { try $0.admitFixture(fitting, now: now, receiptTimeMs: nil) }
        let body = try payload.encode(limits: limits)
        XCTAssertEqual(body.count, bodyMaximum)
        let carrier = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest,
            body: body, signature: Data(count: 64)).encode(maximumBodyBytes: bodyMaximum)
        XCTAssertLessThanOrEqual(carrier.count, maximum)
        try owner.close()
    }

    func testStartupFailureClosesBothStoresAndPreservesPreparedEpochForRecovery() throws {
        let fixture = try Fixture(), owner = try requestStartupOwner(fixture), clock = try AuthorityClock()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.prepareRequests(clockEpoch: clock.epoch, maximumPayloadBytes: 16384))
        XCTAssertThrowsError(try owner.withRequests { _ in XCTFail("request owner escaped failed startup") })
        try fixture.reopen()
        let prepared = try fixture.store.read()
        XCTAssertNotNil(prepared.pending)
        XCTAssertFalse(prepared.recoveryRequired)
        XCTAssertNotEqual(prepared.pending?.journalEpoch, fixture.epoch)
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
        XCTAssertNil(try fixture.store.read().pending)
    }

    func testPairedAuthorityOwnerChecksContinuityAndClosesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
        XCTAssertEqual(try owner.read { try $0.epoch(Data(repeating: 3, count: 16))?.head }, 0)
        XCTAssertThrowsError(try owner.write { _ in XCTFail("raw write callback ran") }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        try fixture.sql("UPDATE continuity_v1 SET repair=1")
        XCTAssertThrowsError(try owner.read { _ in XCTFail("read callback ran after repair marker") })
        try owner.close()
        try fixture.reopen()
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
    }

    func testRejectedReentrantClosePreservesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
        let head = try owner.read { transaction in
            XCTAssertThrowsError(try owner.close()) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
            return try transaction.epoch(Data(repeating: 3, count: 16))?.head
        }
        XCTAssertEqual(head, 0)
        XCTAssertThrowsError(try fixture.openJournal()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertThrowsError(try fixture.openStore()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertEqual(try owner.read { try $0.epoch(Data(repeating: 3, count: 16))?.head }, 0)
        try owner.close()
        try owner.close()
        try fixture.reopen()
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testPairedAuthorityOwnerRejectsHistoryLossAndReleasesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try fixture.journal.close(); fixture.store.close()
        XCTAssertThrowsError(try AuthorityJournal(storage: fixture.openTransferredStorage())) {
            guard case AuthorityStorageStartupError.historyRecoveryRequired = $0 else { return XCTFail("wrong startup failure") }
        }
        try fixture.reopen()
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testExpiryServicePreparesRequestsWithTheCallerClockEpoch() throws {
        let fixture = try Fixture()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) {
            _ = try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
            return try $0.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ",
                identifier: "dev.sebastiano.remozio.macos.transport", installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: 3, count: 20), active: true)]), expectedRevision: nil)
        }
        try fixture.journal.close(); fixture.store.close()
        let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
        let configuration = try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: fixture.root.appendingPathComponent("journal").path, serviceName: "dev.remozio.authority.test",
            teamID: "ABCDEFGHIJ", transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: 3, count: 20)],
            transportUID: 501, continuityDirectory: fixture.root.appendingPathComponent("continuity").path)
        let clock = try AuthorityClock()
        let service = try AuthorityService(configuration: configuration, journal: owner, expiryClock: { try clock.now() },
            reconcileExpired: { _ in }, validateSelf: { _ in })
        // This is the operation the first maintenance tick performs, without activating a privileged listener.
        XCTAssertTrue(try owner.withRequests { try $0.expirePending(now: clock.now(), receiptTimeMs: nil).isEmpty })
        XCTAssertTrue(try owner.withRequests { try $0.expirePending(now: clock.now(), receiptTimeMs: nil).isEmpty })
        try service.close()
        try fixture.reopen()
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testServiceClosesPairedStoresOnShutdownAndConstructionFailure() throws {
        for wrongScope in [false, true] {
            let fixture = try Fixture()
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            _ = try commits.write(epoch: fixture.epoch) {
                _ = try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
                return try $0.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ",
                    identifier: "dev.sebastiano.remozio.macos.transport", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: Data(repeating: 3, count: 20), active: true)]), expectedRevision: nil)
            }
            try fixture.journal.close(); fixture.store.close()
            let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
            let configuration = try AuthorityServiceConfiguration(macID: Data(repeating: wrongScope ? 9 : 1, count: 16),
                accountID: Data(repeating: 2, count: 16), journalDirectory: fixture.root.appendingPathComponent("journal").path,
                serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ", transportIdentifier: "dev.sebastiano.remozio.macos.transport",
                transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501,
                continuityDirectory: fixture.root.appendingPathComponent("continuity").path)
            if wrongScope {
                XCTAssertThrowsError(try AuthorityService(configuration: configuration, journal: owner, validateSelf: { _ in }))
            } else {
                let service = try AuthorityService(configuration: configuration, journal: owner, validateSelf: { _ in })
                XCTAssertThrowsError(try fixture.openJournal())
                XCTAssertThrowsError(try fixture.openStore())
                try service.close()
            }
            XCTAssertThrowsError(try owner.read { _ in 1 })
            try fixture.reopen()
            XCTAssertFalse(try fixture.store.read().recoveryRequired)
        }
    }

    func testStartupRetryReleasesJournalWhileContinuityIsBusy() throws {
        let fixture = try Fixture()
        try fixture.journal.close()
        let anchor = fixture.root.path, limits = fixture.limits
        let waiting = expectation(description: "continuity contention")
        waiting.assertForOverFulfill = false
        let running = expectation(description: "paired storage acquired")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 1000, maximumRetryMilliseconds: 1000, open: {
            let owner = try AuthorityJournal(storage: Fixture.openTransferredStorage(anchor: anchor, limits: limits))
            return { try owner.close() }
        }, report: {
            if case .waiting = $0 { waiting.fulfill() }
            if $0 == .running { running.fulfill() }
        })
        defer { try? runner.close() }
        try runner.start()
        wait(for: [waiting], timeout: 3)
        let availableJournal = try fixture.openJournal()
        try availableJournal.close()
        fixture.store.close()
        wait(for: [running], timeout: 5)
        XCTAssertThrowsError(try fixture.openJournal()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertThrowsError(try fixture.openStore()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        try runner.close()
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    func testTrustGenerationChangesOnlyForAuthorityStateAndBindsFreshEpoch() throws {
        let fixture = try Fixture()
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        _ = try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        }
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        try commits.write(epoch: fixture.epoch) { _ in () }
        try commits.write(epoch: fixture.epoch) { try fixture.append($0) }
        XCTAssertEqual(try fixture.store.read().committed.generation, 4)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.descriptor.generation }, 7)
        let next = Data(repeating: 9, count: 16)
        let stale = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        XCTAssertThrowsError(try stale.start(descriptor: fixture.descriptor(next))) {
            guard case JournalStartupRecovery.Failure.invalidEpoch = $0 else { return XCTFail("wrong error") }
        }
        XCTAssertNil(try fixture.journal.read { try $0.epoch(next) })
        let current = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        guard case .recovering = try current.start(descriptor: fixture.descriptor(next, generation: 8)) else {
            return XCTFail("startup did not begin")
        }
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(next)?.descriptor.generation }, 8)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        guard case .complete = try current.advance() else { return XCTFail("recovery did not complete") }
    }

    func testTrustGenerationRecoveryFinalizesOnlyOnce() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        })
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 7)
        XCTAssertEqual(try fixture.store.read().pending?.authorityGeneration, 8)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        let recovered = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        try recovered.write(epoch: fixture.epoch) { _ in () }
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
    }

    func testLegacyPreparedBoundaryAndInterruptedUpgradeRemainRecoverable() throws {
        let fixture = try Fixture(authorityGeneration: nil)
        let legacy = try fixture.store.read().committed
        XCTAssertNil(legacy.authorityGeneration)
        let pending = try fixture.observed(generation: 2, authorityGeneration: nil)
        try fixture.store.prepare(expected: legacy, candidate: pending)
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .finalized(pending))
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) { _ in () })
        XCTAssertNil(try fixture.store.read().committed.authorityGeneration)
        XCTAssertEqual(try fixture.store.read().pending?.authorityGeneration, 2)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 2)
        XCTAssertEqual(try fixture.store.read().committed.generation, 3)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.descriptor.generation }, 7)
    }

    func testTrustGenerationExhaustionRollsBackTrustButAllowsAuditWrites() throws {
        let fixture = try Fixture(authorityGeneration: .max)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        try commits.write(epoch: fixture.epoch) { try fixture.append($0) }
        let before = try fixture.store.read()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        })
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
        XCTAssertThrowsError(try fixture.journal.read { try $0.approvalTrustSnapshot() }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
    }

    func testCodePolicyMigrationCommitsWithAuthorityGenerationAndLeavesLedgerUnchanged() throws {
        let fixture = try Fixture(), before = try fixture.store.read().committed
        XCTAssertNil(try fixture.journal.read { try $0.codePolicy() })
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let initial = try coordinator.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        let installed = try fixture.store.read().committed
        XCTAssertNotEqual(installed.authorityDigest, before.authorityDigest)
        XCTAssertEqual(installed.authorityGeneration, 8)
        XCTAssertEqual(installed.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(installed.journalHead, before.journalHead)
        let noOp = try coordinator.write(epoch: fixture.epoch) { try $0.installCodePolicy(initial.policy, expectedRevision: initial.revision) }
        XCTAssertEqual(noOp, initial)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        XCTAssertEqual(try fixture.store.read().committed.authorityDigest, installed.authorityDigest)
        let inactive = try coordinator.write(epoch: fixture.epoch) {
            try $0.installCodePolicy(codePolicy(installed: 4, minimum: 3, active: false), expectedRevision: initial.revision)
        }
        XCTAssertNotEqual(inactive.revision, initial.revision)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 9)
        try fixture.reopen()
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, inactive)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store),
            .unchanged(try fixture.store.read().committed))
        let next = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let active = try next.write(epoch: fixture.epoch) {
            try $0.installCodePolicy(codePolicy(installed: 5, minimum: 3), expectedRevision: inactive.revision)
        }
        XCTAssertTrue(active.policy.entries[0].active)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 10)
    }

    func testCodePolicyStaleRevisionAndRollbackCannotCommitEvenWhenCaught() throws {
        let fixture = try Fixture()
        let initial = try fixture.journal.write { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        for revision in [nil, UUID()] {
            XCTAssertThrowsError(try fixture.journal.write { try $0.installCodePolicy(initial.policy, expectedRevision: revision) }) {
                XCTAssertEqual($0 as? AuthorityCodePolicyError, .staleRevision)
            }
        }
        XCTAssertThrowsError(try fixture.journal.write { transaction in
            _ = try transaction.installCodePolicy(codePolicy(installed: 5, minimum: 3), expectedRevision: initial.revision)
            XCTAssertThrowsError(try transaction.installCodePolicy(initial.policy, expectedRevision: initial.revision))
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, initial)
        XCTAssertThrowsError(try fixture.journal.write {
            try $0.installCodePolicy(codePolicy(installed: 3, minimum: 2), expectedRevision: initial.revision)
        }) { XCTAssertEqual($0 as? AuthorityCodePolicyError, .rollback) }
        XCTAssertThrowsError(try fixture.journal.read { try $0.installCodePolicy(initial.policy, expectedRevision: initial.revision) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let escaped = try fixture.journal.read { $0 }
        XCTAssertThrowsError(try escaped.codePolicy()) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, initial)
    }

    func testCodePolicyMigrationPreparationFailureRestoresSchema12() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.sql("CREATE TRIGGER fail_prepare BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) })
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertNil(try fixture.journal.read { try $0.codePolicy() })
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
    }

    func testCodePolicyMigrationRollbackAfterPreparationDiscardsCandidate() throws {
        let fixture = try Fixture(), before = try fixture.store.read().committed
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            _ = try transaction.installCodePolicy(codePolicy(), expectedRevision: nil)
            XCTAssertThrowsError(try transaction.installCodePolicy(codePolicy(), expectedRevision: nil))
        })
        let candidate = try XCTUnwrap(fixture.store.read().pending)
        XCTAssertNotEqual(candidate.authorityDigest, before.authorityDigest)
        XCTAssertEqual(candidate.ledgerDigest, before.ledgerDigest)
        try fixture.reopen()
        XCTAssertNil(try fixture.journal.read { try $0.codePolicy() })
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .discarded(before))
    }

    func testCodePolicyMigrationFinalizationFailureRecoversSchema13Once() throws {
        let fixture = try Fixture(), before = try fixture.store.read().committed
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) })
        let candidate = try XCTUnwrap(fixture.store.read().pending)
        XCTAssertEqual(candidate.authorityGeneration, 8)
        XCTAssertEqual(candidate.ledgerDigest, before.ledgerDigest)
        try fixture.reopen()
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy()?.policy }, try codePolicy())
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .finalized(candidate))
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(candidate))
    }

    func testMissingSchema13PolicyCannotBeTreatedAsNewInstallation() throws {
        let fixture = try Fixture()
        _ = try fixture.journal.write { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        try fixture.sql("DELETE FROM authority_code_policy_v1", journal: true)
        try fixture.reopen()
        XCTAssertThrowsError(try fixture.journal.write { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }) {
            XCTAssertEqual($0 as? AuthorityCodePolicyError, .corruptData)
        }
    }

    func testLegacyCodePolicyUpgradePreservesUnchangedRoleRevisionAcrossReopen() throws {
        let fixture = try Fixture()
        let legacyPolicy = try legacyCodePolicy()
        let initial = try fixture.journal.write { try $0.installCodePolicy(legacyPolicy, expectedRevision: nil) }
        let legacyBytes = try initial.policy.bytes.map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE authority_code_policy_v1 SET policy=x'\(legacyBytes)'", journal: true)
        try fixture.reopen()
        let legacy = try XCTUnwrap(fixture.journal.read { try $0.codePolicy() })
        XCTAssertEqual(legacy.roleRevisions[.authority], initial.revision)
        let unrelated = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.transport",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
        let extended = try AuthorityCodePolicy(entries: legacy.policy.entries + [unrelated])
        let upgraded = try fixture.journal.write { try $0.installCodePolicy(extended, expectedRevision: legacy.revision) }
        XCTAssertEqual(upgraded.roleRevisions[.authority], legacy.roleRevisions[.authority])
        XCTAssertNotNil(upgraded.roleRevisions[.transport])
        try fixture.reopen()
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, upgraded)
        let noOp = try fixture.journal.write { try $0.installCodePolicy(extended, expectedRevision: upgraded.revision) }
        XCTAssertEqual(noOp, upgraded)
    }

    private func legacyCodePolicy() throws -> AuthorityCodePolicy {
        let limits = try CBORLimits(maxBytes: 8192, maxDepth: 4, maxItems: 256)
        guard case .map(var fields) = try DeterministicCBOR.decode(codePolicy().bytes, limits: limits) else {
            throw AuthorityCodePolicyError.corruptData
        }
        fields[0] = .unsigned(1)
        return try AuthorityCodePolicy.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
    }

    func testCommandHelperCatalogUpgradePreservesCheckpointAndRoleFloorsAcrossReopen() throws {
        let fixture = try Fixture()
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let legacy = try legacyCodePolicy()
        let initial = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(legacy, expectedRevision: nil) }
        let before = try fixture.store.read().committed
        let child = try AuthorityCodeEntry(role: .commandChild, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.command-child",
            installedGeneration: 5, minimumGeneration: 4, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
        let monitor = try AuthorityCodeEntry(role: .commandMonitor, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.command-monitor",
            installedGeneration: 3, minimumGeneration: 2, codeDirectoryHash: Data(repeating: 4, count: 20), active: false)
        let policy = try AuthorityCodePolicy(entries: initial.policy.entries + [child, monitor])
        let upgraded = try commits.write(epoch: fixture.epoch) {
            try $0.installCodePolicy(policy, expectedRevision: initial.revision)
        }
        let after = try fixture.store.read().committed
        XCTAssertEqual(upgraded.policy.formatVersion, 3)
        XCTAssertEqual(upgraded.roleRevisions[.authority], initial.roleRevisions[.authority])
        XCTAssertNotNil(upgraded.roleRevisions[.commandChild])
        XCTAssertNotNil(upgraded.roleRevisions[.commandMonitor])
        XCTAssertEqual(upgraded.policy.entries.first { $0.role == .authority }, initial.policy.entries.first)
        XCTAssertEqual(upgraded.policy.entries.first { $0.role == .commandChild }, child)
        XCTAssertEqual(upgraded.policy.entries.first { $0.role == .commandMonitor }, monitor)
        XCTAssertEqual(after.authorityGeneration, try XCTUnwrap(before.authorityGeneration) + 1)
        XCTAssertNotEqual(after.authorityDigest, before.authorityDigest)
        XCTAssertEqual(after.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(after.journalHead, before.journalHead)
        try fixture.reopen()
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, upgraded)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(after))
        XCTAssertThrowsError(try fixture.journal.write {
            try $0.installCodePolicy(legacy, expectedRevision: upgraded.revision)
        }) { XCTAssertEqual($0 as? AuthorityCodePolicyError, .rollback) }
        XCTAssertEqual(try fixture.journal.read { try $0.codePolicy() }, upgraded)
        XCTAssertEqual(try fixture.store.read().committed, after)
    }

    private func recoveringOwner(_ fixture: Fixture,
                                 validateSelf: (JournalTransaction) throws -> Void = { transaction in
                                     let entry = try XCTUnwrap(transaction.codePolicy()?.policy.entries.first { $0.role == .authority })
                                     _ = try AuthoritySelfValidation.requirement(for: entry)
                                 }) throws -> AuthorityJournal {
        try fixture.journal.close(); fixture.store.close()
        return try AuthorityJournal(recovering: fixture.openTransferredStorage(), macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), validateSelf: validateSelf)
    }

    func testRecoveringOwnerValidatesBeforeAnyRecoveryWriteAndReleasesStoresOnFailure() throws {
        for prepared in [false, true] {
            let fixture = try Fixture()
            if prepared { _ = try prepareLostHistory(fixture) }
            else { try fixture.journal.write { try fixture.append($0) } }
            let before = try fixture.journal.read { try $0.continuityDigests() }
            let intent = try fixture.store.historyRecovery()
            XCTAssertThrowsError(try recoveringOwner(fixture, validateSelf: { _ in throw Fault.injected })) {
                guard case Fault.injected = $0 else { return XCTFail("wrong validation failure") }
            }
            try fixture.reopen()
            XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests() }, before)
            XCTAssertEqual(try fixture.store.historyRecovery(), intent)
            XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        }
    }

    func testRecoveringOwnerRequiresRealSelfValidationByDefault() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.journal.close(); fixture.store.close()
        // The unit-test process cannot satisfy this fixture's signed authority requirement.
        XCTAssertThrowsError(try AuthorityJournal(recovering: fixture.openTransferredStorage(),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16)))
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        XCTAssertNil(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch) })
    }

    func testRecoveringOwnerKeepsRequestsClosedUntilFreshStartupEpoch() throws {
        let fixture = try Fixture()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        }
        let intent = try prepareLostHistory(fixture)
        let owner = try recoveringOwner(fixture)
        XCTAssertThrowsError(try owner.withRequests { _ in XCTFail("request admission escaped history recovery") })
        XCTAssertEqual(try owner.read { try $0.epoch(intent.recoveryEpoch)?.head }, 1)
        let clock = try AuthorityClock()
        try owner.prepareRequests(clockEpoch: clock.epoch, maximumPayloadBytes: 16384)
        XCTAssertTrue(try owner.withRequests { try $0.expirePending(now: clock.now(), receiptTimeMs: nil).isEmpty })
        try owner.close()
        try fixture.reopen()
        let current = try fixture.store.read().committed
        XCTAssertNotEqual(current.journalEpoch, intent.recoveryEpoch)
        XCTAssertNotEqual(current.journalEpoch, fixture.epoch)
        let descriptor = try XCTUnwrap(fixture.journal.read { try $0.epoch(current.journalEpoch)?.descriptor })
        XCTAssertEqual(descriptor.cause, .restart)
        XCTAssertEqual(descriptor.previousEpoch, intent.recoveryEpoch)
        XCTAssertNil(try fixture.store.historyRecovery())
    }

    func testServiceRecoversHistoryThenPreparesRequestOwnerBeforeMaintenance() throws {
        let fixture = try Fixture()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let authority = try XCTUnwrap(codePolicy().entries.first)
        _ = try commits.write(epoch: fixture.epoch) {
            _ = try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
            return try $0.installCodePolicy(AuthorityCodePolicy(entries: [authority, AuthorityCodeEntry(role: .transport,
                teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.transport", installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: 3, count: 20), active: true)]), expectedRevision: nil)
        }
        try fixture.journal.write { try fixture.append($0) }
        let owner = try recoveringOwner(fixture)
        let configuration = try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: fixture.root.appendingPathComponent("journal").path, serviceName: "dev.remozio.authority.test",
            teamID: "ABCDEFGHIJ", transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: 3, count: 20)],
            transportUID: 501, continuityDirectory: fixture.root.appendingPathComponent("continuity").path)
        let clock = try AuthorityClock()
        let service = try AuthorityService(configuration: configuration, journal: owner, expiryClock: { try clock.now() },
            reconcileExpired: { _ in }, validateSelf: { _ in })
        XCTAssertTrue(try owner.withRequests { try $0.expirePending(now: clock.now(), receiptTimeMs: nil).isEmpty })
        try service.close()
        try fixture.reopen()
        let current = try fixture.store.read().committed
        let descriptor = try XCTUnwrap(fixture.journal.read { try $0.epoch(current.journalEpoch)?.descriptor })
        XCTAssertEqual(descriptor.cause, .restart)
        let recoveryEpoch = try XCTUnwrap(descriptor.previousEpoch)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(recoveryEpoch)?.descriptor.cause }, .recovery)
        XCTAssertNotNil(try fixture.journal.read { try $0.historyRecovery(epoch: recoveryEpoch) })
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(current))
    }

    func testRecoveringOwnerRetriesFailedFinalizationWithoutAnotherGap() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try recoveringOwner(fixture))
        try fixture.reopen()
        let candidate = try XCTUnwrap(fixture.store.historyRecoveryCandidate())
        try fixture.sql("DROP TRIGGER fail_finalize")
        let owner = try recoveringOwner(fixture)
        XCTAssertEqual(try owner.read { try $0.epoch(intent.recoveryEpoch)?.head }, 1)
        try owner.close()
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, candidate)
    }

    func testRecoveringOwnerReportsAuthorityMismatchAsRepairAndReleasesStores() throws {
        let fixture = try Fixture()
        _ = try prepareLostHistory(fixture)
        try fixture.sql("DELETE FROM authority_code_policy_v1", journal: true)
        XCTAssertThrowsError(try recoveringOwner(fixture, validateSelf: { _ in })) {
            XCTAssertEqual(AuthorityStartupFailure(error: $0), .repairRequired)
        }
        try fixture.reopen()
        XCTAssertThrowsError(try fixture.store.historyRecovery()) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
    }

    private func recoverHistory(_ fixture: Fixture) throws -> ContinuityCheckpoint {
        try JournalHistoryRecovery.recover(journal: fixture.journal, continuity: fixture.store,
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
    }

    func testHistoryRecoveryClassifiesLossAndDoesNotRepeatCompletedRecovery() throws {
        let fixture = try Fixture()
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        let before = try fixture.store.read().committed
        XCTAssertEqual(try recoverHistory(fixture), before)
        try fixture.journal.write { try fixture.append($0) }
        let result = try recoverHistory(fixture)
        XCTAssertNotEqual(result.journalEpoch, before.journalEpoch)
        XCTAssertEqual(result.authorityDigest, before.authorityDigest)
        XCTAssertEqual(result.journalHead, 1)
        let intent = try XCTUnwrap(fixture.journal.read { try $0.historyRecovery(epoch: result.journalEpoch) })
        XCTAssertEqual(intent.previous.committed, before)
        XCTAssertEqual(result.generation, before.generation + 1)
        try fixture.reopen()
        XCTAssertEqual(try recoverHistory(fixture), result)
        XCTAssertNil(try fixture.store.historyRecovery())
    }

    func testHistoryRecoveryRejectsUnconfiguredPolicyBeforePreparingIntent() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        let before = try fixture.journal.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try recoverHistory(fixture)) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
        XCTAssertNil(try fixture.store.historyRecovery())
        XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests() }, before)
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testHistoryRecoveryArchivesFurtherLossBeforeAndAfterCandidateCommit() throws {
        for commitCandidate in [false, true] {
            let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
            if commitCandidate {
                try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
                XCTAssertThrowsError(try resumeHistory(fixture))
                try fixture.sql("DROP TRIGGER fail_finalize")
            }
            let candidate = try fixture.store.historyRecoveryCandidate()
            _ = try fixture.journal.write { try $0.createEpoch(fixture.descriptor(Data(repeating: 6, count: 16))) }
            try fixture.reopen()
            let result = try recoverHistory(fixture)
            XCTAssertNotEqual(result.journalEpoch, intent.recoveryEpoch)
            XCTAssertEqual(result.authorityDigest, intent.authorityDigest)
            XCTAssertEqual(result.generation, intent.checkpointGeneration)
            try fixture.reopen()
            let archive = try XCTUnwrap(fixture.store.supersededHistoryRecovery(epoch: intent.recoveryEpoch))
            XCTAssertEqual(archive.intent, intent)
            XCTAssertEqual(archive.candidate, candidate)
            XCTAssertEqual(try recoverHistory(fixture), result)
        }
    }

    func testHistoryRecoveryArchiveFailurePreservesOriginalAttemptForRetry() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        _ = try fixture.journal.write { try $0.createEpoch(fixture.descriptor(Data(repeating: 6, count: 16))) }
        try fixture.sql("CREATE TRIGGER fail_replace BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try recoverHistory(fixture))
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        XCTAssertNil(try fixture.store.supersededHistoryRecovery(epoch: intent.recoveryEpoch))
        try fixture.sql("DROP TRIGGER fail_replace")
        let result = try recoverHistory(fixture)
        XCTAssertEqual(try fixture.store.read().committed, result)
        XCTAssertEqual(try fixture.store.supersededHistoryRecovery(epoch: intent.recoveryEpoch)?.intent, intent)
    }

    func testHistoryRecoveryRequiresRepairForChangedAuthorityWithOrWithoutAnIntent() throws {
        for prepared in [false, true] {
            let fixture = try Fixture()
            if prepared { _ = try prepareLostHistory(fixture) }
            else {
                let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
                _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
            }
            try fixture.sql("DELETE FROM authority_code_policy_v1", journal: true)
            XCTAssertThrowsError(try recoverHistory(fixture)) {
                XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
            }
            try fixture.reopen()
            XCTAssertThrowsError(try fixture.store.historyRecovery()) {
                XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
            }
        }
    }

    private func prepareLostHistory(_ fixture: Fixture) throws -> HistoryRecoveryIntent {
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(codePolicy(), expectedRevision: nil) }
        let previous = try fixture.store.read()
        try fixture.journal.write { try fixture.append($0) }
        let digests = try fixture.journal.read { try $0.continuityDigests() }
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: digests.authority,
            ledgerDigest: digests.ledger, recoveryEpoch: Data(repeating: 9, count: 16))
        try fixture.store.prepareHistoryRecovery(intent)
        return intent
    }

    private func resumeHistory(_ fixture: Fixture) throws -> ContinuityCheckpoint {
        try JournalHistoryRecovery.resume(journal: fixture.journal, continuity: fixture.store,
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
    }

    func testHistoryResumeRejectsUnconfiguredSchemaBeforeMutatingJournal() throws {
        let fixture = try Fixture(), previous = try fixture.store.read()
        try fixture.journal.write { try fixture.append($0) }
        let before = try fixture.journal.read { try $0.continuityDigests() }
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: before.authority,
            ledgerDigest: before.ledger, recoveryEpoch: Data(repeating: 9, count: 16))
        try fixture.store.prepareHistoryRecovery(intent)
        XCTAssertThrowsError(try resumeHistory(fixture)) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
        XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests() }, before)
        XCTAssertNil(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch) })
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        try fixture.reopen()
        XCTAssertThrowsError(try resumeHistory(fixture)) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
        XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests() }, before)
    }

    func testHistoryResumeCommitsGapAndPreservesOldEvidenceAcrossReopen() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        let result = try resumeHistory(fixture)
        XCTAssertEqual(result.journalHead, 1)
        XCTAssertEqual(result.journalEpoch, intent.recoveryEpoch)
        XCTAssertEqual(result.authorityDigest, intent.authorityDigest)
        XCTAssertEqual(result.authorityGeneration, intent.authorityGeneration)
        let page = try fixture.journal.read {
            try $0.page(epoch: intent.recoveryEpoch, after: 0, maximumRecords: 2, maximumBytes: 16384)
        }
        XCTAssertEqual(page.canonicalRecords.count, 1)
        let gap = try AuditEventMetadata.decode(XCTUnwrap(page.canonicalRecords.first), limits: fixture.limits)
        XCTAssertEqual(gap.kind, .recovery)
        XCTAssertEqual(gap.outcome, .unresolved)
        XCTAssertNil(gap.requestID)
        XCTAssertNil(gap.droppedEventCount)
        XCTAssertNil(gap.eventTimeMs)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, result)
        XCTAssertNil(try fixture.store.historyRecovery())
        XCTAssertEqual(try fixture.journal.read { try $0.historyRecovery(epoch: intent.recoveryEpoch) }, intent)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.head }, 1)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(result))
        XCTAssertThrowsError(try resumeHistory(fixture))
    }

    func testHistoryResumeAfterFailedFinalizationDoesNotAppendAgain() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try resumeHistory(fixture))
        let candidate = try XCTUnwrap(fixture.store.historyRecoveryCandidate())
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try resumeHistory(fixture), candidate)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch)?.head }, 1)
    }

    func testHistoryPreparationFailureRollsBackGapAndCanResume() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.sql("CREATE TRIGGER fail_prepare BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try resumeHistory(fixture))
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        try fixture.reopen()
        XCTAssertNil(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch) })
        XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests().ledger }, intent.ledgerDigest)
        try fixture.sql("DROP TRIGGER fail_prepare")
        _ = try resumeHistory(fixture)
    }

    func testHistoryResumeReconstructsExactCandidateAfterJournalCommitFailure() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.withJournalReader {
            XCTAssertThrowsError(try resumeHistory(fixture)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .storage(SQLITE_BUSY))
            }
        }
        let candidate = try XCTUnwrap(fixture.store.historyRecoveryCandidate())
        try fixture.reopen()
        XCTAssertNil(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch) })
        XCTAssertEqual(try fixture.journal.read { try $0.continuityDigests().ledger }, intent.ledgerDigest)
        XCTAssertEqual(try resumeHistory(fixture), candidate)
        XCTAssertEqual(try fixture.store.read().committed, candidate)
    }

    func testHistoryResumeRejectsNewLossWithoutDiscardingRetainedEvidence() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        _ = try fixture.journal.write { try $0.createEpoch(fixture.descriptor(Data(repeating: 6, count: 16))) }
        XCTAssertThrowsError(try resumeHistory(fixture))
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        XCTAssertNil(try fixture.journal.read { try $0.epoch(intent.recoveryEpoch) })
    }

    func testHistoryResumeDoesNotBlessChangesAfterCandidateCommit() throws {
        let fixture = try Fixture(), intent = try prepareLostHistory(fixture)
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try resumeHistory(fixture))
        let candidate = try XCTUnwrap(fixture.store.historyRecoveryCandidate())
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try fixture.journal.write { try $0.createEpoch(fixture.descriptor(Data(repeating: 6, count: 16))) }
        try fixture.reopen()
        XCTAssertThrowsError(try resumeHistory(fixture))
        XCTAssertEqual(try fixture.store.historyRecovery(), intent)
        XCTAssertEqual(try fixture.store.historyRecoveryCandidate(), candidate)
        XCTAssertThrowsError(try fixture.store.read())
    }

    func testHistoryResumeMarksChangedAuthorityForRepair() throws {
        let fixture = try Fixture()
        _ = try prepareLostHistory(fixture)
        try fixture.sql("DELETE FROM authority_code_policy_v1", journal: true)
        XCTAssertThrowsError(try resumeHistory(fixture)) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
        try fixture.reopen()
        XCTAssertThrowsError(try fixture.store.historyRecovery()) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
    }

    private func codePolicy(installed: UInt64 = 4, minimum: UInt64 = 2, active: Bool = true) throws -> AuthorityCodePolicy {
        try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .authority, teamID: "ABCDEF1234", identifier: "dev.sebastiano.remozio.macos.authority",
            installedGeneration: installed, minimumGeneration: minimum, codeDirectoryHash: Data(repeating: 8, count: 20), active: active)])
    }

    final class Fixture {
        let root: URL
        let epoch = Data(repeating: 3, count: 16)
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        var journal: JournalDatabase!
        var store: ContinuityStore!
        var writer: AuditEpochWriter!
        init(authorityGeneration: UInt64? = 7) throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Fault.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["journal", "continuity"] {
                let directory = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                for file in ["writer.lock", "\(name).sqlite"] {
                    let fd = Darwin.open(directory.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw Fault.injected }
                    Darwin.close(fd)
                }
            }
            journal = try openJournal(initialize: true)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Data(repeating: 1, count: 16)), 2: .bytes(Data(repeating: 2, count: 16)),
                3: .bytes(epoch), 4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            writer = try journal.write { try $0.createEpoch(descriptor) }
            store = try openStore(initial: observed(generation: 1, authorityGeneration: authorityGeneration))
        }
        deinit { try? journal?.close(); store?.close(); try? FileManager.default.removeItem(at: root) }
        func openJournal(initialize: Bool = false) throws -> sending JournalDatabase {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: geteuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10,
                busyMilliseconds: 100, initialize: initialize)
        }
        func openStore(initial: ContinuityCheckpoint? = nil, directory: String = "continuity",
                       excludingDirectory: ProtectedStorageLease.DirectoryIdentity? = nil) throws -> sending ContinuityStore {
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: directory, owner: geteuid(), excludingDirectory: excludingDirectory),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: initial)
        }
        func reopen() throws {
            try journal.close(); store.close()
            journal = try openJournal(); store = try openStore()
        }
        func observed(generation: UInt64, authorityGeneration: UInt64? = 7) throws -> ContinuityCheckpoint {
            try journal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: generation, authorityGeneration: authorityGeneration) }
        }
        func openTransferredStorage(readOnlyForCutover: Bool = false) throws -> sending AuthorityStorage {
            try Self.openTransferredStorage(anchor: root.path, limits: limits, readOnlyForCutover: readOnlyForCutover)
        }
        static func openTransferredStorage(anchor: String, limits: CBORLimits,
                                           readOnlyForCutover: Bool = false) throws -> sending AuthorityStorage {
            return try AuthorityStorage(openJournal: {
                try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: geteuid()),
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                    recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                    maximumConsumptions: 10, busyMilliseconds: 100, initialize: false, readOnlyForCutover: readOnlyForCutover)
            }, openContinuity: { journalDirectory in
                try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: geteuid(),
                    excludingDirectory: journalDirectory),
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                    initialize: nil, readOnlyForCutover: readOnlyForCutover)
            })
        }
        func descriptor(_ next: Data, generation: UInt64 = 7) throws -> AuditEpochDescriptor {
            try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Data(repeating: 1, count: 16)), 2: .bytes(Data(repeating: 2, count: 16)),
                3: .bytes(next), 4: .unsigned(generation), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
        }
        func append(_ transaction: JournalTransaction) throws {
            let event = try AuditEventMetadata(eventID: Data(repeating: 4, count: 16), macID: Data(repeating: 1, count: 16),
                accountID: Data(repeating: 2, count: 16), journalEpoch: epoch, sequence: 1, requestID: nil,
                eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .consumed, category: .command, action: nil,
                decisionPhoneID: nil, authentication: .system, outcome: .accepted, reason: .none,
                droppedEventCount: nil, peerDeviceID: nil).encode(limits: limits)
            try transaction.append(event, writer: writer, expectedHead: 0)
        }
        func withJournalReader(_ body: () throws -> Void) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent("journal/journal.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw Fault.injected }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, "BEGIN; SELECT count(*) FROM sqlite_schema", nil, nil, nil) == SQLITE_OK else {
                throw Fault.injected
            }
            defer { sqlite3_exec(connection, "ROLLBACK", nil, nil, nil) }
            try body()
        }
        func sql(_ query: String, journal: Bool = false) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent(journal ? "journal/journal.sqlite" : "continuity/continuity.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw Fault.injected }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, query, nil, nil, nil) == SQLITE_OK else { throw Fault.injected }
        }
    }
}
