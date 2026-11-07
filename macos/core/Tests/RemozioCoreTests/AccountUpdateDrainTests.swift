import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AccountUpdateDrainTests: XCTestCase {
    private enum Fault: Error { case injected }
    private final class Gates {
        let files: BoundAdmissionRegistrationFixture
        let registration: UpdateAdmissionRegistrationRecord
        init(_ f: RootUpdateSchedulingFixture) throws {
            files = try .init(machine: f.data.machine)
            registration = try XCTUnwrap(f.data.machine.store.updateAdmissionRegistration())
        }
        func barrier(_ scope: UpdateAdmissionScope) throws -> UpdateAdmissionBarrier {
            let identity: PreparationFileIdentity
            switch scope {
            case .machine: identity = registration.machine
            case .account(let id): identity = try XCTUnwrap(registration.accounts.first { $0.accountID == id }).identity
            }
            return try .init(directory: files.directory(), owner: getuid(), expected: identity, scope: scope)
        }
        func boundary(_ account: Data) throws -> UpdateAdmissionBoundary {
            try .init(machine: barrier(.machine), account: barrier(.account(account)))
        }
        func attach(_ owner: ApprovalRequestCoordinator, account: Data) throws {
            try owner.attachReleaseActivityBarrier(files.activity())
            try owner.attachUpdateAdmissionBoundary(boundary(account))
        }
        func assertClosed(_ account: Data, file: StaticString = #filePath, line: UInt = #line) throws {
            XCTAssertThrowsError(try boundary(account).acquireAdmission(), file: file, line: line) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy, file: file, line: line)
            }
        }
        func assertOpen(_ account: Data) throws {
            let token = try boundary(account).acquireAdmission(); try token.validate(); token.close()
        }
    }
    private func control(_ action: UpdateSchedulingAction, _ f: RootUpdateSchedulingFixture) throws -> UpdateSchedulingControl {
        let reply = try f.issue(action)
        return try .decode(RootUpdateSchedulingChallenge.decode(reply.canonicalChallenge, limits: f.data.limits).canonicalControl,
            limits: f.data.limits)
    }
    private func freshOwner(_ f: RootUpdateSchedulingFixture) throws -> ApprovalRequestCoordinator {
        try .init(database: f.data.db, continuity: f.data.store, writer: f.data.writer, clockEpoch: UUID(),
            maximumRequests: 10, maximumRetainedBytes: 65536, requestLimits: f.data.limits, captureLimits: f.data.limits,
            decisionLimits: f.data.limits, signingLimits: f.data.limits, auditLimits: f.data.limits)
    }
    func testSignedDrainClosesOnlyItsAccountAndPreservesPendingWork() throws {
        let f = try RootUpdateSchedulingFixture(updateOwner: .otherAccount), gates = try Gates(f)
        try gates.attach(f.owner, account: f.data.accountID)
        let draft = try ApprovalRequestDraft(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            requiredFeatures: [], capture: Data([0xa0]),
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: f.data.now(), deadlineMilliseconds: 2000, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2900)
        let request = try f.owner.admitFixture(draft, now: f.data.nextNow(), receiptTimeMs: nil)
        XCTAssertEqual(try f.consume(control(.installWhenCurrentWorkFinishes, f)).requestedAction, .installWhenCurrentWorkFinishes)
        try gates.assertClosed(f.data.accountID); try gates.assertOpen(Data(repeating: 96, count: 16))
        XCTAssertThrowsError(try f.owner.admitFixture(draft, now: f.data.nextNow(), receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
        }
        XCTAssertThrowsError(try gates.files.activity().acquireExclusive())
        XCTAssertEqual(try f.owner.markPresented(requestID: request.requestID, now: f.data.nextNow(), receiptTimeMs: nil).phase, .presented)
        _ = try f.owner.expirePending(now: f.data.now(2000), receiptTimeMs: nil)
        XCTAssertEqual(try f.owner.state(requestID: request.requestID).phase, .expired)
        let quiet = try gates.files.activity().acquireExclusive(); quiet.close()
        try gates.assertClosed(f.data.accountID)
    }
    func testCancelRetainsClosedAdmissionThroughTheFinalCheckpointRead() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f)); let cancel = try control(.cancelDrain, f)
        var checks = 0
        let accepted = try f.consume(cancel, verifyHost: { tx in
            checks += 1; try gates.assertClosed(f.data.accountID); try f.checkHost(tx)
        })
        XCTAssertGreaterThanOrEqual(checks, 3); XCTAssertEqual(accepted.requestedAction, .cancelDrain)
        try gates.assertOpen(f.data.accountID)
    }
    func testOwnerDeferralReopensItsDrainOnlyAfterCheckpointCompletion() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f))
        let deferred = try f.consume(control(.deferUpdate, f), verifyHost: { tx in
            try gates.assertClosed(f.data.accountID); try f.checkHost(tx)
        })
        XCTAssertEqual(deferred.requestedAction, .deferUpdate); try gates.assertOpen(f.data.accountID)
    }
    func testInvalidSignatureCannotCloseAdmissionOrConsumeTheControl() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let pending = try control(.installWhenCurrentWorkFinishes, f), peer = try f.data.binding()
        XCTAssertThrowsError(try f.data.withCandidate { candidate in
            try f.owner.consumeUpdateScheduling(candidate: candidate, canonicalControl: pending.encode(limits: f.data.limits),
                signature: Data(repeating: 0, count: 64), binding: peer, verifyHost: { tx in
                    XCTAssertNoThrow(try gates.assertOpen(f.data.accountID)); try f.checkHost(tx)
                },
                now: f.data.nextNow, wall: { 1500 })
        })
        try gates.assertOpen(f.data.accountID)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
    }
    func testBusyAdmissionRollsBackTheDrainAndPermitsTheOriginalControlAfterRelease() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let pending = try control(.installWhenCurrentWorkFinishes, f), token = try gates.boundary(f.data.accountID).acquireAdmission()
        XCTAssertThrowsError(try f.consume(pending)) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertFalse(f.owner.retired); XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        XCTAssertNil(try f.status().requestedAction); token.close()
        XCTAssertEqual(try f.consume(pending).requestedAction, .installWhenCurrentWorkFinishes)
        try gates.assertClosed(f.data.accountID)
    }
    func testRestartRestoresTheDrainWithoutAnEnabledSchedulingPolicy() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f)); f.owner.close(); try f.data.reopen(schedulingEnabled: false)
        let before = try f.data.store.read(), resumed = try freshOwner(f); defer { resumed.close() }
        try gates.attach(resumed, account: f.data.accountID); try gates.assertClosed(f.data.accountID)
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertThrowsError(try f.data.db.read { try $0.updateSchedulingIntent() }) {
            XCTAssertEqual($0 as? UpdateSchedulingJournalError, .disabled)
        }
    }
    func testStartupWithOlderStorageDoesNotCreateSchedulingTablesOrPolicy() throws {
        let f = try RootUpdateSchedulingFixture(enabled: false), gates = try Gates(f)
        let before = try f.data.db.read { try $0.storageSchemaVersion }, checkpoint = try f.data.store.read()
        try gates.attach(f.owner, account: f.data.accountID); try gates.assertOpen(f.data.accountID)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, before)
        XCTAssertEqual(try f.data.store.read(), checkpoint)
        XCTAssertThrowsError(try f.data.db.read { try $0.updateSchedulingIntent() })
    }
    func testCorruptRetainedStatePreventsAdmissionAttachment() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f))
        try f.data.sql("PRAGMA ignore_check_constraints=ON; UPDATE update_scheduling_state_v1 SET generation=x'01'; PRAGMA ignore_check_constraints=OFF", journal: true)
        XCTAssertThrowsError(try gates.attach(f.owner, account: f.data.accountID))
        XCTAssertTrue(f.owner.retired)
    }
    func testAnUncertainCheckpointCannotRestartWithoutRecovery() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let pending = try control(.installWhenCurrentWorkFinishes, f)
        try f.data.sql("CREATE TRIGGER fail_drain_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try f.consume(pending)); XCTAssertTrue(f.owner.retired)
        XCTAssertNotNil(try f.data.store.read().pending)
        try f.data.sql("DROP TRIGGER fail_drain_finalize"); try f.data.reopen(schedulingEnabled: false)
        XCTAssertThrowsError(try freshOwner(f))
    }
    func testFailedCancelKeepsTheExistingDrainAndDoesNotConsumeItsControl() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f)); let cancel = try control(.cancelDrain, f)
        var checks = 0
        XCTAssertThrowsError(try f.consume(cancel, verifyHost: { tx in
            checks += 1; try f.checkHost(tx); if checks == 2 { throw Fault.injected }
        }))
        try gates.assertClosed(f.data.accountID)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: cancel.operationID) })
        _ = try f.consume(cancel); try gates.assertOpen(f.data.accountID)
    }
    func testNewGenerationReleasesTheOldDrainAfterItsOfferCheckpoint() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let old = try f.consume(control(.installWhenCurrentWorkFinishes, f))
        let current = try XCTUnwrap(f.data.machine.store.updateCandidate())
        _ = try f.data.machine.select(f.data.machine.copy(), replacing: current)
        let offered = try f.data.withCandidate { candidate in
            try f.owner.retainUpdateSchedulingOffer(candidate: candidate, expected: old.snapshot, verifyHost: { tx in
                try gates.assertClosed(f.data.accountID); try f.checkHost(tx)
            })
        }
        XCTAssertNil(offered.requestedAction); XCTAssertGreaterThan(offered.snapshot.generation, old.snapshot.generation)
        try gates.assertOpen(f.data.accountID)
    }
    func testADeferredIntentDoesNotRestoreAnAccountDrain() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f)
        _ = try f.consume(control(.deferUpdate, f)); f.owner.close(); try f.data.reopen(schedulingEnabled: false)
        let resumed = try freshOwner(f); defer { resumed.close() }
        try gates.attach(resumed, account: f.data.accountID); try gates.assertOpen(f.data.accountID)
    }
    func testRestoreCanRetainAccountClosureWhileTheMachineGateIsClosed() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f)
        _ = try f.consume(control(.installWhenCurrentWorkFinishes, f)); f.owner.close()
        let global = try gates.barrier(.machine).beginDrain(); defer { global.close() }
        let resumed = try freshOwner(f); defer { resumed.close() }
        try gates.attach(resumed, account: f.data.accountID)
        global.close(); try gates.assertClosed(f.data.accountID)
    }
    func testTheRetainedStateReaderCannotEscapeItsTransaction() throws {
        let f = try RootUpdateSchedulingFixture(); var saved: JournalTransaction?
        try f.data.db.read { tx in saved = tx; _ = try tx.retainedUpdateSchedulingIntentForAdmission() }
        XCTAssertThrowsError(try XCTUnwrap(saved).retainedUpdateSchedulingIntentForAdmission())
    }
    func testTheSignaturePreflightDoesNotConsumeOrCheckpointTheControl() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let pending = try control(.installWhenCurrentWorkFinishes, f), peer = try f.data.binding(), before = try f.data.store.read()
        let checked = try f.data.withCandidate { candidate in
            try f.data.db.read { tx in
                try tx.verifyUpdateSchedulingControl(candidate: candidate, canonicalControl: pending.encode(limits: f.data.limits),
                    signature: f.data.sign(pending), binding: peer, nowUnixMillis: 1500, now: f.data.nextNow())
            }
        }
        XCTAssertEqual(checked.control, pending); XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        try gates.assertOpen(f.data.accountID)
    }
    func testSlowPreflightCannotCloseAdmissionAfterTheChallengeExpires() throws {
        let f = try RootUpdateSchedulingFixture(), gates = try Gates(f); try gates.attach(f.owner, account: f.data.accountID)
        let pending = try control(.installWhenCurrentWorkFinishes, f); var samples = 0
        XCTAssertThrowsError(try f.consume(pending, now: {
            samples += 1; return f.data.now(samples == 1 ? 200 : 2000)
        }))
        XCTAssertEqual(samples, 2); XCTAssertFalse(f.owner.retired)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        try gates.assertOpen(f.data.accountID)
    }
}
