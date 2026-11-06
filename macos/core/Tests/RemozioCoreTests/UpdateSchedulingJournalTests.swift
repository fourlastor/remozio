import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class UpdateSchedulingJournalTests: XCTestCase {
    private enum Fault: Error { case injected }
    private func rejects<Value>(_ expected: UpdateSchedulingJournalError, _ body: () throws -> Value,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? UpdateSchedulingJournalError, expected, file: file, line: line)
        }
    }
    func testStorageUpgradeIsExplicitAtomicAndPreservesExistingReaders() throws {
        let f = try Fixture()
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 16)
        rejects(.unavailableSchema) { try f.db.read { try $0.updateSchedulingIntent() } }
        let before = try f.store.read().committed
        XCTAssertThrowsError(try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) {
            try $0.installUpdateSchedulingStorage(); throw Fault.injected
        })
        XCTAssertFalse(f.commits.retired)
        XCTAssertEqual(try f.store.read().committed, before)
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 16)
        try f.install()
        let after = try f.store.read().committed
        XCTAssertNotEqual(before.authorityDigest, after.authorityDigest)
        XCTAssertEqual(before.ledgerDigest, after.ledgerDigest)
        XCTAssertEqual(before.journalHead, after.journalHead)
        XCTAssertNil(try f.commits.read { try $0.updateSchedulingIntent() })
        try f.install()
        XCTAssertEqual(try f.store.read().committed.authorityDigest, after.authorityDigest)
        try f.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store), .unchanged(try f.store.read().committed))
        XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, 17)
        XCTAssertNotNil(try f.commits.read { try $0.codePolicy() })
        try f.commits.write(epoch: f.epoch) { try $0.installCommandSubmissionReplay(); try $0.installGatewaySubmissionHistory(f.gateway) }
        XCTAssertEqual(try f.commits.read { try $0.gatewayAuthorityHead(f.gateway) }, 0)
    }
    func testSchedulingStorageOpensFromCommandSchemaWithoutEnablingOptionalGateway() throws {
        let f = try Fixture(gatewayEnabled: false)
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 15)
        let before = try f.store.read().committed
        let trust = try f.binding(), policy = try f.db.read { try $0.codePolicy() }
        rejects(.unavailableSchema) { try f.db.read { try $0.updateSchedulingIntent() } }
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 15)
        try f.install()
        XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, 17)
        XCTAssertEqual(try f.binding().revision, trust.revision)
        XCTAssertEqual(try f.commits.read { try $0.codePolicy()?.revision }, policy?.revision)
        let after = try f.store.read().committed
        XCTAssertNotEqual(after.authorityDigest, before.authorityDigest)
        XCTAssertEqual(after.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(after.journalHead, before.journalHead)
        XCTAssertThrowsError(try f.db.read { try $0.gatewayAuthorityHead(f.gateway) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .disabled)
        }
        try f.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store), .unchanged(after))
        XCTAssertNil(try f.commits.read { try $0.updateSchedulingIntent() })
        _ = try f.offer()
        let control = try f.issue(.deferUpdate)
        XCTAssertEqual(try f.consume(control).requestedAction, .deferUpdate)
        let retained = try f.commits.read { try $0.updateSchedulingIntent() }
        let checkpoint = try f.store.read().committed
        try f.install()
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent() }, retained)
        XCTAssertEqual(try f.store.read().committed.authorityDigest, checkpoint.authorityDigest)
        XCTAssertThrowsError(try f.db.read { try $0.gatewayAuthorityHead(f.gateway) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .disabled)
        }
    }

    func testCommandSchemaUpgradeRollsBackBothNewTablesBeforeCheckpointCommit() throws {
        let f = try Fixture(gatewayEnabled: false)
        let before = try f.store.read().committed
        XCTAssertThrowsError(try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) {
            try $0.installUpdateSchedulingStorage(); throw Fault.injected
        })
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 15)
        XCTAssertEqual(try f.store.read().committed, before)
        XCTAssertFalse(f.commits.retired)
        try f.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store), .unchanged(before))
        try f.install()
        XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, 17)
        XCTAssertNil(try f.commits.read { try $0.updateSchedulingIntent() })
    }

    func testCommandSchemaUpgradeRecoversBothContinuityFailureBoundaries() throws {
        for finalize in [false, true] {
            let f = try Fixture(gatewayEnabled: false), before = try f.store.read().committed
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try f.sql("CREATE TRIGGER fail_command_upgrade BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try f.install())
            XCTAssertTrue(f.commits.retired)
            let pending = try f.store.read().pending
            XCTAssertEqual(pending != nil, finalize)
            try f.sql("DROP TRIGGER fail_command_upgrade")
            try f.reopen()
            let recovered = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
            if finalize { XCTAssertEqual(recovered, .finalized(try XCTUnwrap(pending))) }
            else { XCTAssertEqual(recovered, .unchanged(before)) }
            XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, finalize ? 17 : 15)
            try f.install()
            XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, 17)
            XCTAssertThrowsError(try f.db.read { try $0.gatewayAuthorityHead(f.gateway) }) {
                XCTAssertEqual($0 as? GatewayAuthorityError, .disabled)
            }
        }
    }

    private func signSubmission(_ value: GatewaySubmissionControl, fixture f: Fixture) throws -> Data {
        try f.rootKey.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: value.kind,
            canonicalPayload: value.encode(limits: f.limits), payloadLimits: f.limits, inputLimits: f.limits)).rawRepresentation
    }

    private func rotateSubmission(_ f: Fixture, now: UInt64 = 100) throws -> GatewayAuthorityEnvelope {
        try f.commits.write(epoch: f.epoch) { try $0.rotateGatewaySubmission(
            publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, registration: f.gateway,
            registrationActive: true, expectedHead: 0, nowUnixMillis: 1000, now: f.now(now),
            sign: { try self.signSubmission($0, fixture: f) }) }
    }

    func testSchedulingMigrationPreservesPendingGatewayCredentialAndOriginalDeadlines() throws {
        let f = try Fixture()
        let rotation = try rotateSubmission(f)
        let value = try GatewaySubmissionControl.decode(rotation.canonicalPayload, limits: f.limits)
        try f.install()
        XCTAssertEqual(try f.commits.read { try $0.gatewayAuthorityHead(f.gateway) }, 1)
        XCTAssertEqual(try f.commits.read { try $0.desiredGatewaySubmission(f.gateway)?.control.operationID }, rotation.operationID)
        let pending = try f.commits.read { try $0.pendingGatewaySubmission(operationID: rotation.operationID,
            registration: f.gateway, registrationActive: true, nowUnixMillis: 1999, now: f.now(1099)) }
        XCTAssertEqual(pending?.canonicalPayload, rotation.canonicalPayload)
        XCTAssertEqual(pending?.signature, rotation.signature)
        XCTAssertEqual(value.issuedAtUnixMillis, 1000)
        XCTAssertEqual(value.expiresAtUnixMillis, 2000)
        XCTAssertThrowsError(try f.db.read { try $0.pendingGatewaySubmission(operationID: rotation.operationID,
            registration: f.gateway, registrationActive: true, nowUnixMillis: 2000, now: f.now(1100)) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        XCTAssertEqual(try f.commits.read { try $0.desiredGatewaySubmission(f.gateway)?.control.operationID }, rotation.operationID)
    }

    func testSchemaSeventeenSupportsGatewayRotationRenewalAndRevocationAfterReopen() throws {
        let f = try Fixture(submissionHistory: false)
        XCTAssertEqual(try f.db.read { try $0.storageSchemaVersion }, 15)
        try f.install()
        let first = try rotateSubmission(f)
        try f.reopen()
        _ = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
        let renewed = try f.commits.write(epoch: f.epoch) { try $0.renewGatewaySubmission(operationID: first.operationID,
            registration: f.gateway, registrationActive: true, expectedHead: 1, nowUnixMillis: 3000,
            now: f.now(200), sign: { try self.signSubmission($0, fixture: f) }) }
        let firstValue = try GatewaySubmissionControl.decode(first.canonicalPayload, limits: f.limits)
        let renewedValue = try GatewaySubmissionControl.decode(renewed.canonicalPayload, limits: f.limits)
        XCTAssertNotEqual(firstValue.credentialID, renewedValue.credentialID)
        XCTAssertEqual(firstValue.publicKey, renewedValue.publicKey)
        XCTAssertEqual(renewed.revision, 2)
        let revoked = try f.commits.write(epoch: f.epoch) { try $0.revokeGatewaySubmission(
            credentialID: renewedValue.credentialID, registration: f.gateway, registrationActive: true,
            expectedHead: 2, nowUnixMillis: 3001, now: f.now(201), sign: { try self.signSubmission($0, fixture: f) }) }
        XCTAssertEqual(revoked.revision, 3)
        XCTAssertNil(try f.commits.read { try $0.desiredGatewaySubmission(f.gateway) })
        XCTAssertEqual(try f.commits.read { try $0.gatewayAuthorityHead(f.gateway) }, 3)
        try f.commits.write(epoch: f.epoch) { try $0.installGatewaySubmissionHistory(f.gateway) }
        XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, 17)
        XCTAssertEqual(try f.commits.read { try $0.gatewayAuthorityHead(f.gateway) }, 3)
    }

    func testOlderAndUnconfiguredOwnersCannotEnableStorage() throws {
        let older = try Fixture(prepare: false)
        rejects(.unavailableSchema) { try older.commits.write(epoch: older.epoch, recoverRejectedBody: true) { try $0.installUpdateSchedulingStorage() } }
        XCTAssertEqual(try older.db.read { try $0.storageSchemaVersion }, 12)
        let disabled = try Fixture(enabled: false)
        rejects(.disabled) { try disabled.commits.write(epoch: disabled.epoch, recoverRejectedBody: true) { try $0.installUpdateSchedulingStorage() } }
        XCTAssertEqual(try disabled.db.read { try $0.storageSchemaVersion }, 16)
    }
    func testActionsConsumeExactlyOnceAndHistoricalRevisionsSurviveRestart() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        var controls: [UpdateSchedulingControl] = []
        for action in UpdateSchedulingAction.allCases {
            let value = try f.issue(action)
            let result = try f.consume(value)
            controls.append(value)
            XCTAssertEqual(result.requestedAction, action)
            XCTAssertEqual(result.snapshot.revision, value.expectedRevision + 1)
            XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) }, result.snapshot.revision)
            rejects(.alreadyConsumed) { try f.consume(value) }
            XCTAssertFalse(f.commits.retired)
        }
        let retained = try f.commits.read { try $0.updateSchedulingIntent() }
        try f.reopen()
        _ = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent() }, retained)
        for value in controls {
            XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) }, value.expectedRevision + 1)
            rejects(.alreadyConsumed) { try f.consume(value) }
        }
    }
    func testReplacementOfferInvalidatesUnusedControlsWithoutResettingSameReleaseIntent() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let accepted = try f.issue(.installWhenCurrentWorkFinishes), result = try f.consume(accepted)
        XCTAssertEqual(try f.offer(expected: result.snapshot), result)
        let pending = try f.issue(.cancelDrain)
        let replacement = try f.offer(update: 31, expected: result.snapshot)
        XCTAssertEqual(replacement.snapshot.generation, 2)
        XCTAssertNotEqual(replacement.snapshot.updateID, result.snapshot.updateID)
        XCTAssertEqual(replacement.snapshot.revision, 0)
        XCTAssertNil(replacement.requestedAction)
        XCTAssertThrowsError(try f.consume(pending)) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .staleSchedulingState) }
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: accepted.operationID) }, 1)
        rejects(.conflict) { try f.offer(update: 32, expected: result.snapshot) }
    }
    func testCompetingControlsCannotBothChangeOneSchedulingRevision() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let first = try f.issue(.deferUpdate), second = try f.issue(.installWhenCurrentWorkFinishes)
        let result = try f.consume(first), before = try f.store.read()
        XCTAssertThrowsError(try f.consume(second)) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .staleSchedulingState) }
        XCTAssertEqual(try f.store.read(), before)
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent() }, result)
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: second.operationID) })
    }
    func testCorrectlySignedAlterationDoesNotConsumeTheOriginalChallenge() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let value = try f.issue(.deferUpdate)
        guard case .map(var fields) = try DeterministicCBOR.decode(value.encode(limits: f.limits), limits: f.limits) else { return XCTFail() }
        fields[13] = .unsigned(0)
        let altered = try UpdateSchedulingControl.decode(DeterministicCBOR.encode(.map(fields), limits: f.limits), limits: f.limits)
        XCTAssertThrowsError(try f.consume(altered)) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .wrongChallenge) }
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) })
        XCTAssertEqual(try f.consume(value).requestedAction, .deferUpdate)
    }
    func testUnusedChallengesCannotSurviveOwnerRestartEvenWithTheSameClockEpoch() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let pending = try f.issue(.installWhenCurrentWorkFinishes)
        try f.reopen(); _ = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
        rejects(.unavailableChallenge) { try f.consume(pending) }
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        let fresh = try f.issue(.deferUpdate)
        XCTAssertNotEqual(fresh.challenge, pending.challenge)
        XCTAssertNotEqual(fresh.operationID, pending.operationID)
        XCTAssertEqual(try f.consume(fresh).requestedAction, .deferUpdate)
    }
    func testRejectedSignaturesExpiryAndTransportChangesLeaveTheOperationUnused() throws {
        for variant in 0..<4 {
            let f = try Fixture(); try f.install(); _ = try f.offer()
            let value = try f.issue(.cancelDrain)
            let badPeer = try AuthorityPeerBinding(scope: f.binding().scope,
                transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: f.binding().revision)
            XCTAssertThrowsError(try f.consume(value, signature: variant == 0 ? Data(repeating: 0, count: 64) : nil,
                binding: variant == 1 ? badPeer : nil, wall: variant == 2 ? 999 : variant == 3 ? 2000 : 1500))
            XCTAssertFalse(f.commits.retired)
            XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) })
            XCTAssertEqual(try f.consume(value).snapshot.revision, 1)
        }
    }
    func testRevocationInvalidatesIssuedControlsInTheSameProtectedWriter() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let value = try f.issue(.deferUpdate), binding = try f.binding()
        let removal = try EnrollmentGatewayRemoval(registration: f.gateway, expectedHead: 0, nowUnixMillis: 1400,
            now: f.nextNow(), sign: { revocation in
                try f.rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                    canonicalPayload: revocation.encode(limits: f.limits), payloadLimits: f.limits, inputLimits: f.limits)).rawRepresentation
            })
        _ = try f.commits.write(epoch: f.epoch) {
            try $0.revokeApprovalEnrollment(phoneID: value.phoneID, epoch: value.enrollmentEpoch,
                expectedTrustRevision: binding.revision, eventID: f.id(22), receiptTimeMs: 1400,
                writer: f.writer, expectedAuditHead: 1, gateway: removal)
        }
        XCTAssertThrowsError(try f.consume(value, binding: binding)) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) })
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent()?.snapshot.revision }, 0)
    }
    func testBoundedHistoryFailsClosedWithoutDeletingConsumedOperations() throws {
        let f = try Fixture(maximum: 1); try f.install(); _ = try f.offer()
        let value = try f.issue(.deferUpdate); _ = try f.consume(value)
        rejects(.capacityExceeded) { try f.issue(.cancelDrain) }
        XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) }, 1)
    }
    func testReadOnlyEscapedAndSwallowedFailuresCannotCommit() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let value = try f.issue(.deferUpdate), peer = try f.binding()
        let readMoment = f.nextNow()
        XCTAssertThrowsError(try f.withCandidate { candidate in try f.db.read {
            try $0.consumeUpdateSchedulingControl(candidate: candidate, canonicalControl: value.encode(limits: f.limits),
                signature: f.sign(value), binding: peer, nowUnixMillis: 1500, now: readMoment)
        } }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        var escaped: JournalTransaction?
        try f.db.read { escaped = $0 }
        XCTAssertThrowsError(try XCTUnwrap(escaped).updateSchedulingIntent())
        let before = try f.store.read(), writeMoment = f.nextNow()
        XCTAssertThrowsError(try f.withCandidate { candidate in try f.db.write { tx in
            _ = try tx.consumeUpdateSchedulingControl(candidate: candidate, canonicalControl: value.encode(limits: f.limits), signature: f.sign(value),
                binding: peer, nowUnixMillis: 1500, now: writeMoment)
            _ = try? tx.retainUpdateSchedulingOffer(candidate: candidate, expected: nil)
        } }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try f.store.read(), before)
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) })
        XCTAssertEqual(try f.consume(value).snapshot.revision, 1)
    }
    func testConsumeFailuresNeverReleaseAResultAndReconcileBothDurableStores() throws {
        for finalize in [false, true] {
            let f = try Fixture(); try f.install(); _ = try f.offer()
            let value = try f.issue(.installWhenCurrentWorkFinishes), before = try f.store.read().committed
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try f.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            var released = false
            XCTAssertThrowsError(try { _ = try f.consume(value); released = true }())
            XCTAssertFalse(released)
            XCTAssertTrue(f.commits.retired)
            let pending = try f.store.read().pending
            XCTAssertEqual(pending != nil, finalize)
            try f.sql("DROP TRIGGER fail_update")
            try f.reopen()
            let recovered = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
            if finalize { XCTAssertEqual(recovered, .finalized(try XCTUnwrap(pending))) }
            else { XCTAssertEqual(recovered, .unchanged(before)) }
            XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: value.operationID) }, finalize ? 1 : nil)
            XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent()?.snapshot.revision }, finalize ? 1 : 0)
            rejects(finalize ? .alreadyConsumed : .unavailableChallenge) { try f.consume(value) }
        }
    }
    func testSchemaUpgradeFailuresReconcileWithoutInventingOrLosingTables() throws {
        for finalize in [false, true] {
            let f = try Fixture(), before = try f.store.read().committed
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try f.sql("CREATE TRIGGER fail_update_schema BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try f.install())
            XCTAssertTrue(f.commits.retired)
            let pending = try f.store.read().pending
            try f.sql("DROP TRIGGER fail_update_schema")
            try f.reopen()
            let result = try JournalCheckpointRecovery.reconcile(journal: f.db, continuity: f.store)
            if finalize { XCTAssertEqual(result, .finalized(try XCTUnwrap(pending))) }
            else { XCTAssertEqual(result, .unchanged(before)) }
            XCTAssertEqual(try f.commits.read { try $0.storageSchemaVersion }, finalize ? 17 : 16)
            try f.install()
        }
    }
    func testUncheckpointedSchedulingTamperClosesTheWriterBeforeAnyNewIntent() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let value = try f.issue(.deferUpdate)
        try f.sql("UPDATE update_scheduling_state_v1 SET revision=x'0000000000000009' WHERE id=1", journal: true)
        XCTAssertThrowsError(try f.consume(value))
        XCTAssertTrue(f.commits.retired)
    }

    func testNewAccountAdoptsTheCurrentMachineGenerationWithoutInventingAnEarlierOffer() throws {
        let f = try Fixture(); try f.install()
        let first = try f.machine.select(f.machine.copy())
        let retired = try f.machine.store.retireUpdateCandidate(first)
        let second = try f.machine.select(first.preparation, replacing: retired)
        XCTAssertEqual(second.generation, 2)
        let before = try f.store.read().committed
        let beforePolicy = try f.commits.read { try $0.codePolicy() }
        let beforeRuntime = try f.machine.store.retainedRuntimeCompatibilityInputs()
        let bound = try f.retainCurrent()
        XCTAssertEqual(bound.snapshot.generation, second.generation)
        XCTAssertEqual(bound.snapshot.updateID, second.updateID)
        XCTAssertEqual(bound.snapshot.revision, 0); XCTAssertNil(bound.requestedAction)
        let after = try f.store.read().committed
        XCTAssertGreaterThan(after.currentAuthorityGeneration, before.currentAuthorityGeneration)
        XCTAssertEqual(after.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(after.journalHead, before.journalHead)
        XCTAssertEqual(try f.commits.read { try $0.codePolicy() }, beforePolicy)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs(), beforeRuntime)
    }
    func testWithdrawnAndReselectedSameReleaseCannotReviveUnusedControls() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        let committed = try f.issue(.deferUpdate); _ = try f.consume(committed)
        let pending = try f.issue(.cancelDrain)
        let first = try XCTUnwrap(f.machine.store.updateCandidate())
        let retired = try f.machine.store.retireUpdateCandidate(first)
        XCTAssertThrowsError(try f.issue(.deferUpdate))
        XCTAssertThrowsError(try f.consume(pending))
        let second = try f.machine.select(first.preparation, replacing: retired)
        XCTAssertEqual(first.updateID, second.updateID)
        let original = try XCTUnwrap(f.commits.read { try $0.updateSchedulingIntent() })
        XCTAssertThrowsError(try f.issue(.deferUpdate)) {
            XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .staleSchedulingState)
        }
        let next = try f.retainCurrent(expected: original.snapshot)
        XCTAssertEqual(next.snapshot.generation, second.generation); XCTAssertEqual(next.snapshot.revision, 0)
        XCTAssertNil(next.requestedAction)
        XCTAssertThrowsError(try f.consume(pending)) {
            XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .staleSchedulingState)
        }
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        XCTAssertEqual(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: committed.operationID) }, 1)
        let fresh = try f.issue(.installWhenCurrentWorkFinishes)
        XCTAssertEqual(fresh.expectedGeneration, second.generation)
        XCTAssertEqual(try f.consume(fresh).requestedAction, .installWhenCurrentWorkFinishes)
    }
    func testAnEscapedLeaseExpiresBeforeItCanBindIssueOrConsume() throws {
        let f = try Fixture(); try f.install(); let initial = try f.offer()
        let control = try f.issue(.deferUpdate), peer = try f.binding()
        var captured: LiveUpdateSchedulingCandidate?
        try f.withCandidate { captured = $0 }
        let escaped = try XCTUnwrap(captured)
        XCTAssertEqual(escaped.description, "LiveUpdateSchedulingCandidate(redacted)")
        XCTAssertEqual(escaped.debugDescription, escaped.description)
        XCTAssertThrowsError(try escaped.requireCurrent(macID: f.macID, accountID: f.accountID)) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .expired)
        }
        let before = try f.store.read()
        rejectsExpired { try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) {
            try $0.retainUpdateSchedulingOffer(candidate: escaped, expected: initial.snapshot)
        } }
        let now = f.nextNow()
        rejectsExpired { try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) {
            try $0.issueUpdateSchedulingControl(candidate: escaped, action: .deferUpdate,
                expected: initial.snapshot, binding: peer, nowUnixMillis: 1000, now: now)
        } }
        rejectsExpired { try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) {
            try $0.consumeUpdateSchedulingControl(candidate: escaped, canonicalControl: control.encode(limits: f.limits),
                signature: f.sign(control), binding: peer, nowUnixMillis: 1500, now: now)
        } }
        XCTAssertEqual(try f.store.read(), before)
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) })
        XCTAssertEqual(try f.consume(control).snapshot.revision, 1)
    }
    func testAnotherAccountsLiveLeaseCannotSelectThisAccountsOffer() throws {
        let first = try Fixture(), second = try Fixture(); try first.install(); try second.install()
        _ = try first.offer()
        try first.withCandidate { candidate in
            XCTAssertThrowsError(try second.commits.write(epoch: second.epoch, recoverRejectedBody: true) {
                try $0.retainUpdateSchedulingOffer(candidate: candidate, expected: nil)
            }) { XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .wrongScope) }
            XCTAssertThrowsError(try candidate.requireCurrent(macID: first.id(99), accountID: first.accountID)) {
                XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .wrongScope)
            }
            try candidate.requireCurrent(macID: first.macID, accountID: first.accountID)
        }
        XCTAssertNil(try second.commits.read { try $0.updateSchedulingIntent() })
    }
    func testCallbackFailureRetiresItsLeaseWithoutRetiringTheCurrentCandidate() throws {
        let f = try Fixture(); try f.install(); _ = try f.offer()
        var escaped: LiveUpdateSchedulingCandidate?
        XCTAssertThrowsError(try f.withCandidate { candidate -> Int in escaped = candidate; throw Fault.injected })
        rejectsExpired { try XCTUnwrap(escaped).requireCurrent(macID: f.macID, accountID: f.accountID) }
        XCTAssertTrue(try XCTUnwrap(f.machine.store.updateCandidate()).selected)
        XCTAssertEqual(try f.consume(f.issue(.deferUpdate)).snapshot.revision, 1)
    }
    func testAccountCommitKeepsTheMachineSelectionOwnedUntilBothStoresFinish() throws {
        let f = try Fixture(); try f.install(); let initial = try f.offer()
        let selected = try XCTUnwrap(f.machine.store.updateCandidate())
        let retained = try f.withCandidate { candidate in
            try f.commits.write(epoch: f.epoch, recoverRejectedBody: true) { tx in
                XCTAssertThrowsError(try f.machine.store.retireUpdateCandidate(selected)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                return try tx.retainUpdateSchedulingOffer(candidate: candidate, expected: initial.snapshot)
            }
        }
        XCTAssertEqual(retained, initial)
        XCTAssertEqual(try f.machine.store.updateCandidate(), selected)
    }
    func testRestoredOlderMachineRecordCannotLowerTheAccountSchedulingGeneration() throws {
        let f = try Fixture(); try f.install(); let original = try f.offer()
        let first = try XCTUnwrap(f.machine.store.updateCandidate())
        let retired = try f.machine.store.retireUpdateCandidate(first)
        _ = try f.machine.select(first.preparation, replacing: retired)
        let newer = try f.retainCurrent(expected: original.snapshot)
        try f.restoreCandidateForFault(first)
        rejects(.conflict) { try f.retainCurrent(expected: newer.snapshot) }
        XCTAssertThrowsError(try f.issue(.deferUpdate)) {
            XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .staleSchedulingState)
        }
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent() }, newer)
    }
    func testMaximumMachineGenerationDoesNotChangeSecurityFloorsOrWrap() throws {
        let f = try Fixture(); try f.install(); let original = try f.offer()
        let first = try XCTUnwrap(f.machine.store.updateCandidate())
        let maximum = try UpdateSchedulingCandidateRecord(macID: first.macID, installationID: first.installationID,
            inventoryRevision: first.inventoryRevision, preparation: first.preparation, generation: .max)
        try f.restoreCandidateForFault(maximum)
        let before = try f.store.read().committed
        let beforePolicy = try f.commits.read { try $0.codePolicy() }
        let beforeRuntime = try f.machine.store.retainedRuntimeCompatibilityInputs()
        let bound = try f.retainCurrent(expected: original.snapshot)
        XCTAssertEqual(bound.snapshot.generation, .max)
        let control = try f.issue(.deferUpdate)
        XCTAssertEqual(control.expectedGeneration, .max)
        let result = try f.consume(control)
        XCTAssertEqual(result.snapshot.generation, .max); XCTAssertEqual(result.snapshot.revision, 1)
        XCTAssertEqual(try f.retainCurrent(expected: result.snapshot), result)
        let after = try f.store.read().committed
        XCTAssertGreaterThan(after.currentAuthorityGeneration, before.currentAuthorityGeneration)
        XCTAssertEqual(after.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(after.journalHead, before.journalHead)
        XCTAssertEqual(try f.commits.read { try $0.codePolicy() }, beforePolicy)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs(), beforeRuntime)
    }
    private func rejectsExpired<Value>(_ body: () throws -> Value, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .expired, file: file, line: line)
        }
    }

    private typealias Fixture = UpdateSchedulingAccountFixture

}
