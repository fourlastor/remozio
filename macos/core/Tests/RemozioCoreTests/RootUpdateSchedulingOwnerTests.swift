import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RootUpdateSchedulingOwnerTests: XCTestCase {
    private enum Fault: Error { case injected }
    func testEveryActionUsesTheCommittedChallengeAndConsumesExactlyOnce() throws {
        let f = try Fixture()
        for action in UpdateSchedulingAction.allCases {
            let reply = try f.issue(action)
            let response = try RootUpdateSchedulingChallenge.decode(reply.canonicalChallenge, limits: f.data.limits)
            let control = try UpdateSchedulingControl.decode(response.canonicalControl, limits: f.data.limits)
            XCTAssertEqual(response.queryNonce, f.nonce); XCTAssertEqual(control.action, action)
            XCTAssertEqual(control.macID, f.data.macID); XCTAssertEqual(control.accountID, f.data.accountID)
            XCTAssertTrue(try RootUpdateSchedulingChallengeSignature.verify(signature: reply.signature,
                authorityPublicKey: f.data.rootKey.publicKey.x963Representation, wireVersion: 1,
                canonicalPayload: reply.canonicalChallenge, payloadLimits: f.data.limits, inputLimits: f.data.limits))
            XCTAssertNil(try f.data.store.read().pending)
            let result = try f.consume(control)
            XCTAssertEqual(result.requestedAction, action)
            XCTAssertEqual(result.snapshot.revision, control.expectedRevision + 1)
            XCTAssertNil(try f.data.store.read().pending)
            XCTAssertThrowsError(try f.consume(control)); XCTAssertFalse(f.owner.retired)
        }
    }
    func testStatusIsReadOnlyAndDoesNotCreateAChallenge() throws {
        let f = try Fixture(), before = try f.data.store.read()
        XCTAssertEqual(try f.status(), try f.status()); XCTAssertEqual(try f.data.store.read(), before)
    }
    func testMalformedNonceFailsBeforeCommitOrSigning() throws {
        let f = try Fixture(), before = try f.data.store.read(); var signed = false
        XCTAssertThrowsError(try f.issue(.deferUpdate, nonce: Data(repeating: 1, count: 31), sign: { _ in signed = true; return Data() }))
        XCTAssertFalse(signed); XCTAssertEqual(try f.data.store.read(), before); XCTAssertFalse(f.owner.retired)
    }
    func testWrongAuthenticatedTransportFailsBeforeSigningAndPreservesTheCheckpoint() throws {
        let f = try Fixture(), before = try f.data.store.read(), original = try f.data.binding()
        let peer = try AuthorityPeerBinding(scope: original.scope,
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: original.revision)
        var signed = false
        XCTAssertThrowsError(try f.issue(.deferUpdate, binding: peer, sign: { _ in signed = true; return Data() }))
        XCTAssertFalse(signed); XCTAssertEqual(try f.data.store.read(), before); XCTAssertFalse(f.owner.retired)
    }
    func testFailedRootSignatureDoesNotPublishOrConsumeTheRetainedControl() throws {
        let f = try Fixture(), before = try f.status()
        XCTAssertThrowsError(try f.issue(.deferUpdate, sign: { _ in Data(repeating: 0, count: 64) })) {
            XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .invalidSignature)
        }
        XCTAssertEqual(try f.status(), before); XCTAssertNil(try f.data.store.read().pending)
        XCTAssertFalse(f.owner.retired)
    }
    func testExpiryDuringSigningCannotPublishAResponse() throws {
        let f = try Fixture(); var clock: UInt64 = 100
        XCTAssertThrowsError(try f.issue(.deferUpdate, now: { f.data.now(clock) }, sign: { input in
            clock = 5000; return try f.data.rootKey.signature(for: input).rawRepresentation
        })) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .expired) }
        XCTAssertEqual(try f.status().snapshot.revision, 0)
    }
    func testExpiryDuringTheFinalHostReadCannotPublishAResponse() throws {
        let f = try Fixture(); var clock: UInt64 = 100, checks = 0
        XCTAssertThrowsError(try f.issue(.deferUpdate, now: { f.data.now(clock) }, verifyHost: { tx in
            try f.checkHost(tx); checks += 1; if checks == 3 { clock = 5000 }
        })) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .expired) }
        XCTAssertEqual(checks, 3); XCTAssertEqual(try f.status().snapshot.revision, 0)
    }
    func testClockRegressionAndFailureRetireTheOwnerBeforePublication() throws {
        for fail in [false, true] {
            let f = try Fixture(); var calls = 0
            XCTAssertThrowsError(try f.issue(.deferUpdate, now: {
                calls += 1
                if calls == 4 { if fail { throw Fault.injected }; return f.data.now(99) }
                return f.data.now(UInt64(100 + calls))
            }))
            XCTAssertTrue(f.owner.retired); XCTAssertThrowsError(try f.status())
        }
    }
    func testHostFailureBeforeIssuanceLeavesTheCheckpointUnchanged() throws {
        let f = try Fixture(), before = try f.data.store.read()
        XCTAssertThrowsError(try f.issue(.deferUpdate, verifyHost: { _ in throw Fault.injected }))
        XCTAssertEqual(try f.data.store.read(), before); XCTAssertFalse(f.owner.retired)
    }
    func testExpiryBeforeTheCommitBoundaryRollsBackConsumption() throws {
        let f = try Fixture(), control = try f.control(), before = try f.data.store.read(); var samples = 0
        XCTAssertThrowsError(try f.consume(control, now: {
            samples += 1; return f.data.now(samples == 1 ? 200 : 5000)
        })) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .expired) }
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) })
    }
    func testSlowFinalHostValidationCannotCommitAnExpiredControl() throws {
        let f = try Fixture(), control = try f.control(), before = try f.data.store.read()
        var clock: UInt64 = 200, checks = 0
        XCTAssertThrowsError(try f.consume(control, now: { f.data.now(clock) }, verifyHost: { tx in
            try f.checkHost(tx); checks += 1; if checks == 2 { clock = 5000 }
        })) { XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .expired) }
        XCTAssertEqual(checks, 2); XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) })
    }
    func testFailedFinalHostValidationReturnsNoOfferResultAfterDurableRetention() throws {
        let f = try Fixture(), before = try f.status()
        let current = try XCTUnwrap(f.data.machine.store.updateCandidate())
        let withdrawn = try f.data.machine.store.retireUpdateCandidate(current)
        _ = try f.data.machine.select(current.preparation, replacing: withdrawn)
        var checks = 0
        XCTAssertThrowsError(try f.data.withCandidate { candidate in
            try f.owner.retainUpdateSchedulingOffer(candidate: candidate, expected: before.snapshot, verifyHost: { tx in
                try f.checkHost(tx); checks += 1; if checks == 2 { throw Fault.injected }
            })
        })
        XCTAssertEqual(checks, 2); XCTAssertNil(try f.data.store.read().pending)
        XCTAssertEqual(try f.status().snapshot.generation, before.snapshot.generation + 1)
    }
    func testAClockFailureAfterCommitReturnsNoSuccessAndRetainsReconciliationState() throws {
        let f = try Fixture(), control = try f.control(); var samples = 0
        XCTAssertThrowsError(try f.consume(control, now: {
            samples += 1; if samples == 3 { throw Fault.injected }; return f.data.now(UInt64(200 + samples))
        }))
        XCTAssertTrue(f.owner.retired); XCTAssertNil(try f.data.store.read().pending)
        XCTAssertEqual(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) }, 1)
        XCTAssertEqual(try f.data.db.read { try $0.updateSchedulingIntent()?.requestedAction }, .deferUpdate)
    }
    func testUncertainChallengeCommitNeverCallsTheSigner() throws {
        for finalize in [false, true] {
            let f = try Fixture(); let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try f.data.sql("CREATE TRIGGER fail_root_update BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END")
            var signed = false
            XCTAssertThrowsError(try f.issue(.deferUpdate, sign: { _ in signed = true; return Data() }))
            XCTAssertFalse(signed); XCTAssertTrue(f.owner.retired)
            XCTAssertEqual(try f.data.store.read().pending != nil, finalize)
        }
    }
    func testAnOwnerWithoutTheIndependentCheckpointCannotIssueOrRetain() throws {
        let f = try Fixture(checkpointed: false)
        XCTAssertThrowsError(try f.issue(.deferUpdate)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable) }
        XCTAssertThrowsError(try f.data.withCandidate {
            try f.owner.retainUpdateSchedulingOffer(candidate: $0, expected: nil, verifyHost: f.checkHost)
        })
    }
    func testPolicyAttachmentIsExplicitAndRejectsReplacementConfiguration() throws {
        let f = try Fixture(enabled: false)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 16)
        let policy = try UpdateSchedulingJournalPolicy(clockEpoch: f.data.clock, challengeLifetimeMillis: 1000,
            maximumOperations: 20, payloadLimits: f.data.limits, signingLimits: f.data.limits)
        XCTAssertTrue(try f.data.db.enableUpdateSchedulingPolicy(policy, macID: f.data.macID, accountID: f.data.accountID))
        XCTAssertFalse(try f.data.db.enableUpdateSchedulingPolicy(policy, macID: f.data.macID, accountID: f.data.accountID))
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 16)
        let changed = try UpdateSchedulingJournalPolicy(clockEpoch: UUID(), challengeLifetimeMillis: 1000,
            maximumOperations: 20, payloadLimits: f.data.limits, signingLimits: f.data.limits)
        XCTAssertThrowsError(try f.data.db.enableUpdateSchedulingPolicy(changed, macID: f.data.macID, accountID: f.data.accountID))
        try f.data.withCandidate {
            try f.owner.enableUpdateSchedulingStorage(candidate: $0, verifyHost: f.checkHost)
            _ = try f.owner.retainUpdateSchedulingOffer(candidate: $0, expected: nil, verifyHost: f.checkHost)
        }
        XCTAssertEqual(try f.status().snapshot.generation, 1)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 17)
    }
    func testNativeEntryPointsRefuseOrdinaryIdentityBeforeCallbacksOrMutation() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("This case requires an ordinary process identity.") }
        let f = try Fixture(), peer = try f.data.binding(), before = try f.data.store.read()
        let directory = f.data.root.appendingPathComponent("ordinary-root")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for name in ["writer.lock", "journal.sqlite"] {
            XCTAssertTrue(FileManager.default.createFile(atPath: directory.appendingPathComponent(name).path,
                contents: Data(), attributes: [.posixPermissions: 0o600]))
        }
        let journal = AuthorityJournal(database: try JournalDatabase(lease: ProtectedJournalLease(anchor: f.data.root.path,
            relativeDirectory: "ordinary-root", owner: getuid()), macID: f.data.macID, accountID: f.data.accountID,
            recordLimits: f.data.limits, descriptorLimits: f.data.limits, decisionLimits: f.data.limits,
            maximumConsumptions: 20, busyMilliseconds: 100, initialize: true))
        defer { try? journal.close() }
        let policy = try UpdateSchedulingJournalPolicy(clockEpoch: f.data.clock, challengeLifetimeMillis: 1000,
            maximumOperations: 20, payloadLimits: f.data.limits, signingLimits: f.data.limits)
        var sampled = false
        try f.data.withCandidate { candidate in
            XCTAssertThrowsError(try journal.enableUpdateScheduling(candidate: candidate, policy: policy,
                macID: f.data.macID, accountID: f.data.accountID)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            XCTAssertThrowsError(try journal.retainUpdateSchedulingOffer(candidate: candidate, expected: nil)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try journal.observeUpdateScheduling(candidate: candidate, binding: peer)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try journal.consumeUpdateScheduling(candidate: candidate, canonicalControl: Data(),
                signature: Data(), binding: peer, now: { sampled = true; return f.data.now() }, wall: { 1000 })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
        XCTAssertFalse(sampled); XCTAssertEqual(try f.data.store.read(), before)
    }

    private typealias Fixture = RootUpdateSchedulingFixture

}
