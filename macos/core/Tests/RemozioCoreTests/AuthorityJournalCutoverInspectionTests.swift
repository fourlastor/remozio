import CryptoKit
import Darwin
import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class AuthorityJournalCutoverInspectionTests: XCTestCase {
    private typealias Fixture = CutoverJournalFixture
    private enum Failure: Error { case expected }
    private func files(_ fixture: Fixture) throws -> [String: Data] {
        var result: [String: Data] = [:]
        for name in ["journal", "continuity"] {
            let directory = fixture.root.appendingPathComponent(name)
            for file in try FileManager.default.contentsOfDirectory(atPath: directory.path) {
                result[name + "/" + file] = try Data(contentsOf: directory.appendingPathComponent(file))
            }
        }
        return result
    }
    private func stop(_ fixture: Fixture) throws { try fixture.journal.close(); fixture.store.close() }
    private func inspection(_ fixture: Fixture, policy: AuthorityCodePolicy? = nil,
                            verify: @escaping () throws -> Void = {}) throws -> AuthorityJournalCutoverInspection {
        try stop(fixture)
        return try AuthorityJournalCutoverInspection(storage: fixture.openTransferredStorage(readOnlyForCutover: true),
            expectedPolicy: policy, verifyCurrent: verify)
    }
    private func policy(_ hash: UInt8 = 1) throws -> AuthorityCodePolicy {
        try .init(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority", installedGeneration: 1,
            minimumGeneration: 1, codeDirectoryHash: Data(repeating: hash, count: 20), active: true)])
    }
    private func addOutcomes(_ phases: [RequestPhase], to fixture: Fixture) throws {
        let limits = fixture.limits, key = P256.Signing.PrivateKey(), clock = UUID()
        func id(_ byte: UInt8, count: Int = 16) -> Data { Data(repeating: byte, count: count) }
        func unique() -> Data { var value = UUID().uuid; return withUnsafeBytes(of: &value) { Data($0) } }
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let keys = try [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: key.publicKey.x963Representation)]
        let trust = try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: UUID(), authorityCapabilities: capabilities,
            allowedContracts: [contract], enrollments: [.init(phoneID: id(5), active: true, capabilities: capabilities, keys: keys)])
        try CheckpointedJournal(journal: fixture.journal, continuity: fixture.store).write(epoch: fixture.epoch) { transaction in
            var head = try XCTUnwrap(transaction.epoch(fixture.epoch)).head
            for phase in phases {
                let action = CapturedAction(choice: phase == .declined ? .decline : .execute, scope: .currentRequest)
                let requestID = unique()
                let payload = try IssuedRequestPayload(contract: contract, macID: id(1), accountID: id(2), requestID: requestID,
                    challenge: id(9, count: 32), requiredFeatures: [], createdUnixMilliseconds: 100, expiresUnixMilliseconds: 200,
                    canonicalCapture: DeterministicCBOR.encode(.map([0: .text("disposable fixture")]), limits: limits),
                    permittedActions: [CapturedAction(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                    bodyLimits: limits, captureLimits: limits)
                let request = try RetainedApprovalRequest(payload: payload, phase: .presented,
                    admittedAt: AuthorityMoment(epoch: clock, milliseconds: 100), deadlineMilliseconds: 200)
                let declined = phase == .declined
                let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: requestID,
                    requestDigest: payload.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: payload.challenge,
                    phoneID: id(5), keyID: id(declined ? 7 : 6), action: action).encode(limits: limits)
                let signature = try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
                    purpose: declined ? .cancellation : .biometricAuthorization, canonicalPayload: decision,
                    payloadLimits: limits, inputLimits: limits)).rawRepresentation
                _ = try transaction.consume(canonicalDecision: decision, signature: signature, retained: request, trust: trust,
                    now: AuthorityMoment(epoch: clock, milliseconds: 150), eventID: unique(), receiptTimeMs: nil,
                    writer: fixture.writer, expectedHead: head, requestLimits: limits, signingLimits: limits)
                head += 1
                let events: [RequestEvent]
                switch phase {
                case .declined, .authorized: events = []
                case .executing: events = [.beginDispatch]
                case .unknown: events = [.beginDispatch, .loseOutcome]
                case .succeeded: events = [.beginDispatch, .verifySuccess]
                case .failed: events = [.beginDispatch, .verifyFailure]
                case .cancelled: events = [.proveNoDispatch]
                default: throw Failure.expected
                }
                for (revision, event) in events.enumerated() {
                    _ = try transaction.transitionConsumption(requestID: requestID, expectedRevision: UInt64(revision), event: event,
                        eventID: unique(), receiptTimeMs: nil, writer: fixture.writer, expectedHead: head)
                    head += 1
                }
            }
        }
    }
    func testEmptyJournalRemainsUnchangedAndBothWriterLeasesStayHeld() throws {
        let fixture = try Fixture(), before = try files(fixture), current = try inspection(fixture)
        XCTAssertEqual(current.snapshot.totalOutcomes, 0); XCTAssertFalse(current.snapshot.requiresStartupOutcomeRecovery)
        try current.validate()
        XCTAssertThrowsError(try fixture.openJournal()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        XCTAssertThrowsError(try fixture.openStore()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        XCTAssertEqual(try files(fixture), before)
        try current.close(); try current.close()
        let journal = try fixture.openJournal(); try journal.close()
        let continuity = try fixture.openStore(); continuity.close()
        XCTAssertThrowsError(try current.validate())
        XCTAssertEqual(try files(fixture), before)
    }
    func testInterruptedRowsAndTerminalUnknownsArePreservedWithoutRestoringAPermit() throws {
        let fixture = try Fixture()
        try addOutcomes([.authorized, .executing, .unknown, .cancelled, .succeeded, .failed, .declined], to: fixture)
        let checkpoint = try fixture.store.read().committed, before = try files(fixture), current = try inspection(fixture)
        defer { try? current.close() }
        XCTAssertEqual(current.snapshot.totalOutcomes, 7); XCTAssertEqual(current.snapshot.interruptedAuthorizations, 1)
        XCTAssertEqual(current.snapshot.interruptedDispatches, 1); XCTAssertEqual(current.snapshot.terminalUnknowns, 1)
        XCTAssertTrue(current.snapshot.requiresStartupOutcomeRecovery)
        XCTAssertEqual(current.snapshot.checkpoint, checkpoint); try current.validate()
        XCTAssertEqual(try files(fixture), before)
    }
    func testTerminalUnknownHistoryAloneDoesNotRequireStartupOutcomeRecovery() throws {
        let fixture = try Fixture(); try addOutcomes([.unknown], to: fixture)
        let current = try inspection(fixture); defer { try? current.close() }
        XCTAssertFalse(current.snapshot.requiresStartupOutcomeRecovery); XCTAssertEqual(current.snapshot.terminalUnknowns, 1)
        try current.validate()
    }
    func testMultiplePagesAreCountedUnderOneCommittedBoundary() throws {
        let fixture = try Fixture(maximumConsumptions: 300)
        try addOutcomes(Array(repeating: .authorized, count: 257), to: fixture)
        let before = try files(fixture), current = try inspection(fixture); defer { try? current.close() }
        XCTAssertEqual(current.snapshot.totalOutcomes, 257); XCTAssertEqual(current.snapshot.interruptedAuthorizations, 257)
        try current.validate(); XCTAssertEqual(try files(fixture), before)
    }
    func testReadOnlyConnectionsRejectEveryMutationBeforeItsBody() throws {
        let fixture = try Fixture(); try stop(fixture)
        let journal = try fixture.openJournal(readOnlyForCutover: true)
        let store = try fixture.openStore(readOnlyForCutover: true)
        defer { try? journal.close(); store.close() }
        let before = try files(fixture), checkpoint = try store.read().committed
        XCTAssertThrowsError(try journal.write { _ in XCTFail("Read-only journal executed a write body") }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        XCTAssertThrowsError(try store.requireRecovery()) { XCTAssertEqual($0 as? ContinuityStoreError, .unavailable) }
        let candidate = try checkpoint.successor(authorityDigest: checkpoint.authorityDigest, ledgerDigest: checkpoint.ledgerDigest,
            journalEpoch: checkpoint.journalEpoch, journalHead: checkpoint.journalHead)
        XCTAssertThrowsError(try store.prepare(expected: checkpoint, candidate: candidate))
        XCTAssertEqual(try files(fixture), before)
    }
    func testWritableConnectionsCannotBeLabeledAsCutoverInspectionAndFailureReleasesThem() throws {
        let fixture = try Fixture(); try stop(fixture)
        XCTAssertThrowsError(try AuthorityJournalCutoverInspection(storage: fixture.openTransferredStorage(), expectedPolicy: nil, verifyCurrent: {})) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let journal = try fixture.openJournal(); try journal.close()
        let store = try fixture.openStore(); store.close()
    }
    func testPendingCheckpointAndRepairFlagsAreNotRecoveredOrRewritten() throws {
        for repair in [false, true] {
            let fixture = try Fixture(), checkpoint = try fixture.store.read().committed
            if repair { try fixture.store.requireRecovery() }
            else {
                let candidate = try checkpoint.successor(authorityDigest: checkpoint.authorityDigest, ledgerDigest: checkpoint.ledgerDigest,
                    journalEpoch: checkpoint.journalEpoch, journalHead: checkpoint.journalHead)
                try fixture.store.prepare(expected: checkpoint, candidate: candidate)
            }
            let before = try files(fixture)
            XCTAssertThrowsError(try inspection(fixture)); XCTAssertEqual(try files(fixture), before)
            let journal = try fixture.openJournal(); try journal.close()
        }
    }
    func testExpectedCodePolicyMustMatchTheCommittedJournal() throws {
        let fixture = try Fixture(), selected = try policy()
        _ = try CheckpointedJournal(journal: fixture.journal, continuity: fixture.store).write(epoch: fixture.epoch) {
            try $0.installCodePolicy(selected, expectedRevision: nil)
        }
        let before = try files(fixture)
        XCTAssertThrowsError(try inspection(fixture, policy: policy(2))) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
        XCTAssertEqual(try files(fixture), before)
        let current = try inspection(fixture, policy: selected); defer { try? current.close() }
        XCTAssertEqual(current.snapshot.schemaVersion, 13); try current.validate()
    }
    func testWALHeadersAndEveryRecoverySidecarAreRefusedWithoutRepair() throws {
        for name in ["journal", "continuity"] {
            for variant in 0..<4 {
                let fixture = try Fixture(); try stop(fixture)
                let path = fixture.root.appendingPathComponent(name + "/" + name + ".sqlite")
                if variant == 0 {
                    var bytes = try Data(contentsOf: path); bytes[18] = 2; bytes[19] = 2; try bytes.write(to: path)
                } else {
                    let sidecar = URL(fileURLWithPath: path.path + ["", "-journal", "-wal", "-shm"][variant])
                    try Data([0x77]).write(to: sidecar); XCTAssertEqual(chmod(sidecar.path, 0o600), 0)
                }
                let before = try files(fixture)
                XCTAssertThrowsError(try inspection(fixture)); XCTAssertEqual(try files(fixture), before)
            }
        }
    }
    func testLostOwnerRetiresValidationButKeepsBothLeasesUntilClose() throws {
        let fixture = try Fixture(); var valid = true
        let current = try inspection(fixture, verify: { if !valid { throw Failure.expected } })
        valid = false; XCTAssertThrowsError(try current.validate())
        valid = true; XCTAssertThrowsError(try current.validate())
        XCTAssertThrowsError(try fixture.openJournal()); XCTAssertThrowsError(try fixture.openStore())
        try current.close()
        let journal = try fixture.openJournal(); try journal.close()
    }
    func testConstructorOwnerFailureReleasesBothTransferredLeases() throws {
        let fixture = try Fixture(), before = try files(fixture)
        XCTAssertThrowsError(try inspection(fixture, verify: { throw Failure.expected }))
        XCTAssertEqual(try files(fixture), before)
        let journal = try fixture.openJournal(); try journal.close()
        let store = try fixture.openStore(); store.close()
    }
    func testMismatchedCheckpointIsRefusedWithoutMarkingRepairOrRewritingFiles() throws {
        let fixture = try Fixture()
        _ = try fixture.journal.write { try $0.installCodePolicy(policy(), expectedRevision: nil) }
        let before = try files(fixture)
        XCTAssertThrowsError(try inspection(fixture)) { XCTAssertEqual($0 as? CheckpointedJournal.Failure, .boundaryMismatch) }
        XCTAssertEqual(try files(fixture), before)
        let store = try fixture.openStore(); defer { store.close() }
        XCTAssertFalse(try store.read().recoveryRequired)
    }
    func testReadOnlyModeCannotInitializeEitherStore() throws {
        let fixture = try Fixture(), checkpoint = try fixture.store.read().committed
        try stop(fixture)
        let before = try files(fixture)
        XCTAssertThrowsError(try fixture.openJournal(initialize: true, readOnlyForCutover: true))
        XCTAssertThrowsError(try fixture.openStore(initial: checkpoint, readOnlyForCutover: true))
        XCTAssertEqual(try files(fixture), before)
        let journal = try fixture.openJournal(); try journal.close()
        let store = try fixture.openStore(); store.close()
    }
    func testReplacedDatabaseRetiresInspectionAndRetainsItsWriterLocksThroughCleanup() throws {
        let fixture = try Fixture(), current = try inspection(fixture)
        let path = fixture.root.appendingPathComponent("journal/journal.sqlite"), old = path.appendingPathExtension("old")
        XCTAssertEqual(rename(path.path, old.path), 0)
        try Data(contentsOf: old).write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
        XCTAssertThrowsError(try current.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try fixture.openJournal()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        XCTAssertThrowsError(try fixture.openStore()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try current.close()
        let journal = try fixture.openJournal(); try journal.close()
        let store = try fixture.openStore(); store.close()
    }
    func testNativeInitializedFactoryRefusesOrdinaryIdentityBeforeOpeningStores() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        let fixture = try RuntimeActivationFixture(), activityFixture = try ReleaseActivityFixture(), activity = try activityFixture.open()
        let token = try activity.acquireExclusive(); defer { token.close() }
        let initial = try XCTUnwrap(fixture.machine.initialization(accountID: fixture.account.accountID))
        XCTAssertThrowsError(try AuthorityJournalCutoverInspection.openInitialized(initialization: initial, policy: fixture.plan.host.codePolicy,
            rootActivity: token, verifyOwnerAndFence: { XCTFail("Root guard must precede store access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
    }
}
