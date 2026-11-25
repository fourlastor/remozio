import CryptoKit
import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class ConsumptionJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let clock = UUID()
    private let key = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var bounds: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 512) } }
    private func open(_ fixture: Fixture, initialize: Bool = false, migrate: Int64? = nil, maximum: Int = 10,
                      account: UInt8 = 2) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(1), accountID: id(account), recordLimits: bounds,
            descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: maximum, busyMilliseconds: 100,
            initialize: initialize, migrateFromVersion: migrate)
    }
    private func descriptor(_ epoch: UInt8 = 3) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bounds), limits: bounds)
    }
    private func request(_ number: UInt8 = 4, kind: RequestKind = .command, action: CapturedAction? = nil,
                         phase: RequestPhase = .presented, challenge: UInt8 = 9) throws -> RetainedApprovalRequest {
        let selected = action ?? CapturedAction(choice: .execute, scope: .currentRequest)
        let payload = try IssuedRequestPayload(contract: RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1),
            macID: id(1), accountID: id(2), requestID: id(number), challenge: id(challenge, count: 32), requiredFeatures: [],
            createdUnixMilliseconds: 100, expiresUnixMilliseconds: 200,
            canonicalCapture: DeterministicCBOR.encode(.map([0: .text("private synthetic capture never persisted")]), limits: bounds),
            permittedActions: [selected, CapturedAction(choice: .decline, scope: .currentRequest)], bodyLimits: bounds, captureLimits: bounds)
        return try RetainedApprovalRequest(payload: payload, phase: phase,
            admittedAt: AuthorityMoment(epoch: clock, milliseconds: 100), deadlineMilliseconds: 200)
    }
    private func trust(_ request: RetainedApprovalRequest, active: Bool = true) throws -> ApprovalTrustSnapshot {
        let capabilities = ContractCapabilities(contracts: [request.payload.contract: []])
        let keys = try [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: key.publicKey.x963Representation)]
        return try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: UUID(), authorityCapabilities: capabilities,
            allowedContracts: [request.payload.contract], enrollments: [5, 8].map {
                try ApprovalEnrollment(phoneID: id($0), active: active, capabilities: capabilities, keys: keys)
            })
    }
    private func consume(_ transaction: JournalTransaction, _ writer: AuditEpochWriter, request: RetainedApprovalRequest,
                         head: UInt64 = 0, phone: UInt8 = 5, action: CapturedAction? = nil, event: UInt8 = 10,
                         now: UInt64 = 150, active: Bool = true, damageSignature: Bool = false) throws -> ConsumptionReceipt {
        let selected = action ?? request.payload.permittedActions[0]
        let requirement = try ActionPolicy.requirement(for: selected, requestKind: request.payload.contract.requestKind,
                                                       retainedPermittedActions: Set(request.payload.permittedActions))
        let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: request.payload.requestID,
            requestDigest: request.payload.requestDigest(bodyLimits: bounds, signingLimits: bounds), challenge: request.payload.challenge,
            phoneID: id(phone), keyID: id(requirement.keyClass == .biometric ? 6 : 7), action: selected).encode(limits: bounds)
        let purpose: SigningPurpose
        switch requirement.purpose {
        case .cancellation: purpose = .cancellation
        case .oneTimeUI: purpose = .oneTimeUI
        case .biometricAuthorization: purpose = .biometricAuthorization
        }
        var signature = try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: purpose,
            canonicalPayload: decision, payloadLimits: bounds, inputLimits: bounds)).rawRepresentation
        if damageSignature { signature[0] ^= 1 }
        return try transaction.consume(canonicalDecision: decision, signature: signature, retained: request, trust: trust(request, active: active),
            now: AuthorityMoment(epoch: clock, milliseconds: now), eventID: id(event), receiptTimeMs: 12345,
            writer: writer, expectedHead: head, requestLimits: bounds, signingLimits: bounds)
    }

    func testSignedPageContainsOnlyCommittedConsumptionAndOutcomeEvents() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let receipt = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write {
            _ = try transition($0, writer)
            throw Failure.injected
        })
        let outcome = try database.write { try transition($0, writer, event: .loseOutcome) }
        let replies = try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: key.publicKey.x963Representation,
            limits: AuditReplyLimits(batch: bounds, record: bounds, history: bounds, descriptor: bounds,
                signing: bounds, maximumRecords: 10)) { try self.key.signature(for: $0).rawRepresentation }
        let query = try AuditPageRequest(nonce: id(9, count: 32), epoch: id(3), generation: 7, after: 0)
        let reply = try replies.page(query, journal: database)
        XCTAssertTrue(try AuditBatchSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: reply.canonicalBody, payloadLimits: bounds, inputLimits: bounds))
        let batch = try AuditBatch.decode(reply.canonicalBody, batchLimits: bounds, recordLimits: bounds, maximumRecords: 10)
        XCTAssertEqual(batch.records, [receipt.event, outcome.event])
        XCTAssertEqual(batch.records.map(\.kind), [.consumed, .unknownOutcome])
        XCTAssertEqual(batch.head, 2)
    }

    func testFirstVerifiedPhoneWinsAndReopenCannotChangeItsDecision() throws {
        for firstDeclines in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true), request = try request()
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let decline = CapturedAction(choice: .decline, scope: .currentRequest)
            let winner = try database.write { try consume($0, writer, request: request, action: firstDeclines ? decline : nil) }
            XCTAssertEqual(winner.event.authentication, firstDeclines ? .decisionKey : .biometricKey)
            XCTAssertEqual(winner.event.outcome, firstDeclines ? .noDispatch : .accepted)
            XCTAssertThrowsError(try database.write { try consume($0, writer, request: request, head: 1, phone: 8,
                                                                 action: firstDeclines ? nil : decline, event: 11) }) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
            }
            XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
            XCTAssertEqual(try database.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords },
                           try [winner.event.encode(limits: bounds)])
            try database.close()
            let reopened = try open(fixture), newer = try reopened.write { try $0.createEpoch(descriptor(12)) }
            XCTAssertEqual(try reopened.read { try $0.consumption(requestID: id(4)) }, winner)
            XCTAssertThrowsError(try reopened.write { try consume($0, newer, request: request) }) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
            }
            XCTAssertEqual(try reopened.read { try $0.epoch(id(12))?.head }, 0)
            try reopened.close()
            XCTAssertNil(try Data(contentsOf: URL(fileURLWithPath: fixture.path)).range(of: Data("private synthetic capture never persisted".utf8)))
        }
    }

    func testAnotherAccountCannotConsumeTheRetainedRequest() throws {
        let firstFixture = try Fixture(), first = try open(firstFixture, initialize: true)
        let writer = try first.write { try $0.createEpoch(descriptor()) }
        let secondFixture = try Fixture(), second = try open(secondFixture, initialize: true, account: 9)
        XCTAssertThrowsError(try second.write { try consume($0, writer, request: request()) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .wrongScope)
        }
        XCTAssertNil(try second.read { try $0.consumption(requestID: id(4)) })
        XCTAssertNil(try first.read { try $0.consumption(requestID: id(4)) })
    }

    func testDuplicateAuditEventCannotLeaveASecondConsumption() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), head: 1) })
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(20)) })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testChangedChallengeCannotReuseConsumedRequestIdentity() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(challenge: 20), head: 1) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
        }
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
    }

    func testCurrentSignatureEnrollmentExpiryAndLifecycleAreCheckedBeforeWrites() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        for (phase, now, active, damaged, error) in [
            (RequestPhase.cancelled, UInt64(150), true, false, DecisionVerificationError.unavailableRequest),
            (.presented, 200, true, false, .expired), (.presented, 99, true, false, .invalidClock),
            (.presented, 150, false, false, .unavailableEnrollment), (.presented, 150, true, true, .invalidSignature),
        ] {
            XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(phase: phase), now: now,
                                                                 active: active, damageSignature: damaged) }) {
                XCTAssertEqual($0 as? DecisionVerificationError, error)
            }
            XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testUIActionsKeepTheirRequiredAuthenticationAndAuditCategory() throws {
        let cases: [(RequestKind, CapturedAction, AuditCategory, AuditAuthentication)] = [
            (.littleSnitch, .init(choice: .allowOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .denyOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .allowRule, scope: .forever), .littleSnitch, .biometricKey),
            (.onePasswordAccess, .init(choice: .approveAccess, scope: .currentRequest), .onePasswordAccess, .biometricKey),
            (.onePasswordUnlock, .init(choice: .unlockVault, scope: .currentRequest), .onePasswordUnlock, .biometricKey),
        ]
        for (kind, action, category, authentication) in cases {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let result = try database.write { try consume($0, writer, request: request(kind: kind, action: action)) }
            XCTAssertEqual(result.event.category, category)
            XCTAssertEqual(result.event.authentication, authentication)
            XCTAssertEqual(result.event.action, AuditActionMetadata(action: action))
            XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, result)
        }
    }

    func testFailureInEitherTableRollsBackBothEvenWhenCaught() throws {
        for table in ["consumptions_v1", "audit_records_v1"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            try fixture.sql("CREATE TRIGGER fail_write BEFORE INSERT ON \(table) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try database.write { transaction in
                XCTAssertThrowsError(try consume(transaction, writer, request: request()))
            }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
            XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
            try fixture.sql("DROP TRIGGER fail_write")
            _ = try database.write { try consume($0, writer, request: request()) }
        }
    }

    func testCallbackAndAutomaticRollbackLeaveNoPartialConsumption() throws {
        for automatic in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            if automatic { try fixture.sql("CREATE TRIGGER fail_write BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ROLLBACK,'injected'); END") }
            XCTAssertThrowsError(try database.write {
                _ = try consume($0, writer, request: request())
                throw Failure.injected
            })
            if automatic { XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) } }
            try database.close()
            if automatic { try fixture.sql("DROP TRIGGER fail_write") }
            let reopened = try open(fixture)
            XCTAssertNil(try reopened.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testHeadMismatchRollsBackInsertedConsumptionAndRetiresOwner() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), event: 11) }) {
            XCTAssertEqual($0 as? AuditJournalError, .headMismatch)
        }
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertNil(try reopened.read { try $0.consumption(requestID: id(20)) })
        XCTAssertNotNil(try reopened.read { try $0.consumption(requestID: id(4)) })
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testCapacityAndAuditRetentionNeverEvictOrResetTheWinner() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture, initialize: true, maximum: 0))
        let database = try open(fixture, initialize: true, maximum: 1)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        try database.write { try $0.prune(epoch: id(3), through: 1, expectedHead: 1) }
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), head: 1, event: 11) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .capacityExceeded)
        }
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(20)) })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testReadOnlyAndExpiredHandlesCannotConsume() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.read { try consume($0, writer, request: request()) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let escaped = try database.write { $0 }
        XCTAssertThrowsError(try consume(escaped, writer, request: request()))
        XCTAssertThrowsError(try escaped.consumption(requestID: id(4)))
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
    }

    func testExplicitVersionOneMigrationPreservesHistoryAndRejectsWrongScope() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let prior = try database.write { try consume($0, writer, request: request()) }
        try database.close()
        // Recreate the pre-consumption v1 layout. This is a fixture, never a recovery operation.
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; DROP TABLE consumption_outcomes_v1; DROP TABLE consumptions_v1; PRAGMA user_version=1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, migrate: 1, account: 9))
        XCTAssertEqual(try fixture.version(), 1)
        let migrated = try open(fixture, migrate: 1)
        XCTAssertEqual(try migrated.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 1, maximumBytes: 16384).canonicalRecords },
                       try [prior.event.encode(limits: bounds)])
        XCTAssertNil(try migrated.read { try $0.consumption(requestID: id(4)) }) // Audit history never recreates authority state.
        try migrated.close()
        XCTAssertEqual(try fixture.version(), 12)
        XCTAssertThrowsError(try open(fixture, migrate: 1))
        let reopened = try open(fixture)
        try reopened.close()
    }

    func testFailedMigrationAndMissingLedgerDoNotResetStorage() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try database.close()
        try fixture.sql("PRAGMA user_version=1") // Deliberate conflicting table.
        XCTAssertThrowsError(try open(fixture, migrate: 1))
        XCTAssertEqual(try fixture.version(), 1)
        try fixture.sql("PRAGMA user_version=12; DROP TABLE consumption_outcomes_v1; DROP TABLE consumptions_v1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, initialize: true))
        XCTAssertEqual(try fixture.version(), 12)
    }

    func testMalformedAndInconsistentReceiptsFailBoundedReads() throws {
        for mutation in ["UPDATE consumptions_v1 SET decision=x'01'", "UPDATE consumptions_v1 SET event=zeroblob(17000)",
                         "UPDATE consumptions_v1 SET request=zeroblob(16)"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request()) }
            try fixture.sql(mutation)
            let queryID = mutation.contains("request=") ? id(0) : id(4)
            XCTAssertThrowsError(try database.read { try $0.consumption(requestID: queryID) })
        }
    }

    private func transition(_ transaction: JournalTransaction, _ writer: AuditEpochWriter, request: UInt8 = 4,
                            revision: UInt64 = 0, event: RequestEvent = .beginDispatch, eventID: UInt8 = 11,
                            head: UInt64 = 1) throws -> ConsumptionOutcome {
        try transaction.transitionConsumption(requestID: id(request), expectedRevision: revision, event: event,
            eventID: id(eventID), receiptTimeMs: 12400, writer: writer, expectedHead: head)
    }

    func testCheckpointedStartupResumesAcrossBatchesWithoutRewritingTerminalOutcomes() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request(4)) }
        _ = try database.write { try consume($0, writer, request: request(6), head: 1, event: 11) }
        _ = try database.write { try transition($0, writer, request: 6, eventID: 12, head: 2) }
        let directory = fixture.root.appendingPathComponent("continuity")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        for name in ["writer.lock", "continuity.sqlite"] {
            let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
            guard fd >= 0 else { throw Failure.injected }
            Darwin.close(fd)
        }
        func openStore(_ initial: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: fixture.root.path,
                relativeDirectory: "continuity", owner: getuid()), macID: id(1), accountID: id(2), initialize: initial)
        }
        let initial = try database.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: id(3), generation: 1, authorityGeneration: try descriptor().generation) }
        let store = try openStore(initial)
        try database.close()
        let reopened = try open(fixture)
        let startup = try JournalStartupRecovery(journal: reopened, continuity: store, maximumRecords: 1, maximumBytes: 16384)
        guard case .recovering = try startup.start(descriptor: descriptor(20)) else { return XCTFail("startup did not begin") }
        guard case .recovering = try startup.advance() else { return XCTFail("first batch ended too soon") }
        XCTAssertThrowsError(try startup.completedWriter())
        let first = try XCTUnwrap(reopened.read { try $0.consumptionOutcome(requestID: id(4)) })
        XCTAssertEqual(first.phase, .unknown)
        XCTAssertEqual(try reopened.read { try $0.consumptionOutcome(requestID: id(6))?.phase }, .executing)
        XCTAssertEqual(try store.read().committed.journalHead, 1)
        try reopened.close(); store.close()
        let restarted = try open(fixture), restartedStore = try openStore()
        defer { try? restarted.close(); restartedStore.close() }
        let retry = try JournalStartupRecovery(journal: restarted, continuity: restartedStore,
            maximumRecords: 1, maximumBytes: 16384)
        guard case .recovering = try retry.start(descriptor: descriptor(21)) else { return XCTFail("restart did not begin") }
        guard case .recovering = try retry.advance() else { return XCTFail("terminal page ended too soon") }
        XCTAssertThrowsError(try retry.completedWriter())
        guard case .complete = try retry.advance() else { return XCTFail("second page did not finish") }
        XCTAssertEqual(try retry.completedWriter().epoch, id(21))
        XCTAssertEqual(try restarted.read { try $0.consumptionOutcome(requestID: id(4)) }, first)
        let second = try XCTUnwrap(restarted.read { try $0.consumptionOutcome(requestID: id(6)) })
        XCTAssertEqual(second.phase, .unknown)
        XCTAssertEqual(second.event.journalEpoch, id(21))
        XCTAssertEqual(second.revision, 2)
        XCTAssertEqual(try restartedStore.read().committed.journalHead, 1)
        XCTAssertNil(try restartedStore.read().pending)
    }

    func testRecoveryPagesAreOrderedBoundedAndKeepOutcomeEvidence() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request(6), event: 10) }
        _ = try database.write { try consume($0, writer, request: request(4), head: 1, event: 11) }
        _ = try database.write { try transition($0, writer, request: 6, eventID: 12, head: 2) }
        let first = try database.read { try $0.consumptionOutcomes(maximumRecords: 1, maximumBytes: 16384) }
        XCTAssertEqual(first.outcomes.map { $0.receipt.decision.requestID }, [id(4)])
        XCTAssertEqual(first.outcomes.first?.phase, .authorized)
        XCTAssertEqual(first.nextRequestID, id(4))
        let second = try database.read { try $0.consumptionOutcomes(afterRequestID: first.nextRequestID, maximumRecords: 1, maximumBytes: 16384) }
        XCTAssertEqual(second.outcomes.map { $0.receipt.decision.requestID }, [id(6)])
        XCTAssertEqual(second.outcomes.first?.phase, .executing)
        XCTAssertNil(second.nextRequestID)
        XCTAssertThrowsError(try database.read { try $0.consumptionOutcomes(maximumRecords: 1, maximumBytes: 1) }) {
            XCTAssertEqual($0 as? ConsumptionOutcomeError, .pageTooSmall)
        }
        let escaped = try database.read { $0 }
        XCTAssertThrowsError(try escaped.consumptionOutcomes(maximumRecords: 1, maximumBytes: 16384))
        try database.close()
        let reopened = try open(fixture)
        let all = try reopened.read { try $0.consumptionOutcomes(maximumRecords: 256, maximumBytes: 16384) }
        XCTAssertEqual(all.outcomes, first.outcomes + second.outcomes)
        XCTAssertNil(all.nextRequestID)
    }

    func testRecoveryBatchRecordsUnknownOnceInFreshEpoch() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request(4)) }
        _ = try database.write { try consume($0, writer, request: request(6), head: 1, event: 11) }
        _ = try database.write { try transition($0, writer, request: 6, eventID: 12, head: 2) }
        try database.close()
        let reopened = try open(fixture)
        let fresh = try reopened.write { try $0.createEpoch(descriptor(20)) }
        let first = try reopened.write { try $0.reconcileInterruptedConsumptions(maximumRecords: 1, maximumBytes: 16384,
                                                                               writer: fresh, expectedHead: 0) }
        XCTAssertEqual(first.changedCount, 1)
        XCTAssertEqual(first.nextRequestID, id(4))
        let second = try reopened.write { try $0.reconcileInterruptedConsumptions(afterRequestID: first.nextRequestID,
            maximumRecords: 1, maximumBytes: 16384, writer: fresh, expectedHead: first.journalHead) }
        XCTAssertEqual(second.changedCount, 1)
        XCTAssertNil(second.nextRequestID)
        XCTAssertEqual(second.journalHead, 2)
        for requestID in [id(4), id(6)] {
            let outcome = try XCTUnwrap(reopened.read { try $0.consumptionOutcome(requestID: requestID) })
            XCTAssertEqual(outcome.phase, .unknown)
            XCTAssertEqual(outcome.event.reason, .authorityRestarted)
            XCTAssertEqual(outcome.event.journalEpoch, id(20))
        }
        let retry = try reopened.write { try $0.reconcileInterruptedConsumptions(maximumRecords: 256, maximumBytes: 16384,
                                                                               writer: fresh, expectedHead: 2) }
        XCTAssertEqual(retry.changedCount, 0)
        XCTAssertEqual(retry.journalHead, 2)
    }

    func testRecoveryPageByteBoundaryAndCorruptOutcomeFailWithoutSkipping() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let receipt = try database.write { try consume($0, writer, request: request(4)) }
        _ = try database.write { try consume($0, writer, request: request(6), head: 1, event: 11) }
        let size = try receipt.decision.encode(limits: bounds).count + receipt.event.encode(limits: bounds).count
        let page = try database.read { try $0.consumptionOutcomes(maximumRecords: 256, maximumBytes: size) }
        XCTAssertEqual(page.outcomes.count, 1)
        XCTAssertEqual(page.nextRequestID, id(4))
        XCTAssertThrowsError(try database.read { try $0.consumptionOutcomes(maximumRecords: 1, maximumBytes: size - 1) })
        try fixture.sql("UPDATE consumptions_v1 SET event=x'00' WHERE request=x'06060606060606060606060606060606'")
        XCTAssertThrowsError(try database.read { try $0.consumptionOutcomes(afterRequestID: page.nextRequestID,
                                                                         maximumRecords: 256, maximumBytes: 16384) })
    }

    func testRecoveryBatchRollsBackEarlierOutcomesWhenLaterAuditInsertFails() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request(4)) }
        _ = try database.write { try consume($0, writer, request: request(6), head: 1, event: 11) }
        try database.close()
        let reopened = try open(fixture)
        let fresh = try reopened.write { try $0.createEpoch(descriptor(20)) }
        try fixture.sql("CREATE TRIGGER fail_second BEFORE INSERT ON audit_records_v1 WHEN NEW.sequence=x'0000000000000002' BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try reopened.write { transaction in
            XCTAssertThrowsError(try transaction.reconcileInterruptedConsumptions(maximumRecords: 256, maximumBytes: 16384,
                                                                                  writer: fresh, expectedHead: 0))
        })
        for requestID in [id(4), id(6)] {
            XCTAssertEqual(try reopened.read { try $0.consumptionOutcome(requestID: requestID)?.phase }, .authorized)
        }
        XCTAssertEqual(try reopened.read { try $0.epoch(id(20))?.head }, 0)
        try fixture.sql("DROP TRIGGER fail_second")
        let retried = try reopened.write { try $0.reconcileInterruptedConsumptions(maximumRecords: 256, maximumBytes: 16384,
                                                                                 writer: fresh, expectedHead: 0) }
        XCTAssertEqual(retried.changedCount, 2)
        XCTAssertEqual(retried.journalHead, 2)
    }

    func testRecoveryRejectsLiveEpochAndStaleEmptyBatchHead() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try $0.reconcileInterruptedConsumptions(maximumRecords: 1, maximumBytes: 16384,
                                                                                       writer: writer, expectedHead: 1) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .invalidConfiguration)
        }
        XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4))?.phase }, .authorized)
        XCTAssertThrowsError(try database.write { try $0.reconcileInterruptedConsumptions(afterRequestID: id(255),
            maximumRecords: 1, maximumBytes: 16384, writer: writer, expectedHead: 0) }) {
            XCTAssertEqual($0 as? AuditJournalError, .headMismatch)
        }
    }

    func testDurableVerifiedOutcomesKeepTheWinnerAcrossReopen() throws {
        for (event, phase) in [(RequestEvent.verifySuccess, RequestPhase.succeeded), (.verifyFailure, .failed)] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let receipt = try database.write { try consume($0, writer, request: request()) }
            let initial = try XCTUnwrap(database.read { try $0.consumptionOutcome(requestID: id(4)) })
            XCTAssertEqual(initial.revision, 0); XCTAssertEqual(initial.phase, .authorized)
            let attempted = try database.write { try transition($0, writer) }
            XCTAssertEqual(attempted.revision, 1); XCTAssertEqual(attempted.phase, .executing)
            let result = try database.write { try transition($0, writer, revision: 1, event: event, eventID: 12, head: 2) }
            XCTAssertEqual(result.phase, phase); XCTAssertEqual(result.revision, 2)
            XCTAssertEqual(result.receipt, receipt)
            XCTAssertEqual(result.event.authentication, .system)
            for late in [RequestEvent.beginDispatch, .verifySuccess, .verifyFailure, .loseOutcome] {
                XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 2, event: late, eventID: 13, head: 3) }) {
                    XCTAssertEqual($0 as? LifecycleError, .terminal)
                }
            }
            XCTAssertEqual(try database.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 3, maximumBytes: 16384).canonicalRecords },
                           try [receipt.event, attempted.event, result.event].map { try $0.encode(limits: bounds) })
            try database.close()
            let reopened = try open(fixture)
            XCTAssertEqual(try reopened.read { try $0.consumptionOutcome(requestID: id(4)) }, result)
            XCTAssertEqual(try reopened.read { try $0.consumption(requestID: id(4)) }, receipt)
        }
    }

    func testUnknownIsTerminalBeforeAndAfterDispatchAttempt() throws {
        for attempted in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request()) }
            if attempted { _ = try database.write { try transition($0, writer) } }
            let unknown = try database.write { try transition($0, writer, revision: attempted ? 1 : 0, event: .loseOutcome,
                                                              eventID: 12, head: attempted ? 2 : 1) }
            XCTAssertEqual(unknown.phase, .unknown)
            for event in [RequestEvent.beginDispatch, .verifySuccess, .proveNoDispatch, .restartAuthority] {
                XCTAssertThrowsError(try database.write { try transition($0, writer, revision: unknown.revision, event: event,
                                                                          eventID: 13, head: attempted ? 3 : 2) }) {
                    XCTAssertEqual($0 as? LifecycleError, .terminal)
                }
            }
            XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4)) }, unknown)
        }
    }

    func testStaleAndInvalidOutcomeTransitionsLeaveHistoryUnchanged() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        for event in [RequestEvent.verifySuccess, .verifyFailure, .present, .authorize, .expire, .cancel] {
            XCTAssertThrowsError(try database.write { try transition($0, writer, event: event) }) {
                XCTAssertEqual($0 as? LifecycleError, .invalidTransition)
            }
        }
        XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 1) }) {
            XCTAssertEqual($0 as? ConsumptionOutcomeError, .staleRevision)
        }
        XCTAssertThrowsError(try database.write { try transition($0, writer, request: 20) }) {
            XCTAssertEqual($0 as? ConsumptionOutcomeError, .missingConsumption)
        }
        let attempted = try database.write { try transition($0, writer) }
        XCTAssertThrowsError(try database.write { try transition($0, writer, event: .loseOutcome, eventID: 12, head: 2) }) {
            XCTAssertEqual($0 as? ConsumptionOutcomeError, .staleRevision)
        }
        XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4)) }, attempted)
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 2)
    }

    func testDeclineCannotDispatchAndNoDispatchProofRequiresThePreDispatchPhase() throws {
        for declined in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request(), action: declined ? .init(choice: .decline, scope: .currentRequest) : nil) }
            if declined {
                XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4))?.phase }, .declined)
                XCTAssertThrowsError(try database.write { try transition($0, writer) }) { XCTAssertEqual($0 as? LifecycleError, .terminal) }
            } else {
                let result = try database.write { try transition($0, writer, event: .proveNoDispatch) }
                XCTAssertEqual(result.phase, .cancelled); XCTAssertEqual(result.event.outcome, .noDispatch)
                XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 1, head: 2) }) {
                    XCTAssertEqual($0 as? LifecycleError, .terminal)
                }
            }
        }
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        _ = try database.write { try transition($0, writer) }
        XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 1, event: .proveNoDispatch, eventID: 12, head: 2) }) {
            XCTAssertEqual($0 as? LifecycleError, .invalidTransition)
        }
    }

    func testRestartObservationUsesFreshEpochWithoutReconsumingOldRequest() throws {
        for attempted in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let receipt = try database.write { try consume($0, writer, request: request()) }
            if attempted { _ = try database.write { try transition($0, writer) } }
            try database.close()
            let reopened = try open(fixture), fresh = try reopened.write { try $0.createEpoch(descriptor(12)) }
            let outcome = try reopened.write { try transition($0, fresh, revision: attempted ? 1 : 0,
                                                              event: .restartAuthority, eventID: 13, head: 0) }
            XCTAssertEqual(outcome.phase, .unknown); XCTAssertEqual(outcome.event.reason, .authorityRestarted)
            XCTAssertEqual(outcome.event.journalEpoch, id(12)); XCTAssertEqual(outcome.receipt, receipt)
            XCTAssertEqual(try reopened.read { try $0.consumptionOutcome(requestID: id(4)) }, outcome)
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, attempted ? 2 : 1)
            XCTAssertThrowsError(try reopened.write { try consume($0, fresh, request: request(), head: 1) }) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
            }
        }
    }

    func testOutcomeAndAuditRollbackTogetherOnInsertUpdateAndCaughtFailures() throws {
        for updating in [false, true] {
            for table in ["consumption_outcomes_v1", "audit_records_v1"] {
                let fixture = try Fixture(), database = try open(fixture, initialize: true)
                let writer = try database.write { try $0.createEpoch(descriptor()) }
                _ = try database.write { try consume($0, writer, request: request()) }
                if updating { _ = try database.write { try transition($0, writer) } }
                let before = try database.read { try $0.consumptionOutcome(requestID: id(4)) }
                let operation = updating && table == "consumption_outcomes_v1" ? "UPDATE" : "INSERT"
                try fixture.sql("CREATE TRIGGER fail_outcome BEFORE \(operation) ON \(table) BEGIN SELECT RAISE(ABORT,'injected'); END")
                XCTAssertThrowsError(try database.write { transaction in
                    XCTAssertThrowsError(try transition(transaction, writer, revision: updating ? 1 : 0,
                        event: .loseOutcome, eventID: 12, head: updating ? 2 : 1))
                }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
                XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4)) }, before)
                XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, updating ? 2 : 1)
            }
        }
    }

    func testOutcomeAutomaticRollbackAndHeadMismatchRetireOwnerWithoutPhantomResult() throws {
        for automatic in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request()) }
            let before = try database.write { try transition($0, writer) }
            if automatic { try fixture.sql("CREATE TRIGGER fail_outcome BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ROLLBACK,'injected'); END") }
            XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 1, event: .verifySuccess,
                                                                      eventID: 12, head: automatic ? 2 : 1) })
            XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
            try database.close()
            if automatic { try fixture.sql("DROP TRIGGER fail_outcome") }
            let reopened = try open(fixture)
            XCTAssertEqual(try reopened.read { try $0.consumptionOutcome(requestID: id(4)) }, before)
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 2)
        }
    }

    func testOutcomeCallbackRollbackAndDuplicateEventPreservePreviousState() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write {
            _ = try transition($0, writer)
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4))?.revision }, 0)
        _ = try database.write { try transition($0, writer) }
        XCTAssertThrowsError(try database.write { try transition($0, writer, revision: 1, event: .verifyFailure, eventID: 11, head: 2) })
        XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4))?.phase }, .executing)
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 2)
    }

    func testOutcomesRemainAvailableAtLedgerCapacityAndAfterAuditPruning() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true, maximum: 1)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let receipt = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), head: 1, event: 20) })
        _ = try database.write { try transition($0, writer) }
        let outcome = try database.write { try transition($0, writer, revision: 1, event: .verifySuccess, eventID: 12, head: 2) }
        try database.write { try $0.prune(epoch: id(3), through: 3, expectedHead: 3) }
        XCTAssertEqual(try database.read { try $0.consumptionOutcome(requestID: id(4)) }, outcome)
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, receipt)
    }

    func testOutcomeTransactionLifetimeAndAccountIsolation() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.read { try transition($0, writer) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try database.write { $0 }
        XCTAssertThrowsError(try transition(escaped, writer))
        XCTAssertThrowsError(try escaped.consumptionOutcome(requestID: id(4)))
        let otherFixture = try Fixture(), other = try open(otherFixture, initialize: true, account: 9)
        XCTAssertNil(try other.read { try $0.consumptionOutcome(requestID: id(4)) })
        XCTAssertThrowsError(try other.write { try transition($0, writer) }) {
            XCTAssertEqual($0 as? ConsumptionOutcomeError, .missingConsumption)
        }
    }

    func testVersionTwoMigrationKeepsReceiptsAndCreatesNoOutcomeClaims() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let receipt = try database.write { try consume($0, writer, request: request()) }
        try database.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; DROP TABLE consumption_outcomes_v1; PRAGMA user_version=2")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, migrate: 2, account: 9))
        let migrated = try open(fixture, migrate: 2)
        let outcome = try XCTUnwrap(migrated.read { try $0.consumptionOutcome(requestID: id(4)) })
        XCTAssertEqual(outcome.receipt, receipt); XCTAssertEqual(outcome.revision, 0)
        XCTAssertEqual(outcome.phase, .authorized) // Stored receipt only; startup recovery must reconcile this.
        try migrated.close()
        XCTAssertEqual(try fixture.version(), 12)
        for version: Int64 in [0, 1, 2, 3, 4, 5, 6, 99] { XCTAssertThrowsError(try open(fixture, migrate: version)) }
    }

    func testFailedOutcomeMigrationRollsBackTheNewConsumptionTable() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try database.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; DROP TABLE consumption_outcomes_v1; DROP TABLE consumptions_v1; PRAGMA user_version=1; CREATE TABLE consumption_outcomes_v1(conflict INTEGER)")
        XCTAssertThrowsError(try open(fixture, migrate: 1))
        XCTAssertEqual(try fixture.version(), 1)
        XCTAssertNoThrow(try fixture.sql("CREATE TABLE consumptions_v1(probe INTEGER)"))
    }

    func testMalformedAndImpossibleOutcomeRowsFailBoundedReads() throws {
        for mutation in ["UPDATE consumption_outcomes_v1 SET event=x'01'",
                         "UPDATE consumption_outcomes_v1 SET event=zeroblob(17000)",
                         "PRAGMA ignore_check_constraints=ON; UPDATE consumption_outcomes_v1 SET revision=0",
                         "UPDATE consumption_outcomes_v1 SET revision=2",
                         "UPDATE consumption_outcomes_v1 SET event=(SELECT event FROM consumptions_v1)"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request()) }
            _ = try database.write { try transition($0, writer) }
            try fixture.sql(mutation)
            XCTAssertThrowsError(try database.read { try $0.consumptionOutcome(requestID: id(4)) })
        }
    }

    private final class Fixture {
        let root: URL
        var path: String { root.appendingPathComponent("store/journal.sqlite").path }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: root.appendingPathComponent("store"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(root.appendingPathComponent("store/" + name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        private func connection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
            var db: OpaquePointer?
            let rc = sqlite3_open(path, &db)
            defer { if let db { sqlite3_close(db) } }
            guard rc == SQLITE_OK, let db else { throw Failure.injected }
            return try body(db)
        }
        func sql(_ query: String) throws {
            try connection { guard sqlite3_exec($0, query, nil, nil, nil) == SQLITE_OK else { throw Failure.injected } }
        }
        func version() throws -> Int64 {
            try connection { db in
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw Failure.injected }
                return sqlite3_column_int64(stmt, 0)
            }
        }
    }
}
