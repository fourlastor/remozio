import CryptoKit
import Darwin
import Foundation
import Synchronization
import LocalAuthentication
import Security
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class ApprovalRequestCoordinatorTests: XCTestCase {
    private enum Failure: Error { case fixture }
    private let clock = UUID()
    private let key = P256.Signing.PrivateKey()
    private let decisionKey = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 12, maxItems: 256) } }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1) } }
    private var capabilities: ContractCapabilities { get throws { try .init(contracts: [contract: [1]]) } }
    private func now(_ n: UInt64 = 110) -> AuthorityMoment { .init(epoch: clock, milliseconds: n) }
    private func draft(capture: Data = Data([0xa0]), deadline: UInt64 = 200) throws -> ApprovalRequestDraft {
        try .init(contract: contract, requiredFeatures: [1], capture: capture,
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: now(100), deadlineMilliseconds: deadline, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
    }
    private func descriptor(_ epoch: UInt8) throws -> AuditEpochDescriptor {
        try .decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(UInt64(epoch)), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
    }
    private func open(_ fixture: Fixture, initialize: Bool, routingPolicy: RoutingJournalPolicy? = nil) throws -> JournalDatabase {
        try .init(lease: fixture.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 30, busyMilliseconds: 100, initialize: initialize, routingPolicy: routingPolicy)
    }
    private func setup(_ fixture: Fixture, routingPolicy: RoutingJournalPolicy? = nil) throws -> (JournalDatabase, AuditEpochWriter) {
        let db = try open(fixture, initialize: true, routingPolicy: routingPolicy)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor(3)) }
        let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation),
            ]))
        _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
            eventID: id(30), receiptTimeMs: 900, writer: writer, expectedAuditHead: 0) }
        return (db, writer)
    }
    private func owner(_ db: JournalDatabase, _ writer: AuditEpochWriter, maximum: Int = 8, bytes: Int = 32768,
                       wakes: Int = 1024) throws -> ApprovalRequestCoordinator {
        try .init(database: db, writer: writer, clockEpoch: clock, maximumRequests: maximum, maximumRetainedBytes: bytes,
            requestLimits: limits, captureLimits: limits, decisionLimits: limits, signingLimits: limits, auditLimits: limits,
            maximumWakeDeliveries: wakes)
    }
    private func journalOwner(_ fixture: Fixture, enrollment: StoredApprovalEnrollment? = nil) throws -> AuthorityJournal {
        let limits = try limits, capabilities = try capabilities, contract = try contract
        let descriptor = try descriptor(3), clock = clock, anchor = fixture.root.path
        let db = try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 30, busyMilliseconds: 100, initialize: true)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor) }
        if let enrollment {
            _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
                eventID: Data(repeating: 30, count: 16), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
        }
        let requests = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: clock,
            maximumRequests: 8, maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        return AuthorityJournal(requests: requests)
    }
    func testPublicGenericCommandAdmissionRejectsBeforeClockAndStorageChanges() throws {
        for checkpointed in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture)
            let requests: ApprovalRequestCoordinator, store: ContinuityStore?
            if checkpointed {
                let owned = try checkpointedOwner(fixture, db, writer)
                requests = owned.0; store = owned.1
            } else { requests = try owner(db, writer); store = nil }
            defer { try? db.close(); store?.close() }
            let before = try events(db, writer), boundary = try store?.read()
            XCTAssertThrowsError(try requests.admit(draft(), now: now(150), receiptTimeMs: nil)) {
                XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft)
            }
            XCTAssertEqual(try events(db, writer), before)
            if let boundary { XCTAssertEqual(try store?.read(), boundary) }
            // The rejected call must not advance the owner's clock or prevent later fixture work.
            let request = try requests.admitFixture(draft(), now: now(), receiptTimeMs: nil)
            XCTAssertEqual(try requests.state(requestID: request.requestID).phase, .queued)
        }
    }

    func testPublicGenericNonCommandAdmissionPreservesExistingActions() throws {
        for (kind, choice) in [(RequestKind.onePasswordAccess, ActionChoice.approveAccess),
                               (.onePasswordUnlock, .unlockVault), (.littleSnitch, .allowOnce)] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true)
            defer { try? db.close() }
            let contract = try RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1)
            let capabilities = ContractCapabilities(contracts: [contract: []])
            _ = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let writer = try db.write { try $0.createEpoch(descriptor(3)) }, requests = try owner(db, writer)
            let actions = [CapturedAction(choice: choice, scope: .currentRequest), CapturedAction(choice: .decline, scope: .currentRequest)]
            let observed = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]), actions: actions,
                firstObservedAt: now(100), deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
            let request = try requests.admit(observed, now: now(), receiptTimeMs: nil)
            XCTAssertEqual(request.contract, contract); XCTAssertEqual(request.permittedActions, actions)
            XCTAssertEqual(try requests.state(requestID: request.requestID).phase, .queued)
            XCTAssertEqual(try events(db, writer).last?.kind, .requestCreated)
        }
    }

    func testSharedJournalOwnsRequestStateAndRejectsReentry() throws {
        let fixture = try Fixture(), journal = try journalOwner(fixture)
        let draft = try draft(), time = now()
        let request = try journal.withRequests { try $0.admitFixture(draft, now: time, receiptTimeMs: 1001) }
        let state = try journal.withRequests { owner in
            XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot().revision })
            XCTAssertThrowsError(try journal.close())
            XCTAssertThrowsError(try journal.withRequests { try $0.state(requestID: request.requestID) })
            return try owner.state(requestID: request.requestID)
        }
        XCTAssertEqual(state.phase, .queued)
        try journal.read { _ in
            XCTAssertThrowsError(try journal.withRequests { try $0.state(requestID: request.requestID) }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID) }, state)
        try journal.close()
        XCTAssertThrowsError(try journal.withRequests { try $0.state(requestID: request.requestID) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
    }
    func testSharedRequestOperationExcludesTrustReads() throws {
        let fixture = try Fixture(), journal = try journalOwner(fixture)
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let attempted = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let operation = expectation(description: "request operation"), reader = expectation(description: "trust reader")
        DispatchQueue.global().async {
            defer { operation.fulfill() }
            do {
                try journal.withRequests { _ in
                    entered.signal()
                    guard release.wait(timeout: .now() + 5) == .success else { throw Failure.fixture }
                }
            } catch { XCTFail("Request operation failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            defer { finished.signal(); reader.fulfill() }
            attempted.signal()
            do { _ = try journal.trustSnapshot(maximumPayloadBytes: 1024) }
            catch { XCTFail("Trust read failed: \(error)") }
        }
        XCTAssertEqual(attempted.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(finished.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        wait(for: [operation, reader], timeout: 3)
        try journal.close()
    }
    func testExpirySweepHandlesOnlyElapsedPendingRequestsOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let queued = try owner.admitFixture(draft(), now: now(), receiptTimeMs: 1001)
        let presented = try owner.admitFixture(draft(), now: now(), receiptTimeMs: 1001)
        _ = try owner.markPresented(requestID: presented.requestID, now: now(), receiptTimeMs: 1001)
        let later = try owner.admitFixture(draft(deadline: 300), now: now(), receiptTimeMs: 1001)
        let authorized = try owner.admitFixture(draft(), now: now(), receiptTimeMs: 1001)
        _ = try consume(owner, authorized)
        XCTAssertTrue(try owner.expirePending(now: now(199), receiptTimeMs: 1099).isEmpty)
        let expired = try owner.expirePending(now: now(200), receiptTimeMs: 1100)
        XCTAssertEqual(Set(expired.map(\.requestID)), Set([queued.requestID, presented.requestID]))
        XCTAssertTrue(expired.allSatisfy { $0.phase == .expired && $0.reason == .authorizationExpired })
        XCTAssertEqual(try owner.state(requestID: later.requestID).phase, .queued)
        XCTAssertEqual(try owner.state(requestID: authorized.requestID).phase, .authorized)
        let count = try events(db, writer).count
        XCTAssertTrue(try owner.expirePending(now: now(201), receiptTimeMs: 1101).isEmpty)
        XCTAssertEqual(try events(db, writer).count, count)
        try db.close()
    }
    func testExpirySweepRollsBackEveryRequestWhenLaterAuditInsertFails() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let first = try owner.admitFixture(draft(), now: now(), receiptTimeMs: 1001)
        let second = try owner.admitFixture(draft(), now: now(), receiptTimeMs: 1001)
        let count = try events(db, writer).count
        try fixture.sql("CREATE TRIGGER fail_sweep BEFORE INSERT ON audit_records_v1 WHEN (SELECT COUNT(*) FROM audit_records_v1) > \(count) BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.expirePending(now: now(200), receiptTimeMs: 1100))
        XCTAssertEqual(try owner.state(requestID: first.requestID).phase, .queued)
        XCTAssertEqual(try owner.state(requestID: second.requestID).phase, .queued)
        XCTAssertEqual(try events(db, writer).count, count)
        try fixture.sql("DROP TRIGGER fail_sweep")
        XCTAssertEqual(try owner.expirePending(now: now(200), receiptTimeMs: 1100).count, 2)
        try db.close()
    }
    func testExpirySweepRejectsClosedStorageEvenWhenEmpty() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        try db.close()
        XCTAssertThrowsError(try owner.expirePending(now: now(200), receiptTimeMs: 1100)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
    }
    private func decision(_ request: IssuedRequestPayload, decline: Bool = false) throws -> (Data, Data) {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            phoneID: id(5), keyID: id(decline ? 7 : 6), action: request.permittedActions[decline ? 1 : 0]).encode(limits: limits)
        return (body, try (decline ? decisionKey : key).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: decline ? .cancellation : .biometricAuthorization,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation)
    }
    private func consume(_ owner: ApprovalRequestCoordinator, _ request: IssuedRequestPayload, time: UInt64 = 110) throws -> ConsumptionReceipt {
        let (body, signature) = try decision(request)
        return try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), now: now(time), receiptTimeMs: 1001)
    }
    private func events(_ db: JournalDatabase, _ writer: AuditEpochWriter) throws -> [AuditEventMetadata] {
        try db.read { try $0.page(epoch: writer.epoch, after: 0, maximumRecords: 50, maximumBytes: 32768).canonicalRecords.map {
            try AuditEventMetadata.decode($0, limits: limits)
        } }
    }

    private func checkpointedOwner(_ fixture: Fixture, _ db: JournalDatabase, _ writer: AuditEpochWriter) throws -> (ApprovalRequestCoordinator, ContinuityStore) {
        let directory = fixture.root.appendingPathComponent("continuity")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for name in ["writer.lock", "continuity.sqlite"] {
            let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
            guard fd >= 0 else { throw Failure.fixture }; Darwin.close(fd)
        }
        let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch,
            generation: 1, authorityGeneration: 3) }
        let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity", owner: getuid()),
            macID: id(1), accountID: id(2), initialize: initial)
        let owner = try ApprovalRequestCoordinator(database: db, continuity: store, writer: writer, clockEpoch: clock,
            maximumRequests: 8, maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        return (owner, store)
    }

    private func assertCheckpoint(_ db: JournalDatabase, _ store: ContinuityStore, _ writer: AuditEpochWriter) throws {
        let state = try store.read()
        XCTAssertNil(state.pending)
        XCTAssertEqual(state.committed, try db.read { try CheckpointedJournal.checkpoint(transaction: $0,
            epoch: writer.epoch, generation: state.committed.generation, authorityGeneration: state.committed.authorityGeneration) })
    }

    func testPairedStartupMarksInterruptedConsumptionUnknownWithoutRestoringRequest() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture)
        let (requests, store) = try checkpointedOwner(fixture, db, writer)
        let request = try requests.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        _ = try consume(requests, request)
        try db.close(); store.close()
        let limits = try limits, anchor = fixture.root.path
        let storage = try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), recordLimits: limits,
                descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 30, busyMilliseconds: 100, initialize: false)
        }, openContinuity: { excluded in
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: getuid(),
                excludingDirectory: excluded), macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: nil)
        })
        let restarted = try AuthorityJournal(storage: storage)
        try restarted.prepareRequests(clockEpoch: AuthorityClock().epoch, maximumPayloadBytes: 4096)
        let requestID = request.requestID
        let outcome = try restarted.withRequests { try $0.historicalOutcome(requestID: requestID) }
        XCTAssertEqual(outcome?.phase, .unknown)
        XCTAssertEqual(outcome?.event.reason, .authorityRestarted)
        XCTAssertThrowsError(try restarted.withRequests { try $0.state(requestID: requestID) })
        try restarted.close()
    }

    private func pairingAttempt(_ db: JournalDatabase, authority: P256.Signing.PrivateKey,
                                replacement: PairingReplacement? = nil) throws -> (PairingEnrollmentAttempt, Data) {
        let trust = try db.read { try $0.approvalTrustSnapshot() }
        let scope = try ChannelScope(macID: id(1), accountID: id(2), phoneID: id(8), enrollmentEpoch: id(10))
        let phoneKey = P256.Signing.PrivateKey(), transport = P256.Signing.PrivateKey()
        let offers = try [ChannelRole.phone, .mac].enumerated().map { index, role in
            try ChannelOffer(role: role, scope: scope, nonce: id(UInt8(20 + index), 32), envelopeVersions: [1],
                requests: [ChannelRequestCapability(kind: 0, wireVersion: 1, schemaVersion: 1, features: [1])], auditVersions: [1])
        }
        var revision = trust.revision.uuid
        let transcript = try PairingTranscript(setupID: id(31), challenge: id(32, 32), phone: offers[0], mac: offers[1],
            minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: authority.publicKey.x963Representation,
            macTransportKey: transport.publicKey.x963Representation,
            transportKey: PairingKey(keyID: id(33), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            decisionKey: PairingKey(keyID: id(34), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: PairingKey(keyID: id(35), publicKey: phoneKey.publicKey.x963Representation),
            enrollmentTag: id(36, 32), replacement: replacement, expectedTrustRevision: withUnsafeBytes(of: &revision) { Data($0) },
            issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
        return (try PairingEnrollmentAttempt(transcript: transcript, trusted: trust, authorizedReplacement: replacement,
            authorityPublicKey: authority.publicKey.x963Representation, transportPublicKey: transport.publicKey.x963Representation,
            minimumEnvelopeVersion: 1, started: now(100), startedAtUnixMillis: 1000, deadlineMilliseconds: 1100),
            try phoneKey.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation)
    }
    private func pairingBinding(_ db: JournalDatabase) throws -> AuthorityPeerBinding {
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096) }
        return AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first { $0.scope.phoneID == id(8) }), revision: trust.revision)
    }
    private func commitPairing(_ requests: ApprovalRequestCoordinator, _ attempt: PairingEnrollmentAttempt, proof: Data,
                               authority: P256.Signing.PrivateKey, replacement: Bool = false,
                               authorize: () throws -> Void = {}, verify: (JournalTransaction) throws -> Void = { _ in },
                               clock: (() throws -> AuthorityMoment)? = nil, sign: ((Data) throws -> Data)? = nil) throws -> Data {
        try requests.commitPairing(attempt, biometricProof: proof, authorityPublicKey: authority.publicKey.x963Representation,
            addEventID: id(40), removalEventID: replacement ? id(41) : nil, receiptTimeMs: 1001, gateway: nil,
            verifyHost: verify, recheckAdministrator: authorize, now: clock ?? { self.now() },
            sign: sign ?? { try authority.signature(for: $0).rawRepresentation }).receipt
    }

    func testPairingProductionBoundaryRejectsAnUnpairedJournalOwner() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), unpaired = try owner(db, writer)
        defer { try? db.close() }
        let before = try events(db, writer)
        XCTAssertThrowsError(try unpaired.requirePairingCheckpoint()) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable)
        }
        XCTAssertEqual(try events(db, writer), before)
        let (paired, store) = try checkpointedOwner(fixture, db, writer)
        defer { store.close() }
        XCTAssertNoThrow(try paired.requirePairingCheckpoint())
        try assertCheckpoint(db, store, writer)
    }

    func testPairingCommitsCheckpointBeforeSigningAndRejectsReplay() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey()
        let (requests, store) = try checkpointedOwner(fixture, db, writer), (attempt, proof) = try pairingAttempt(db, authority: authority)
        defer { try? db.close(); store.close() }
        var authorized = 0, signed = 0
        let receipt = try commitPairing(requests, attempt, proof: proof, authority: authority, authorize: { authorized += 1 }, sign: {
            signed += 1; try self.assertCheckpoint(db, store, writer)
            XCTAssertEqual(try store.read().committed.generation, 2)
            XCTAssertEqual(try db.read { try $0.approvalEnrollments().count }, 2)
            return try authority.signature(for: $0).rawRepresentation
        })
        XCTAssertEqual(authorized, 1); XCTAssertEqual(signed, 1)
        XCTAssertTrue(try attempt.transcript.verify(signature: receipt, publicKey: authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertFalse(try attempt.transcript.verify(signature: receipt, publicKey: authority.publicKey.x963Representation, purpose: .phoneBiometric))
        let eventsBefore = try events(db, writer)
        XCTAssertThrowsError(try commitPairing(requests, attempt, proof: proof, authority: authority))
        XCTAssertEqual(try events(db, writer), eventsBefore); try assertCheckpoint(db, store, writer)
    }

    func testPairingDeniedConsentBadProofAndExpiryNeverSignOrEnroll() throws {
        for mode in 0...3 {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey()
            let (requests, store) = try checkpointedOwner(fixture, db, writer), (attempt, proof) = try pairingAttempt(db, authority: authority)
            defer { try? db.close(); store.close() }
            let before = try db.read { try $0.approvalTrustSnapshot().revision }, eventsBefore = try events(db, writer)
            var signed = false
            XCTAssertThrowsError(try commitPairing(requests, attempt, proof: mode == 1 ? id(0, 64) : proof, authority: authority,
                authorize: { if mode == 0 { throw Failure.fixture } }, clock: {
                    if mode == 3 { throw Failure.fixture }
                    return self.now(mode == 2 ? 1100 : 110)
                }, sign: { _ in signed = true; throw Failure.fixture }))
            XCTAssertFalse(signed); XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, before)
            XCTAssertEqual(try events(db, writer), eventsBefore); try assertCheckpoint(db, store, writer)
        }
    }

    func testPairingLostReceiptRecoversAfterRestartWithoutAnotherCommit() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey()
        let (requests, store) = try checkpointedOwner(fixture, db, writer), (attempt, proof) = try pairingAttempt(db, authority: authority)
        XCTAssertThrowsError(try commitPairing(requests, attempt, proof: proof, authority: authority, sign: { _ in throw Failure.fixture }))
        try assertCheckpoint(db, store, writer)
        let expectedEvents = try events(db, writer)
        requests.close(); try db.close(); store.close()
        let reopened = try open(fixture, initialize: false)
        let continuity = try ContinuityStore(lease: ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity", owner: getuid()),
            macID: id(1), accountID: id(2), initialize: nil)
        defer { try? reopened.close(); continuity.close() }
        let restarted = try ApprovalRequestCoordinator(database: reopened, continuity: continuity, writer: writer, clockEpoch: UUID(),
            maximumRequests: 8, maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        let receipt = try XCTUnwrap(restarted.pairingReceipt(setupID: attempt.transcript.setupID, binding: pairingBinding(reopened),
            authorityPublicKey: authority.publicKey.x963Representation, verifyHost: { _ in },
            sign: { try authority.signature(for: $0).rawRepresentation }))
        XCTAssertTrue(try attempt.transcript.verify(signature: receipt, publicKey: authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(try events(reopened, writer), expectedEvents); try assertCheckpoint(reopened, continuity, writer)
    }

    func testPairingReceiptRequiresCurrentBindingAndExpectedAuthority() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey(), requests = try owner(db, writer)
        defer { try? db.close() }
        let (attempt, proof) = try pairingAttempt(db, authority: authority)
        _ = try commitPairing(requests, attempt, proof: proof, authority: authority)
        let binding = try pairingBinding(db), before = try events(db, writer)
        let stale = try AuthorityPeerBinding(scope: binding.scope, transportPublicKey: binding.transportPublicKey, revision: UUID())
        var signed = 0
        func receipt(_ setup: Data, _ peer: AuthorityPeerBinding, _ key: Data) throws -> Data? {
            try requests.pairingReceipt(setupID: setup, binding: peer, authorityPublicKey: key, verifyHost: { _ in }, sign: {
                signed += 1; return try authority.signature(for: $0).rawRepresentation
            })
        }
        XCTAssertThrowsError(try receipt(attempt.transcript.setupID, stale, authority.publicKey.x963Representation))
        XCTAssertThrowsError(try receipt(attempt.transcript.setupID, binding, P256.Signing.PrivateKey().publicKey.x963Representation))
        XCTAssertNil(try receipt(id(99), binding, authority.publicKey.x963Representation))
        XCTAssertEqual(signed, 0)
        XCTAssertThrowsError(try requests.pairingReceipt(setupID: attempt.transcript.setupID, binding: binding,
            authorityPublicKey: authority.publicKey.x963Representation, verifyHost: { _ in }, sign: { _ in self.id(0, 64) }))
        XCTAssertEqual(try events(db, writer), before)
    }

    func testPairingReplacementUsesOneCheckpointForRevocationEnrollmentAndAudit() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey()
        let (requests, store) = try checkpointedOwner(fixture, db, writer)
        defer { try? db.close(); store.close() }
        let (attempt, proof) = try pairingAttempt(db, authority: authority, replacement: PairingReplacement(phoneID: id(5), epoch: id(9)))
        _ = try commitPairing(requests, attempt, proof: proof, authority: authority, replacement: true, sign: {
            try self.assertCheckpoint(db, store, writer)
            XCTAssertEqual(try store.read().committed.generation, 2)
            let enrollments = try db.read { try $0.approvalEnrollments() }
            XCTAssertFalse(try XCTUnwrap(enrollments.first { $0.approval.phoneID == self.id(5) }).approval.active)
            XCTAssertTrue(try XCTUnwrap(enrollments.first { $0.approval.phoneID == self.id(8) }).approval.active)
            XCTAssertEqual(try self.events(db, writer).count, 3)
            return try authority.signature(for: $0).rawRepresentation
        })
    }

    func testPairingRevokedWhileSigningCannotReturnReceipt() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey(), requests = try owner(db, writer)
        defer { try? db.close() }
        let (attempt, proof) = try pairingAttempt(db, authority: authority)
        _ = try commitPairing(requests, attempt, proof: proof, authority: authority)
        let binding = try pairingBinding(db)
        XCTAssertThrowsError(try requests.pairingReceipt(setupID: attempt.transcript.setupID, binding: binding,
            authorityPublicKey: authority.publicKey.x963Representation, verifyHost: { _ in }, sign: { input in
                _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: self.id(8), epoch: self.id(10),
                    expectedTrustRevision: binding.revision, eventID: self.id(42), receiptTimeMs: 3000, writer: writer, expectedAuditHead: 2) }
                return try authority.signature(for: input).rawRepresentation
            }))
        var signed = false
        XCTAssertThrowsError(try requests.pairingReceipt(setupID: attempt.transcript.setupID, binding: binding,
            authorityPublicKey: authority.publicKey.x963Representation, verifyHost: { _ in }, sign: { _ in signed = true; throw Failure.fixture }))
        XCTAssertFalse(signed)
    }

    func testPairingHostRecheckFailureLeavesRecoverableCommittedState() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), authority = P256.Signing.PrivateKey()
        let (requests, store) = try checkpointedOwner(fixture, db, writer), (attempt, proof) = try pairingAttempt(db, authority: authority)
        defer { try? db.close(); store.close() }
        var checks = 0
        XCTAssertThrowsError(try commitPairing(requests, attempt, proof: proof, authority: authority, verify: { _ in
            checks += 1; if checks == 3 { throw Failure.fixture }
        }))
        XCTAssertEqual(checks, 3); try assertCheckpoint(db, store, writer)
        XCTAssertNotNil(try requests.pairingReceipt(setupID: attempt.transcript.setupID, binding: pairingBinding(db),
            authorityPublicKey: authority.publicKey.x963Representation, verifyHost: { _ in },
            sign: { try authority.signature(for: $0).rawRepresentation }))
    }

    func testRequestLifecycleCommitsIndependentCheckpointBeforeEachResult() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture)
        let (owner, store) = try checkpointedOwner(fixture, db, writer)
        defer { store.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        try assertCheckpoint(db, store, writer)
        XCTAssertEqual(try store.read().committed.generation, 2)
        _ = try consume(owner, request)
        try assertCheckpoint(db, store, writer)
        XCTAssertEqual(try store.read().committed.generation, 3)
        _ = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now(120), receiptTimeMs: nil)
        try assertCheckpoint(db, store, writer)
        let result = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .loseOutcome, now: now(130), receiptTimeMs: nil)
        XCTAssertEqual(result.phase, .unknown)
        try assertCheckpoint(db, store, writer)
        XCTAssertEqual(try store.read().committed.generation, 5)
        XCTAssertEqual(try store.read().committed.currentAuthorityGeneration, 3)
    }

    func testInvalidSignatureDoesNotRetireHealthyCheckpointedRequestOwner() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture)
        let (owner, store) = try checkpointedOwner(fixture, db, writer)
        defer { store.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let (body, _) = try decision(request), before = try store.read()
        XCTAssertThrowsError(try owner.consume(canonicalDecision: body, signature: Data(repeating: 0, count: 64),
            authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(9), now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try store.read(), before)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
        _ = try consume(owner, request)
        try assertCheckpoint(db, store, writer)
    }

    func testAdmissionAndConsumptionWithholdResultsOnCheckpointFailure() throws {
        for consumption in [false, true] {
            for finalize in [false, true] {
                let fixture = try Fixture(), (db, writer) = try setup(fixture)
                let (owner, store) = try checkpointedOwner(fixture, db, writer)
                defer { store.close() }
                let request = try consumption ? owner.admitFixture(draft(), now: now(), receiptTimeMs: nil) : nil
                let before = try store.read()
                let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
                try fixture.sql("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", continuity: true)
                if let request {
                    XCTAssertThrowsError(try consume(owner, request))
                    XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now()))
                    XCTAssertEqual(try db.read { try $0.consumption(requestID: request.requestID) != nil }, finalize)
                } else {
                    XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil))
                }
                XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil))
                let after = try store.read()
                XCTAssertEqual(after.committed, before.committed)
                XCTAssertEqual(after.pending != nil, finalize)
            }
        }
    }

    func testCheckpointedExpiryAndCancellationCommitBeforeReleasingCapture() throws {
        for expire in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture)
            let (owner, store) = try checkpointedOwner(fixture, db, writer)
            defer { store.close() }
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
            if expire { _ = try owner.expirePending(now: now(200), receiptTimeMs: nil) }
            else { _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(), receiptTimeMs: nil) }
            XCTAssertEqual(try owner.state(requestID: request.requestID).phase, expire ? .expired : .cancelled)
            try assertCheckpoint(db, store, writer)
            XCTAssertEqual(try store.read().committed.generation, 3)
        }
    }

    func testAdmissionCreatesFreshBindingsAndAuditsMetadataBeforeReturning() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let secret = try DeterministicCBOR.encode(.map([0: .text("synthetic-sensitive-capture")]), limits: limits)
        let a = try owner.admitFixture(draft(capture: secret), now: now(), receiptTimeMs: 1000)
        let b = try owner.admitFixture(draft(capture: secret), now: now(), receiptTimeMs: 1000)
        XCTAssertNotEqual(a.requestID, b.requestID)
        XCTAssertNotEqual(a.challenge, b.challenge)
        XCTAssertEqual(a.macID, id(1)); XCTAssertEqual(a.accountID, id(2))
        let retained = try owner.pendingRequest(requestID: a.requestID, now: now(150), receiptTimeMs: nil)
        XCTAssertEqual(retained.payload, a); XCTAssertEqual(retained.admittedAt, now(100))
        XCTAssertEqual(retained.deadlineMilliseconds, 200)
        let records = try events(db, writer)
        XCTAssertEqual(records.map(\.kind), [.enrollmentAdded, .requestCreated, .requestCreated])
        XCTAssertEqual(records[1].requestID, a.requestID)
        XCTAssertFalse(try Data(contentsOf: URL(fileURLWithPath: fixture.path)).contains(Data("synthetic-sensitive-capture".utf8)))
    }

    func testPresentationIsIdempotentAndFirstDecisionOwnsStateAndLedger() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let presented = try owner.markPresented(requestID: request.requestID, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(presented.phase, .presented)
        XCTAssertEqual(try owner.markPresented(requestID: request.requestID, now: now(), receiptTimeMs: nil), presented)
        let winner = try consume(owner, request)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .authorized)
        XCTAssertEqual(try owner.consumedRequest(requestID: request.requestID, now: now()).payload, request)
        XCTAssertThrowsError(try consume(owner, request)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .notPending) }
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.receipt, winner)
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .consumed }.count, 1)
    }

    func testRetiringPendingRequestPreventsEvenValidSignedDecisions() throws {
        for (reason, expected, statusReason) in [(PendingRequestRetirement.cancelled, RequestPhase.cancelled, RequestStatusReason.userCancelled), (.targetTimedOut, .expired, .targetTimedOut), (.targetDisappeared, .unknown, .targetDisappeared), (.authorityRestart, .cancelled, .authorityRestarted)] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
            XCTAssertEqual(try owner.retirePending(requestID: request.requestID, reason: reason, now: now(), receiptTimeMs: nil).phase, expected)
            XCTAssertThrowsError(try consume(owner, request))
            XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
            XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
            let state = try owner.state(requestID: request.requestID)
            XCTAssertEqual(state.reason, statusReason)
            XCTAssertEqual(state.terminalAt, now())
            XCTAssertNil(state.decisionPhoneID)
            if reason == .targetDisappeared { XCTAssertEqual(try events(db, writer).last?.reason, .targetDisappeared) }
        }
    }

    func testDeadlineIsEnforcedBeforeConsumptionAndExpiresExactlyOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try consume(owner, request, time: 200)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .expired) }
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .authorizationExpired)
        XCTAssertEqual(try owner.state(requestID: request.requestID).terminalAt, now(200))
        XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(201), receiptTimeMs: nil))
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
    }

    func testChannelEpochRevocationAndSignatureUseCurrentStoredTrust() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), (body, signature) = try decision(request)
        for (phone, epoch, sig) in [(id(8), id(9), signature), (id(5), id(8), signature), (id(5), id(9), Data(repeating: 0, count: 64))] {
            XCTAssertThrowsError(try owner.consume(canonicalDecision: body, signature: sig, authenticatedPhoneID: phone,
                authenticatedEnrollmentEpoch: epoch, now: now(), receiptTimeMs: nil))
        }
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertThrowsError(try consume(owner, request))
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
    }

    func testJournalFailuresNeverPublishProvisionalAdmissionConsumptionOrRetirement() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 1)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil))
        try fixture.sql("DROP TRIGGER fail_audit")
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try consume(owner, request))
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil).payload, request)
        try fixture.sql("DROP TRIGGER fail_audit")
        _ = try consume(owner, request)
    }

    func testOutcomesRetainBindingUntilTerminalAndNeverRetryUnknown() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        _ = try consume(owner, request)
        let dispatched = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now(210), receiptTimeMs: nil)
        XCTAssertEqual(dispatched.phase, .executing)
        XCTAssertEqual(try owner.consumedRequest(requestID: request.requestID, now: now(220)).payload, request)
        let unknown = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .loseOutcome, now: now(230), receiptTimeMs: nil)
        XCTAssertEqual(unknown.phase, .unknown)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .unknown)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .outcomeUnavailable)
        XCTAssertEqual(try owner.state(requestID: request.requestID).terminalAt, now(230))
        XCTAssertEqual(try owner.state(requestID: request.requestID).decisionPhoneID, id(5))
        XCTAssertThrowsError(try owner.recordOutcome(requestID: request.requestID, expectedRevision: 2, event: .verifySuccess, now: now(240), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now(240)))
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertThrowsError(try owner.state(requestID: request.requestID))
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID), unknown)
    }

    func testCapacityCannotDiscardLiveOrConsumedRequestsAndClearsAfterTerminal() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 1)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.forgetTerminal(requestID: request.requestID))
        _ = try consume(owner, request)
        XCTAssertThrowsError(try owner.forgetTerminal(requestID: request.requestID))
        _ = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .proveNoDispatch, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .noDispatchProved)
        try owner.forgetTerminal(requestID: request.requestID)
        let replacement = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertNotEqual(replacement.requestID, request.requestID)
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.phase, .cancelled)
    }

    func testClockDiscontinuityRetiresTheOwnerAndStorageClosureBlocksSnapshots() throws {
        for changedEpoch in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
            let bad = changedEpoch ? AuthorityMoment(epoch: UUID(), milliseconds: 111) : now(109)
            XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: bad, receiptTimeMs: nil))
            XCTAssertThrowsError(try owner.state(requestID: request.requestID)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable) }
            XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(111), receiptTimeMs: nil))
        }
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        try db.close()
        XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.state(requestID: request.requestID))
    }

    func testRestartDoesNotRestorePendingOrConsumedExecutionBindings() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), first = try owner(db, writer)
        let pending = try first.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let consumed = try first.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let receipt = try consume(first, consumed)
        try db.close()
        let reopened = try open(fixture, initialize: false), nextWriter = try reopened.write { try $0.createEpoch(descriptor(4)) }
        let next = try owner(reopened, nextWriter)
        XCTAssertThrowsError(try next.pendingRequest(requestID: pending.requestID, now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try next.consumedRequest(requestID: consumed.requestID, now: now()))
        XCTAssertEqual(try next.historicalOutcome(requestID: consumed.requestID)?.receipt, receipt)
    }

    func testDeclineUsesDecisionKeyAndReleasesCaptureWithoutExecution() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), (body, signature) = try decision(request, decline: true)
        let receipt = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), now: now(), receiptTimeMs: nil)
        XCTAssertEqual(receipt.event.outcome, .noDispatch)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .declined)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .declined)
        XCTAssertEqual(try owner.state(requestID: request.requestID).decisionPhoneID, id(5))
        XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now()))
        XCTAssertThrowsError(try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now(), receiptTimeMs: nil))
    }

    func testByteBudgetReleasesOnlyAtTerminalAndInvalidDraftsDoNotConsumeCapacity() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, bytes: 4096)
        XCTAssertThrowsError(try owner.admitFixture(draft(capture: Data([0xff])), now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.admitFixture(draft(deadline: 110), now: now(), receiptTimeMs: nil))
        let capture = try DeterministicCBOR.encode(.map([0: .bytes(id(42, 2800))]), limits: limits)
        let request = try owner.admitFixture(draft(capture: capture), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.admitFixture(draft(capture: capture), now: now(), receiptTimeMs: nil))
        _ = try consume(owner, request)
        XCTAssertThrowsError(try owner.admitFixture(draft(capture: capture), now: now(), receiptTimeMs: nil))
        _ = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .proveNoDispatch, now: now(), receiptTimeMs: nil)
        _ = try owner.admitFixture(draft(capture: capture), now: now(), receiptTimeMs: nil)
    }

    func testTargetTimeoutIsDistinctFromAnUnelapsedDeadline() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .deadlineElapsed, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        _ = try owner.retirePending(requestID: request.requestID, reason: .targetTimedOut, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(try events(db, writer).last?.reason, .targetTimedOut)
    }

    func testOwnedQueuedAndDisappearedStatesRoundTripThroughStatusCodec() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        for disappeared in [false, true] {
            if disappeared { _ = try owner.retirePending(requestID: request.requestID, reason: .targetDisappeared, now: now(), receiptTimeMs: nil) }
            let state = try owner.state(requestID: request.requestID)
            let status = try state.statusPayload(observationID: id(40), observationRevision: state.revision,
                now: now(130), estimatedLifetimeMs: nil, lateObservation: false)
            XCTAssertEqual(state.phase, disappeared ? .unknown : .queued)
            XCTAssertEqual(status.phase, disappeared ? .cancelled : .queued)
            XCTAssertEqual(status.reason, disappeared ? .targetDisappeared : .none)
            let later = try state.statusPayload(observationID: id(40), observationRevision: state.revision + 1,
                now: now(150), estimatedLifetimeMs: nil, lateObservation: false)
            XCTAssertEqual(later.terminalAgeMs, status.terminalAgeMs)
            XCTAssertEqual(later.observedAgeMs, 50)
            XCTAssertThrowsError(try state.statusPayload(observationID: id(40), observationRevision: 10,
                now: .init(epoch: UUID(), milliseconds: 130), estimatedLifetimeMs: nil, lateObservation: false))
            XCTAssertEqual(status.observedAgeMs, 30)
            XCTAssertEqual(status.terminalAgeMs, disappeared ? 10 : nil)
            XCTAssertEqual(try RequestStatusPayload.decode(status.encode(limits: limits), limits: limits), status)
        }
    }

    func testDeliveryClosesFromOwnerStateAfterEveryPendingExit() throws {
        enum Exit: CaseIterable { case cancelled, timedOut, disappeared, restart, declined, authorized, deadline }
        for exit in Exit.allCases {
            for started in [false, true] {
                let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
                let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
                let retained = try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil)
                let delivery = try PendingRequestDelivery(request: retained)
                var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
                let routing = router.evaluate(mode: .away, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
                let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: now(), receiptTimeMs: nil) { _ in true }
                XCTAssertEqual(queued.active.count, 1)
                let trust = try db.read { try $0.requestDeliveryTrust() }
                if started {
                    XCTAssertNotNil(delivery.beginDelivery(id: queued.active[0].id, current: retained, routing: routing,
                        trust: trust, now: now()).delivery)
                }
                switch exit {
                case .cancelled, .timedOut, .disappeared, .restart:
                    let reason: PendingRequestRetirement = switch exit {
                    case .cancelled: .cancelled
                    case .timedOut: .targetTimedOut
                    case .disappeared: .targetDisappeared
                    default: .authorityRestart
                    }
                    _ = try owner.retirePending(requestID: request.requestID, reason: reason, now: now(), receiptTimeMs: nil)
                case .declined:
                    let (body, signature) = try decision(request, decline: true)
                    _ = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
                        authenticatedEnrollmentEpoch: id(9), now: now(), receiptTimeMs: nil)
                case .authorized: _ = try consume(owner, request)
                case .deadline: break
                }
                let time = now(exit == .deadline ? 200 : 120)
                let closed = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: time, receiptTimeMs: nil) { _ in XCTFail("Closed request must not enqueue"); return true }
                XCTAssertEqual(closed.closure, .requestPhase(try owner.state(requestID: request.requestID).phase))
                XCTAssertEqual(closed.withdrawn, queued.active)
                XCTAssertTrue(closed.active.isEmpty); XCTAssertTrue(closed.dispatched.isEmpty)
                let repeated = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: time, receiptTimeMs: nil) { _ in XCTFail(); return true }
                XCTAssertTrue(repeated.withdrawn.isEmpty)
                XCTAssertNil(delivery.beginDelivery(id: queued.active[0].id, current: retained, routing: routing,
                    trust: trust, now: time).delivery)
            }
        }
    }

    func testFailedExpiryCannotPublishDeliveryWithdrawalBeforeCommit() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let delivery = try PendingRequestDelivery(request: owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        let routing = router.evaluate(mode: .away, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
        let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(), receiptTimeMs: nil) { _ in true }
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(200), receiptTimeMs: nil) { _ in XCTFail(); return true })
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        try fixture.sql("DROP TRIGGER fail_audit")
        let closed = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(200), receiptTimeMs: nil) { _ in XCTFail(); return true }
        XCTAssertEqual(closed.withdrawn, queued.active)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
    }

    private func routing(_ mode: RoutingMode = .away) throws -> PresenceRouting {
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        return router.evaluate(mode: mode, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
    }

    private func queuedDelivery(_ owner: ApprovalRequestCoordinator) throws -> (IssuedRequestPayload, PendingRequestDelivery, PhoneRequestDelivery) {
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let delivery = try PendingRequestDelivery(request: owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing(), now: now(), receiptTimeMs: nil) { _ in true }
        return (request, delivery, try XCTUnwrap(queued.active.first))
    }

    func testWakePublicationDoesNotDispatchOrDisableSignedFrameRetrieval() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let initial = try owner.reconcileWakePublications(routing: routing(), now: now(120), receiptTimeMs: nil)
        let grant = try XCTUnwrap(initial.registrations.first)
        XCTAssertEqual(grant.requestID, request.requestID); XCTAssertTrue(initial.readyDeliveryIDs.isEmpty)
        XCTAssertTrue(try owner.acknowledgeWakeRegistration(grant, routing: routing(), now: now(130), receiptTimeMs: nil))
        let registered = try owner.reconcileWakePublications(routing: routing(), now: now(140), receiptTimeMs: nil)
        XCTAssertTrue(registered.registrations.isEmpty); XCTAssertEqual(registered.readyDeliveryIDs, [grant.id])
        let frame = try XCTUnwrap(owner.retainedDeliveryFrame(binding: frameBinding(db), requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(150) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }))
        let message = try ApprovalMessage.decode(frame, maximumBodyBytes: 4096)
        XCTAssertEqual(try IssuedRequestPayload.decode(message.body, bodyLimits: limits, captureLimits: limits,
            localCapabilities: capabilities).requestID, request.requestID)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
    }
    func testWakeWithdrawalSurvivesTerminalForgetAndBlocksStaleRegistrationAcknowledgment() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let grant = try XCTUnwrap(owner.reconcileWakePublications(routing: routing(), now: now(120), receiptTimeMs: nil).registrations.first)
        _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(130), receiptTimeMs: nil)
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertFalse(try owner.acknowledgeWakeRegistration(grant, routing: routing(), now: now(140), receiptTimeMs: nil))
        let pending = try owner.reconcileWakePublications(routing: routing(), now: now(150), receiptTimeMs: nil)
        XCTAssertEqual(pending.withdrawals, [grant]); XCTAssertTrue(pending.readyDeliveryIDs.isEmpty)
        XCTAssertTrue(pending.registrations.isEmpty)
        XCTAssertTrue(try owner.acknowledgeWakeWithdrawal(grant)); XCTAssertFalse(try owner.acknowledgeWakeWithdrawal(grant))
        XCTAssertTrue(try owner.reconcileWakePublications(routing: routing(), now: now(160), receiptTimeMs: nil).withdrawals.isEmpty)
    }
    func testWakeExpiryDuringRegistrationRetainsOriginalGrantForWithdrawal() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let grant = try XCTUnwrap(owner.reconcileWakePublications(routing: routing(), now: now(120), receiptTimeMs: nil).registrations.first)
        XCTAssertEqual(grant.deadlineMilliseconds, 200)
        XCTAssertFalse(try owner.acknowledgeWakeRegistration(grant, routing: routing(), now: now(201), receiptTimeMs: nil))
        let expired = try owner.reconcileWakePublications(routing: routing(), now: now(202), receiptTimeMs: nil)
        XCTAssertEqual(expired.withdrawals, [grant]); XCTAssertTrue(expired.readyDeliveryIDs.isEmpty)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
    }
    func testWakePresenceAndBoundedWithdrawalQueuePreserveIndependentOriginalRequests() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, wakes: 1)
        let first = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let grant = try XCTUnwrap(owner.reconcileWakePublications(routing: routing(), now: now(120), receiptTimeMs: nil).registrations.first)
        XCTAssertTrue(try owner.acknowledgeWakeRegistration(grant, routing: routing(), now: now(125), receiptTimeMs: nil))
        let local = try owner.reconcileWakePublications(routing: routing(.present), now: now(130), receiptTimeMs: nil)
        XCTAssertTrue(local.readyDeliveryIDs.isEmpty); XCTAssertTrue(local.withdrawals.isEmpty)
        XCTAssertEqual(try owner.reconcileWakePublications(routing: routing(), now: now(135), receiptTimeMs: nil).readyDeliveryIDs, [grant.id])
        _ = try owner.retirePending(requestID: first.requestID, reason: .cancelled, now: now(140), receiptTimeMs: nil)
        try owner.forgetTerminal(requestID: first.requestID)
        let second = try owner.admitFixture(draft(), now: now(150), receiptTimeMs: nil)
        let full = try owner.reconcileWakePublications(routing: routing(), now: now(155), receiptTimeMs: nil)
        XCTAssertTrue(full.registrations.isEmpty); XCTAssertEqual(full.withdrawals, [grant]); XCTAssertEqual(full.capacityLimitedRecipients, 1)
        XCTAssertTrue(try owner.acknowledgeWakeWithdrawal(grant))
        let resumed = try owner.reconcileWakePublications(routing: routing(), now: now(160), receiptTimeMs: nil)
        let next = try XCTUnwrap(resumed.registrations.first)
        XCTAssertEqual(next.requestID, second.requestID); XCTAssertEqual(next.deadlineMilliseconds, 200)
        XCTAssertNotEqual(next.id, grant.id); XCTAssertEqual(resumed.capacityLimitedRecipients, 0)
        XCTAssertTrue(resumed.withdrawals.isEmpty)
    }

    func testHandoffBackpressureKeepsOriginalIdentityAndAcceptsOnlyOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        var attempts: [PhoneRequestDelivery] = []
        let refused = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(120), receiptTimeMs: nil) { attempts.append($0); return false }
        XCTAssertNil(refused.delivery); XCTAssertTrue(refused.update.dispatched.isEmpty)
        XCTAssertEqual(refused.update.active, [queued])
        let accepted = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(150), receiptTimeMs: nil) { attempts.append($0); return true }
        XCTAssertEqual(accepted.delivery, queued); XCTAssertEqual(accepted.update.dispatched, [queued])
        XCTAssertEqual(attempts, [queued, queued])
        let duplicate = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(160), receiptTimeMs: nil) { _ in XCTFail("Already handed off"); return true }
        XCTAssertNil(duplicate.delivery); XCTAssertEqual(duplicate.update.dispatched, [queued])
        XCTAssertEqual(try events(db, writer).map(\.kind), [.enrollmentAdded, .requestCreated])
    }

    func testHandoffRechecksPresenceAfterPreparationWithoutLosingQueuedWork() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let local = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(.present), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Now local"); return true }
        XCTAssertNil(local.delivery); XCTAssertEqual(local.update.active, [queued])
        XCTAssertTrue(local.update.withdrawn.isEmpty); XCTAssertTrue(local.update.dispatched.isEmpty)
        let resumed = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(130), receiptTimeMs: nil) { XCTAssertEqual($0, queued); return true }
        XCTAssertEqual(resumed.delivery, queued)
    }

    func testHandoffRechecksJournalRevocationAfterPreparation() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Stale trust"); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
        XCTAssertTrue(result.update.active.isEmpty)
    }

    func testHandoffClosesFromCurrentOwnerAfterResolutionAndCaptureRelease() throws {
        for decline in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            let (body, signature) = try decision(request, decline: decline)
            _ = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), now: now(120), receiptTimeMs: nil)
            let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                routing: routing(), now: now(130), receiptTimeMs: nil) { _ in XCTFail("Already resolved"); return true }
            XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
            XCTAssertEqual(result.update.closure, .requestPhase(decline ? .declined : .authorized))
        }
    }

    func testHandoffExpiryCommitsBeforeWithdrawalAndStorageFailureNeverSends() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(200), receiptTimeMs: nil) { _ in XCTFail("Expiry commit failed"); return true })
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        try fixture.sql("DROP TRIGGER fail_audit")
        let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(200), receiptTimeMs: nil) { _ in XCTFail("Expired"); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
        XCTAssertEqual(result.update.closure, .requestPhase(.expired))
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
    }

    func testHandoffRejectsUnknownIdentityAndMismatchedController() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let unknown = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: UUID(),
            routing: routing(), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Unknown identity"); return true }
        XCTAssertNil(unknown.delivery); XCTAssertEqual(unknown.update.active, [queued])
        let other = try owner.admitFixture(draft(), now: now(120), receiptTimeMs: nil)
        let mismatched = try owner.handoffDelivery(requestID: other.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(130), receiptTimeMs: nil) { _ in XCTFail("Wrong request controller"); return true }
        XCTAssertNil(mismatched.delivery); XCTAssertEqual(mismatched.update.withdrawn, [queued])
        XCTAssertEqual(mismatched.update.closure, .requestChanged)
    }

    func testHandoffClockDiscontinuityAndClosedJournalCannotReachTransport() throws {
        for close in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            if close { try db.close() }
            let time = close ? now(120) : AuthorityMoment(epoch: UUID(), milliseconds: 120)
            XCTAssertThrowsError(try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                routing: routing(), now: time, receiptTimeMs: nil) { _ in XCTFail("Unavailable authority"); return true })
        }
    }

    func testPendingDiscoveryIsStableBoundedAndDoesNotMarkHandoff() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 2)
        let first = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let second = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let binding = try frameBinding(db)
        let expected = [first.requestID, second.requestID].sorted { $0.lexicographicallyPrecedes($1) }
        XCTAssertEqual(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(120)), expected)
        XCTAssertEqual(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(130)), expected)
        XCTAssertTrue(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(.present), now: now(140)).isEmpty)
        XCTAssertThrowsError(try owner.admitFixture(draft(), now: now(140), receiptTimeMs: nil))
        XCTAssertEqual(try owner.state(requestID: first.requestID).phase, .queued)
        XCTAssertEqual(try events(db, writer).map(\.kind), [.enrollmentAdded, .requestCreated, .requestCreated])
    }
    func testPendingDiscoveryKeepsHandedOffRequestAndLeavesExpiryForMaintenance() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        _ = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation })
        XCTAssertEqual(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(.present), now: now(130)), [request.requestID])
        XCTAssertTrue(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(200)).isEmpty)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        XCTAssertEqual(try events(db, writer).map(\.kind), [.enrollmentAdded, .requestCreated])
        XCTAssertTrue(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(201)).isEmpty)
        let expired = try owner.expirePending(now: now(202), receiptTimeMs: nil)
        XCTAssertEqual(expired.map(\.requestID), [request.requestID])
        XCTAssertEqual(expired.map(\.phase), [.expired])
        XCTAssertTrue(try owner.expirePending(now: now(203), receiptTimeMs: nil).isEmpty)
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertTrue(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(210)).isEmpty)
    }
    func testPendingDiscoveryRejectsStaleEnrollmentAndOmitsRetiredRequests() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(120), receiptTimeMs: nil)
        XCTAssertTrue(try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: now(130)).isEmpty)
        let stale = AuthorityPeerBinding(peer: try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096).peers.first }), revision: UUID())
        XCTAssertThrowsError(try owner.pendingDeliveryRequestIDs(binding: stale, routing: routing(), now: now(140)))
    }
    private func frameBinding(_ db: JournalDatabase) throws -> AuthorityPeerBinding {
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096) }
        return AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first), revision: trust.revision)
    }
    func testRetainedFrameRetriesWithoutSigningOrConsumingAndSurvivesLocalPresence() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        var signatures = 0
        let first = try XCTUnwrap(owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { signatures += 1; return try self.key.signature(for: $0).rawRepresentation }))
        let second = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing(.present) }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Retry must use retained frame"); throw Failure.fixture })
        XCTAssertEqual(first, second); XCTAssertEqual(signatures, 1)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        XCTAssertNil(try db.read { try $0.consumption(requestID: request.requestID) })
        let carrier = try ApprovalMessage.decode(first, maximumBodyBytes: 4096)
        XCTAssertEqual(carrier.body, try request.encode(limits: limits))
    }
    func testRetainedFrameSuppressesNewLocalDeliveryAndRechecksAfterSigner() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let local = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing(.present) }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Local request signed"); throw Failure.fixture })
        XCTAssertNil(local)
        var signed = false
        let changed = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing(signed ? .present : .away) }, receiptTimeMs: nil,
            signer: { signed = true; return try self.key.signature(for: $0).rawRepresentation })
        XCTAssertTrue(signed); XCTAssertNil(changed)
        let retried = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(140) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation })
        XCTAssertNotNil(retried)
    }
    func testRetainedFrameCannotSurviveExpiryOrTargetRetirement() throws {
        for expires in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
            XCTAssertNotNil(try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { try self.key.signature(for: $0).rawRepresentation }))
            if !expires { _ = try owner.retirePending(requestID: request.requestID, reason: .targetDisappeared, now: now(130), receiptTimeMs: nil) }
            let frame = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(expires ? 200 : 140) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { _ in XCTFail("Terminal request signed"); throw Failure.fixture })
            XCTAssertNil(frame)
        }
    }
    func testRetainedFrameSharesBytesButKeepsDeliveryAndRevocationPerPhone() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        let other = try StoredApprovalEnrollment(epoch: id(19), notificationTag: id(20, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(15), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(16), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                EnrolledApprovalKey(id: id(17), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
        _ = try db.write { try $0.addApprovalEnrollment(other, expectedTrustRevision: revision,
            eventID: id(32), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1) }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096) }
        let first = AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first { $0.scope.phoneID == id(5) }), revision: trust.revision)
        let second = AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first { $0.scope.phoneID == id(15) }), revision: trust.revision)
        let frame = try XCTUnwrap(owner.retainedDeliveryFrame(binding: first, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }))
        let local = try owner.retainedDeliveryFrame(binding: second, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing(.present) }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Shared frame signed again"); throw Failure.fixture })
        XCTAssertNil(local)
        let delivered = try owner.retainedDeliveryFrame(binding: second, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(140) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Shared frame signed again"); throw Failure.fixture })
        XCTAssertEqual(frame, delivered)
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: trust.revision,
            eventID: id(33), receiptTimeMs: nil, writer: writer, expectedAuditHead: 3) }
        let current = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096) }
        let remaining = AuthorityPeerBinding(peer: try XCTUnwrap(current.peers.first { $0.scope.phoneID == id(15) }), revision: current.revision)
        let retried = try owner.retainedDeliveryFrame(binding: remaining, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(150) }, routing: { try self.routing(.present) }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Surviving phone signed again"); throw Failure.fixture })
        XCTAssertEqual(frame, retried)
        XCTAssertThrowsError(try owner.retainedDeliveryFrame(binding: first, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(150) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Revoked phone signed"); throw Failure.fixture }))
    }
    func testForgottenAndUnknownFrameRequestsReturnAbsenceWithoutHidingStorageFailure() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(120), receiptTimeMs: nil)
        try owner.forgetTerminal(requestID: request.requestID)
        for requestID in [request.requestID, id(99)] {
            XCTAssertNil(try owner.retainedDeliveryFrame(binding: binding, requestID: requestID,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(130) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { _ in XCTFail("Unknown request signed"); throw Failure.fixture }))
        }
        let next = try owner.admitFixture(draft(), now: now(140), receiptTimeMs: nil)
        XCTAssertNotNil(try owner.retainedDeliveryFrame(binding: binding, requestID: next.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(150) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }))
        try db.close()
        XCTAssertThrowsError(try owner.retainedDeliveryFrame(binding: binding, requestID: id(99),
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(160) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Closed storage signed"); throw Failure.fixture }))
    }
    func testRetainedFrameBudgetIsReclaimedAfterRetirement() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, bytes: 4096)
        let binding = try frameBinding(db)
        let capture = try DeterministicCBOR.encode(.map([0: .bytes(id(77, 2800))]), limits: limits)
        for _ in 0..<3 {
            let request = try owner.admitFixture(draft(capture: capture), now: now(120), receiptTimeMs: nil)
            XCTAssertNotNil(try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { try self.key.signature(for: $0).rawRepresentation }))
            _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(120), receiptTimeMs: nil)
            try owner.forgetTerminal(requestID: request.requestID)
        }
    }
    func testRetainedFrameRechecksBindingAndKeyBeforeRetry() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        _ = try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation })
        XCTAssertThrowsError(try owner.retainedDeliveryFrame(binding: binding, requestID: request.requestID,
            authorityPublicKey: decisionKey.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Changed key signed"); throw Failure.fixture }))
        let stale = AuthorityPeerBinding(peer: try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096).peers.first }), revision: UUID())
        XCTAssertThrowsError(try owner.retainedDeliveryFrame(binding: stale, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(140) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Stale binding signed"); throw Failure.fixture }))
    }
    private func exchangeDecision(_ request: IssuedRequestPayload, phone: UInt8 = 5, keyID: UInt8 = 6,
                                  decline: Bool = false, purpose: SigningPurpose? = nil,
                                  signer: P256.Signing.PrivateKey? = nil) throws -> Data {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            phoneID: id(phone), keyID: id(keyID), action: request.permittedActions[decline ? 1 : 0]).encode(limits: limits)
        let purpose = purpose ?? (decline ? .cancellation : .biometricAuthorization)
        let signature = try (signer ?? (decline ? decisionKey : key)).signature(for: SigningInput.make(wireVersion: 1,
            messageType: .decision, purpose: purpose, canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return try ApprovalMessage(wireVersion: 1, type: .decision, purpose: purpose,
            body: body, signature: signature).encode(maximumBodyBytes: 3968)
    }
    private func exchangeStatus(_ bytes: Data?) throws -> RequestStatusPayload {
        let message = try ApprovalMessage.decode(XCTUnwrap(bytes), maximumBodyBytes: 3968)
        XCTAssertEqual(message.type, .status); XCTAssertEqual(message.purpose, .status)
        XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, messageType: .status, purpose: .status, canonicalPayload: message.body,
            payloadLimits: limits, inputLimits: limits))
        return try RequestStatusPayload.decode(message.body, limits: limits)
    }
    private func exchange(_ owner: ApprovalRequestCoordinator, _ binding: AuthorityPeerBinding, _ requestID: Data,
                          decision: Data? = nil, time: UInt64 = 120) throws -> Data? {
        try owner.exchangeRequest(binding: binding, requestID: requestID, decisionFrame: decision,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 3968,
            now: { self.now(time) }, receiptTimeMs: nil, signer: { try self.key.signature(for: $0).rawRepresentation })
    }
    func testExchangeStatusKeepsObservationAndAdvancesAgeWithoutChangingRequestPhase() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let original = try draft()
        let observed = ApprovalRequestDraft(contract: original.contract, requiredFeatures: original.requiredFeatures,
            capture: original.capture, actions: original.actions, firstObservedAt: original.firstObservedAt,
            deadlineMilliseconds: original.deadlineMilliseconds, createdUnixMilliseconds: original.createdUnixMilliseconds,
            expiresUnixMilliseconds: original.expiresUnixMilliseconds, observationID: id(40),
            estimatedLifetimeMilliseconds: 60_000, lateObservation: true)
        let request = try owner.admitFixture(observed, now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let first = try exchangeStatus(exchange(owner, binding, request.requestID))
        let later = try exchangeStatus(exchange(owner, binding, request.requestID, time: 140))
        XCTAssertEqual(first.phase, .queued); XCTAssertEqual(later.phase, .queued)
        XCTAssertEqual(first.observationID, id(40)); XCTAssertEqual(later.observationID, first.observationID)
        XCTAssertEqual(first.revision, 1); XCTAssertEqual(later.revision, 2)
        XCTAssertEqual(first.observedAgeMs, 20); XCTAssertEqual(later.observedAgeMs, 40)
        XCTAssertEqual(first.authorizationRemainingMs, 80); XCTAssertEqual(later.authorizationRemainingMs, 60)
        XCTAssertEqual(later.estimatedLifetimeMs, 60_000); XCTAssertTrue(later.lateObservation)
        XCTAssertEqual(later.requestDigest, try request.requestDigest(bodyLimits: limits, signingLimits: limits))
        XCTAssertEqual(later.challenge, request.challenge)
        XCTAssertEqual(try owner.state(requestID: request.requestID).revision, 1)
    }
    func testExchangeConsumesBiometricDecisionAndRetainsWinnerOnRetry() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let decision = try exchangeDecision(request)
        let winner = try exchangeStatus(exchange(owner, binding, request.requestID, decision: decision))
        XCTAssertEqual(winner.phase, .authorized); XCTAssertEqual(winner.decisionPhoneID, id(5))
        let count = try events(db, writer).count
        let retry = try exchangeStatus(exchange(owner, binding, request.requestID, decision: decision, time: 130))
        XCTAssertEqual(retry.phase, .authorized); XCTAssertEqual(retry.decisionPhoneID, id(5))
        XCTAssertGreaterThan(retry.revision, winner.revision)
        XCTAssertEqual(try events(db, writer).count, count)
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.phase, .authorized)
    }
    func testExchangeDeclineUsesDecisionKeyAndTerminalStatusReleasesCapture() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let first = try exchangeStatus(exchange(owner, binding, request.requestID,
            decision: exchangeDecision(request, keyID: 7, decline: true)))
        XCTAssertEqual(first.phase, .declined); XCTAssertEqual(first.reason, .declined)
        XCTAssertEqual(first.terminalAgeMs, 20); XCTAssertNil(first.authorizationRemainingMs)
        let later = try exchangeStatus(exchange(owner, binding, request.requestID, time: 150))
        XCTAssertEqual(later.terminalAgeMs, first.terminalAgeMs); XCTAssertEqual(later.observedAgeMs, 50)
        XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now(150)))
    }
    func testExchangeSecondPhoneReceivesFirstWinnerWithoutAnotherConsumption() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        let otherKey = P256.Signing.PrivateKey()
        let second = try StoredApprovalEnrollment(epoch: id(19), notificationTag: id(20, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(15), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(16), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                EnrolledApprovalKey(id: id(17), keyClass: .decision, publicKey: otherKey.publicKey.x963Representation)]))
        _ = try db.write { try $0.addApprovalEnrollment(second, expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: head($0, writer)) }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096) }
        let first = AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first { $0.scope.phoneID == id(5) }), revision: trust.revision)
        let other = AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first { $0.scope.phoneID == id(15) }), revision: trust.revision)
        _ = try exchange(owner, first, request.requestID, decision: exchangeDecision(request))
        let count = try events(db, writer).count
        let loser = try exchangeStatus(exchange(owner, other, request.requestID,
            decision: exchangeDecision(request, phone: 15, keyID: 17, decline: true, signer: otherKey), time: 130))
        XCTAssertEqual(loser.phase, .authorized); XCTAssertEqual(loser.decisionPhoneID, id(5))
        XCTAssertEqual(try events(db, writer).count, count)
    }
    func testExchangeRejectsForgedDecisionBindingsPurposeAndSignatureBeforeConsumption() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let other = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        for bytes in [try exchangeDecision(request, phone: 15), try exchangeDecision(other),
                      try exchangeDecision(request, purpose: .cancellation),
                      try exchangeDecision(request, keyID: 7, signer: decisionKey),
                      try exchangeDecision(request, signer: P256.Signing.PrivateKey())] {
            XCTAssertThrowsError(try exchange(owner, binding, request.requestID, decision: bytes))
            XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
            XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
        }
        _ = try exchange(owner, binding, request.requestID, decision: exchangeDecision(request))
        XCTAssertThrowsError(try exchange(owner, binding, request.requestID,
            decision: exchangeDecision(request, signer: P256.Signing.PrivateKey())))
    }
    func testExchangeDiscardsPendingStatusWhenSigningCrossesDeadline() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        var signs = 0
        let bytes = try owner.exchangeRequest(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 3968,
            now: { self.now(signs == 0 ? 120 : 200) }, receiptTimeMs: nil,
            signer: { signs += 1; return try self.key.signature(for: $0).rawRepresentation })
        let status = try exchangeStatus(bytes)
        XCTAssertEqual(signs, 2); XCTAssertEqual(status.phase, .expired)
        XCTAssertEqual(status.revision, 2); XCTAssertEqual(status.terminalAgeMs, 100)
        XCTAssertEqual(status.reason, .authorizationExpired)
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
    }
    func testExchangeDecisionCrossingDeadlineReturnsExpiryWithoutConsumption() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        var samples = 0
        let bytes = try owner.exchangeRequest(binding: binding, requestID: request.requestID,
            decisionFrame: exchangeDecision(request), authorityPublicKey: key.publicKey.x963Representation,
            maximumBodyBytes: 3968, now: { samples += 1; return self.now(samples == 1 ? 120 : 200) },
            receiptTimeMs: nil, signer: { try self.key.signature(for: $0).rawRepresentation })
        XCTAssertEqual(try exchangeStatus(bytes).phase, .expired)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
    }
    func testExchangeWithPairedStorageCommitsConsumptionBeforeStatusReply() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture)
        let (owner, store) = try checkpointedOwner(fixture, db, writer)
        defer { store.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let status = try exchangeStatus(exchange(owner, binding, request.requestID, decision: exchangeDecision(request)))
        XCTAssertEqual(status.phase, .authorized)
        try assertCheckpoint(db, store, writer)
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.phase, .authorized)
    }
    func testExchangeLostSignedReplyPreservesCommittedConsumption() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        XCTAssertThrowsError(try owner.exchangeRequest(binding: binding, requestID: request.requestID,
            decisionFrame: exchangeDecision(request), authorityPublicKey: key.publicKey.x963Representation,
            maximumBodyBytes: 3968, now: { self.now(120) }, receiptTimeMs: nil, signer: { _ in throw Failure.fixture }))
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.phase, .authorized)
        let status = try exchangeStatus(exchange(owner, binding, request.requestID, time: 130))
        XCTAssertEqual(status.phase, .authorized); XCTAssertEqual(status.revision, 2)
    }
    func testExchangeUnknownAndForgottenRequestAreAbsenceNotTerminalClaims() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer), binding = try frameBinding(db)
        XCTAssertNil(try exchange(owner, binding, id(99)))
        let request = try owner.admitFixture(draft(), now: now(120), receiptTimeMs: nil)
        _ = try owner.retirePending(requestID: request.requestID, reason: .targetDisappeared, now: now(120), receiptTimeMs: nil)
        let disappeared = try exchangeStatus(exchange(owner, binding, request.requestID, time: 130))
        XCTAssertEqual(disappeared.phase, .cancelled); XCTAssertEqual(disappeared.reason, .targetDisappeared)
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertNil(try exchange(owner, binding, request.requestID, time: 140))
        try db.close()
        XCTAssertThrowsError(try exchange(owner, binding, request.requestID, time: 150))
    }
    func testExchangeRejectsStaleBindingBeforeSignerAndChecksOutputBudget() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let stale = AuthorityPeerBinding(peer: try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096).peers.first }), revision: UUID())
        XCTAssertThrowsError(try owner.exchangeRequest(binding: stale, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 3968,
            now: { self.now(120) }, receiptTimeMs: nil, signer: { _ in XCTFail("Stale binding signed"); throw Failure.fixture }))
        XCTAssertThrowsError(try owner.exchangeRequest(binding: binding, requestID: request.requestID,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 20,
            now: { self.now(120) }, receiptTimeMs: nil, signer: { _ in XCTFail("Oversized body signed"); throw Failure.fixture }))
    }
    func testExchangeRejectsWrongAuthoritySignatureAndRegressingFinalClock() throws {
        for regression in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
            var signed = false
            XCTAssertThrowsError(try owner.exchangeRequest(binding: binding, requestID: request.requestID,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 3968,
                now: { self.now(regression && signed ? 100 : 120) }, receiptTimeMs: nil,
                signer: { signed = true; return try (regression ? self.key : self.decisionKey).signature(for: $0).rawRepresentation }))
        }
    }
    private func head(_ transaction: JournalTransaction, _ writer: AuditEpochWriter) throws -> UInt64 {
        try XCTUnwrap(transaction.epoch(writer.epoch)).head
    }

    func testSignedHandoffBindsExactRetainedPayloadAndHonorsBackpressure() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        var frames: [Data] = []
        for accepted in [false, true] {
            let result = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { try self.key.signature(for: $0).rawRepresentation }) { recipient, frame in
                    XCTAssertEqual(recipient, queued); frames.append(frame); return accepted
                }
            XCTAssertEqual(result.delivery, accepted ? queued : nil)
        }
        XCTAssertEqual(frames.count, 2)
        for frame in frames {
            let message = try ApprovalMessage.decode(frame, maximumBodyBytes: 4096)
            XCTAssertEqual(message.type, .request); XCTAssertEqual(message.purpose, .issuedRequest)
            XCTAssertEqual(message.body, try request.encode(limits: limits))
            XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey.x963Representation,
                wireVersion: 1, messageType: .request, purpose: .issuedRequest, canonicalPayload: message.body,
                payloadLimits: limits, inputLimits: limits))
            XCTAssertFalse(try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey.x963Representation,
                wireVersion: 1, messageType: .status, purpose: .status, canonicalPayload: message.body,
                payloadLimits: limits, inputLimits: limits))
        }
        let duplicate = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }) { _, _ in XCTFail("Duplicate handoff"); return true }
        XCTAssertNil(duplicate.delivery)
        XCTAssertEqual(duplicate.update.dispatched, [queued])
    }

    func testSignedHandoffSamplesExpiryAndPresenceAfterSigning() throws {
        for expired in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            var signed = false
            let result = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(signed && expired ? 200 : 120) },
                routing: { try self.routing(signed && !expired ? .present : .away) }, receiptTimeMs: nil,
                signer: { signed = true; return try self.key.signature(for: $0).rawRepresentation }) { _, _ in
                    XCTFail("No bytes may leave after expiry or local presence"); return true
                }
            XCTAssertTrue(signed); XCTAssertNil(result.delivery)
            if expired {
                XCTAssertEqual(result.update.withdrawn, [queued])
                XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
            } else { XCTAssertEqual(result.update.active, [queued]); XCTAssertTrue(result.update.dispatched.isEmpty) }
        }
    }

    func testSignedHandoffRejectsBadSignerWithoutConsumingQueueOwnership() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        for signature in [Data(repeating: 0, count: 64), Data(), try decisionKey.signature(for: Data([1])).rawRepresentation] {
            XCTAssertThrowsError(try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
                now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil, signer: { _ in signature }) { _, _ in
                    XCTFail("Invalid signature escaped"); return true
                }) { XCTAssertEqual($0 as? DecisionVerificationError, .invalidSignature) }
        }
        let accepted = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }) { _, _ in true }
        XCTAssertEqual(accepted.delivery, queued)
    }

    func testSignedHandoffRejectsBadKeyAndBodyBudgetBeforeSigning() throws {
        for (publicKey, maximum) in [(Data(), 4096), (key.publicKey.x963Representation, 1),
                                     (key.publicKey.x963Representation, 16_777_216)] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            XCTAssertThrowsError(try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                authorityPublicKey: publicKey, maximumBodyBytes: maximum,
                now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
                signer: { _ in XCTFail("Invalid configuration reached signer"); return Data() }) { _, _ in XCTFail(); return true })
        }
    }

    func testSignedHandoffWithdrawsRevokedEnrollmentWithoutSending() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        let result = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(120) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { try self.key.signature(for: $0).rawRepresentation }) { _, _ in XCTFail("Revoked recipient"); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
    }

    func testSignedHandoffClosesTerminalRequestWithoutSigning() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        _ = try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(120), receiptTimeMs: nil)
        let result = try owner.handoffSignedDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: key.publicKey.x963Representation, maximumBodyBytes: 4096,
            now: { self.now(130) }, routing: { try self.routing() }, receiptTimeMs: nil,
            signer: { _ in XCTFail("Terminal request reached signer"); return Data() }) { _, _ in XCTFail(); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
    }

    func testRequestFrameAccessRechecksPolicyAndEnrollmentInsideRequestOwnership() throws {
        let fixture = try Fixture()
        let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities,
                keys: [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                       EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation)]))
        let journal = try journalOwner(fixture, enrollment: enrollment)
        defer { try? journal.close() }
        let entry = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.transport",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: id(3, 20), active: true)
        let installed = try journal.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: nil) }
        let draft = try draft(), time = now()
        let payload = try journal.withRequests { try $0.admitFixture(draft, now: time, receiptTimeMs: nil) }
        let peer = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.transport",
            approvedCodeDirectoryHashes: [id(3, 20)], expectedUserID: 501)
        let access = try AuthorityTransportAccess(journal: journal, peerPolicy: peer, macID: id(1), accountID: id(2),
            maximumPayloadBytes: 4096, minimumEnvelopeVersion: 1, auditVersions: [])
        let trust = try access.snapshot()
        let binding = AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first), revision: trust.revision)
        let result = try access.requestFrame(binding: binding, requestID: payload.requestID) { requests, received, requestID in
            XCTAssertEqual(received.scope.phoneID, binding.scope.phoneID)
            XCTAssertEqual(try requests.state(requestID: requestID).phase, .queued)
            XCTAssertThrowsError(try journal.write { _ in XCTFail("Reentered root owner") }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
            return Data([7])
        }
        XCTAssertEqual(result, Data([7]))
        let discoveryRouting = try routing(), discoveryTime = now(120)
        let pending = try access.pendingRequestIDs(binding: binding) { requests, received in
            XCTAssertThrowsError(try journal.write { _ in XCTFail("Reentered discovery owner") }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
            return try requests.pendingDeliveryRequestIDs(binding: received, routing: discoveryRouting, now: discoveryTime)
        }
        XCTAssertEqual(pending, [payload.requestID])
        let stale = try AuthorityPeerBinding(scope: binding.scope, transportPublicKey: binding.transportPublicKey, revision: UUID())
        XCTAssertThrowsError(try access.requestFrame(binding: stale, requestID: payload.requestID) { _, _, _ in
            XCTFail("Stale enrollment reached handler"); return nil
        }) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try access.pendingRequestIDs(binding: stale) { _, _ in
            XCTFail("Stale enrollment reached discovery"); return []
        }) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try access.exchangeRequest(binding: stale, requestID: payload.requestID, decisionFrame: nil) { _, _, _, _ in
            XCTFail("Stale enrollment reached exchange"); return nil
        }) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        let changed = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.transport",
            installedGeneration: 2, minimumGeneration: 2, codeDirectoryHash: id(4, 20), active: true)
        _ = try journal.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [changed]), expectedRevision: installed.revision) }
        XCTAssertThrowsError(try access.requestFrame(binding: binding, requestID: payload.requestID) { _, _, _ in
            XCTFail("Obsolete transport reached handler"); return nil
        }) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
        XCTAssertThrowsError(try access.pendingRequestIDs(binding: binding) { _, _ in
            XCTFail("Obsolete transport reached discovery"); return []
        }) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
        XCTAssertThrowsError(try access.exchangeRequest(binding: binding, requestID: payload.requestID, decisionFrame: nil) { _, _, _, _ in
            XCTFail("Obsolete transport reached exchange"); return nil
        }) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }

    }

    private final class Fixture {
        let root: URL
        var path: String { root.appendingPathComponent("store/journal.sqlite").path }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.fixture }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.fixture }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ sql: String, continuity: Bool = false) throws {
            var db: OpaquePointer?
            guard sqlite3_open(continuity ? root.appendingPathComponent("continuity/continuity.sqlite").path : path, &db) == SQLITE_OK, let db else { throw Failure.fixture }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.fixture }
        }
    }

    private final class ProviderEnvironment: @unchecked Sendable {
        private let lock = NSLock()
        let epoch: UUID
        let authorityKey = P256.Signing.PrivateKey()
        private var time: UInt64 = 120
        private var mode: RoutingMode = .away
        private var count = 0
        var afterSign: (@Sendable () -> Void)?
        init(epoch: UUID) { self.epoch = epoch }
        var signatures: Int { lock.withLock { count } }
        func set(time: UInt64? = nil, mode: RoutingMode? = nil) {
            lock.withLock { if let time { self.time = time }; if let mode { self.mode = mode } }
        }
        func now() -> AuthorityMoment { lock.withLock { AuthorityMoment(epoch: epoch, milliseconds: time) } }
        func route() throws -> PresenceRouting {
            let mode = lock.withLock { self.mode }
            var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
            return router.evaluate(mode: mode, snapshot: .init(), now: .init(epoch: epoch, milliseconds: now().milliseconds))
        }
        func sign(_ input: Data) throws -> Data {
            lock.withLock { count += 1 }
            let bytes = try authorityKey.signature(for: input).rawRepresentation
            afterSign?()
            return bytes
        }
    }
    private func providerConfiguration(_ fixture: Fixture, maximum: Int = 4096, account: UInt8 = 2) throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: id(1), accountID: id(account), journalDirectory: fixture.path.replacingOccurrences(of: "/journal.sqlite", with: ""),
            serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ", transportIdentifier: "dev.remozio.transport",
            transportHashes: [id(3, 20)], transportUID: 501, maximumPayloadBytes: maximum)
    }
    private func providers(_ configuration: AuthorityServiceConfiguration, _ environment: ProviderEnvironment) throws -> AuthorityRequestProviders {
        try AuthorityRequestProviders(configuration: configuration, publicKey: environment.authorityKey.publicKey.x963Representation,
            signing: { try environment.sign($0) }, routing: { try environment.route() })
    }
    private func verifyProviderFrame(_ bytes: Data, _ environment: ProviderEnvironment, type: ApprovalMessageType) throws -> ApprovalMessage {
        let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: 3968)
        XCTAssertEqual(message.type, type)
        XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: environment.authorityKey.publicKey.x963Representation,
            wireVersion: 1, messageType: type, purpose: message.purpose, canonicalPayload: message.body,
            payloadLimits: limits, inputLimits: limits))
        return message
    }
    func testComposedProvidersUseOneAuthorityForDiscoveryRequestsAndDecisions() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let environment = ProviderEnvironment(epoch: clock), providers = try providers(providerConfiguration(fixture), environment)
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        XCTAssertEqual(try providers.pendingRequestIDs(owner, binding, clock), [request.requestID])
        let frame = try XCTUnwrap(providers.requestFrame(owner, binding, request.requestID, clock))
        _ = try verifyProviderFrame(frame, environment, type: .request)
        let status = try XCTUnwrap(providers.exchangeRequest(owner, binding, request.requestID, nil, clock))
        _ = try verifyProviderFrame(status, environment, type: .status)
        let (body, signature) = try decision(request)
        let carrier = try ApprovalMessage(wireVersion: 1, type: .decision, purpose: .biometricAuthorization,
            body: body, signature: signature).encode(maximumBodyBytes: 3968)
        let accepted = try XCTUnwrap(providers.exchangeRequest(owner, binding, request.requestID, carrier, clock))
        let message = try verifyProviderFrame(accepted, environment, type: .status)
        XCTAssertEqual(try RequestStatusPayload.decode(message.body, limits: limits).phase, .authorized)
        XCTAssertEqual(try owner.state(requestID: request.requestID).decisionPhoneID, id(5))
        XCTAssertNil(try providers.requestFrame(owner, binding, request.requestID, clock))
        XCTAssertTrue(try providers.pendingRequestIDs(owner, binding, clock).isEmpty)
        XCTAssertNotNil(try db.read { try $0.consumption(requestID: request.requestID) })
    }
    func testAccountPresenceProvidersUseDurableModeAndRecheckDuringSigning() throws {
        let fixture = try Fixture(), policy = try RoutingJournalPolicy(clockEpoch: clock, challengeLifetimeMillis: 100,
            maximumOperations: 8, payloadLimits: limits, signingLimits: limits)
        let (db, writer) = try setup(fixture, routingPolicy: policy), owner = try owner(db, writer)
        defer { try? db.close() }
        let first = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let second = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let binding = try frameBinding(db), environment = ProviderEnvironment(epoch: clock)
        let source = AuthorityPresenceRuntime(configuration: try .init(macID: id(1), accountID: id(2), ownerUID: 502,
            policy: .init(observationLifetimeMilliseconds: 50, unavailableGraceMilliseconds: 0)), clockEpoch: clock)
        let providers = try AuthorityRequestProviders(configuration: providerConfiguration(fixture),
            publicKey: environment.authorityKey.publicKey.x963Representation,
            signing: { try environment.sign($0) }, routing: { XCTFail("Account routing used a separate mode cache"); return try environment.route() },
            presence: source)
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        let observer = UUID(), sampled = PresenceMoment(epoch: self.clock, milliseconds: 120)
        try source.publish(.init(remoteWorkspace: .init(.usable, observedAt: sampled)), observer: observer,
            sampledAt: now(120), now: now(120))
        XCTAssertTrue(try providers.pendingRequestIDs(owner, binding, clock).isEmpty)
        XCTAssertNil(try providers.requestFrame(owner, binding, first.requestID, clock))
        XCTAssertEqual(environment.signatures, 0)
        _ = try owner.setLocalRoutingMode(.away, expectedRevision: 0, now: now(120), receiptTimeMs: nil)
        let frame = try XCTUnwrap(providers.requestFrame(owner, binding, first.requestID, clock))
        _ = try verifyProviderFrame(frame, environment, type: .request)
        _ = try owner.setLocalRoutingMode(.automatic, expectedRevision: 1, now: now(120), receiptTimeMs: nil)
        XCTAssertEqual(try providers.pendingRequestIDs(owner, binding, clock), [first.requestID])
        // A delivered request stays available when the Mac becomes present.
        XCTAssertEqual(try providers.requestFrame(owner, binding, first.requestID, clock), frame)
        environment.set(time: 170)
        XCTAssertEqual(Set(try providers.pendingRequestIDs(owner, binding, clock)), Set([first.requestID, second.requestID]))
        environment.afterSign = {
            let sample = PresenceMoment(epoch: environment.epoch, milliseconds: 171)
            environment.set(time: 171)
            _ = try? source.publish(.init(remoteWorkspace: .init(.usable, observedAt: sample)), observer: observer,
                sampledAt: environment.now(), now: environment.now())
        }
        XCTAssertNil(try providers.requestFrame(owner, binding, second.requestID, clock))
        XCTAssertEqual(try owner.state(requestID: second.requestID).phase, .queued)
        XCTAssertEqual(environment.signatures, 2)
        XCTAssertNotNil(try providers.exchangeRequest(owner, binding, first.requestID, nil, clock))
    }

    func testPublicHardwareBundleSignsRealRootRequestAndStatus() throws {
        guard SecureEnclave.isAvailable else { throw XCTSkip("Requires Secure Enclave hardware; production custody remains unproved") }
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        var failure: Unmanaged<CFError>?
        let access = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage, &failure))
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        let config = try providerConfiguration(fixture)
        let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2), key: key)
        let signer = try EnclaveAuthorityRequestSigner.restore(record.encode(), configuration: config, expectedPublicKey: key.publicKey.x963Representation)
        let environment = ProviderEnvironment(epoch: clock)
        let bundle = try AuthorityRequestProviders(configuration: config, signer: signer, routing: { try environment.route() })
        XCTAssertThrowsError(try AuthorityRequestProviders(configuration: providerConfiguration(fixture, account: 8), signer: signer,
            routing: { try environment.route() })) {
            XCTAssertEqual($0 as? AuthorityRequestSignerError, .wrongIdentity)
        }
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let frame = try XCTUnwrap(bundle.requestFrame(owner, binding, request.requestID, clock))
        let status = try XCTUnwrap(bundle.exchangeRequest(owner, binding, request.requestID, nil, clock))
        for (bytes, type): (Data, ApprovalMessageType) in [(frame, .request), (status, .status)] {
            let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: 3968)
            XCTAssertEqual(message.type, type)
            XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey.x963Representation,
                wireVersion: 1, messageType: type, purpose: message.purpose, canonicalPayload: message.body,
                payloadLimits: limits, inputLimits: limits))
        }
    }

    func testProviderPresenceKeepsReviewedRequestAndReadOnlyStateAvailable() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let first = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), second = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let binding = try frameBinding(db), environment = ProviderEnvironment(epoch: clock)
        let providers = try providers(providerConfiguration(fixture), environment), clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        let frame = try XCTUnwrap(providers.requestFrame(owner, binding, first.requestID, clock))
        environment.set(mode: .present)
        XCTAssertEqual(try providers.pendingRequestIDs(owner, binding, clock), [first.requestID])
        XCTAssertEqual(try providers.requestFrame(owner, binding, first.requestID, clock), frame)
        XCTAssertNil(try providers.requestFrame(owner, binding, second.requestID, clock))
        XCTAssertNotNil(try providers.exchangeRequest(owner, binding, first.requestID, nil, clock))
        XCTAssertEqual(environment.signatures, 2)
    }
    func testProvidersResampleClockAndPresenceAfterNativeSigningBoundary() throws {
        for expire in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            defer { try? db.close() }
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
            let environment = ProviderEnvironment(epoch: clock)
            environment.afterSign = { [weak environment] in environment?.set(time: expire ? 200 : 130, mode: expire ? .away : .present) }
            let providers = try providers(providerConfiguration(fixture), environment), clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
            XCTAssertNil(try providers.requestFrame(owner, binding, request.requestID, clock))
            XCTAssertEqual(try owner.state(requestID: request.requestID).phase, expire ? .expired : .queued)
            XCTAssertNil(try db.read { try $0.consumption(requestID: request.requestID) })
            XCTAssertEqual(try providers.expirePending(owner, clock: clock).map(\.requestID), expire ? [request.requestID] : [])
        }
    }
    func testComposedExpiryUsesSameEpochAndReturnsSignedTerminalState() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let environment = ProviderEnvironment(epoch: clock), providers = try providers(providerConfiguration(fixture), environment)
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        environment.set(time: 200)
        XCTAssertEqual(try providers.expirePending(owner, clock: clock).map(\.requestID), [request.requestID])
        XCTAssertTrue(try providers.expirePending(owner, clock: clock).isEmpty)
        let status = try XCTUnwrap(providers.exchangeRequest(owner, binding, request.requestID, nil, clock))
        let message = try verifyProviderFrame(status, environment, type: .status)
        let payload = try RequestStatusPayload.decode(message.body, limits: limits)
        XCTAssertEqual(payload.phase, .expired); XCTAssertEqual(payload.observedAgeMs, 100)
        XCTAssertNil(try providers.requestFrame(owner, binding, request.requestID, clock))
        XCTAssertTrue(try providers.expirePending(owner, clock: clock).isEmpty)
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
        XCTAssertThrowsError(try providers.expirePending(owner, clock: { AuthorityMoment(epoch: UUID(), milliseconds: 201) }))
    }
    func testFrameExpiryReachesComposedCleanupOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let environment = ProviderEnvironment(epoch: clock), bundle = try providers(providerConfiguration(fixture), environment)
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        XCTAssertNotNil(try bundle.requestFrame(owner, binding, request.requestID, clock))
        environment.set(time: 200)
        XCTAssertNil(try bundle.requestFrame(owner, binding, request.requestID, clock))
        let committed = try owner.state(requestID: request.requestID), auditCount = try events(db, writer).count
        XCTAssertEqual(try bundle.expirePending(owner, clock: clock), [committed])
        XCTAssertEqual(committed.phase, .expired); XCTAssertEqual(committed.terminalAt, now(200))
        XCTAssertEqual(committed.requestDigest, try request.requestDigest(bodyLimits: limits, signingLimits: limits))
        XCTAssertTrue(try bundle.expirePending(owner, clock: clock).isEmpty)
        XCTAssertNil(try bundle.requestFrame(owner, binding, request.requestID, clock))
        XCTAssertEqual(try events(db, writer).count, auditCount)
        XCTAssertNil(try db.read { try $0.consumption(requestID: request.requestID) })
    }
    func testStatusExpirySurvivesSigningFailureAndReachesCleanup() throws {
        for signingFails in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            defer { try? db.close() }
            let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
            let environment = ProviderEnvironment(epoch: clock)
            let bundle = try AuthorityRequestProviders(configuration: providerConfiguration(fixture),
                publicKey: environment.authorityKey.publicKey.x963Representation,
                signing: { input in
                    if signingFails { throw Failure.fixture }
                    return try environment.sign(input)
                }, routing: { try environment.route() })
            let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
            environment.set(time: 200)
            if signingFails {
                XCTAssertThrowsError(try bundle.exchangeRequest(owner, binding, request.requestID, nil, clock)) {
                    guard case Failure.fixture = $0 else { return XCTFail("Unexpected signing failure") }
                }
            } else {
                let frame = try XCTUnwrap(bundle.exchangeRequest(owner, binding, request.requestID, nil, clock))
                let message = try verifyProviderFrame(frame, environment, type: .status)
                let status = try RequestStatusPayload.decode(message.body, limits: limits)
                XCTAssertEqual(status.phase, .expired); XCTAssertEqual(status.observedAgeMs, 100)
            }
            let committed = try owner.state(requestID: request.requestID)
            XCTAssertEqual(try bundle.expirePending(owner, clock: clock), [committed])
            XCTAssertEqual(committed.phase, .expired)
            XCTAssertTrue(try bundle.expirePending(owner, clock: clock).isEmpty)
            XCTAssertNil(try db.read { try $0.consumption(requestID: request.requestID) })
        }
    }
    func testRejectedDecisionAfterExpiryStillReachesCleanup() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let environment = ProviderEnvironment(epoch: clock), bundle = try providers(providerConfiguration(fixture), environment)
        let clock: @Sendable () throws -> AuthorityMoment = { environment.now() }
        let (body, originalSignature) = try decision(request)
        var signature = originalSignature; signature[0] ^= 1
        let decision = try ApprovalMessage(wireVersion: 1, type: .decision, purpose: .biometricAuthorization,
            body: body, signature: signature).encode(maximumBodyBytes: 3968)
        environment.set(time: 200)
        XCTAssertThrowsError(try bundle.exchangeRequest(owner, binding, request.requestID, decision, clock)) {
            XCTAssertEqual($0 as? DecisionVerificationError, .invalidSignature)
        }
        XCTAssertEqual(try bundle.expirePending(owner, clock: clock).map(\.requestID), [request.requestID])
        XCTAssertTrue(try bundle.expirePending(owner, clock: clock).isEmpty)
        XCTAssertEqual(environment.signatures, 0)
        XCTAssertNil(try db.read { try $0.consumption(requestID: request.requestID) })
    }
    func testForgottenExpiryPreservesCleanupAndConsumesCapacityUntilDrained() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 1)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(200), receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .expired)
        }
        let committed = try owner.state(requestID: request.requestID)
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertThrowsError(try owner.state(requestID: request.requestID)) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .unknownRequest)
        }
        XCTAssertThrowsError(try owner.admitFixture(draft(deadline: 300), now: now(200), receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .capacityExceeded)
        }
        XCTAssertEqual(try owner.expirePending(now: now(200), receiptTimeMs: nil), [committed])
        let replacement = try owner.admitFixture(draft(deadline: 300), now: now(200), receiptTimeMs: nil)
        XCTAssertNotEqual(replacement.requestID, request.requestID)
        XCTAssertTrue(try owner.expirePending(now: now(200), receiptTimeMs: nil).isEmpty)
    }
    func testAuditFailureDoesNotDiscardEarlierHandlerExpiry() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let requests = try (0..<3).map { _ in try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil) }
        XCTAssertThrowsError(try owner.pendingRequest(requestID: requests[0].requestID, now: now(200), receiptTimeMs: nil))
        let committed = try owner.state(requestID: requests[0].requestID), count = try events(db, writer).count
        try fixture.sql("CREATE TRIGGER fail_sweep BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.expirePending(now: now(200), receiptTimeMs: nil))
        XCTAssertEqual(try owner.state(requestID: requests[0].requestID), committed)
        for request in requests.dropFirst() { XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued) }
        XCTAssertEqual(try events(db, writer).count, count)
        try fixture.sql("DROP TRIGGER fail_sweep")
        XCTAssertEqual(Set(try owner.expirePending(now: now(200), receiptTimeMs: nil).map(\.requestID)), Set(requests.map(\.requestID)))
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 3)
        XCTAssertTrue(try owner.expirePending(now: now(200), receiptTimeMs: nil).isEmpty)
    }
    func testExplicitTargetExpiryIsReportedWithoutNewAuditOnDrain() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil)
        let committed = try owner.retirePending(requestID: request.requestID, reason: .targetTimedOut, now: now(120), receiptTimeMs: nil)
        let count = try events(db, writer).count
        XCTAssertEqual(try owner.expirePending(now: now(130), receiptTimeMs: nil), [committed])
        XCTAssertEqual(committed.reason, .targetTimedOut); XCTAssertEqual(committed.terminalAt, now(120))
        XCTAssertTrue(try owner.expirePending(now: now(140), receiptTimeMs: nil).isEmpty)
        XCTAssertEqual(try events(db, writer).count, count)
    }
    private final class ExpiryObservations: @unchecked Sendable {
        private let lock = NSLock()
        private var states: [ApprovalRequestState] = []
        private var failed = false
        func append(_ batch: [ApprovalRequestState]) { lock.withLock { states += batch } }
        func fail() { lock.withLock { failed = true } }
        var result: ([ApprovalRequestState], Bool) { lock.withLock { (self.states, self.failed) } }
    }
    func testConcurrentRequestExpiryAndSweepReportOneTransition() throws {
        for _ in 0..<4 {
            let fixture = try Fixture(), journal = try journalOwner(fixture)
            defer { try? journal.close() }
            let draft = try draft(), admissionTime = now(), expiryTime = now(200)
            let requestID = try journal.withRequests { try $0.admitFixture(draft, now: admissionTime, receiptTimeMs: nil).requestID }
            let observations = ExpiryObservations(), group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do {
                    try journal.withRequests { _ = try $0.pendingRequest(requestID: requestID, now: expiryTime, receiptTimeMs: nil) }
                    observations.fail()
                } catch let error as ApprovalCoordinatorError {
                    if error != .expired && error != .notPending { observations.fail() }
                } catch { observations.fail() }
            }
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do { try journal.withRequests { observations.append(try $0.expirePending(now: expiryTime, receiptTimeMs: nil)) } }
                catch { observations.fail() }
            }
            XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
            let (states, failed) = observations.result
            XCTAssertFalse(failed); XCTAssertEqual(states.map(\.requestID), [requestID])
            XCTAssertEqual(states.first?.phase, .expired)
            XCTAssertTrue(try journal.withRequests { try $0.expirePending(now: expiryTime, receiptTimeMs: nil).isEmpty })
            let epoch = id(3), eventLimits = try limits
            let expiredEvents = try journal.read { tx in
                let records = try tx.page(epoch: epoch, after: 0, maximumRecords: 50, maximumBytes: 32768).canonicalRecords
                return try records.map { try AuditEventMetadata.decode($0, limits: eventLimits) }.filter { $0.kind == .expired }.count
            }
            XCTAssertEqual(expiredEvents, 1)
        }
    }
    func testProviderScopeRejectsBeforeSignerAndPresenceCallbacks() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let request = try owner.admitFixture(draft(), now: now(), receiptTimeMs: nil), binding = try frameBinding(db)
        let environment = ProviderEnvironment(epoch: clock)
        let providers = try AuthorityRequestProviders(configuration: providerConfiguration(fixture, account: 8),
            publicKey: environment.authorityKey.publicKey.x963Representation, signing: { _ in XCTFail("Wrong-scope signer"); return Data() },
            routing: { XCTFail("Wrong-scope presence"); return try environment.route() })
        let clock: @Sendable () throws -> AuthorityMoment = { XCTFail("Wrong-scope clock"); return environment.now() }
        XCTAssertThrowsError(try providers.pendingRequestIDs(owner, binding, clock))
        XCTAssertThrowsError(try providers.requestFrame(owner, binding, request.requestID, clock))
        XCTAssertThrowsError(try providers.exchangeRequest(owner, binding, request.requestID, nil, clock))
        XCTAssertEqual(environment.signatures, 0)
    }
    func testProviderBudgetRejectsRequestThatUsesReservedCarrierSpace() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        defer { try? db.close() }
        let capture = try DeterministicCBOR.encode(.map([0: .bytes(Data(count: 800))]), limits: limits)
        let retained = try owner.admitFixture(draft(capture: capture), now: now(), receiptTimeMs: nil)
        let size = try retained.encode(limits: limits).count
        XCTAssertGreaterThan(size, 896); XCTAssertLessThanOrEqual(size, 1024)
        let binding = try frameBinding(db), environment = ProviderEnvironment(epoch: clock)
        let providers = try providers(providerConfiguration(fixture, maximum: 1024), environment)
        XCTAssertThrowsError(try providers.requestFrame(owner, binding, retained.requestID, { environment.now() }))
        XCTAssertEqual(environment.signatures, 0)
        XCTAssertEqual(try owner.state(requestID: retained.requestID).phase, .queued)
    }
    func testProvidersRejectInvalidPublicKeysAndTinyCarrierBudget() throws {
        let fixture = try Fixture(), environment = ProviderEnvironment(epoch: clock)
        for publicKey in [Data(), Data(count: 65)] {
            XCTAssertThrowsError(try AuthorityRequestProviders(configuration: providerConfiguration(fixture), publicKey: publicKey,
                signing: { _ in XCTFail("Invalid key reached signer"); return Data() }, routing: { try environment.route() }))
        }
        XCTAssertThrowsError(try providers(providerConfiguration(fixture, maximum: 128), environment))
        let bundle = try providers(providerConfiguration(fixture), environment)
        XCTAssertNoThrow(try bundle.requireConfiguration(providerConfiguration(fixture)))
        XCTAssertThrowsError(try bundle.requireConfiguration(providerConfiguration(fixture, maximum: 8192)))
    }
}

extension ApprovalRequestCoordinatorTests {
    private func noticeAccess(_ journal: AuthorityJournal) throws -> (AuthorityTransportAccess, AuthorityPeerBinding) {
        let entry = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.transport",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: id(3, 20), active: true)
        _ = try journal.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: nil) }
        let peer = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.transport",
            approvedCodeDirectoryHashes: [id(3, 20)], expectedUserID: 501)
        let access = try AuthorityTransportAccess(journal: journal, peerPolicy: peer, macID: id(1), accountID: id(2),
            maximumPayloadBytes: 4096, minimumEnvelopeVersion: 1, auditVersions: [])
        let trust = try access.snapshot()
        return (access, AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first), revision: trust.revision))
    }

    func testCommandNoticeFollowsRealExchangeAndStatusSignerFailure() throws {
        for signingFailure in [false, true] {
            let fixture = try Fixture(), authorityKey = key
            let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
                identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                    EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation)]))
            let journal = try journalOwner(fixture, enrollment: enrollment); defer { try? journal.close() }
            let (access, binding) = try noticeAccess(journal), draft = try draft(), observed = now(), moment = now(120)
            let request = try journal.withRequests { try $0.admitFixture(draft, now: observed, receiptTimeMs: nil) }
            let decision = try exchangeDecision(request), notices = Mutex<[AuthorityCommandAuthorizationNotice]>([])
            let execute = {
                try access.exchangeRequest(binding: binding, requestID: request.requestID, decisionFrame: decision,
                    handler: { owner, authenticated, id, frame in
                        try owner.exchangeRequest(binding: authenticated, requestID: id, decisionFrame: frame,
                            authorityPublicKey: authorityKey.publicKey.x963Representation, maximumBodyBytes: 3968,
                            now: { moment }, receiptTimeMs: nil, signer: {
                                if signingFailure { throw Failure.fixture }
                                return try authorityKey.signature(for: $0).rawRepresentation
                            })
                    }, onCommandAuthorized: { notice in notices.withLock { $0.append(notice) } })
            }
            if signingFailure { XCTAssertThrowsError(try execute()) } else {
                XCTAssertEqual(try exchangeStatus(execute()).phase, .authorized)
            }
            XCTAssertEqual(notices.withLock { $0.count }, 1)
            XCTAssertEqual(notices.withLock { $0.first?.requestID }, request.requestID)
            XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .authorized)
            for frame: Data? in [nil, decision] {
                let response = try access.exchangeRequest(binding: binding, requestID: request.requestID, decisionFrame: frame,
                    handler: { owner, authenticated, id, frame in
                        try owner.exchangeRequest(binding: authenticated, requestID: id, decisionFrame: frame,
                            authorityPublicKey: authorityKey.publicKey.x963Representation, maximumBodyBytes: 3968,
                            now: { moment }, receiptTimeMs: nil, signer: { try authorityKey.signature(for: $0).rawRepresentation })
                    }, onCommandAuthorized: { _ in XCTFail("Status or repeated decision scheduled a second execution") })
                XCTAssertEqual(try exchangeStatus(response).phase, .authorized)
            }
        }
    }

    func testCommandNoticeKeepsTransportAndEnrollmentGatesBeforeExchange() throws {
        let fixture = try Fixture()
        let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities,
                keys: [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                       EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation)]))
        let journal = try journalOwner(fixture, enrollment: enrollment); defer { try? journal.close() }
        let (access, binding) = try noticeAccess(journal)
        let stale = try AuthorityPeerBinding(scope: binding.scope, transportPublicKey: binding.transportPublicKey, revision: UUID())
        XCTAssertThrowsError(try access.exchangeRequest(binding: stale, requestID: id(20), decisionFrame: Data([1]),
            handler: { _, _, _, _ in XCTFail("Stale enrollment reached exchange"); return nil },
            onCommandAuthorized: { _ in XCTFail("Stale enrollment notified executor") })) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
            }
        let policy = try journal.read { try XCTUnwrap($0.codePolicy()) }
        let changed = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.transport",
            installedGeneration: 2, minimumGeneration: 2, codeDirectoryHash: id(4, 20), active: true)
        _ = try journal.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [changed]), expectedRevision: policy.revision) }
        XCTAssertThrowsError(try access.exchangeRequest(binding: binding, requestID: id(20), decisionFrame: Data([1]),
            handler: { _, _, _, _ in XCTFail("Retired transport reached exchange"); return nil },
            onCommandAuthorized: { _ in XCTFail("Retired transport notified executor") })) {
                XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch)
            }
    }
    private func noticeUIJournal(_ fixture: Fixture, contract: RequestContract) throws -> AuthorityJournal {
        let limits = try limits, scopeClock = clock, anchor = fixture.root.path
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let epochDescriptor = try descriptor(3), eventID = id(30)
        let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation)]))
        let db = try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 30, busyMilliseconds: 100, initialize: true)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(epochDescriptor) }
        _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
            eventID: eventID, receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
        let coordinator = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: scopeClock,
            maximumRequests: 8, maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        return AuthorityJournal(requests: coordinator)
    }

    func testCommandNoticeIgnoresRealNonCommandAuthorizations() throws {
        let cases: [(RequestKind, CapturedAction, Bool)] = [
            (.onePasswordAccess, .init(choice: .approveAccess, scope: .currentRequest), false),
            (.onePasswordUnlock, .init(choice: .unlockVault, scope: .currentRequest), false),
            (.littleSnitch, .init(choice: .allowRule, scope: .forever), false),
            (.littleSnitch, .init(choice: .allowOnce, scope: .currentRequest), true)
        ]
        for (kind, action, decisionOnly) in cases {
            let fixture = try Fixture(), authorityKey = key
            let contract = try RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1)
            let journal = try noticeUIJournal(fixture, contract: contract)
            defer { try? journal.close() }
            let observed = now(), moment = now(120)
            let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
                actions: [action, .init(choice: .decline, scope: .currentRequest)], firstObservedAt: now(100),
                deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
            let request = try journal.withRequests { try $0.admit(draft, now: observed, receiptTimeMs: nil) }
            let (access, binding) = try noticeAccess(journal)
            let decision = try exchangeDecision(request, keyID: decisionOnly ? 7 : 6,
                purpose: decisionOnly ? .oneTimeUI : .biometricAuthorization, signer: decisionOnly ? decisionKey : key)
            let response = try access.exchangeRequest(binding: binding, requestID: request.requestID, decisionFrame: decision,
                handler: { owner, authenticated, id, frame in
                    try owner.exchangeRequest(binding: authenticated, requestID: id, decisionFrame: frame,
                        authorityPublicKey: authorityKey.publicKey.x963Representation, maximumBodyBytes: 3968,
                        now: { moment }, receiptTimeMs: nil, signer: { try authorityKey.signature(for: $0).rawRepresentation })
                }, onCommandAuthorized: { _ in XCTFail("UI authorization notified the command executor") })
            XCTAssertEqual(try exchangeStatus(response).phase, .authorized)
        }
    }
}
