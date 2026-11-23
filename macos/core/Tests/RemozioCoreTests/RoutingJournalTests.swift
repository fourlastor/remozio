import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class RoutingJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let key = P256.Signing.PrivateKey()
    private let rootKey = P256.Signing.PrivateKey()
    private let clock = UUID()
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024) } }
    private func now(_ n: UInt64 = 100) -> AuthorityMoment { .init(epoch: clock, milliseconds: n) }
    private func open(_ f: Fixture, initialize: Bool = false, migrate: Int64? = nil, maximum: Int = 20) throws -> JournalDatabase {
        try JournalDatabase(lease: f.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100, initialize: initialize, migrateFromVersion: migrate,
            routingPolicy: RoutingJournalPolicy(clockEpoch: clock, challengeLifetimeMillis: 1000, maximumOperations: maximum,
                payloadLimits: limits, signingLimits: limits))
    }
    private func setup(_ f: Fixture, maximum: Int = 20) throws -> (JournalDatabase, AuditEpochWriter, UUID) {
        let db = try open(f, initialize: true, maximum: maximum)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let empty = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(3)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        let enrolled = try StoredApprovalEnrollment(epoch: id(4), notificationTag: Data(repeating: 5, count: 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(6), keyClass: .decision, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(7), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
        let revision = try db.write { try $0.addApprovalEnrollment(enrolled, expectedTrustRevision: empty, eventID: id(8),
            receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
        return (db, writer, revision)
    }
    private func requestOwner(_ db: JournalDatabase, writer: AuditEpochWriter) throws -> ApprovalRequestCoordinator {
        try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: clock, maximumRequests: 4,
            maximumRetainedBytes: 16384, requestLimits: limits, captureLimits: limits, decisionLimits: limits,
            signingLimits: limits, auditLimits: limits)
    }
    private func presence(mac: UInt8 = 1, account: UInt8 = 2) throws -> AuthorityPresenceRuntime {
        let policy = try PresenceConfiguration(idleMilliseconds: 500, observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 200)
        return AuthorityPresenceRuntime(configuration: try .init(macID: id(mac), accountID: id(account), ownerUID: 501, policy: policy), clockEpoch: clock)
    }
    private func usableSnapshot(_ moment: UInt64 = 100) -> PresenceSnapshot {
        let at = PresenceMoment(epoch: clock, milliseconds: moment)
        return PresenceSnapshot(remoteWorkspace: .init(.usable, observedAt: at), locked: .init(true, observedAt: at),
            displays: .init([.asleep], observedAt: at))
    }
    func testRequestOwnerCommitsLocalModeAndAuditBeforeReturning() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer)
        defer { owner.close(); try? db.close() }
        XCTAssertEqual(try owner.localRoutingState(), RoutingState(mode: .automatic, revision: 0))
        XCTAssertEqual(try owner.setLocalRoutingMode(.present, expectedRevision: 0, now: now(), receiptTimeMs: 1200),
            RoutingState(mode: .present, revision: 1))
        fails(.conflict) { try owner.setLocalRoutingMode(.away, expectedRevision: 0, now: now(101), receiptTimeMs: 1201) }
        XCTAssertEqual(try owner.localRoutingState(), RoutingState(mode: .present, revision: 1))
        _ = try owner.setLocalRoutingMode(.away, expectedRevision: 1, now: now(102), receiptTimeMs: 1202)
        let records = try db.read { try $0.page(epoch: id(3), after: 1, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        let events = try records.map { try AuditEventMetadata.decode($0, limits: limits) }
        XCTAssertEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.kind == .routingChanged && $0.authentication == .localUser && $0.requestID == nil })
        owner.close()
        XCTAssertThrowsError(try owner.localRoutingState())
    }
    func testPresenceRuntimeReadsDurableManualModesInsteadOfObserverClaims() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        XCTAssertTrue(try runtime.publish(usableSnapshot(), observer: UUID(), sampledAt: now(), now: now()))
        XCTAssertEqual(try runtime.routing(owner: owner, now: now()).reason, .remoteDesktop)
        _ = try owner.setLocalRoutingMode(.away, expectedRevision: 0, now: now(200), receiptTimeMs: 1200)
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(201)),
            PresenceRouting(destination: .phones, reason: .manualAway, detectionLimited: false))
        _ = try owner.setLocalRoutingMode(.present, expectedRevision: 1, now: now(202), receiptTimeMs: 1202)
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(203)).reason, .manualPresent)
        _ = try owner.setLocalRoutingMode(.automatic, expectedRevision: 2, now: now(204), receiptTimeMs: 1204)
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(205)).reason, .remoteDesktop)
    }
    func testOnlyCurrentObserverWithdrawalClearsPresenceAndGraceIsBounded() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let first = UUID(), second = UUID()
        _ = try runtime.publish(usableSnapshot(), observer: first, sampledAt: now(), now: now())
        _ = try runtime.publish(usableSnapshot(110), observer: second, sampledAt: now(110), now: now(110))
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(110)).reason, .remoteDesktop)
        runtime.withdraw(observer: first)
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(111)).reason, .remoteDesktop)
        runtime.withdraw(observer: second)
        let grace = try runtime.routing(owner: owner, now: now(120))
        XCTAssertEqual(grace.destination, .localMac); XCTAssertEqual(grace.reason, .detectorUnavailable); XCTAssertTrue(grace.detectionLimited)
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(320)).destination, .phones)
    }
    func testPresenceRejectsFutureStaleMixedEpochAndUnboundedSamplesWithoutReplacingCurrentData() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let observer = UUID()
        _ = try runtime.publish(usableSnapshot(), observer: observer, sampledAt: now(), now: now())
        XCTAssertFalse(try runtime.publish(usableSnapshot(99), observer: UUID(), sampledAt: now(99), now: now(110)))
        XCTAssertThrowsError(try runtime.publish(usableSnapshot(111), observer: observer, sampledAt: now(111), now: now(110)))
        XCTAssertThrowsError(try runtime.publish(usableSnapshot(), observer: observer, sampledAt: now(), now: now(1100)))
        XCTAssertThrowsError(try runtime.publish(usableSnapshot(), observer: observer,
            sampledAt: AuthorityMoment(epoch: UUID(), milliseconds: 100), now: now()))
        var mixed = usableSnapshot()
        mixed.locked = .init(false, observedAt: PresenceMoment(epoch: clock, milliseconds: 99))
        XCTAssertThrowsError(try runtime.publish(mixed, observer: observer, sampledAt: now(), now: now()))
        mixed = usableSnapshot(); mixed.displays = .init(Array(repeating: .asleep, count: 33), observedAt: PresenceMoment(epoch: clock, milliseconds: 100))
        XCTAssertThrowsError(try runtime.publish(mixed, observer: observer, sampledAt: now(), now: now()))
        mixed = usableSnapshot(); mixed.lastQualifyingInputMilliseconds = .init(101, observedAt: PresenceMoment(epoch: clock, milliseconds: 100))
        XCTAssertThrowsError(try runtime.publish(mixed, observer: observer, sampledAt: now(), now: now()))
        XCTAssertEqual(try runtime.routing(owner: owner, now: now(110)).reason, .remoteDesktop)
    }
    func testPreparedDeliveryRoutingRefreshesTimeWithoutARequestOwnerRead() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        _ = try runtime.publish(usableSnapshot(), observer: UUID(), sampledAt: now(), now: now())
        let callback = try runtime.deliveryRouting(owner: owner)
        XCTAssertEqual(try db.read { _ in try callback(now()) }.reason, .remoteDesktop)
        XCTAssertEqual(try callback(now(1300)).destination, .phones)
        runtime.close()
        XCTAssertThrowsError(try callback(now(1301)))
    }
    func testMissingOrUnsupportedSignalsRemainExplicitAndCannotCrossAccountScope() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let unknown = try runtime.routing(owner: owner, now: now())
        XCTAssertEqual(unknown.reason, .detectorUnavailable); XCTAssertEqual(unknown.destination, .phones); XCTAssertTrue(unknown.detectionLimited)
        XCTAssertThrowsError(try presence(mac: 9).routing(owner: owner, now: now())) { XCTAssertEqual($0 as? AuthorityPresenceError, .wrongScope) }
        XCTAssertThrowsError(try presence(account: 9).routing(owner: owner, now: now())) { XCTAssertEqual($0 as? AuthorityPresenceError, .wrongScope) }
        let at = PresenceMoment(epoch: clock, milliseconds: 110)
        let limited = PresenceSnapshot(remoteWorkspace: .init(.unsupported, observedAt: at), locked: .init(false, observedAt: at),
            displays: .init([.awake(.unknown)], observedAt: at), lastQualifyingInputMilliseconds: .init(100, observedAt: at))
        _ = try runtime.publish(limited, observer: UUID(), sampledAt: now(110), now: now(110))
        let active = try runtime.routing(owner: owner, now: now(110))
        XCTAssertEqual(active.reason, .active); XCTAssertEqual(active.destination, .localMac); XCTAssertTrue(active.detectionLimited)
    }

    private func issue(_ db: JournalDatabase, trust: UUID, revision: UInt64 = 0, moment: UInt64 = 100) throws -> RoutingAwayControl {
        try db.write { try issue($0, trust: trust, revision: revision, moment: moment) }
    }
    private func issue(_ tx: JournalTransaction, trust: UUID, revision: UInt64 = 0, moment: UInt64) throws -> RoutingAwayControl {
        try tx.issueRoutingChallenge(authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(4), expectedTrustRevision: trust,
            expectedRoutingRevision: revision, nowUnixMillis: 1000, now: now(moment))
    }
    private func apply(_ tx: JournalTransaction, _ control: RoutingAwayControl, trust: UUID, writer: AuditEpochWriter,
                       head: UInt64 = 1, wall: UInt64 = 1100, moment: UInt64 = 200, signingKey: P256.Signing.PrivateKey? = nil,
                       event: UInt8 = 9) throws -> RoutingChange {
        let payload = try control.encode(limits: limits)
        let signature = try (signingKey ?? key).signature(for: RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: payload,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return try tx.applyRoutingAway(canonicalPayload: payload, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(4), expectedTrustRevision: trust, nowUnixMillis: wall, now: now(moment),
            eventID: id(event), writer: writer, expectedAuditHead: head)
    }
    private func local(_ db: JournalDatabase, _ mode: RoutingMode, writer: AuditEpochWriter, revision: UInt64, head: UInt64) throws -> RoutingState {
        try db.write { try $0.setLocalRoutingMode(mode, expectedRevision: revision, eventID: id(UInt8(20 + head)), receiptTimeMs: 1200,
            writer: writer, expectedAuditHead: head) }
    }
    private func fails(_ error: RoutingJournalError, _ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { XCTAssertEqual($0 as? RoutingJournalError, error, file: file, line: line) }
    }

    func testLocalModesNeedNoApprovalSetupInNewOrMigratedJournal() throws {
        for migrate in [false, true] {
            let f = try Fixture()
            var db = try open(f, initialize: true)
            if migrate {
                try db.close()
                try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; PRAGMA user_version=6")
                db = try open(f, migrate: 6)
            }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(3)),
                4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            for (index, mode) in [RoutingMode.present, .away, .automatic].enumerated() {
                XCTAssertEqual(try local(db, mode, writer: writer, revision: UInt64(index), head: UInt64(index)),
                    RoutingState(mode: mode, revision: UInt64(index + 1)))
            }
            XCTAssertThrowsError(try db.read { try $0.approvalTrustSnapshot() }) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
            }
            let rows = try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
            XCTAssertEqual(rows.count, 3)
            for row in rows {
                let event = try AuditEventMetadata.decode(row, limits: limits)
                XCTAssertEqual(event.macID, id(1)); XCTAssertEqual(event.accountID, id(2))
                XCTAssertEqual(event.kind, .routingChanged); XCTAssertEqual(event.authentication, .localUser)
            }
        }
    }

    func testModesPersistAndPhoneRetryNeverOverridesLaterLocalChoice() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f)
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .automatic, revision: 0))
        let control = try issue(db, trust: trust)
        let result = try db.write { try apply($0, control, trust: trust, writer: writer) }
        XCTAssertTrue(result.inserted); XCTAssertEqual(result.state, RoutingState(mode: .away, revision: 1))
        _ = try local(db, .present, writer: writer, revision: 1, head: 2)
        let retry = try db.write { try apply($0, control, trust: trust, writer: writer, head: 999, wall: 9999, moment: 2000) }
        XCTAssertFalse(retry.inserted); XCTAssertEqual(retry.state, result.state)
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .present, revision: 2))
        let records = try db.read { try $0.page(epoch: id(3), after: 1, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        let events = try records.map { try AuditEventMetadata.decode($0, limits: limits) }
        XCTAssertEqual(events.map(\.kind), [.routingChanged, .routingChanged])
        XCTAssertEqual(events.map(\.authentication), [.decisionKey, .localUser])
        XCTAssertEqual(events.first?.decisionPhoneID, id(5))
        XCTAssertTrue(events.allSatisfy { $0.action == nil && $0.requestID == nil })
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.routingState() }, RoutingState(mode: .present, revision: 2))
        XCTAssertFalse(try reopened.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
    }

    func testConcurrentPhoneAndLocalChoicesUseRevisionCompareAndSwap() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f)
        let first = try issue(db, trust: trust), second = try issue(db, trust: trust)
        XCTAssertNotEqual(first.challenge, second.challenge); XCTAssertNotEqual(first.operationID, second.operationID)
        _ = try db.write { try apply($0, first, trust: trust, writer: writer) }
        fails(.conflict) { try db.write { try apply($0, second, trust: trust, writer: writer) } }
        fails(.conflict) { try local(db, .present, writer: writer, revision: 0, head: 2) }
        _ = try local(db, .automatic, writer: writer, revision: 1, head: 2)
        let pending = try issue(db, trust: trust, revision: 2, moment: 200)
        _ = try local(db, .present, writer: writer, revision: 2, head: 3)
        fails(.conflict) { try db.write { try apply($0, pending, trust: trust, writer: writer, head: 4) } }
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .present, revision: 3))
    }

    func testExpiryAndRestartInvalidateUnconsumedChallenges() throws {
        for (wall, moment) in [(UInt64(2000), UInt64(200)), (UInt64(1100), UInt64(1100)), (UInt64(999), UInt64(200))] {
            let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
            fails(.expired) { try db.write { try apply($0, control, trust: trust, writer: writer, wall: wall, moment: moment) } }
            XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
        }
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        try db.close()
        let reopened = try open(f)
        fails(.unavailableChallenge) { try reopened.write { try apply($0, control, trust: trust, writer: writer) } }
        let fresh = try issue(reopened, trust: trust, moment: 200)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(12)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let nextWriter = try reopened.write { try $0.createEpoch(descriptor) }
        XCTAssertTrue(try reopened.write { try apply($0, fresh, trust: trust, writer: nextWriter, head: 0) }.inserted)
    }

    func testRevocationAndWrongSignaturesCannotChangeRouting() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        fails(.invalidSignature) { try db.write { try apply($0, control, trust: trust, writer: writer, signingKey: P256.Signing.PrivateKey()) } }
        let removed = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(4), expectedTrustRevision: trust,
            eventID: id(10), receiptTimeMs: 1200, writer: writer, expectedAuditHead: 1).revision }
        XCTAssertThrowsError(try db.write { try apply($0, control, trust: trust, writer: writer, head: 2) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.write { try apply($0, control, trust: removed, writer: writer, head: 2) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
    }

    func testFailedAuditOrConsumptionWriteRollsBackAllRoutingEffects() throws {
        for table in ["routing_state_v1", "routing_operations_v1", "audit_records_v1"] {
            let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
            let action = table == "audit_records_v1" ? "INSERT" : "UPDATE"
            try f.sql("CREATE TRIGGER reject_write BEFORE \(action) ON \(table) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try db.write { try apply($0, control, trust: trust, writer: writer) })
            XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
            XCTAssertEqual(try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords.count }, 1)
            try f.sql("DROP TRIGGER reject_write")
            XCTAssertTrue(try db.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
        }
    }

    func testReadOnlyEscapedAndSwallowedFailureCannotMutate() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        XCTAssertThrowsError(try db.read { try apply($0, control, trust: trust, writer: writer) })
        var escaped: JournalTransaction?
        _ = try db.read { escaped = $0; return try $0.routingState() }
        XCTAssertThrowsError(try escaped?.routingState())
        XCTAssertThrowsError(try db.write { tx in
            _ = try? tx.setLocalRoutingMode(.present, expectedRevision: 99, eventID: id(11), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 1)
            return try apply(tx, control, trust: trust, writer: writer)
        })
        XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
    }

    func testExpiredRoutingChallengesReleaseCapacityAcrossMoreThanAThousandIssues() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f, maximum: 1024)
        defer { try? db.close() }
        let (first, last) = try db.write { tx in
            let first = try issue(tx, trust: trust, moment: 100)
            var last = first
            for index in 1...1024 {
                last = try issue(tx, trust: trust, moment: 100 + UInt64(index) * 1_000)
            }
            return (first, last)
        }
        XCTAssertNotEqual(first.operationID, last.operationID)
        fails(.unavailableChallenge) {
            try db.write { try apply($0, first, trust: trust, writer: writer, moment: 1_024_100) }
        }
        XCTAssertEqual(try db.read { try $0.routingState() }, .init(mode: .automatic, revision: 0))
        XCTAssertEqual(try db.read { try $0.epoch(writer.epoch)?.head }, 1)
        XCTAssertTrue(try db.write { try apply($0, last, trust: trust, writer: writer, moment: 1_024_101) }.inserted)
    }

    func testFullLiveRoutingStoreKeepsReceiptsUntilTheirDeadline() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f, maximum: 2)
        defer { try? db.close() }
        let first = try issue(db, trust: trust)
        let result = try db.write { try apply($0, first, trust: trust, writer: writer) }
        let pending = try issue(db, trust: trust, revision: 1, moment: 250)
        let before = try db.read { try $0.continuityDigests() }
        fails(.capacityExceeded) { try issue(db, trust: trust, revision: 1, moment: 1_099) }
        XCTAssertEqual(try db.read { try $0.continuityDigests() }, before)
        let retry = try db.write { try apply($0, first, trust: trust, writer: writer, moment: 1_099) }
        XCTAssertEqual(retry.state, result.state)
        XCTAssertFalse(retry.inserted)
        _ = try issue(db, trust: trust, revision: 1, moment: 1_100)
        fails(.unavailableChallenge) {
            try db.write { try apply($0, first, trust: trust, writer: writer, moment: 1_100) }
        }
        XCTAssertEqual(try db.read { try $0.routingState() }, result.state)
        XCTAssertEqual(try db.read { try $0.epoch(writer.epoch)?.head }, 2)
        XCTAssertTrue(try db.write { try apply($0, pending, trust: trust, writer: writer, head: 2, moment: 1_101, event: 10) }.inserted)
    }

    func testRoutingCleanupPrunesUnusedChallengesBeforeOldestReceipts() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f, maximum: 4)
        defer { try? db.close() }
        let oldest = try issue(db, trust: trust, moment: 100)
        let first = try db.write { try apply($0, oldest, trust: trust, writer: writer, moment: 150) }
        let newer = try issue(db, trust: trust, revision: 1, moment: 160)
        let second = try db.write { try apply($0, newer, trust: trust, writer: writer, head: 2, moment: 200, event: 10) }
        let unused = try issue(db, trust: trust, revision: 2, moment: 220)
        let live = try issue(db, trust: trust, revision: 2, moment: 1_500)

        _ = try issue(db, trust: trust, revision: 2, moment: 1_500)
        fails(.unavailableChallenge) {
            try db.write { try apply($0, unused, trust: trust, writer: writer, moment: 1_500) }
        }
        let oldRetry = try db.write { try apply($0, oldest, trust: trust, writer: writer, moment: 1_500) }
        XCTAssertFalse(oldRetry.inserted)
        XCTAssertEqual(oldRetry.state, first.state)

        _ = try issue(db, trust: trust, revision: 2, moment: 1_501)
        fails(.unavailableChallenge) {
            try db.write { try apply($0, oldest, trust: trust, writer: writer, moment: 1_501) }
        }
        let newRetry = try db.write { try apply($0, newer, trust: trust, writer: writer, moment: 1_501) }
        XCTAssertFalse(newRetry.inserted)
        XCTAssertEqual(newRetry.state, second.state)
        XCTAssertEqual(try db.read { try $0.routingState() }, second.state)
        XCTAssertEqual(try db.read { try $0.epoch(writer.epoch)?.head }, 3)
        XCTAssertTrue(try db.write { try apply($0, live, trust: trust, writer: writer, head: 3, moment: 1_502, event: 11) }.inserted)
    }

    func testFullRoutingStoreReclaimsPreviousRunRowsOnDemand() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f, maximum: 2)
        let accepted = try issue(db, trust: trust, moment: 100)
        let before = try db.write { try apply($0, accepted, trust: trust, writer: writer, moment: 200) }
        let unused = try issue(db, trust: trust, revision: 1, moment: 250)
        try db.close()
        let reopened = try open(f, maximum: 2)
        defer { try? reopened.close() }

        _ = try issue(reopened, trust: trust, revision: 1, moment: 10)
        fails(.unavailableChallenge) {
            try reopened.write { try apply($0, unused, trust: trust, writer: writer, moment: 10) }
        }
        XCTAssertEqual(try reopened.write { try apply($0, accepted, trust: trust, writer: writer, moment: 10) }.state,
                       before.state)
        _ = try issue(reopened, trust: trust, revision: 1, moment: 11)
        fails(.unavailableChallenge) {
            try reopened.write { try apply($0, accepted, trust: trust, writer: writer, moment: 11) }
        }
        XCTAssertEqual(try reopened.read { try $0.routingState() }, before.state)
        XCTAssertEqual(try reopened.read { try $0.epoch(writer.epoch)?.head }, 2)
    }

    func testRoutingCleanupRollsBackWithFailedIssueAndLeavesCheckpointIntact() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f, maximum: 1)
        defer { try? db.close() }
        let original = try issue(db, trust: trust)
        let before = try db.read {
            try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch, generation: 1, authorityGeneration: 1)
        }
        let continuity = try f.makeContinuity(mac: id(1), account: id(2), initial: before)
        defer { continuity.close() }
        let commits = CheckpointedJournal(journal: db, continuity: continuity)
        let initial = try continuity.read()
        try f.sql("CREATE TRIGGER reject_routing_issue BEFORE INSERT ON routing_operations_v1 BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        XCTAssertThrowsError(try commits.write(epoch: writer.epoch, recoverRejectedBody: true) {
            try issue($0, trust: trust, moment: 1_100)
        })
        XCTAssertFalse(commits.retired)
        XCTAssertEqual(try continuity.read(), initial)
        XCTAssertEqual(try commits.read { try $0.continuityDigests().authority }, before.authorityDigest)
        try f.sql("DROP TRIGGER reject_routing_issue")
        let fresh = try commits.write(epoch: writer.epoch) { try issue($0, trust: trust, moment: 1_100) }
        XCTAssertNotEqual(fresh.operationID, original.operationID)
        let after = try continuity.read()
        XCTAssertNotEqual(after.committed.authorityDigest, before.authorityDigest)
        XCTAssertEqual(after.committed.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(after.committed.journalHead, before.journalHead)
        XCTAssertNil(after.pending)
        XCTAssertEqual(try commits.read { try $0.routingState() }, .init(mode: .automatic, revision: 0))
    }

    func testStorageCapacityClockAndCorruptionFailuresDoNotResetState() throws {
        let f = try Fixture(), (db, _, trust) = try setup(f, maximum: 1)
        _ = try issue(db, trust: trust)
        fails(.capacityExceeded) { try issue(db, trust: trust) }
        fails(.invalidClock) { try issue(db, trust: trust, moment: 99) }
        XCTAssertThrowsError(try db.read { try $0.routingState() }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try db.close()
        let reopened = try open(f)
        try f.sql("PRAGMA ignore_check_constraints=ON; UPDATE routing_state_v1 SET revision=x'00'")
        fails(.corruptData) { try reopened.read { try $0.routingState() } }
    }

    func testSignedChangesToRetainedFieldsCannotExtendOrRedirectAChallenge() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        guard case let .map(original) = try DeterministicCBOR.decode(control.encode(limits: limits), limits: limits) else { return XCTFail() }
        for field in UInt64(1)...10 {
            var changed = original
            switch changed[field] {
            case var .bytes(value): value[0] ^= 1; changed[field] = .bytes(value)
            case let .unsigned(value): changed[field] = .unsigned(value + 1)
            default: return XCTFail()
            }
            let altered = try RoutingAwayControl.decode(DeterministicCBOR.encode(.map(changed), limits: limits), limits: limits)
            XCTAssertThrowsError(try db.write { try apply($0, altered, trust: trust, writer: writer) })
        }
        var wrongKey = original; wrongKey[7] = .bytes(id(7))
        let biometric = try RoutingAwayControl.decode(DeterministicCBOR.encode(.map(wrongKey), limits: limits), limits: limits)
        fails(.wrongKey) { try db.write { try apply($0, biometric, trust: trust, writer: writer) } }
        XCTAssertTrue(try db.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
    }

    func testFailedMigrationPreservesExistingModeAndVersion() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f)
        _ = try local(db, .present, writer: writer, revision: 0, head: 1)
        try db.close()
        try f.sql("PRAGMA user_version=6")
        XCTAssertThrowsError(try open(f, migrate: 6))
        try f.sql("PRAGMA user_version=12")
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.routingState() }, RoutingState(mode: .present, revision: 1))
    }

    func testSchemaSixMigrationPreservesEnrollmentAndInitializesAutomatic() throws {
        let f = try Fixture(), (db, _, trust) = try setup(f)
        try db.close()
        try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; PRAGMA user_version=6")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 6)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().revision }, trust)
        XCTAssertEqual(try migrated.read { try $0.routingState() }, RoutingState(mode: .automatic, revision: 0))
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func makeContinuity(mac: Data, account: Data, initial: ContinuityCheckpoint) throws -> ContinuityStore {
            let directory = root.appendingPathComponent("continuity")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "continuity.sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }
                Darwin.close(fd)
            }
            return try ContinuityStore(lease: .init(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: mac, accountID: account, initialize: initial)
        }
        func sql(_ sql: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
}


extension RoutingJournalTests {
    private func binding(_ db: JournalDatabase) throws -> AuthorityPeerBinding {
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 16384) }
        return AuthorityPeerBinding(peer: try XCTUnwrap(trust.peers.first), revision: trust.revision)
    }
    private func route(_ owner: ApprovalRequestCoordinator, _ runtime: AuthorityPresenceRuntime, _ binding: AuthorityPeerBinding,
                       _ frame: PhoneRoutingFrame, at: UInt64 = 100, wall: UInt64? = 1000,
                       sign: ((Data) throws -> Data)? = nil) throws -> RoutingStatusResponse {
        let reply = try owner.phoneRouting(frame, binding: binding, authorityPublicKey: rootKey.publicKey.x963Representation,
            now: { self.now(at) }, wallTime: { wall }, routing: { try runtime.routing(owner: $0, now: $1) },
            signer: sign ?? { try self.rootKey.signature(for: $0).rawRepresentation })
        return try verified(reply, expectedNonce: frame.queryNonce)
    }
    private func verified(_ frame: PhoneRoutingFrame, expectedNonce: Data) throws -> RoutingStatusResponse {
        guard case .response(let nonce, let body, let signature) = frame else { throw Failure.injected }
        XCTAssertEqual(nonce, expectedNonce)
        XCTAssertTrue(try RoutingStatusSignature.verify(signature: signature, publicKey: rootKey.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: body, inputLimits: .init(maxBytes: 3200, maxDepth: 2, maxItems: 16)))
        let status = try RoutingStatusResponse.decode(body); XCTAssertEqual(status.queryNonce, expectedNonce); return status
    }
    private func signedControl(_ status: RoutingStatusResponse) throws -> (Data, Data) {
        let body = try XCTUnwrap(status.canonicalChallenge)
        return (body, try key.signature(for: RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: body,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation)
    }
    private func nonce(_ n: UInt8) -> Data { Data(repeating: n, count: 32) }

    func testPhoneRoutingStatusAndChallengeRemainAvailableWhilePresentSuppressesApprovalDelivery() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        _ = try runtime.publish(usableSnapshot(), observer: UUID(), sampledAt: now(), now: now())
        let peer = try binding(db)
        let first = try route(owner, runtime, peer, .status(queryNonce: nonce(1)), wall: nil)
        XCTAssertEqual(first.state.mode, .automatic); XCTAssertEqual(first.state.reason, .remoteDesktop)
        _ = try owner.setLocalRoutingMode(.present, expectedRevision: 0, now: now(101), receiptTimeMs: 1001)
        let status = try route(owner, runtime, peer, .status(queryNonce: nonce(2)), at: 102, wall: nil)
        XCTAssertEqual(status.state.mode, .present); XCTAssertEqual(status.state.revision, 1)
        let challenge = try route(owner, runtime, peer, .challenge(queryNonce: nonce(3), expectedRevision: 1), at: 103)
        XCTAssertEqual(challenge.outcome, .challenge)
        let control = try RoutingAwayControl.decode(XCTUnwrap(challenge.canonicalChallenge), limits: limits)
        XCTAssertEqual(control.macID, id(1)); XCTAssertEqual(control.accountID, id(2)); XCTAssertEqual(control.phoneID, id(5))
        XCTAssertEqual(control.enrollmentEpoch, id(4)); XCTAssertEqual(control.keyID, id(6)); XCTAssertEqual(control.expectedRevision, 1)
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .present, revision: 1))
        XCTAssertEqual(try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords.count }, 2)
    }
    func testPhoneRoutingAppliedReceiptNeverClaimsAHistoricalAwayModeIsCurrent() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db)
        let issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
        let (body, signature) = try signedControl(issued)
        let applied = try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature), at: 110, wall: 1100)
        XCTAssertEqual(applied.outcome, .applied); XCTAssertEqual(applied.appliedRevision, 1)
        XCTAssertEqual(applied.state.mode, .away); XCTAssertEqual(applied.state.revision, 1)
        XCTAssertEqual(applied.controlDigest, Data(SHA256.hash(data: body)))
        _ = try owner.setLocalRoutingMode(.present, expectedRevision: 1, now: now(120), receiptTimeMs: 1200)
        let historical = try route(owner, runtime, peer, .apply(queryNonce: nonce(3), canonicalControl: body, signature: signature), at: 2000, wall: 9999)
        XCTAssertEqual(historical.outcome, .applied); XCTAssertEqual(historical.appliedRevision, 1)
        XCTAssertEqual(historical.state.mode, .present); XCTAssertEqual(historical.state.revision, 2)
        let records = try db.read { try $0.page(epoch: id(3), after: 1, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        let events = try records.map { try AuditEventMetadata.decode($0, limits: limits) }
        XCTAssertEqual(events.map { $0.authentication }, [.decisionKey, .localUser])
        XCTAssertTrue(events.allSatisfy { $0.requestID == nil && $0.action == nil })
    }
    func testPhoneRoutingConflictsReturnCurrentStateWithoutAnotherModeChange() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db), issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
        let (body, signature) = try signedControl(issued)
        _ = try owner.setLocalRoutingMode(.present, expectedRevision: 0, now: now(110), receiptTimeMs: 1100)
        let conflict = try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature), at: 120)
        XCTAssertEqual(conflict.outcome, .conflict); XCTAssertEqual(conflict.state.mode, .present); XCTAssertEqual(conflict.state.revision, 1)
        XCTAssertEqual(conflict.controlDigest, Data(SHA256.hash(data: body))); XCTAssertNil(conflict.appliedRevision)
        let staleQuery = try route(owner, runtime, peer, .challenge(queryNonce: nonce(3), expectedRevision: 0), at: 130)
        XCTAssertEqual(staleQuery.outcome, .conflict); XCTAssertEqual(staleQuery.state.revision, 1)
        XCTAssertNil(staleQuery.canonicalChallenge); XCTAssertNil(staleQuery.controlDigest)
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .present, revision: 1))
    }
    func testPhoneRoutingWrongDecisionSignatureAndBiometricKeyCannotConsumeTheChallenge() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db), issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
        let (body, signature) = try signedControl(issued)
        fails(.invalidSignature) { try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: Data(repeating: 0, count: 64)), at: 110) }
        guard case .map(var fields) = try DeterministicCBOR.decode(body, limits: limits) else { return XCTFail() }
        fields[7] = .bytes(id(7)); let altered = try DeterministicCBOR.encode(.map(fields), limits: limits)
        fails(.wrongKey) { try route(owner, runtime, peer, .apply(queryNonce: nonce(3), canonicalControl: altered, signature: signature), at: 120) }
        XCTAssertEqual(try owner.localRoutingState().revision, 0)
        XCTAssertEqual(try route(owner, runtime, peer, .apply(queryNonce: nonce(4), canonicalControl: body, signature: signature), at: 130).state.mode, .away)
    }
    func testPhoneRoutingExpiredChallengeLeavesModeAndAuditUnchanged() throws {
        for wallExpired in [false, true] {
            let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
            defer { runtime.close(); owner.close(); try? db.close() }
            let peer = try binding(db), issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
            let (body, signature) = try signedControl(issued)
            fails(.expired) { try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature),
                at: wallExpired ? 110 : 1100, wall: wallExpired ? 2000 : 1100) }
            XCTAssertEqual(try owner.localRoutingState(), .init(mode: .automatic, revision: 0))
            XCTAssertEqual(try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords.count }, 1)
        }
    }
    func testPhoneRoutingRevokedOrWrongScopePeerCannotReadOrChangeTheAccount() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db)
        let otherScope = try ChannelScope(macID: id(9), accountID: id(2), phoneID: id(5), enrollmentEpoch: id(4))
        let wrong = try AuthorityPeerBinding(scope: otherScope, transportPublicKey: peer.transportPublicKey, revision: peer.revision)
        XCTAssertThrowsError(try route(owner, runtime, wrong, .status(queryNonce: nonce(1))))
        let revision = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(4), expectedTrustRevision: trust,
            eventID: id(11), receiptTimeMs: 1100, writer: writer, expectedAuditHead: 1).revision }
        XCTAssertThrowsError(try route(owner, runtime, peer, .status(queryNonce: nonce(2)), at: 110))
        let removed = try AuthorityPeerBinding(scope: peer.scope, transportPublicKey: peer.transportPublicKey, revision: revision)
        XCTAssertThrowsError(try route(owner, runtime, removed, .challenge(queryNonce: nonce(3), expectedRevision: 0), at: 120))
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .automatic, revision: 0))
    }
    func testPhoneRoutingSignerFailureAfterCommitRequiresReconciliationInsteadOfRollback() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db), issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
        let (body, signature) = try signedControl(issued)
        XCTAssertThrowsError(try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature), at: 110, sign: { _ in throw Failure.injected }))
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .away, revision: 1))
        let status = try route(owner, runtime, peer, .status(queryNonce: nonce(3)), at: 120)
        XCTAssertEqual(status.state.mode, .away); XCTAssertEqual(status.state.revision, 1)
        XCTAssertEqual(try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords.count }, 2)
    }
    func testPhoneRoutingRejectsWrongSignerAndMissingMutationClockWithoutPublishingOrChangingMode() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db), wrong = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try route(owner, runtime, peer, .status(queryNonce: nonce(1)), sign: { try wrong.signature(for: $0).rawRepresentation }))
        fails(.invalidClock) { try route(owner, runtime, peer, .challenge(queryNonce: nonce(2), expectedRevision: 0), at: 110, wall: nil) }
        XCTAssertThrowsError(try route(owner, runtime, peer, .status(queryNonce: Data()), at: 120))
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .automatic, revision: 0))
    }
    func testPhoneRoutingResignsAfterPresenceChangesDuringSigningWithoutRepeatingAMutation() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        _ = try runtime.publish(usableSnapshot(), observer: UUID(), sampledAt: now(), now: now())
        let peer = try binding(db); var time: UInt64 = 100; var signatures = 0
        let reply = try owner.phoneRouting(.status(queryNonce: nonce(1)), binding: peer, authorityPublicKey: rootKey.publicKey.x963Representation,
            now: { self.now(time) }, wallTime: { nil }, routing: { try runtime.routing(owner: $0, now: $1) }, signer: {
                signatures += 1; time = 1300; return try self.rootKey.signature(for: $0).rawRepresentation
            })
        let result = try verified(reply, expectedNonce: nonce(1)); XCTAssertEqual(signatures, 2)
        XCTAssertEqual(result.state.reason, .detectorUnavailable); XCTAssertEqual(result.state.destination, .phones)
        XCTAssertEqual(result.sampledAtMilliseconds, 1300)
    }
    func testPhoneRoutingDoesNotPublishAChallengeWhoseOriginalDeadlinePassedDuringSigning() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db); var time: UInt64 = 100
        fails(.expired) { try owner.phoneRouting(.challenge(queryNonce: nonce(1), expectedRevision: 0), binding: peer,
            authorityPublicKey: rootKey.publicKey.x963Representation, now: { self.now(time) }, wallTime: { 1000 },
            routing: { try runtime.routing(owner: $0, now: $1) }, signer: {
                time = 1100; return try self.rootKey.signature(for: $0).rawRepresentation
            }) }
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .automatic, revision: 0))
    }
    func testPhoneRoutingAuditFailureRollsBackTheModeAndLeavesTheOriginalChallengeUsable() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db), issued = try route(owner, runtime, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0))
        let (body, signature) = try signedControl(issued)
        try f.sql("CREATE TRIGGER reject_write BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try route(owner, runtime, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature), at: 110))
        XCTAssertEqual(try owner.localRoutingState().revision, 0)
        try f.sql("DROP TRIGGER reject_write")
        XCTAssertEqual(try route(owner, runtime, peer, .apply(queryNonce: nonce(3), canonicalControl: body, signature: signature), at: 120).state.mode, .away)
    }
    func testPhoneRoutingWithholdsTheReplyWhenEnrollmentChangesDuringSigning() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let peer = try binding(db)
        XCTAssertThrowsError(try route(owner, runtime, peer, .status(queryNonce: nonce(1)), sign: { bytes in
            _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: self.id(5), epoch: self.id(4), expectedTrustRevision: trust,
                eventID: self.id(11), receiptTimeMs: 1100, writer: writer, expectedAuditHead: 1) }
            return try self.rootKey.signature(for: bytes).rawRepresentation
        }))
        XCTAssertEqual(try owner.localRoutingState(), .init(mode: .automatic, revision: 0))
    }
}


extension RoutingJournalTests {
    private func providerConfiguration(_ f: Fixture, maximum: Int = 16384) throws -> AuthorityServiceConfiguration {
        try .init(macID: id(1), accountID: id(2), journalDirectory: f.directory, serviceName: "dev.remozio.fixture.routing",
            teamID: "SYNTHETIC1", transportIdentifier: "dev.remozio.fixture.transport",
            transportHashes: [Data(repeating: 7, count: 20)], transportUID: 501, maximumPayloadBytes: maximum)
    }
    private func providers(_ f: Fixture, presence: AuthorityPresenceRuntime? = nil,
                           wall: (@Sendable () -> UInt64?)? = nil, maximum: Int = 16384) throws -> AuthorityRequestProviders {
        let bytes = rootKey.rawRepresentation
        return try .init(configuration: providerConfiguration(f, maximum: maximum), publicKey: rootKey.publicKey.x963Representation,
            signing: { try P256.Signing.PrivateKey(rawRepresentation: bytes).signature(for: $0).rawRepresentation },
            routing: { throw AuthorityPresenceError.unavailable }, presence: presence, routingWallTime: wall)
    }
    func testPhoneRoutingProviderRequiresExplicitPresenceClockAndCompleteCarrierBudget() throws {
        let f = try Fixture(), runtime = try presence(); defer { runtime.close() }
        XCTAssertNil(try providers(f).phoneRouting)
        XCTAssertNil(try providers(f, presence: runtime).phoneRouting)
        XCTAssertThrowsError(try providers(f, wall: { 1000 }))
        XCTAssertThrowsError(try providers(f, presence: runtime, wall: { 1000 }, maximum: 1024))
        XCTAssertNotNil(try providers(f, presence: runtime, wall: { 1000 }).phoneRouting)
    }
    func testPhoneRoutingProviderUsesTheSameProtectedScopeSignerAndAuthorityClockForTheCompleteExchange() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f), owner = try requestOwner(db, writer: writer), runtime = try presence()
        defer { runtime.close(); owner.close(); try? db.close() }
        let provider = try XCTUnwrap(providers(f, presence: runtime, wall: { 1000 }).phoneRouting)
        let peer = try binding(db), epoch = clock
        let issued = try verified(provider(owner, peer, .challenge(queryNonce: nonce(1), expectedRevision: 0),
            { .init(epoch: epoch, milliseconds: 100) }), expectedNonce: nonce(1))
        let (body, signature) = try signedControl(issued)
        let applied = try verified(provider(owner, peer, .apply(queryNonce: nonce(2), canonicalControl: body, signature: signature),
            { .init(epoch: epoch, milliseconds: 110) }), expectedNonce: nonce(2))
        XCTAssertEqual(applied.state.mode, .away); XCTAssertEqual(applied.appliedRevision, 1)
        let status = try verified(provider(owner, peer, .status(queryNonce: nonce(3)),
            { .init(epoch: epoch, milliseconds: 120) }), expectedNonce: nonce(3))
        XCTAssertEqual(status.state.mode, .away); XCTAssertEqual(status.outcome, .status)
        let wrong = try AuthorityPeerBinding(scope: .init(macID: id(9), accountID: id(2), phoneID: id(5), enrollmentEpoch: id(4)),
            transportPublicKey: peer.transportPublicKey, revision: peer.revision)
        XCTAssertThrowsError(try provider(owner, wrong, .status(queryNonce: nonce(4)), { .init(epoch: epoch, milliseconds: 130) }))
    }
    func testPhoneRoutingProviderRejectsAMismatchedPresenceRuntimeBeforeAnyOperation() throws {
        let f = try Fixture(), wrong = try presence(mac: 9); defer { wrong.close() }
        XCTAssertThrowsError(try providers(f, presence: wrong, wall: { 1000 }))
    }
}
