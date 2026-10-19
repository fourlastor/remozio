import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayAuthorityJournalTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private let clockEpoch = UUID()
    private enum Failure: Error { case injected }
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func trust(active: Bool = true, phone: UInt8 = 6, epoch: UInt8 = 7, tag: UInt8 = 6) throws -> GatewayAuthorityTrust {
        try .init(registration: GatewayRegistrationIdentity(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key.publicKey.x963Representation),
            enrollment: GatewayPhoneEnrollment(phoneID: id(phone), epoch: id(epoch), tag: id(tag, count: 32), active: active), active: true)
    }
    private func moment(_ value: UInt64 = 100, epoch: UUID? = nil) -> AuthorityMoment { .init(epoch: epoch ?? clockEpoch, milliseconds: value) }
    private func sign(_ candidate: GatewayTokenCandidate) throws -> Data {
        try key.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: candidate.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func sign(_ activation: GatewayMappingActivation) throws -> Data {
        try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
            canonicalPayload: activation.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func sign(_ revocation: GatewayPhoneRevocation) throws -> Data {
        try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
            canonicalPayload: revocation.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func revoke(_ db: JournalDatabase, head: UInt64, trusted: GatewayAuthorityTrust? = nil,
                        wall: UInt64 = 1010, now: UInt64 = 110) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.revokeGatewayEnrollment(trust: trusted ?? trust(), expectedHead: head,
            nowUnixMillis: wall, now: moment(now), sign: sign) }
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, maximum: Int = 20, enabled: Bool = true,
                      migrate: Int64? = nil, epoch: UUID? = nil) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(2), accountID: id(3), recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100,
            initialize: initialize, migrateFromVersion: migrate,
            gatewayPolicy: enabled ? GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits,
                maximumControls: maximum, candidateLifetimeMillis: 1000, clockEpoch: epoch ?? clockEpoch) : nil)
    }
    private func setup(_ fixture: Fixture, maximum: Int = 20) throws -> JournalDatabase {
        let db = try open(fixture, initialize: true, maximum: maximum)
        try db.write { try $0.configureGatewayAuthority(trust().registration) }
        return db
    }
    private func prepare(_ db: JournalDatabase, head: UInt64 = 0, token: String = "synthetic-token", wall: UInt64 = 1000,
                         now: UInt64 = 100, trusted: GatewayAuthorityTrust? = nil, peer: UInt8 = 6) throws -> GatewayAuthorityEnvelope {
        let trust = try trusted ?? self.trust()
        return try db.write {
            try $0.prepareGatewayCandidate(registrationToken: token, authenticatedPhoneID: id(peer), authenticatedEnrollmentEpoch: trust.enrollment.epoch,
                trust: trust, expectedHead: head, nowUnixMillis: wall, now: moment(now), sign: sign)
        }
    }
    private func candidate(_ envelope: GatewayAuthorityEnvelope) throws -> GatewayTokenCandidate {
        try .decode(envelope.canonicalPayload, limits: limits)
    }
    private func proof(_ envelope: GatewayAuthorityEnvelope) throws -> Data {
        try GatewayTokenProof(binding: candidate(envelope).binding).encode(limits: limits)
    }
    private func consume(_ db: JournalDatabase, _ envelope: GatewayAuthorityEnvelope, head: UInt64 = 1,
                         wall: UInt64 = 1010, now: UInt64 = 110, peer: UInt8 = 6,
                         trusted: GatewayAuthorityTrust? = nil, proofBytes: Data? = nil) throws -> GatewayAuthorityEnvelope {
        let trust = try trusted ?? self.trust()
        return try db.write {
            try $0.consumeGatewayProof(canonicalProof: proofBytes ?? proof(envelope), authenticatedPhoneID: id(peer), authenticatedEnrollmentEpoch: trust.enrollment.epoch,
                trust: trust, expectedHead: head, nowUnixMillis: wall, now: moment(now), sign: sign)
        }
    }

    private func livePolicy(maximum: Int = 20, epoch: UUID? = nil) throws -> GatewayAuthorityPolicy {
        try .init(payloadLimits: limits, signingLimits: limits, maximumControls: maximum, candidateLifetimeMillis: 1000, clockEpoch: epoch ?? clockEpoch)
    }
    func testLiveEnableUsesTheExistingWriterAndDoesNotConfigureRegistrationOrMigrate() throws {
        let f = try Fixture(), db = try open(f, initialize: true, enabled: false)
        defer { try? db.close() }
        XCTAssertThrowsError(try db.read { try $0.gatewayAuthorityHead(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .disabled) }
        XCTAssertTrue(try db.enableGatewayPolicy(livePolicy(), macID: id(2), accountID: id(3)))
        XCTAssertEqual(try f.scalar("PRAGMA user_version"), "12")
        XCTAssertThrowsError(try db.read { try $0.gatewayAuthorityHead(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unconfigured) }
        XCTAssertThrowsError(try f.lease()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try db.write { try $0.configureGatewayAuthority(trust().registration) }
        XCTAssertEqual(try prepare(db).revision, 1)
    }
    func testRepeatedLivePolicyRetainsCandidateClockAndRejectsReplacement() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        defer { try? db.close() }
        XCTAssertFalse(try db.enableGatewayPolicy(livePolicy(), macID: id(2), accountID: id(3)))
        XCTAssertThrowsError(try db.enableGatewayPolicy(livePolicy(maximum: 21), macID: id(2), accountID: id(3))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try db.enableGatewayPolicy(livePolicy(epoch: UUID()), macID: id(2), accountID: id(3))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidConfiguration)
        }
        XCTAssertEqual(try consume(db, first).revision, 2)
    }
    func testLivePolicyRefusesWrongScopeTransactionsAndClosedConnections() throws {
        let f = try Fixture(), db = try open(f, initialize: true, enabled: false), policy = try livePolicy()
        XCTAssertThrowsError(try db.enableGatewayPolicy(policy, macID: id(99), accountID: id(3)))
        try db.read { _ in
            XCTAssertThrowsError(try db.enableGatewayPolicy(policy, macID: id(2), accountID: id(3))) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        XCTAssertTrue(try db.enableGatewayPolicy(policy, macID: id(2), accountID: id(3)))
        try db.close()
        XCTAssertThrowsError(try db.enableGatewayPolicy(policy, macID: id(2), accountID: id(3))) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
    }

    func testCandidateProofAndActivationShareDurableControlHead() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertEqual(first.kind, 1); XCTAssertEqual(first.revision, 1)
        let candidate = try candidate(first)
        XCTAssertEqual(candidate.binding.tokenDigest, Data(SHA256.hash(data: Data("synthetic-token".utf8))))
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1000, now: moment()) }?.signature, first.signature)
        let activation = try consume(db, first)
        XCTAssertEqual(activation.kind, 2); XCTAssertEqual(activation.revision, 2)
        XCTAssertEqual(try GatewayMappingActivation.decode(activation.canonicalPayload, limits: limits).binding, candidate.binding)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "1")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "2")
        XCTAssertNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) })
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: activation.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) }?.signature, activation.signature)
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .alreadyConsumed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(String(reflecting: activation), "GatewayAuthorityEnvelope(redacted)")
    }

    func testWrongPeerWrongProofAndRevokedTrustNeverCallSigner() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        for trusted in [try trust(active: false), try trust(epoch: 8), try trust(phone: 9)] {
            XCTAssertThrowsError(try consume(db, first, trusted: trusted))
        }
        XCTAssertThrowsError(try consume(db, first, peer: 9))
        let other = try GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            phoneID: id(6), enrollmentEpoch: id(7), candidateID: candidate(first).binding.candidateID,
            tokenDigest: candidate(first).binding.tokenDigest, challenge: id(99, count: 32), enrollmentTag: id(6, count: 32))
        var signed = false
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: GatewayTokenProof(binding: other).encode(limits: limits), authenticatedPhoneID: id(6),
                authenticatedEnrollmentEpoch: id(7), trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110),
                sign: { value in signed = true; return try sign(value) })
        })
        XCTAssertFalse(signed)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        _ = try consume(db, first)
    }

    func testNewTokenChoiceSupersedesOldProofAndOutboxWithoutActivatingAnything() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db), second = try prepare(db, head: 1, token: "rotated")
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) })
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "0")
        _ = try consume(db, second, head: 2)
    }

    func testStorageFailureRollsBackProofOutboxAndHeadTogether() throws {
        for trigger in ["BEFORE INSERT ON gateway_outbox_v1", "BEFORE UPDATE ON gateway_root_candidates_v1", "BEFORE UPDATE ON gateway_authority_v1"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try consume(db, first))
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "0")
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try consume(db, first)
        }
    }

    func testSwallowedMutationFailureStillRollsBackOtherJournalWrites() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try db.write {
            _ = try? $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(9), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
            _ = try $0.prepareGatewayCandidate(registrationToken: "next", authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        _ = try consume(db, first)
    }

    func testExpiredAndRestartedCandidatesRequireFreshNonceFromCurrentDesiredState() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try consume(db, first, wall: 2000, now: 1100)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        try db.close()
        let nextEpoch = UUID(), reopened = try open(fixture, epoch: nextEpoch)
        XCTAssertThrowsError(try reopened.read {
            try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 2000, now: moment(100, epoch: nextEpoch))
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        let fresh = try reopened.write {
            try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1, nowUnixMillis: 2000, now: moment(100, epoch: nextEpoch), sign: sign)
        }
        XCTAssertNotEqual(try candidate(fresh).binding.challenge, try candidate(first).binding.challenge)
        XCTAssertNotEqual(try candidate(fresh).binding.candidateID, try candidate(first).binding.candidateID)
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertEqual(fresh.revision, 2)
        XCTAssertEqual(try candidate(fresh).expiresAtUnixMillis, 3000)
    }

    func testBadSignatureCapacityAndWrongHeadCannotCommit() throws {
        let fixture = try Fixture(), db = try setup(fixture, maximum: 2), first = try prepare(db)
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: { _ in Data(repeating: 0, count: 64) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature) }
        _ = try consume(db, first)
        XCTAssertThrowsError(try prepare(db, head: 2, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertThrowsError(try prepare(db, head: 1, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .headMismatch) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testDisabledReadOnlyAndEscapedTransactionNeverWrite() throws {
        let fixture = try Fixture(), disabled = try open(fixture, initialize: true, enabled: false)
        XCTAssertThrowsError(try disabled.write { try $0.configureGatewayAuthority(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .disabled) }
        try disabled.close()
        let db = try open(fixture)
        XCTAssertThrowsError(try db.read { try $0.configureGatewayAuthority(trust().registration) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.write { $0 }
        XCTAssertThrowsError(try escaped.configureGatewayAuthority(trust().registration)) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        try db.write { try $0.configureGatewayAuthority(trust().registration) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
    }

    func testAuthorityControlsDriveTheRealGatewayCandidateAndActivationChecks() throws {
        let fixture = try Fixture(), root = try setup(fixture), first = try prepare(root), trusted = try trust()
        let gateway = try fixture.gateway(identity: trusted.registration, limits: limits, epoch: clockEpoch)
        func gatewayTrust(_ head: UInt64) throws -> GatewayCandidateTrust {
            let r = trusted.registration
            return try GatewayCandidateTrust(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID, gatewayID: r.gatewayID,
                lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey, active: true, revision: UUID(),
                appliedControlRevision: head, enrollment: trusted.enrollment)
        }
        _ = try gateway.admitCandidate(canonicalPayload: first.canonicalPayload, signature: first.signature, wireVersion: 1,
            registrationToken: XCTUnwrap(first.registrationToken), trust: gatewayTrust(0), nowUnixMillis: 1000, now: moment())
        XCTAssertNil(try gateway.activeMapping(trust: gatewayTrust(1)))
        let snapshot = try gatewayTrust(1)
        let reservation = try gateway.reserveProbe(candidateOperationID: first.operationID, trust: snapshot, nowUnixMillis: 1000, now: moment())
        let probe = try gateway.takeProbe(reservation, trust: snapshot, nowUnixMillis: 1000, now: moment())
        let binding = try candidate(first).binding
        XCTAssertEqual(probe.payload.challenge, binding.challenge)
        XCTAssertEqual(probe.payload.candidateID, binding.candidateID)
        try gateway.finishProbe(reservation, outcome: .accepted, now: moment())
        // This fixture stands in for receipt through the authenticated phone channel, not proof of that channel's implementation.
        let activation = try consume(root, first)
        _ = try gateway.applyRecipient(canonicalPayload: activation.canonicalPayload, signature: activation.signature, wireVersion: 1,
            kind: .activation, trust: gatewayTrust(1), nowUnixMillis: 1010, now: moment(110))
        XCTAssertEqual(try gateway.activeMapping(trust: gatewayTrust(2))?.registrationToken, first.registrationToken)
        let retry = try gateway.applyRecipient(canonicalPayload: activation.canonicalPayload, signature: activation.signature, wireVersion: 1,
            kind: .activation, trust: gatewayTrust(2), nowUnixMillis: 1010, now: moment(110))
        XCTAssertFalse(retry.inserted)
        let removal = try revoke(root, head: 2)
        _ = try gateway.applyRecipient(canonicalPayload: removal.canonicalPayload, signature: removal.signature, wireVersion: 1,
            kind: .phoneRevocation, trust: gatewayTrust(2), nowUnixMillis: 1010, now: moment(110))
        XCTAssertNil(try gateway.activeMapping(trust: gatewayTrust(3)))
        XCTAssertTrue(try root.read { try $0.gatewayEnrollmentRevoked(trust: trusted) })
        let removedAgain = try gateway.applyRecipient(canonicalPayload: removal.canonicalPayload, signature: removal.signature, wireVersion: 1,
            kind: .phoneRevocation, trust: gatewayTrust(3), nowUnixMillis: 1010, now: moment(110))
        XCTAssertFalse(removedAgain.inserted)
    }

    func testKnownSchemaThreeMigrationPreservesAuditIdentityAndRequiresExplicitChoice() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(40)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        _ = try db.write { try $0.createEpoch(descriptor) }
        try db.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; PRAGMA user_version=3")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 3)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "12")
        XCTAssertNotNil(try migrated.read { try $0.epoch(id(40)) })
        XCTAssertThrowsError(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unconfigured) }
        try migrated.write { try $0.configureGatewayAuthority(trust().registration) }
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
    }

    func testFailedSchemaThreeMigrationLeavesVersionAndOldTablesIntact() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        try db.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; PRAGMA user_version=3; CREATE TABLE gateway_outbox_v1(conflict INTEGER)")
        XCTAssertThrowsError(try open(fixture, migrate: 3))
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "3")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM sqlite_schema WHERE name='gateway_authority_v1'"), "0")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM sqlite_schema WHERE name='consumption_outcomes_v1'"), "1")
        try fixture.sql("DROP TABLE gateway_outbox_v1")
        let recovered = try open(fixture, migrate: 3)
        try recovered.close()
    }

    func testCorruptHeadTokenConsumptionAndRestoredDesiredPointerRetireOwner() throws {
        for mutation in ["UPDATE gateway_authority_v1 SET head=zeroblob(8)",
                         "UPDATE gateway_outbox_v1 SET signature=zeroblob(64)",
                         "UPDATE gateway_outbox_v1 SET payload=x'01'",
                         "UPDATE gateway_outbox_v1 SET token=x'616263' WHERE kind=1",
                         "UPDATE gateway_root_candidates_v1 SET consumed=NULL"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            _ = try consume(db, first)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        _ = try prepare(db, head: 1)
        let oldID = try candidate(first).binding.candidateID.map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE gateway_desired_tokens_v1 SET candidate=x'\(oldID)'")
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testWallAndMonotonicExpiryAreIndependentAndBadClockRetiresOwner() throws {
        for (wall, now): (UInt64, UInt64) in [(2000, 100), (1000, 1100), (999, 100)] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            XCTAssertThrowsError(try consume(db, first, wall: wall, now: now)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        }
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try consume(db, first, now: 99)) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidClock) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testCandidateCreationFailureNeverReplacesCurrentDesiredToken() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        try fixture.sql("CREATE TRIGGER reject_head BEFORE UPDATE ON gateway_authority_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try prepare(db, head: 1, token: "uncommitted"))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
        try fixture.sql("DROP TRIGGER reject_head")
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1, nowUnixMillis: 1000, now: moment(), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertThrowsError(try prepare(db, head: 2, token: "contains space")) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidToken) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testRevocationRejectsStaleActiveTrustAndLateProofWithoutSigning() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        let removal = try revoke(db, head: 1, trusted: trust(active: false))
        XCTAssertEqual(removal.kind, 3); XCTAssertEqual(removal.revision, 2)
        XCTAssertNil(removal.registrationToken)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        var signed = false
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: { value in signed = true; return try sign(value) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertFalse(signed)
        XCTAssertThrowsError(try prepare(db, head: 2, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.write {
            try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.read {
            try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110))
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertEqual(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(active: false),
            nowUnixMillis: 1010, now: moment(110)) }?.signature, removal.signature)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testInactiveGatewaySuppressesRemovalDeliveryWithoutClearingRevocation() throws {
        let fixture = try Fixture(), db = try setup(fixture), trusted = try trust(active: false)
        let inactive = GatewayAuthorityTrust(registration: trusted.registration, enrollment: trusted.enrollment, active: false)
        let removal = try revoke(db, head: 0, trusted: inactive)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: inactive) })
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: inactive,
            nowUnixMillis: 1010, now: moment(110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration) }
        XCTAssertEqual(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trusted,
            nowUnixMillis: 1010, now: moment(110)) }?.signature, removal.signature)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trusted) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trusted.registration) }, 1)
    }

    func testRevocationSurvivesExpiryAndRestartAndRefreshesOnlyRemoval() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        let removal = try revoke(db, head: 0)
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 2010, now: moment(1110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        try db.close()
        let reopened = try open(fixture)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertThrowsError(try reopened.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 1010, now: moment(110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        XCTAssertThrowsError(try prepare(reopened, head: 1, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        let fresh = try revoke(reopened, head: 1, trusted: trust(active: false), wall: 3000, now: 500)
        XCTAssertNotEqual(fresh.operationID, removal.operationID); XCTAssertEqual(fresh.revision, 2)
        XCTAssertEqual(try GatewayPhoneRevocation.decode(fresh.canonicalPayload, limits: limits).binding,
                       try GatewayPhoneRevocation.decode(removal.canonicalPayload, limits: limits).binding)
        XCTAssertEqual(try reopened.read { try $0.pendingGatewayRevocation(operationID: fresh.operationID, trust: trust(active: false),
            nowUnixMillis: 3000, now: moment(500)) }?.signature, fresh.signature)
        XCTAssertThrowsError(try reopened.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 3000, now: moment(500)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_revocations_v1"), "2")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "0")
    }

    func testOldEpochRemovalPreservesNewEnrollmentAndOtherPhones() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        _ = try prepare(db)
        let newer = try prepare(db, head: 1, trusted: trust(epoch: 8)), other = try prepare(db, head: 2, trusted: trust(phone: 9), peer: 9)
        _ = try revoke(db, head: 3)
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust(epoch: 8)) })
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust(phone: 9)) })
        _ = try consume(db, newer, head: 4, trusted: trust(epoch: 8))
        _ = try consume(db, other, head: 5, peer: 9, trusted: trust(phone: 9))
        _ = try revoke(db, head: 6)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "2")
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(trust: trust(epoch: 8), expectedHead: 7,
            nowUnixMillis: 1010, now: moment(110), sign: sign) }
        XCTAssertEqual(try candidate(fresh).binding.enrollmentEpoch, id(8))
    }

    func testRevocationFailureRollsBackTombstoneDesiredStateAndCounter() throws {
        for trigger in ["BEFORE INSERT ON gateway_revocations_v1", "BEFORE DELETE ON gateway_desired_tokens_v1", "BEFORE UPDATE ON gateway_authority_v1"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try revoke(db, head: 1))
            XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "1")
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try consume(db, first)
        }
    }

    func testRevocationIsAtomicWithAuditAndRejectsReadOnlyOrEscapedTransactions() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(40)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        let event = try AuditEventMetadata(eventID: id(41), macID: id(2), accountID: id(3), journalEpoch: id(40),
            sequence: 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .enrollmentRevoked,
            category: .enrollment, action: nil, decisionPhoneID: nil, authentication: .localAdministrator,
            outcome: .accepted, reason: .revoked, droppedEventCount: nil, peerDeviceID: id(6)).encode(limits: limits)
        XCTAssertThrowsError(try db.write {
            _ = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
            try $0.append(event, writer: writer, expectedHead: 0)
            throw Failure.injected
        })
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.epoch(id(40))?.head }, 0)
        XCTAssertThrowsError(try db.read {
            try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.write { $0 }
        XCTAssertThrowsError(try escaped.gatewayEnrollmentRevoked(trust: trust())) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        try db.write {
            _ = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
            try $0.append(event, writer: writer, expectedHead: 0)
        }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.page(epoch: id(40), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }, [event])
    }

    func testRevocationSignatureCapacityScopeAndIndependentDeadlines() throws {
        let fixture = try Fixture(), db = try setup(fixture, maximum: 2)
        XCTAssertThrowsError(try db.write {
            try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: { _ in id(0, count: 64) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature) }
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        let removal = try revoke(db, head: 0)
        for (wall, now): (UInt64, UInt64) in [(2010, 110), (1009, 110), (1010, 1110)] {
            XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
                nowUnixMillis: wall, now: moment(now)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        }
        _ = try revoke(db, head: 1, now: 1110)
        XCTAssertThrowsError(try revoke(db, head: 2, now: 1110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(phone: 9),
            nowUnixMillis: 1010, now: moment(1110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope) }
    }

    func testRevocationCorruptionRetiresOwner() throws {
        for mutation in ["UPDATE gateway_revocations_v1 SET signature=zeroblob(64)",
                         "UPDATE gateway_revocations_v1 SET payload=x'01'", "UPDATE gateway_revocations_v1 SET phone=zeroblob(16)",
                         "UPDATE gateway_revocations_v1 SET deadline=started", "DELETE FROM gateway_revocations_v1"] {
            let fixture = try Fixture(), db = try setup(fixture)
            _ = try revoke(db, head: 0)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
    }

    func testSchemaFourMigrationPreservesCandidateAndAddsNoRevocation() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        try db.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; PRAGMA user_version=4")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 4)
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertFalse(try migrated.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        let fresh = try migrated.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1,
            nowUnixMillis: 1000, now: moment(), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "12")
    }

    func testFailedSchemaFourMigrationKeepsVersionAndExistingControls() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        _ = try prepare(db); try db.close()
        try fixture.sql("PRAGMA user_version=4")
        XCTAssertThrowsError(try open(fixture, migrate: 4))
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "4")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1")
        let migrated = try open(fixture, migrate: 4)
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
    }

    private func enrollForRecovery(_ db: JournalDatabase, tag: UInt8 = 6, empty: Bool = false, onWriter: (AuditEpochWriter) -> Void = { _ in }) throws -> UUID {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        if empty { return revision }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(20)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        onWriter(writer)
        let value = try StoredApprovalEnrollment(epoch: id(7), notificationTag: id(tag, count: 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(6), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(11), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                EnrolledApprovalKey(id: id(12), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
        return try db.write { try $0.addApprovalEnrollment(value, expectedTrustRevision: revision,
            eventID: id(21), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
    }

    private func lostDelivery(_ db: JournalDatabase) throws -> [GatewayAuthorityEnvelope] {
        var controls: [GatewayAuthorityEnvelope] = []
        do {
            try db.write { tx in
                let trusted = try trust()
                let next = try tx.prepareGatewayCandidate(registrationToken: "lost-remote-token", authenticatedPhoneID: id(6),
                    authenticatedEnrollmentEpoch: id(7), trust: trusted, expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
                controls.append(next)
                controls.append(try tx.consumeGatewayProof(canonicalProof: proof(next), authenticatedPhoneID: id(6),
                    authenticatedEnrollmentEpoch: id(7), trust: trusted, expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: sign))
                throw Failure.injected
            }
        } catch Failure.injected { }
        return controls
    }

    private func recover(_ db: JournalDatabase, _ history: VerifiedGatewayHistory, revision: UUID, local: UInt64 = 1) throws -> GatewayHistoryRecoveryResult {
        try db.write { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: true,
            expectedTrustRevision: revision, expectedLocalRevision: local, now: moment(120)) }
    }

    func testCompleteDeliveryRecoveryRetiresOldProofAndRenewsOnlyLocalDesiredToken() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db, token: "current-local-token"), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot() }.revision, revision)
        for entry in lost {
            XCTAssertNil(try db.read { try $0.pendingGatewayControl(operationID: entry.operationID,
                trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
        }
        XCTAssertThrowsError(try consume(db, first, head: 3, wall: 1020, now: 120)) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(phoneID: id(6), enrollmentEpoch: id(7),
            registration: trust().registration, registrationActive: true, expectedTrustRevision: revision,
            expectedHead: 3, nowUnixMillis: 1020, now: moment(120), sign: sign) }
        XCTAssertEqual(fresh.revision, 4); XCTAssertEqual(fresh.registrationToken, "current-local-token")
        XCTAssertNotEqual(try candidate(fresh).binding.challenge, try candidate(first).binding.challenge)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "2")
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAuthorityHead(trust().registration) }, 4)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
    }

    func testRecoveryRejectsUnknownEnrollmentAndChangedTagsWithoutAdoption() throws {
        for empty in [true, false] {
            let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db, tag: 99, empty: empty)
            let first = try prepare(db), lost = try lostDelivery(db)
            let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
            XCTAssertEqual(try recover(db, history, revision: revision).disposition, .requiresTrustRecovery)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        }
    }

    func testRecoveredRevocationCannotUseDeliveryOnlyCounterRepair() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), candidate = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([candidate, removal], after: 0).1)
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    private func recoverRemoval(_ db: JournalDatabase, _ removal: GatewayAuthorityEnvelope, revision: UUID,
                                writer: AuditEpochWriter) throws -> UUID {
        try db.write { try $0.recoverGatewayRevocation(canonicalPayload: removal.canonicalPayload, signature: removal.signature,
            registration: trust().registration, expectedTrustRevision: revision, eventID: id(22), receiptTimeMs: 1020,
            writer: writer, expectedAuditHead: 1) }
    }

    func testRestrictedRemovalHistoryReconcilesWithoutRestoringAuthorityOrReplayingControl() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        let history = try XCTUnwrap(gatewayEvidence([first, activation, removal], after: 0).1)
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let before = try enrollForRecovery(db, onWriter: { writer = $0 })
        let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.operationID, removal.operationID)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot() }.revision, revision)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "2")
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "1")
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID,
            trust: trust(active: false), nowUnixMillis: 1020, now: moment(120)) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        XCTAssertThrowsError(try prepare(db, head: 3, wall: 1020, now: 120)) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment)
        }
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .localHeadChanged)
        let refreshed = try revoke(db, head: 3, trusted: trust(active: false), wall: 1020, now: 120)
        XCTAssertEqual(refreshed.revision, 4)
        XCTAssertNotEqual(refreshed.operationID, removal.operationID)
        XCTAssertNotNil(try db.read { try $0.pendingGatewayRevocation(operationID: refreshed.operationID,
            trust: trust(active: false), nowUnixMillis: 1020, now: moment(120)) })
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAuthorityHead(trust().registration) }, 4)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
    }

    func testRevocationRestrictionAndHistoryRepairCanCommitTogetherAtSharedBoundary() throws {
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?, removal: GatewayAuthorityEnvelope?
        let before = try enrollForRecovery(db, onWriter: { writer = $0 })
        let first = try prepare(db)
        do {
            try db.write {
                removal = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 1,
                    nowUnixMillis: 1010, now: moment(110), sign: sign)
                throw Failure.injected
            }
        } catch Failure.injected { }
        let evidence = try XCTUnwrap(removal), history = try XCTUnwrap(gatewayEvidence([first, evidence], after: 1).1)
        let revision = try db.write { tx in
            let revision = try tx.recoverGatewayRevocation(canonicalPayload: evidence.canonicalPayload, signature: evidence.signature,
                registration: trust().registration, expectedTrustRevision: before, eventID: id(22), receiptTimeMs: 1020,
                writer: XCTUnwrap(writer), expectedAuditHead: 1)
            let result = try tx.reconcileGatewayDeliveryHistory(history, registrationActive: true,
                expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120))
            XCTAssertEqual(result.disposition, .reconciled)
            return revision
        }
        XCTAssertNotEqual(revision, before)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 2)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
        XCTAssertEqual(try db.write { try $0.recoverGatewayRevocation(canonicalPayload: evidence.canonicalPayload, signature: evidence.signature,
            registration: trust().registration, expectedTrustRevision: revision, eventID: id(23), receiptTimeMs: 1020,
            writer: XCTUnwrap(writer), expectedAuditHead: 2) }, revision)
    }

    func testReconciliationRequiresBothPermanentEvidenceAndInactiveEnrollment() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for missingEvidence in [true, false] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            if missingEvidence { try f.sql("DELETE FROM gateway_recovered_revocations_v1") }
            else { try f.sql("UPDATE approval_enrollments_v1 SET active=1") }
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
        }
    }

    func testRestrictedRemovalReconciliationRollsBackWithoutUndoingCommittedRestriction() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for target in ["gateway_reconciled_controls_v1", "gateway_revocations_v1", "gateway_authority_v1", "gateway_acknowledgment_v1"] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            let operation = target == "gateway_authority_v1" ? "UPDATE" : "INSERT"
            try f.sql("CREATE TRIGGER reject_recovery BEFORE \(operation) ON \(target) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try recover(db, history, revision: revision, local: 0))
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
            try f.sql("DROP TRIGGER reject_recovery")
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .reconciled)
        }
    }

    func testRecoveredRemovalOperationCannotBeReusedByDifferentHistoricalControl() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        let original = try GatewayPhoneRevocation.decode(removal.canonicalPayload, limits: limits)
        for operation in [first.operationID, removal.operationID] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let other = try GatewayPhoneRevocation(binding: original.binding, revision: original.revision, operationID: operation,
                issuedAtUnixMillis: original.issuedAtUnixMillis, expiresAtUnixMillis: original.expiresAtUnixMillis + 1)
            let evidence = try GatewayAuthorityEnvelope(kind: 3, operationID: operation, revision: other.revision,
                canonicalPayload: other.encode(limits: limits), signature: sign(other), registrationToken: nil)
            let revision = try recoverRemoval(db, evidence, revision: before, writer: XCTUnwrap(writer))
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .conflictingLocalHistory)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        }
    }

    func testRestrictedRemovalHistoryCapacityAndUnknownTagStillRefuseAdoption() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for capacity in [true, false] {
            let f = try Fixture(), db = try setup(f, maximum: capacity ? 2 : 20)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, tag: capacity ? 6 : 99, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            if capacity {
                XCTAssertThrowsError(try recover(db, history, revision: revision, local: 0)) {
                    XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded)
                }
            } else {
                XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
            }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        }
    }

    func testUnknownTrustRestrictionPreventsDeliveryRepairEvenForOtherKnownHistory() throws {
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        let b = try candidate(first).binding
        let binding = try GatewayTokenBinding(ownerID: b.ownerID, macID: b.macID, accountID: b.accountID,
            gatewayID: b.gatewayID, lifecycleEpoch: b.lifecycleEpoch, phoneID: b.phoneID, enrollmentEpoch: id(99),
            candidateID: id(97), tokenDigest: b.tokenDigest, challenge: b.challenge, enrollmentTag: b.enrollmentTag)
        let unknown = try GatewayTokenCandidate(binding: binding, revision: 99, operationID: id(98), issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
        let restricted = try db.write { try $0.restrictUnknownGatewayTrust(kind: .candidate, canonicalPayload: unknown.encode(limits: limits),
            signature: sign(unknown), registration: trust().registration, expectedTrustRevision: revision,
            eventID: id(23), receiptTimeMs: 1020, writer: XCTUnwrap(writer), expectedAuditHead: 1) }
        XCTAssertEqual(try recover(db, history, revision: restricted.trustRevision).disposition, .requiresTrustRecovery)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
    }

    func testRecoveryRechecksLocalCounterTrustRevisionRegistrationAndTransactionMode() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertThrowsError(try recover(db, history, revision: UUID())) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try db.write { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: false,
            expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration) }
        XCTAssertThrowsError(try db.read { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: true,
            expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120)) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        _ = try prepare(db, head: 1, now: 120)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .localHeadChanged)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testRecoveryRollsBackReceiptsCounterAcknowledgmentAndCandidateRetirementTogether() throws {
        for target in ["gateway_reconciled_controls_v1", "gateway_root_candidates_v1", "gateway_authority_v1", "gateway_acknowledgment_v1"] {
            let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
            let first = try prepare(db), lost = try lostDelivery(db)
            let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
            let event = target == "gateway_root_candidates_v1" || target == "gateway_authority_v1" ? "UPDATE" : "INSERT"
            try f.sql("CREATE TRIGGER reject_recovery BEFORE \(event) ON \(target) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try recover(db, history, revision: revision))
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
            XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID,
                trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
            try f.sql("DROP TRIGGER reject_recovery")
            XCTAssertEqual(try recover(db, history, revision: revision).disposition, .reconciled)
        }
    }

    func testRecoveryCapacityFailureDoesNotPartiallyAdoptHistory() throws {
        let f = try Fixture(), db = try setup(f, maximum: 2), revision = try enrollForRecovery(db)
        let first = try prepare(db)
        let sourceFixture = try Fixture(), source = try setup(sourceFixture)
        _ = try prepare(source)
        let lost = try lostDelivery(source)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertThrowsError(try recover(db, history, revision: revision)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, first.revision)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryRejectsAnOperationAlreadyRetainedAtAnotherRevision() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db), first = try prepare(db)
        let boundary = try prepare(db, head: 1)
        let original = try candidate(first)
        let reused = try GatewayTokenCandidate(binding: original.binding, revision: 3, operationID: first.operationID,
            issuedAtUnixMillis: original.issuedAtUnixMillis, expiresAtUnixMillis: original.expiresAtUnixMillis)
        let envelope = try GatewayAuthorityEnvelope(kind: 1, operationID: first.operationID, revision: 3,
            canonicalPayload: reused.encode(limits: limits), signature: sign(reused), registrationToken: first.registrationToken)
        let history = try XCTUnwrap(gatewayEvidence([boundary, envelope], after: 2).1)
        XCTAssertEqual(try recover(db, history, revision: revision, local: 2).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryRejectsAConflictingSharedBoundaryWithoutRetiringCandidates() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db), first = try prepare(db)
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), remote = try prepare(source)
        let activation = try consume(source, remote)
        let history = try XCTUnwrap(gatewayEvidence([remote, activation], after: 1).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
        XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID,
            trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
    }

    func testRecoveryRequiresTheSharedReceiptEvenWhenTheSuffixIsComplete() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1, includeBoundary: false).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryDoesNotHideALocalRevocationBehindAnEqualGatewayCounter() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), remote = try prepare(source)
        let activation = try consume(source, remote)
        let history = try XCTUnwrap(gatewayEvidence([remote, activation], after: 1).1)
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        _ = try revoke(db, head: 0)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveredReceiptCorruptionRetiresTheStorageOwner() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        _ = try recover(db, history, revision: revision)
        try f.sql("UPDATE gateway_reconciled_controls_v1 SET signature=zeroblob(64)")
        XCTAssertThrowsError(try db.read { try $0.gatewayAuthorityHead(trust().registration) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testSchemaEightMigrationPreservesDesiredStateAndStartsWithoutRecoveredHistory() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        try db.close()
        try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; PRAGMA user_version=8")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 8)
        XCTAssertEqual(try f.scalar("PRAGMA user_version"), "12")
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
        let fresh = try migrated.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1,
            nowUnixMillis: 1020, now: moment(120), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
    }

    private func verifiedHead(_ controls: [GatewayAuthorityEnvelope]) throws -> VerifiedGatewayHead {
        try gatewayEvidence(controls).0
    }
    func testUnknownSubmissionHistoryCannotRepairPhoneTrustOrAdvanceRootHead() throws {
        for kind in [GatewaySubmissionKind.rotation, .revocation] {
            let fixture = try Fixture(), db = try setup(fixture), registration = try trust().registration
            var writer: AuditEpochWriter?
            let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
            let control = try GatewaySubmissionControl(kind: kind,
                binding: GatewaySubmissionBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5)),
                revision: 1, operationID: id(30), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000,
                credentialID: id(31), publicKey: kind == .rotation ? P256.Signing.PrivateKey().publicKey.x963Representation : nil)
            let payload = try control.encode(limits: limits)
            let signature = try key.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: kind,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
            let envelope = GatewayAuthorityEnvelope(kind: kind.rawValue, operationID: control.operationID,
                revision: 1, canonicalPayload: payload, signature: signature, registrationToken: nil)
            let (head, history) = try gatewayEvidence([envelope], after: 0)
            XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(head) }.disposition, .missingLocalHistory)
            XCTAssertEqual(try db.write { try $0.reconcileGatewayDeliveryHistory(XCTUnwrap(history), registrationActive: true,
                expectedTrustRevision: revision, expectedLocalRevision: 0, now: moment(120)) }.disposition, .requiresTrustRecovery)
            XCTAssertThrowsError(try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
                receiptTimeMs: 1020, writer: XCTUnwrap(writer), expectedAuditHead: 1) }) {
                XCTAssertEqual($0 as? GatewayAuthorityError, .unsupportedSubmissionControl)
            }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(registration) }, 0)
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(registration) })
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot() }.revision, revision)
        }
    }


    private func installSubmissionFeatures(_ db: JournalDatabase) throws {
        try db.write { tx in
            _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [
                AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
                    installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
            ]), expectedRevision: nil)
            try tx.installCommandSubmissionReplay()
            try tx.installGatewaySubmissionHistory(trust().registration)
        }
    }
    private func signSubmission(_ value: GatewaySubmissionControl) throws -> Data {
        try key.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: value.kind,
            canonicalPayload: value.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func rotateSubmission(_ db: JournalDatabase, head: UInt64 = 0, publicKey: Data? = nil,
                                  wall: UInt64 = 1000, now: UInt64 = 100) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.rotateGatewaySubmission(publicKey: publicKey ?? P256.Signing.PrivateKey().publicKey.x963Representation,
            registration: trust().registration, registrationActive: true, expectedHead: head, nowUnixMillis: wall,
            now: moment(now), sign: signSubmission) }
    }
    private func revokeSubmission(_ db: JournalDatabase, credential: Data, head: UInt64, wall: UInt64 = 1000,
                                  now: UInt64 = 100) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.revokeGatewaySubmission(credentialID: credential, registration: trust().registration,
            registrationActive: true, expectedHead: head, nowUnixMillis: wall, now: moment(now), sign: signSubmission) }
    }
    private func submissionValue(_ envelope: GatewayAuthorityEnvelope) throws -> GatewaySubmissionControl {
        try GatewaySubmissionControl.decode(envelope.canonicalPayload, limits: limits)
    }

    func testRootSubmissionInstallIsExplicitAndChangesOnlyAuthorityDigest() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        XCTAssertThrowsError(try rotateSubmission(db))
        XCTAssertThrowsError(try db.write { try $0.installGatewaySubmissionHistory(trust().registration) })
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "12")
        try db.write { tx in
            _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [
                AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
                    installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
            ]), expectedRevision: nil)
            try tx.installCommandSubmissionReplay()
        }
        let before = try db.read { try $0.continuityDigests() }
        XCTAssertThrowsError(try db.write { tx in
            try tx.installGatewaySubmissionHistory(trust().registration)
            throw Failure.injected
        })
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "15")
        XCTAssertEqual(try db.read { try $0.continuityDigests() }, before)
        try db.write { try $0.installGatewaySubmissionHistory(trust().registration) }
        let installed = try db.read { try $0.continuityDigests() }
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "16")
        XCTAssertNotEqual(installed.authority, before.authority); XCTAssertEqual(installed.ledger, before.ledger)
        try db.write { try $0.installGatewaySubmissionHistory(trust().registration) }
        XCTAssertEqual(try db.read { try $0.continuityDigests() }, installed)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.continuityDigests() }, installed)
        XCTAssertEqual(try reopened.read { try $0.codePolicy() }?.policy.entries.count, 1)
        XCTAssertNil(try reopened.read { try $0.historyRecovery(epoch: id(9)) })
    }

    func testRootSubmissionControlsShareHeadCapacityAndAcknowledgment() throws {
        let fixture = try Fixture(), db = try setup(fixture, maximum: 3)
        try installSubmissionFeatures(db)
        let first = try prepare(db), rotation = try rotateSubmission(db, head: 1), value = try submissionValue(rotation)
        XCTAssertEqual(rotation.revision, 2); XCTAssertNil(rotation.registrationToken)
        let removal = try revokeSubmission(db, credential: value.credentialID, head: 2)
        XCTAssertEqual(removal.kind, 5); XCTAssertEqual(removal.revision, 3)
        XCTAssertNil(try db.read { try $0.desiredGatewaySubmission(trust().registration) })
        XCTAssertThrowsError(try rotateSubmission(db, head: 3)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertThrowsError(try prepare(db, head: 3)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        let (head, _) = try gatewayEvidence([first, rotation, removal])
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(head) }.disposition, .recorded)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
    }

    func testRootSubmissionRestartRenewalUsesCurrentIntentAndFreshCredentialIdentity() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        try installSubmissionFeatures(db)
        let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
        let first = try rotateSubmission(db, publicKey: publicKey)
        XCTAssertEqual(try db.read { try $0.pendingGatewaySubmission(operationID: first.operationID,
            registration: trust().registration, registrationActive: true, nowUnixMillis: 1001, now: moment(101)) }?.canonicalPayload, first.canonicalPayload)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertThrowsError(try reopened.read { try $0.pendingGatewaySubmission(operationID: first.operationID,
            registration: trust().registration, registrationActive: true, nowUnixMillis: 1001, now: moment(101)) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        let renewed = try reopened.write { try $0.renewGatewaySubmission(operationID: first.operationID,
            registration: trust().registration, registrationActive: true, expectedHead: 1, nowUnixMillis: 3000,
            now: moment(110), sign: signSubmission) }
        XCTAssertEqual(renewed.revision, 2); XCTAssertNotEqual(renewed.operationID, first.operationID)
        XCTAssertNotEqual(try submissionValue(renewed).credentialID, try submissionValue(first).credentialID)
        XCTAssertEqual(try submissionValue(renewed).publicKey, publicKey)
        XCTAssertThrowsError(try reopened.write { try $0.renewGatewaySubmission(operationID: first.operationID,
            registration: trust().registration, registrationActive: true, expectedHead: 2, nowUnixMillis: 3001,
            now: moment(111), sign: signSubmission) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        _ = try revokeSubmission(reopened, credential: submissionValue(first).credentialID, head: 2, wall: 3001, now: 111)
        XCTAssertEqual(try reopened.read { try $0.desiredGatewaySubmission(trust().registration) }?.control.operationID, renewed.operationID)
        _ = try revokeSubmission(reopened, credential: submissionValue(renewed).credentialID, head: 3, wall: 3002, now: 112)
        XCTAssertNil(try reopened.read { try $0.desiredGatewaySubmission(trust().registration) })
    }

    func testRootSubmissionSignerFailureAndOuterRollbackLeaveNoAuthority() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        try installSubmissionFeatures(db)
        let before = try db.read { try $0.continuityDigests() }, publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertThrowsError(try db.write { try $0.rotateGatewaySubmission(publicKey: publicKey, registration: trust().registration,
            registrationActive: true, expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: { _ in Data(repeating: 0, count: 64) }) })
        XCTAssertThrowsError(try db.write { tx in
            _ = try tx.rotateGatewaySubmission(publicKey: publicKey, registration: trust().registration,
                registrationActive: true, expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signSubmission)
            throw Failure.injected
        })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
        XCTAssertEqual(try db.read { try $0.continuityDigests() }, before)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_submission_outbox_v1"), "0")
    }

    func testRootSubmissionCannotHideRevocationWithAlteredCredentialColumn() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        try installSubmissionFeatures(db)
        let first = try rotateSubmission(db)
        _ = try revokeSubmission(db, credential: submissionValue(first).credentialID, head: 1)
        // Leave an unrelated latest control intact so head validation alone cannot detect the altered older row.
        _ = try revokeSubmission(db, credential: id(99), head: 2)
        try fixture.sql("UPDATE gateway_submission_outbox_v1 SET credential=zeroblob(16) WHERE revision=X'0000000000000002'")
        XCTAssertThrowsError(try db.read { try $0.desiredGatewaySubmission(trust().registration) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { try $0.gatewayAuthorityHead(trust().registration) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .unavailable)
        }
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_submission_outbox_v1"), "3")
    }

    func testRootSubmissionRejectsInactiveAuthorityAndBothDeadlineBoundaries() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        try installSubmissionFeatures(db)
        let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertThrowsError(try db.write { try $0.rotateGatewaySubmission(publicKey: publicKey,
            registration: trust().registration, registrationActive: false, expectedHead: 0,
            nowUnixMillis: 1000, now: moment(100), sign: signSubmission) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration)
        }
        let first = try rotateSubmission(db, publicKey: publicKey), value = try submissionValue(first)
        XCTAssertThrowsError(try db.write { try $0.renewGatewaySubmission(operationID: first.operationID,
            registration: trust().registration, registrationActive: false, expectedHead: 1,
            nowUnixMillis: 1001, now: moment(101), sign: signSubmission) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration)
        }
        let duration = value.expiresAtUnixMillis - value.issuedAtUnixMillis
        for (wall, mono) in [(value.expiresAtUnixMillis, UInt64(102)), (UInt64(1001), 100 + duration)] {
            XCTAssertThrowsError(try db.read { try $0.pendingGatewaySubmission(operationID: first.operationID,
                registration: trust().registration, registrationActive: true, nowUnixMillis: wall, now: moment(mono)) }) {
                XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
            }
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
    }

    func testRootSubmissionRecoveryRetainsReceiptWithoutPhoneTrustChangeOrFreshDeadline() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        try installSubmissionFeatures(db)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        var escaped: GatewayAuthorityEnvelope?
        do {
            try db.write { tx in
                escaped = try tx.rotateGatewaySubmission(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                    registration: trust().registration, registrationActive: true, expectedHead: 0,
                    nowUnixMillis: 1000, now: moment(), sign: signSubmission)
                throw Failure.injected
            }
        } catch Failure.injected {}
        let envelope = try XCTUnwrap(escaped), (head, history) = try gatewayEvidence([envelope], after: 0)
        let repaired = try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: 1020, writer: XCTUnwrap(writer), expectedAuditHead: 1) }
        XCTAssertEqual(repaired.trustRevision, revision); XCTAssertTrue(repaired.changedPhoneIDs.isEmpty)
        XCTAssertEqual(try db.write { try $0.reconcileGatewayDeliveryHistory(XCTUnwrap(history), registrationActive: true,
            expectedTrustRevision: revision, expectedLocalRevision: 0, now: moment(120)) }.disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try db.read { try $0.desiredGatewaySubmission(trust().registration) }?.canonicalPayload, envelope.canonicalPayload)
        XCTAssertThrowsError(try db.read { try $0.pendingGatewaySubmission(operationID: envelope.operationID,
            registration: trust().registration, registrationActive: true, nowUnixMillis: 1020, now: moment(120)) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
    }


    func testRootSubmissionRecoveryRejectsCredentialReuseWithinMissingBatchAtomically() throws {
        for priorKind in [GatewaySubmissionKind.rotation, .revocation] {
            let fixture = try Fixture(), db = try setup(fixture)
            try installSubmissionFeatures(db)
            let first = try rotateSubmission(db), registration = try trust().registration
            let revision = try enrollForRecovery(db)
            let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
            var receipts: [GatewayControlReceipt] = [.submission(GatewaySubmissionReceipt(
                control: try submissionValue(first), canonicalPayload: first.canonicalPayload, signature: first.signature))]
            var last: GatewayAuthorityEnvelope?
            for (number, kind) in [(UInt64(2), priorKind), (UInt64(3), GatewaySubmissionKind.rotation)] {
                let value = try GatewaySubmissionControl(kind: kind,
                    binding: GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID,
                        accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch),
                    revision: number, operationID: id(UInt8(30 + number)), issuedAtUnixMillis: 1000,
                    expiresAtUnixMillis: 2000, credentialID: id(40), publicKey: kind == .rotation ? publicKey : nil)
                let payload = try value.encode(limits: limits), signature = try signSubmission(value)
                _ = try GatewaySubmissionVerifier.authenticate(canonicalPayload: payload, signature: signature, wireVersion: 1,
                    registration: registration, payloadLimits: limits, signingLimits: limits)
                receipts.append(.submission(GatewaySubmissionReceipt(control: value, canonicalPayload: payload, signature: signature)))
                last = GatewayAuthorityEnvelope(kind: kind.rawValue, operationID: value.operationID, revision: number,
                    canonicalPayload: payload, signature: signature, registrationToken: nil)
            }
            let head = try verifiedHead([XCTUnwrap(last)])
            let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
            let page = GatewayControlHistoryPage(registration: registration, afterRevision: 0, throughRevision: 3,
                records: receipts, hasMore: false)
            let history = try XCTUnwrap(collector.accept(VerifiedGatewayControlHistory(page: page,
                receivedAt: moment(120), queryOwnerID: head.queryOwnerID)))
            let before = try db.read { try $0.continuityDigests() }
            XCTAssertEqual(try db.write { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: true,
                expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120)) }.disposition, .conflictingLocalHistory)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(registration) }, 1)
            XCTAssertEqual(try db.read { try $0.continuityDigests() }, before)
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_submission_outbox_v1"), "1")
        }
    }

    private final class EndpointDriver: GatewayRootDriver {
        let endpoint: GatewayXPCEndpoint
        init(_ endpoint: GatewayXPCEndpoint) { self.endpoint = endpoint }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            switch call {
            case .hello: endpoint.hello { reply(.version($0)) }
            case .synchronize(let bytes): endpoint.synchronize(bytes) { reply(.synchronized($0)) }
            case .command(let bytes): endpoint.command(bytes) { reply(.command($0)) }
            }
        }
        func close() { endpoint.close() }
    }

    func testRootOutboxEndpointCoordinatorAndFreshAcknowledgmentRoundTrip() async throws {
        let rootFixture = try Fixture(), root = try setup(rootFixture), registration = try trust().registration
        try installSubmissionFeatures(root)
        let envelope = try rotateSubmission(root), gatewayFixture = try Fixture()
        let database = try gatewayFixture.gateway(identity: registration, limits: limits, epoch: clockEpoch)
        let epoch = clockEpoch, providerCalls = Mutex(0), allowed = Mutex(true)
        let tokens = try FCMTokenSource(now: { .now }, refresh: {
            providerCalls.withLock { $0 += 1 }
            return FCMTokenLease(value: try FCMAccessToken("synthetic"), expiresAt: .now.advanced(by: .seconds(3600)))
        })
        let coordinator = try GatewayDeliveryCoordinator(database: database, identity: registration, tokens: tokens,
            policy: GatewayDeliveryPolicy(maximumFlights: 1, minimumSendIntervalMillis: 10),
            sample: { .init(wall: 1010, moment: AuthorityMoment(epoch: epoch, milliseconds: 110)) },
            sleep: { _ in }, send: { _, _ in providerCalls.withLock { $0 += 1 }; return .accepted })
        let endpoint = GatewayXPCEndpoint(verify: {
            guard allowed.withLock({ $0 }) else { throw GatewayServiceError.wrongAccount }
        }, budget: try AuthorityXPCWorkBudget(maximum: 1), invalidate: {}, synchronize: { _ in }, execute: { command in
            guard case .submission(let payload, let signature, let version) = command else { throw GatewayServiceError.invalidMessage }
            let result = try await coordinator.applySubmission(canonicalPayload: payload, signature: signature, wireVersion: version)
            return try GatewayRootCommand.reply([.bytes(result.receipt.canonicalPayload), .bytes(result.receipt.signature), .boolean(result.inserted)], version: 2)
        })
        let channel = GatewayRootChannel(driver: EndpointDriver(endpoint))
        try await channel.start()
        let applied = try await channel.applySubmission(envelope, registration: registration)
        XCTAssertTrue(applied.inserted); XCTAssertEqual(applied.receipt.canonicalPayload, envelope.canonicalPayload)
        let retry = try await channel.applySubmission(envelope, registration: registration)
        XCTAssertFalse(retry.inserted)

        let gatewayKey = P256.Signing.PrivateKey(), owner = try GatewayHeadQueryOwner(registration: registration,
            gatewayPublicKey: gatewayKey.publicKey.x963Representation, clockEpoch: epoch)
        let query = try owner.makeQuery(now: moment(110))
        let reply = try await coordinator.recoveryHeadReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        let head = try owner.accept(reply, now: moment(111))
        XCTAssertEqual(head.evidence.receipt?.kind, 4)
        XCTAssertEqual(try root.write { try $0.acknowledgeGatewayHead(head) }.disposition, .recorded)
        XCTAssertEqual(providerCalls.withLock { $0 }, 0)
        allowed.withLock { $0 = false }
        do { _ = try await channel.applySubmission(envelope, registration: registration); XCTFail() } catch {}
        XCTAssertEqual(try root.read { try $0.gatewayAuthorityHead(registration) }, 1)
        await channel.close()
        try await coordinator.shutdown()
    }

    private func gatewayEvidence(_ controls: [GatewayAuthorityEnvelope], after: UInt64? = nil, includeBoundary: Bool = true,
                                 maximumRecords: Int = 16, collect: Bool = true, onPage: ((VerifiedGatewayControlHistory) -> Void)? = nil) throws -> (VerifiedGatewayHead, VerifiedGatewayHistory?) {
        let f = try Fixture(), trusted = try trust()
        let gateway = try f.gateway(identity: trusted.registration, limits: limits, epoch: clockEpoch)
        defer { try? gateway.close() }
        for control in controls {
            let r = trusted.registration
            let snapshot = try GatewayCandidateTrust(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
                gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey,
                active: true, revision: UUID(), appliedControlRevision: gateway.head(), enrollment: trusted.enrollment)
            if control.kind == 1 {
                _ = try gateway.admitCandidate(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, registrationToken: XCTUnwrap(control.registrationToken), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            } else if GatewaySubmissionKind(rawValue: control.kind) != nil {
                _ = try gateway.applySubmission(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, trust: GatewaySubmissionTrust(registration: r, active: true, revision: UUID(), appliedControlRevision: gateway.head()),
                    nowUnixMillis: 1010, now: moment(110))
            } else {
                _ = try gateway.applyRecipient(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, kind: XCTUnwrap(GatewayRecipientKind(rawValue: control.kind)), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            }
        }
        let gatewayKey = P256.Signing.PrivateKey()
        let owner = try GatewayHeadQueryOwner(registration: trusted.registration,
            gatewayPublicKey: gatewayKey.publicKey.x963Representation, clockEpoch: clockEpoch)
        let query = try owner.makeQuery(now: moment(110))
        let reply = try gateway.headReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        let head = try owner.accept(reply, now: moment(111))
        guard let after else { return (head, nil) }
        let lowerBound = after == 0 || !includeBoundary ? after : after - 1
        let collector = try GatewayHistoryCollector(head: head, afterRevision: lowerBound)
        let historyQuery = try owner.makeHistoryQuery(afterRevision: lowerBound, throughRevision: head.evidence.revision, maximumRecords: maximumRecords, now: moment(111))
        let historyReply = try gateway.controlHistoryReply(canonicalQuery: historyQuery) { try gatewayKey.signature(for: $0).rawRepresentation }
        let page = try owner.acceptHistory(historyReply, now: moment(112))
        onPage?(page)
        return (head, collect ? try XCTUnwrap(collector.accept(page)) : nil)
    }

    private func withRecoveryAttempt(_ controls: [GatewayAuthorityEnvelope], tag: UInt8 = 6, pageSize: Int = 16,
                                     maximumRecords: Int = 100_000,
                                     prepareLocal: ((JournalDatabase) throws -> [GatewayAuthorityEnvelope])? = nil,
                                     body: (Fixture, JournalDatabase, AuditEpochWriter, GatewayDatabase, P256.Signing.PrivateKey, GatewayRecoveryAttempt) throws -> Void) throws {
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        _ = try enrollForRecovery(db, tag: tag, onWriter: { writer = $0 })
        let audit = try XCTUnwrap(writer)
        let controls = try prepareLocal?(db) ?? controls
        let gf = try Fixture(), trusted = try trust(), r = trusted.registration
        let gateway = try gf.gateway(identity: r, limits: limits, epoch: clockEpoch)
        defer { try? gateway.close(); try? db.close() }
        for control in controls {
            let snapshot = try GatewayCandidateTrust(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
                gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey,
                active: true, revision: UUID(), appliedControlRevision: gateway.head(), enrollment: trusted.enrollment)
            if control.kind == 1 {
                _ = try gateway.admitCandidate(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, registrationToken: XCTUnwrap(control.registrationToken), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            } else {
                _ = try gateway.applyRecipient(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, kind: XCTUnwrap(GatewayRecipientKind(rawValue: control.kind)), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            }
        }
        let gatewayKey = P256.Signing.PrivateKey()
        let attempt = try GatewayRecoveryAttempt(database: db, writer: audit, registration: r,
            gatewayPublicKey: gatewayKey.publicKey.x963Representation, clockEpoch: clockEpoch,
            queryLifetimeMillis: 10, pageSize: pageSize, maximumRecords: maximumRecords)
        try body(f, db, audit, gateway, gatewayKey, attempt)
    }

    private func receiveHead(_ attempt: GatewayRecoveryAttempt, _ gateway: GatewayDatabase,
                             _ gatewayKey: P256.Signing.PrivateKey, now: UInt64 = 110) throws {
        let query = try attempt.makeQuery(now: moment(now))
        let reply = try gateway.headReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        try attempt.accept(reply, now: moment(now + 1))
    }

    private func receivePage(_ attempt: GatewayRecoveryAttempt, _ gateway: GatewayDatabase,
                             _ gatewayKey: P256.Signing.PrivateKey, now: UInt64) throws {
        let query = try attempt.makeQuery(now: moment(now))
        let reply = try gateway.controlHistoryReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        try attempt.accept(reply, now: moment(now + 1))
    }

    func testRecoveryAttemptCheckpointsRestrictionsBeforeCollectingEveryPage() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        try withRecoveryAttempt([first, activation, removal], pageSize: 1) { _, db, _, gateway, key, attempt in
            try receiveHead(attempt, gateway, key)
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(111)))
            var checkpoints = 0
            let checkpoint: (GatewayTrustEvidenceRecovery) throws -> Void = { state in
                checkpoints += 1
                XCTAssertEqual(state.auditHead, 2)
                XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
                XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(self.trust().registration) }, 0)
            }
            try attempt.processPending(receiptTimeMs: 1020, checkpointAndRefresh: checkpoint)
            for time: UInt64 in [112, 114, 116] {
                try receivePage(attempt, gateway, key, now: time)
                try attempt.processPending(receiptTimeMs: 1020, checkpointAndRefresh: checkpoint)
            }
            XCTAssertEqual(checkpoints, 4)
            guard case .history(let history) = attempt.result else { return XCTFail("Missing collected history") }
            XCTAssertEqual(history.records.count, 3)
            XCTAssertEqual(attempt.expectedLocalRevision, 0)
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(118)))
            let revision = try db.read { try $0.approvalTrustSnapshot().revision }
            XCTAssertEqual(try recover(db, history, revision: revision, local: attempt.expectedLocalRevision).disposition, .reconciled)
        }
    }

    func testRecoveryAttemptRetriesCheckpointWithoutRepeatingCommittedRestriction() throws {
        let sf = try Fixture(), source = try setup(sf), removal = try revoke(source, head: 0)
        try withRecoveryAttempt([removal]) { f, db, _, gateway, key, attempt in
            try receiveHead(attempt, gateway, key)
            XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: 1020) { _ in throw Failure.injected })
            let pending = try XCTUnwrap(attempt.pendingCheckpoint)
            XCTAssertEqual(pending.changedPhoneIDs, [id(6)])
            XCTAssertEqual(pending.auditHead, 2)
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(112)))
            try f.sql("CREATE TRIGGER reject_retry BEFORE INSERT ON gateway_recovered_revocations_v1 BEGIN SELECT RAISE(ABORT, 'injected'); END")
            try attempt.processPending(receiptTimeMs: 9000) { state in
                XCTAssertEqual(state.trustRevision, pending.trustRevision)
                XCTAssertEqual(state.changedPhoneIDs, pending.changedPhoneIDs)
                XCTAssertEqual(state.auditHead, 2)
            }
            XCTAssertNil(attempt.pendingCheckpoint)
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
            try receivePage(attempt, gateway, key, now: 112)
        }
    }

    func testRecoveryAttemptRetainsVerifiedReplyAcrossStorageFailure() throws {
        let sf = try Fixture(), source = try setup(sf), removal = try revoke(source, head: 0)
        try withRecoveryAttempt([removal]) { f, db, _, gateway, key, attempt in
            try receiveHead(attempt, gateway, key)
            try f.sql("CREATE TRIGGER reject_recovery BEFORE INSERT ON gateway_recovered_revocations_v1 BEGIN SELECT RAISE(ABORT, 'injected'); END")
            var callbacks = 0
            XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: 1020) { _ in callbacks += 1 })
            XCTAssertEqual(callbacks, 0); XCTAssertNil(attempt.pendingCheckpoint)
            XCTAssertFalse(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
            try f.sql("DROP TRIGGER reject_recovery")
            try attempt.processPending(receiptTimeMs: 1020) { _ in callbacks += 1 }
            XCTAssertEqual(callbacks, 1)
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        }
    }

    func testRecoveryAttemptKeepsRestrictionWhenCollectionHasAGapOrExceedsBound() throws {
        let sf = try Fixture(), source = try setup(sf)
        _ = try prepare(source)
        let removal = try revoke(source, head: 1)
        for maximum in [1, 100] {
            try withRecoveryAttempt([removal], maximumRecords: maximum) { _, db, _, gateway, key, attempt in
                try receiveHead(attempt, gateway, key)
                if maximum == 1 {
                    XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: 1020) { _ in }) {
                        XCTAssertEqual($0 as? GatewayHistoryCollectionError, .capacityExceeded)
                    }
                } else {
                    try attempt.processPending(receiptTimeMs: 1020) { _ in }
                    try receivePage(attempt, gateway, key, now: 112)
                    XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: 1020) { _ in }) {
                        XCTAssertEqual($0 as? GatewayHistoryCollectionError, .incompleteHistory)
                    }
                }
                XCTAssertNil(attempt.result)
                XCTAssertThrowsError(try attempt.makeQuery(now: moment(114))) {
                    XCTAssertEqual($0 as? GatewayRecoveryAttemptError, .stopped)
                }
                XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
                XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            }
        }
    }

    func testRecoveryAttemptExpiresQueriesAndRejectsReplayAndWrongSignature() throws {
        try withRecoveryAttempt([]) { _, _, _, gateway, key, attempt in
            let old = try attempt.makeQuery(now: moment(110))
            let oldReply = try gateway.headReply(canonicalQuery: old) { try key.signature(for: $0).rawRepresentation }
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(111)))
            let fresh = try attempt.makeQuery(now: moment(120))
            XCTAssertThrowsError(try attempt.accept(oldReply, now: moment(120)))
            let reply = try gateway.headReply(canonicalQuery: fresh) { try key.signature(for: $0).rawRepresentation }
            XCTAssertThrowsError(try attempt.accept(GatewayHeadReply(canonicalPayload: reply.canonicalPayload, signature: id(9, count: 64)), now: moment(120)))
            try attempt.accept(reply, now: moment(121))
            XCTAssertThrowsError(try attempt.accept(reply, now: moment(121)))
            var checkpoints = 0
            try attempt.processPending(receiptTimeMs: nil) { _ in checkpoints += 1 }
            XCTAssertEqual(checkpoints, 1)
            guard case .head(let head) = attempt.result else { return XCTFail("Missing empty head") }
            XCTAssertEqual(head.evidence.revision, 0)
        }
    }

    func testRecoveryAttemptStopsAfterCheckpointStateDriftOrInvalidation() throws {
        let sf = try Fixture(), source = try setup(sf), first = try prepare(source)
        let removal = try revoke(source, head: 1)
        for drift in [false, true] {
            try withRecoveryAttempt([first]) { _, db, audit, gateway, key, attempt in
                try receiveHead(attempt, gateway, key)
                XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: 1020) { _ in
                    if drift {
                        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
                        _ = try db.write { try $0.recoverGatewayRevocation(canonicalPayload: removal.canonicalPayload, signature: removal.signature,
                            registration: trust().registration, expectedTrustRevision: revision,
                            eventID: id(50), receiptTimeMs: 1020, writer: audit, expectedAuditHead: 1) }
                    } else {
                        attempt.invalidate()
                    }
                }) {
                    XCTAssertEqual($0 as? GatewayRecoveryAttemptError, drift ? .localStateChanged : .stopped)
                }
                XCTAssertNil(attempt.result)
                XCTAssertThrowsError(try attempt.makeQuery(now: moment(112)))
            }
        }
    }

    func testRecoveryAttemptIncludesSharedBoundaryAndRequiresCurrentLocalHeadAtRepair() throws {
        let sf = try Fixture(), source = try setup(sf), first = try prepare(source), activation = try consume(source, first)
        try withRecoveryAttempt([first, activation]) { _, db, writer, gateway, key, unused in
            unused.invalidate()
            _ = try prepare(db)
            let attempt = try GatewayRecoveryAttempt(database: db, writer: writer, registration: trust().registration,
                gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: clockEpoch)
            XCTAssertEqual(attempt.expectedLocalRevision, 1)
            try receiveHead(attempt, gateway, key)
            try attempt.processPending(receiptTimeMs: nil) { _ in }
            try receivePage(attempt, gateway, key, now: 112)
            try attempt.processPending(receiptTimeMs: nil) { _ in }
            guard case .history(let history) = attempt.result else { return XCTFail("Missing history") }
            XCTAssertEqual(history.afterRevision, 0)
            XCTAssertEqual(history.records.count, 2)
            let revision = try db.read { try $0.approvalTrustSnapshot().revision }
            XCTAssertEqual(try recover(db, history, revision: revision, local: 1).disposition, .conflictingLocalHistory)
            _ = try prepare(db, head: 1, wall: 1020, now: 120)
            XCTAssertEqual(try recover(db, history, revision: revision, local: 1).disposition, .localHeadChanged)
        }
    }

    func testRecoveryAttemptBlocksReentryAndKeepsUnknownTrustRestrictedAfterCollection() throws {
        let sf = try Fixture(), source = try setup(sf), first = try prepare(source)
        try withRecoveryAttempt([first], tag: 99) { _, db, _, gateway, key, attempt in
            try receiveHead(attempt, gateway, key)
            try attempt.processPending(receiptTimeMs: nil) { state in
                XCTAssertEqual(state.restrictedPhoneIDs, [id(6)])
                XCTAssertThrowsError(try attempt.processPending(receiptTimeMs: nil) { _ in })
                XCTAssertThrowsError(try attempt.makeQuery(now: moment(112)))
            }
            try receivePage(attempt, gateway, key, now: 112)
            try attempt.processPending(receiptTimeMs: nil) { _ in }
            guard case .history(let history) = attempt.result else { return XCTFail("Missing history") }
            let revision = try db.read { try $0.approvalTrustSnapshot().revision }
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        }
    }

    func testRecoveryAttemptRejectsNewClockEpochAndInvalidConfiguration() throws {
        try withRecoveryAttempt([]) { _, db, writer, _, key, attempt in
            for pageSize in [0, 17] {
                XCTAssertThrowsError(try GatewayRecoveryAttempt(database: db, writer: writer, registration: trust().registration,
                    gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: clockEpoch, pageSize: pageSize))
            }
            _ = try attempt.makeQuery(now: moment(110))
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(120, epoch: UUID()))) {
                XCTAssertEqual($0 as? GatewayHeadReplyError, .invalidClock)
            }
            XCTAssertThrowsError(try attempt.makeQuery(now: moment(121))) {
                XCTAssertEqual($0 as? GatewayHeadReplyError, .stopped)
            }
        }
    }

    private func collectRecovery(_ attempt: GatewayRecoveryAttempt, _ gateway: GatewayDatabase,
                                 _ key: P256.Signing.PrivateKey) throws {
        try receiveHead(attempt, gateway, key)
        try attempt.processPending(receiptTimeMs: nil) { _ in }
        if attempt.result == nil {
            try receivePage(attempt, gateway, key, now: 112)
            try attempt.processPending(receiptTimeMs: nil) { _ in }
        }
        XCTAssertNotNil(attempt.result)
    }

    func testRecoveryAttemptReconcilesAndRenewsOnlyCurrentDesiredTokenAfterCheckpoint() throws {
        var first: GatewayAuthorityEnvelope?
        try withRecoveryAttempt([], prepareLocal: { db in
            first = try self.prepare(db)
            return [try XCTUnwrap(first)] + (try self.lostDelivery(db))
        }) { f, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            XCTAssertNil(attempt.reconciliationResult)
            var checkpoints = 0
            let resolution = try attempt.reconcile(registrationActive: true, now: moment(120)) { pending in
                checkpoints += 1
                XCTAssertEqual(pending.disposition, .reconciled)
                XCTAssertEqual(pending.localRevision, 3)
                XCTAssertEqual(pending.acknowledgment?.revision, 3)
                XCTAssertEqual(attempt.pendingReconciliationCheckpoint?.localRevision, 3)
                XCTAssertNil(attempt.reconciliationResult)
                XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE run != zeroblob(16)"), "0")
                XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in })
            }
            XCTAssertEqual(checkpoints, 1)
            XCTAssertEqual(resolution.disposition, .reconciled)
            XCTAssertEqual(resolution.reportedRevision, 3)
            XCTAssertEqual(resolution.auditHead, 1)
            XCTAssertTrue(resolution.restrictedPhoneIDs.isEmpty)
            XCTAssertNil(attempt.pendingReconciliationCheckpoint)
            XCTAssertEqual(attempt.reconciliationResult?.disposition, .reconciled)
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(121)) { _ in })
            let next = try db.write { try $0.renewDesiredGatewayCandidate(phoneID: id(6), enrollmentEpoch: id(7),
                registration: trust().registration, registrationActive: true, expectedTrustRevision: resolution.trustRevision,
                expectedHead: resolution.localRevision, nowUnixMillis: 1020, now: moment(120), sign: sign) }
            XCTAssertEqual(next.revision, 4)
            XCTAssertEqual(next.registrationToken, "synthetic-token")
            XCTAssertNotEqual(next.operationID, first?.operationID)
        }
    }

    func testRecoveryAttemptRetriesReconciliationCheckpointWithoutRepeatingRepair() throws {
        try withRecoveryAttempt([], prepareLocal: { db in
            [try self.prepare(db)] + (try self.lostDelivery(db))
        }) { f, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in throw Failure.injected })
            XCTAssertNil(attempt.reconciliationResult)
            let pending = try XCTUnwrap(attempt.pendingReconciliationCheckpoint)
            XCTAssertEqual(pending.disposition, .reconciled)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
            try f.sql("CREATE TRIGGER reject_repair BEFORE INSERT ON gateway_reconciled_controls_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
            let resolution = try attempt.reconcile(registrationActive: true, now: moment(121)) { state in
                XCTAssertEqual(state.disposition, .reconciled)
                XCTAssertEqual(state.trustRevision, pending.trustRevision)
                XCTAssertEqual(state.localRevision, pending.localRevision)
            }
            XCTAssertEqual(resolution.disposition, .reconciled)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "2")
        }
    }

    func testRecoveryAttemptRetainsCollectionAcrossReconciliationStorageFailure() throws {
        try withRecoveryAttempt([], prepareLocal: { db in
            [try self.prepare(db)] + (try self.lostDelivery(db))
        }) { f, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            try f.sql("CREATE TRIGGER reject_ack BEFORE INSERT ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
            var checkpoints = 0
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in checkpoints += 1 })
            XCTAssertEqual(checkpoints, 0)
            XCTAssertNotNil(attempt.result)
            XCTAssertNil(attempt.reconciliationResult)
            XCTAssertNil(attempt.pendingReconciliationCheckpoint)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            try f.sql("DROP TRIGGER reject_ack")
            let resolution = try attempt.reconcile(registrationActive: true, now: moment(121)) { _ in checkpoints += 1 }
            XCTAssertEqual(resolution.disposition, .reconciled)
            XCTAssertEqual(checkpoints, 1)
        }
    }

    func testRecoveryAttemptAcknowledgesKnownHeadAndRetriesOnlyItsCheckpoint() throws {
        for empty in [false, true] {
            try withRecoveryAttempt([], prepareLocal: { db in empty ? [] : [try self.prepare(db)] }) { f, db, _, gateway, key, attempt in
                try collectRecovery(attempt, gateway, key)
                XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in throw Failure.injected })
                let pending = try XCTUnwrap(attempt.pendingReconciliationCheckpoint)
                XCTAssertEqual(pending.disposition, .acknowledged)
                XCTAssertEqual(pending.localRevision, empty ? 0 : 1)
                XCTAssertEqual(pending.acknowledgment?.revision, pending.localRevision)
                try f.sql("CREATE TRIGGER reject_ack BEFORE INSERT ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
                let resolution = try attempt.reconcile(registrationActive: true, now: moment(121)) { _ in }
                XCTAssertEqual(resolution.disposition, .acknowledged)
                XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }, resolution.acknowledgment)
            }
        }
    }

    func testRecoveryAttemptDoesNotCheckpointStaleOrMissingHeadHistory() throws {
        let sf = try Fixture(), source = try setup(sf), remote = try prepare(source)
        for drift in [false, true] {
            try withRecoveryAttempt([remote], prepareLocal: { db in
                _ = try self.prepare(db)
                return [remote]
            }) { _, db, _, gateway, key, attempt in
                try collectRecovery(attempt, gateway, key)
                if drift { _ = try prepare(db, head: 1, now: 120) }
                var checkpoints = 0
                let resolution = try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in checkpoints += 1 }
                XCTAssertEqual(resolution.disposition, drift ? .localHeadChanged : .missingLocalHistory)
                XCTAssertEqual(resolution.localRevision, drift ? 2 : 1)
                XCTAssertNil(resolution.acknowledgment)
                XCTAssertEqual(checkpoints, 0)
                XCTAssertEqual(attempt.reconciliationResult?.disposition, resolution.disposition)
                XCTAssertNil(attempt.pendingReconciliationCheckpoint)
            }
        }
    }

    func testRecoveryAttemptReportsUnknownTrustWithoutCheckpointOrCounterAdoption() throws {
        let sf = try Fixture(), source = try setup(sf), first = try prepare(source)
        try withRecoveryAttempt([first], tag: 99) { _, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            var checkpoints = 0
            let result = try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in checkpoints += 1 }
            XCTAssertEqual(result.disposition, .requiresTrustRecovery)
            XCTAssertEqual(result.restrictedPhoneIDs, [id(6)])
            XCTAssertEqual(result.localRevision, 0)
            XCTAssertNil(result.acknowledgment)
            XCTAssertEqual(checkpoints, 0)
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        }
    }

    func testRecoveryAttemptStopsOnCounterDriftDuringReconciliationCheckpoint() throws {
        try withRecoveryAttempt([], prepareLocal: { db in [try self.prepare(db)] }) { _, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in
                _ = try prepare(db, head: 1, now: 120)
            }) { XCTAssertEqual($0 as? GatewayRecoveryAttemptError, .localStateChanged) }
            XCTAssertNil(attempt.reconciliationResult)
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(121)) { _ in }) {
                XCTAssertEqual($0 as? GatewayRecoveryAttemptError, .stopped)
            }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
            XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration)?.revision }, 1)
        }
    }

    func testRecoveryAttemptDetectsAcknowledgmentDriftBeforeCheckpointRetry() throws {
        var controls: [GatewayAuthorityEnvelope] = []
        try withRecoveryAttempt([], prepareLocal: { db in
            let first = try self.prepare(db)
            controls = [first, try self.consume(db, first)]
            return [first]
        }) { _, db, _, gateway, key, attempt in
            try collectRecovery(attempt, gateway, key)
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(120)) { _ in throw Failure.injected })
            let pending = try XCTUnwrap(attempt.pendingReconciliationCheckpoint)
            XCTAssertEqual(pending.localRevision, 2)
            XCTAssertEqual(pending.acknowledgment?.revision, 1)
            let newer = try verifiedHead(controls)
            XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(newer).disposition }, .recorded)
            var checkpoints = 0
            XCTAssertThrowsError(try attempt.reconcile(registrationActive: true, now: moment(121)) { _ in checkpoints += 1 }) {
                XCTAssertEqual($0 as? GatewayRecoveryAttemptError, .localStateChanged)
            }
            XCTAssertEqual(checkpoints, 0)
            XCTAssertNil(attempt.reconciliationResult)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
            XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration)?.revision }, 2)
        }
    }

    func testRecoveryAttemptRejectsInactiveRegistrationClockRollbackAndCancellationAtReconciliation() throws {
        for mode in 0...3 {
            try withRecoveryAttempt([]) { _, db, _, gateway, key, attempt in
                try collectRecovery(attempt, gateway, key)
                var checkpoints = 0
                XCTAssertThrowsError(try attempt.reconcile(registrationActive: mode != 0,
                    now: mode == 1 ? moment(100) : mode == 2 ? moment(120, epoch: UUID()) : moment(120)) { _ in
                    checkpoints += 1
                    attempt.invalidate()
                }) { error in
                    if mode == 0 { XCTAssertEqual(error as? GatewayAuthorityError, .unavailableRegistration) }
                    else { XCTAssertEqual(error as? GatewayRecoveryAttemptError, mode == 3 ? .stopped : .invalidClock) }
                }
                XCTAssertEqual(checkpoints, mode == 3 ? 1 : 0)
                XCTAssertNil(attempt.reconciliationResult)
                XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration)?.revision }, mode == 3 ? 0 : nil)
            }
        }
    }

    private func recoveryPage(_ controls: [GatewayAuthorityEnvelope], maximum: Int = 16) throws -> (VerifiedGatewayHead, VerifiedGatewayControlHistory) {
        var page: VerifiedGatewayControlHistory?
        let evidence = try gatewayEvidence(controls, after: 0, maximumRecords: maximum, collect: false, onPage: { page = $0 })
        return (evidence.0, try XCTUnwrap(page))
    }
    private func applyEvidence(_ db: JournalDatabase, _ page: VerifiedGatewayControlHistory, revision: UUID,
                               writer: AuditEpochWriter, head: UInt64 = 1) throws -> GatewayTrustEvidenceRecovery {
        try db.write { try $0.recoverGatewayTrust(from: page, expectedTrustRevision: revision,
            receiptTimeMs: 1020, writer: writer, expectedAuditHead: head) }
    }

    func testVerifiedHeadAppliesRemovalBeforeHistoryCollectionAndPageRetryAddsNoEvent() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        let (head, page) = try recoveryPage([first, activation, removal])
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        let audit = try XCTUnwrap(writer)
        let result = try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: 1020, writer: audit, expectedAuditHead: 1) }
        XCTAssertEqual(result.auditHead, 2); XCTAssertEqual(result.changedPhoneIDs, [id(6)])
        XCTAssertTrue(result.restrictedPhoneIDs.isEmpty)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        let retry = try applyEvidence(db, page, revision: result.trustRevision, writer: audit, head: 2)
        XCTAssertEqual(retry.trustRevision, result.trustRevision); XCTAssertEqual(retry.auditHead, 2)
        XCTAssertTrue(retry.changedPhoneIDs.isEmpty)
        let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
        let history = try XCTUnwrap(collector.accept(page))
        XCTAssertEqual(try recover(db, history, revision: retry.trustRevision, local: 0).disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
    }

    func testVerifiedPageCombinesUnknownTrustAndRemovalWithSequentialAuditEvents() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        let (_, page) = try recoveryPage([first, activation, removal])
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, tag: 99, onWriter: { writer = $0 })
        let result = try applyEvidence(db, page, revision: revision, writer: XCTUnwrap(writer))
        XCTAssertEqual(result.auditHead, 3); XCTAssertEqual(result.changedPhoneIDs, [id(6)])
        XCTAssertEqual(result.restrictedPhoneIDs, [id(6)])
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertFalse(try db.read { try XCTUnwrap($0.approvalEnrollments().first).approval.active })
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        let records = try db.read { try $0.page(epoch: id(20), after: 1, maximumRecords: 2, maximumBytes: 16384).canonicalRecords }
        let events = try records.map { try AuditEventMetadata.decode($0, limits: limits) }
        XCTAssertEqual(events.map(\.sequence), [2, 3]); XCTAssertEqual(events.map(\.reason), [.bindingMismatch, .revoked])
        XCTAssertEqual(Set(events.map(\.eventID)).count, 2)
        let retry = try applyEvidence(db, page, revision: result.trustRevision, writer: XCTUnwrap(writer), head: 3)
        XCTAssertEqual(retry.auditHead, 3); XCTAssertTrue(retry.changedPhoneIDs.isEmpty)
        XCTAssertEqual(retry.restrictedPhoneIDs, [id(6)])
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.approvalTrustRestrictions() }, [id(6)])
        XCTAssertEqual(try reopened.read { try $0.epoch(id(20))?.head }, 3)
    }

    func testHistoryGapDoesNotPreventVerifiedRemovalFromRestrictingAuthority() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture)
        _ = try prepare(source)
        let removal = try revoke(source, head: 1)
        let (head, page) = try recoveryPage([removal])
        XCTAssertFalse(page.page.coversRequestedRange)
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        let result = try applyEvidence(db, page, revision: revision, writer: XCTUnwrap(writer))
        let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
        XCTAssertThrowsError(try collector.accept(page)) { XCTAssertEqual($0 as? GatewayHistoryCollectionError, .incompleteHistory) }
        XCTAssertEqual(result.auditHead, 2); XCTAssertEqual(result.changedPhoneIDs, [id(6)])
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
    }

    func testPartialPageAppliesRestrictionWithoutWaitingForLaterPages() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        let (head, page) = try recoveryPage([first, activation, removal], maximum: 2)
        XCTAssertTrue(page.page.hasMore)
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, tag: 99, onWriter: { writer = $0 })
        let result = try applyEvidence(db, page, revision: revision, writer: XCTUnwrap(writer))
        XCTAssertEqual(result.auditHead, 2); XCTAssertEqual(result.restrictedPhoneIDs, [id(6)])
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
        XCTAssertNil(try collector.accept(page))
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
    }

    func testLaterReceiptFailureRollsBackEarlierRestrictionAndAuditThenAllowsRetry() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let (_, page) = try recoveryPage([first, removal])
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, tag: 99, onWriter: { writer = $0 })
        try f.sql("CREATE TRIGGER reject_later BEFORE INSERT ON gateway_recovered_revocations_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try applyEvidence(db, page, revision: revision, writer: XCTUnwrap(writer)))
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.count }, 1)
        XCTAssertTrue(try db.read { try $0.approvalTrustRestrictions().isEmpty })
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.epoch(id(20))?.head }, 1)
        try f.sql("DROP TRIGGER reject_later")
        let result = try applyEvidence(db, page, revision: revision, writer: XCTUnwrap(writer))
        XCTAssertEqual(result.auditHead, 3); XCTAssertEqual(result.restrictedPhoneIDs, [id(6)])
    }

    func testEvidenceRecoveryValidatesRevisionAndWriteModeEvenForEmptyHead() throws {
        let head = try verifiedHead([]), f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        let audit = try XCTUnwrap(writer)
        let result = try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: nil, writer: audit, expectedAuditHead: 1) }
        XCTAssertEqual(result.trustRevision, revision); XCTAssertEqual(result.auditHead, 1)
        XCTAssertTrue(result.changedPhoneIDs.isEmpty)
        XCTAssertThrowsError(try db.read { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: nil, writer: audit, expectedAuditHead: 1) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        XCTAssertThrowsError(try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: UUID(),
            receiptTimeMs: nil, writer: audit, expectedAuditHead: 1) }) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: nil, writer: audit, expectedAuditHead: 0) }) { XCTAssertEqual($0 as? AuditJournalError, .headMismatch) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testEmptyHeadWithAnotherPinnedRegistrationCannotRecoverTrust() throws {
        let head = try verifiedHead([]), f = try Fixture(), db = try open(f, initialize: true)
        var writer: AuditEpochWriter?
        let revision = try enrollForRecovery(db, onWriter: { writer = $0 })
        let r = try trust().registration
        let other = try GatewayRegistrationIdentity(ownerID: id(99), macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        try db.write { try $0.configureGatewayAuthority(other) }
        XCTAssertThrowsError(try db.write { try $0.recoverGatewayTrust(from: head, expectedTrustRevision: revision,
            receiptTimeMs: nil, writer: XCTUnwrap(writer), expectedAuditHead: 1) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope) }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
    }

    func testKnownAcknowledgmentsPersistWithoutChangingAuthorityOrReplayingControls() throws {
        let f = try Fixture(), db = try setup(f)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        let empty = try verifiedHead([])
        let zero = try db.write { try $0.acknowledgeGatewayHead(empty) }
        XCTAssertEqual(zero.disposition, .recorded); XCTAssertEqual(zero.acknowledged?.revision, 0)
        let candidate = try prepare(db), activation = try consume(db, candidate), removal = try revoke(db, head: 2)
        var controls: [GatewayAuthorityEnvelope] = []
        for control in [candidate, activation, removal] {
            controls.append(control)
            let verified = try verifiedHead(controls)
            let result = try db.write { try $0.acknowledgeGatewayHead(verified) }
            XCTAssertEqual(result.disposition, .recorded)
            XCTAssertEqual(result.localRevision, 3); XCTAssertEqual(result.reportedRevision, control.revision)
            XCTAssertEqual(result.acknowledged?.operationID, control.operationID)
            XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(verified) }.disposition, .alreadyRecorded)
        }
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(empty) }.disposition, .olderThanRecorded)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
    }

    func testMissingDeliveryAndRevocationHistoryCannotAdvanceAcknowledgment() throws {
        let f = try Fixture(), db = try setup(f), candidate = try prepare(db)
        let known = try verifiedHead([candidate])
        _ = try db.write { try $0.acknowledgeGatewayHead(known) }
        let otherFixture = try Fixture(), other = try setup(otherFixture)
        let missing = try prepare(other)
        let removal = try revoke(other, head: 1)
        for controls in [[missing], [missing, removal]] {
            let evidence = try verifiedHead(controls)
            let result = try db.write { try $0.acknowledgeGatewayHead(evidence) }
            XCTAssertEqual(result.disposition, .missingLocalHistory)
            XCTAssertEqual(result.acknowledged?.operationID, candidate.operationID)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
    }

    func testConflictingKnownOperationCannotBeAcknowledgedEvenBelowPriorHead() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        let next = try prepare(db, head: 1, now: 110)
        _ = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([next])) }
        let original = try candidate(first)
        let changed = try GatewayTokenCandidate(binding: original.binding, revision: original.revision,
            operationID: original.operationID, issuedAtUnixMillis: 1001, expiresAtUnixMillis: 2000)
        let forged = GatewayAuthorityEnvelope(kind: 1, operationID: first.operationID, revision: first.revision,
            canonicalPayload: try changed.encode(limits: limits), signature: try sign(changed), registrationToken: first.registrationToken)
        let result = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([forged])) }
        XCTAssertEqual(result.disposition, .conflictingLocalHistory)
        XCTAssertEqual(result.acknowledged?.revision, 2)
    }

    func testAcknowledgmentRollbackAndReadOnlyRejectionLeavePriorEvidenceIntact() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        let evidence = try verifiedHead([first])
        XCTAssertThrowsError(try db.read { try $0.acknowledgeGatewayHead(evidence) })
        try f.sql("CREATE TRIGGER reject_ack BEFORE INSERT ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(evidence) })
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        try f.sql("DROP TRIGGER reject_ack")
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(evidence) }.disposition, .recorded)
        let next = try prepare(db, head: 1, now: 110), nextEvidence = try verifiedHead([next])
        try f.sql("CREATE TRIGGER reject_ack BEFORE UPDATE ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(nextEvidence) })
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 1)
        try f.sql("DROP TRIGGER reject_ack")
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(nextEvidence) }.acknowledged?.revision, 2)
    }

    func testAcknowledgmentCannotCrossRegistrationScope() throws {
        let f = try Fixture(), db = try open(f, initialize: true), r = try trust().registration
        let other = try GatewayRegistrationIdentity(ownerID: id(90), macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        try db.write { try $0.configureGatewayAuthority(other) }
        let verified = try verifiedHead([])
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(verified) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope)
        }
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(other) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(other) }, 0)
    }

    func testAcknowledgmentCorruptionDoesNotBecomeDeliveryEvidence() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        _ = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([first])) }
        try f.sql("UPDATE gateway_acknowledgment_v1 SET operation=zeroblob(16)")
        XCTAssertThrowsError(try db.read { try $0.gatewayAcknowledgment(trust().registration) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testSchemaSevenMigrationStartsWithUnknownAcknowledgmentAndPreservesControlHistory() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        try db.close()
        try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; PRAGMA user_version=7")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 7)
        XCTAssertEqual(try f.scalar("PRAGMA user_version"), "12")
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertNil(try migrated.read { try $0.gatewayAcknowledgment(trust().registration) })
        let result = try migrated.write { try $0.acknowledgeGatewayHead(verifiedHead([first])) }
        XCTAssertEqual(result.disposition, .recorded)
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
        func gateway(identity: GatewayRegistrationIdentity, limits: CBORLimits, epoch: UUID) throws -> GatewayDatabase {
            let directory = root.appendingPathComponent("gateway").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "gateway.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
            return try GatewayDatabase(lease: ProtectedGatewayLease(anchor: root.path, relativeDirectory: "gateway", serviceUID: geteuid(), ancestorUID: geteuid()),
                identity: identity, payloadLimits: limits, signingLimits: limits, maximumOperations: 20,
                maximumPendingPerEnrollment: 5, maximumLifetimeMillis: 1000, clockEpoch: epoch, busyMilliseconds: 100,
                initialize: true, probePolicy: GatewayProbePolicy(maximumAttempts: 2, minimumRetryDelayMillis: 50, maximumTTLSeconds: 60))
        }
        func sql(_ sql: String) throws {
            try connection { db in guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected } }
        }
        func scalar(_ sql: String) throws -> String? {
            try connection { db in
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw Failure.injected }
                return sqlite3_column_text(stmt, 0).map { String(cString: $0) }
            }
        }
        private func connection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            return try body(db)
        }
    }
}
