import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class EnrollmentJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let key = P256.Signing.PrivateKey()
    private let rootKey = P256.Signing.PrivateKey()
    private let clock = UUID()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024) } }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1) } }
    private var capabilities: ContractCapabilities { get throws { try .init(contracts: [contract: []]) } }
    private func moment() -> AuthorityMoment { .init(epoch: clock, milliseconds: 110) }
    private func enrollment(phone: UInt8 = 5, epoch: UInt8 = 9, signingKey: P256.Signing.PrivateKey? = nil) throws -> StoredApprovalEnrollment {
        let biometric = signingKey ?? key
        return try StoredApprovalEnrollment(epoch: id(epoch), notificationTag: id(phone, count: 32), identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(phone), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(phone * 2), keyClass: .biometric, publicKey: biometric.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(phone * 2 + 1), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
    }
    private func descriptor(epoch: UInt8 = 3) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, migrate: Int64? = nil, maximum: Int = 50) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100, initialize: initialize, migrateFromVersion: migrate,
            gatewayPolicy: GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: maximum,
                candidateLifetimeMillis: 1000, clockEpoch: clock),
            routingPolicy: RoutingJournalPolicy(clockEpoch: clock, challengeLifetimeMillis: 1000, maximumOperations: 20,
                payloadLimits: limits, signingLimits: limits))
    }
    private func setup(_ fixture: Fixture, maximum: Int = 50) throws -> (JournalDatabase, AuditEpochWriter, UUID) {
        let db = try open(fixture, initialize: true, maximum: maximum)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor()) }
        return (db, writer, revision)
    }
    private func add(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 0,
                     phone: UInt8 = 5, epoch: UInt8 = 9, signingKey: P256.Signing.PrivateKey? = nil) throws -> UUID {
        try db.write { try $0.addApprovalEnrollment(enrollment(phone: phone, epoch: epoch, signingKey: signingKey), expectedTrustRevision: revision,
            eventID: id(UInt8(head + 40)), receiptTimeMs: 1000, writer: writer, expectedAuditHead: head) }
    }
    private func remove(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 1,
                        gateway: EnrollmentGatewayRemoval? = nil) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(UInt8(head + 40)), receiptTimeMs: 1000, writer: writer, expectedAuditHead: head, gateway: gateway) }
    }
    private func request() throws -> RetainedApprovalRequest {
        let action = CapturedAction(choice: .execute, scope: .currentRequest)
        return try RetainedApprovalRequest(payload: IssuedRequestPayload(contract: contract, macID: id(1), accountID: id(2), requestID: id(4),
            challenge: id(30, count: 32), requiredFeatures: [], createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000,
            canonicalCapture: DeterministicCBOR.encode(.map([0: .text("synthetic request")]), limits: limits), permittedActions: [action],
            bodyLimits: limits, captureLimits: limits), phase: .presented, admittedAt: .init(epoch: clock, milliseconds: 100), deadlineMilliseconds: 1100)
    }
    private func consume(_ transaction: JournalTransaction, writer: AuditEpochWriter, revision: UUID, head: UInt64,
                         phone: UInt8 = 5, signingKey: P256.Signing.PrivateKey? = nil) throws -> ConsumptionReceipt {
        let retained = try request()
        let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: id(4),
            requestDigest: retained.payload.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: retained.payload.challenge,
            phoneID: id(phone), keyID: id(phone * 2), action: retained.payload.permittedActions[0]).encode(limits: limits)
        let signature = try (signingKey ?? key).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
            purpose: .biometricAuthorization, canonicalPayload: decision, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return try transaction.consume(canonicalDecision: decision, signature: signature, retained: retained,
            expectedTrustRevision: revision, now: moment(), eventID: id(80), receiptTimeMs: 1000,
            writer: writer, expectedHead: head, requestLimits: limits, signingLimits: limits)
    }
    private func identity() throws -> GatewayRegistrationIdentity {
        try .init(ownerID: id(11), macID: id(1), accountID: id(2), gatewayID: id(12), lifecycleEpoch: id(13), rootPublicKey: rootKey.publicKey.x963Representation)
    }
    private func gatewayRemoval(head: UInt64 = 0, validSignature: Bool = true) throws -> EnrollmentGatewayRemoval {
        try .init(registration: identity(), expectedHead: head, nowUnixMillis: 1000, now: moment()) { value in
            if !validSignature { return self.id(0, count: 64) }
            return try self.rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                canonicalPayload: value.encode(limits: self.limits), payloadLimits: self.limits, inputLimits: self.limits)).rawRepresentation
        }
    }

    private func pairing(_ db: JournalDatabase, biometric: P256.Signing.PrivateKey,
                         replacement: PairingReplacement? = nil, minimum: UInt64 = 1) throws -> (PairingEnrollmentAttempt, Data) {
        let trusted = try db.read { try $0.approvalTrustSnapshot() }
        let scope = try ChannelScope(macID: id(1), accountID: id(2), phoneID: id(8), enrollmentEpoch: id(10))
        let offers = try [ChannelRole.phone, .mac].enumerated().map { index, role in
            try ChannelOffer(role: role, scope: scope, nonce: id(UInt8(20 + index), count: 32), envelopeVersions: [minimum],
                requests: [ChannelRequestCapability(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [])
        }
        var revision = trusted.revision.uuid
        let transport = P256.Signing.PrivateKey().publicKey.x963Representation
        let transcript = try PairingTranscript(setupID: id(30), challenge: id(31, count: 32), phone: offers[0], mac: offers[1],
            minimumEnvelopeVersion: minimum, selectedEnvelopeVersion: minimum, macAuthorityKey: rootKey.publicKey.x963Representation,
            macTransportKey: transport,
            transportKey: PairingKey(keyID: id(32), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            decisionKey: PairingKey(keyID: id(33), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: PairingKey(keyID: id(34), publicKey: biometric.publicKey.x963Representation),
            enrollmentTag: id(35, count: 32), replacement: replacement,
            expectedTrustRevision: withUnsafeBytes(of: &revision) { Data($0) }, issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
        let attempt = try PairingEnrollmentAttempt(transcript: transcript, trusted: trusted, authorizedReplacement: replacement,
            authorityPublicKey: rootKey.publicKey.x963Representation, transportPublicKey: transport, minimumEnvelopeVersion: minimum,
            started: .init(epoch: clock, milliseconds: 100), startedAtUnixMillis: 1000, deadlineMilliseconds: 1100)
        return (attempt, try biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation)
    }

    func testDirectTrustUsesCurrentJournalBindingsAndRejectsStaleOrForgedPeers() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        XCTAssertTrue(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.isEmpty })
        let revision = try add(db, writer: writer, revision: empty)
        let trust = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 2048, auditVersions: [1]) }
        let peer = try XCTUnwrap(trust.peers.first)
        XCTAssertEqual(trust.revision, revision); XCTAssertEqual(trust.macID, id(1)); XCTAssertEqual(trust.accountID, id(2))
        XCTAssertEqual(peer.scope, try ChannelScope(macID: id(1), accountID: id(2), phoneID: id(5), enrollmentEpoch: id(9)))
        XCTAssertEqual(peer.maximumPayloadBytes, 2048); XCTAssertEqual(peer.minimumEnvelopeVersion, 1)
        XCTAssertEqual(peer.auditVersions, [1]); XCTAssertEqual(peer.requests.map(\.kind), [0])
        try db.read { try $0.requireDirectApprovalPeer(peer, expectedTrustRevision: revision) }
        let row = try XCTUnwrap(db.read { try $0.approvalEnrollments().first })
        XCTAssertEqual(try P256.Signing.PublicKey(derRepresentation: peer.transportPublicKey).x963Representation, row.identityPublicKey)
        for scope in [try ChannelScope(macID: id(99), accountID: id(2), phoneID: id(5), enrollmentEpoch: id(9)),
                      try ChannelScope(macID: id(1), accountID: id(2), phoneID: id(5), enrollmentEpoch: id(99))] {
            let forged = try DirectApprovalPeer(scope: scope, transportPublicKey: peer.transportPublicKey,
                requests: [], auditVersions: [], maximumPayloadBytes: 1024)
            XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalPeer(forged, expectedTrustRevision: revision) }) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
            }
        }
        let wrongKey = try DirectApprovalPeer(scope: peer.scope, transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation,
            requests: [], auditVersions: [], maximumPayloadBytes: 1024)
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalPeer(wrongKey, expectedTrustRevision: revision) })
        let removed = try remove(db, writer: writer, revision: revision)
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalPeer(peer, expectedTrustRevision: revision) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalPeer(peer, expectedTrustRevision: removed.revision) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertTrue(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.isEmpty })
    }

    func testDecodedIPCBindingRechecksCurrentJournalRevisionAndIdentity() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let peer = try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.first })
        let bytes = try AuthorityTrustCodec.encodeBinding(AuthorityPeerBinding(peer: peer, revision: revision))
        let binding = try AuthorityTrustCodec.decodeBinding(bytes, expectedMacID: id(1), expectedAccountID: id(2))
        try db.read { try $0.requireDirectApprovalBinding(binding) }
        let wrong = try AuthorityPeerBinding(scope: peer.scope, transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: revision)
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalBinding(wrong) })
        let revoked = try remove(db, writer: writer, revision: revision)
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalBinding(binding) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalBinding(AuthorityPeerBinding(peer: peer, revision: revoked.revision)) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
    }

    func testDirectTrustRetainsThePairingFloorAcrossRestartAndHonorsHigherLocalPolicy() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key, minimum: 2)
        _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        try db.close()
        let reopened = try open(fixture)
        for minimum in [UInt64(1), 2, 3] {
            let trust = try reopened.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024, minimumEnvelopeVersion: minimum) }
            XCTAssertEqual(trust.peers.first?.minimumEnvelopeVersion, max(2, minimum))
        }
    }

    func testDirectTrustRejectsInvalidRetainedProofAndRetiresTheJournalOwner() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        try fixture.sql("UPDATE pairing_commits_v1 SET proof=zeroblob(64)")
        XCTAssertThrowsError(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testDirectTrustFiltersContractsAndIntersectsFeatures() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        let other = try RequestContract(requestKind: .littleSnitch, wireVersion: 1, schemaVersion: 1)
        let local = try ContractCapabilities(contracts: [contract: [7, 8], other: []])
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: local, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor()) }
        let original = try enrollment()
        let row = try StoredApprovalEnrollment(epoch: original.epoch, notificationTag: original.notificationTag,
            identityPublicKey: original.identityPublicKey, approval: ApprovalEnrollment(phoneID: original.approval.phoneID, active: true,
                capabilities: ContractCapabilities(contracts: [contract: [8, 9], other: []]), keys: original.approval.keys))
        _ = try db.write { try $0.addApprovalEnrollment(row, expectedTrustRevision: revision,
            eventID: id(40), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
        let peer = try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.first })
        XCTAssertEqual(peer.requests.count, 1); XCTAssertEqual(peer.requests.first?.kind, 0)
        XCTAssertEqual(peer.requests.first?.features, [8])
        for bytes in [0, 16_777_217] {
            XCTAssertThrowsError(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: bytes) })
        }
        XCTAssertThrowsError(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024, minimumEnvelopeVersion: 0) })
        XCTAssertThrowsError(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024, auditVersions: [0]) })
        XCTAssertEqual(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.count }, 1)
    }

    func testDirectTrustBoundsAdvertisedFeaturesWithoutChangingDurablePolicy() throws {
        for count in [64, 65, 128] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true)
            let features = Set((1...count).map(UInt64.init))
            let policy = try ContractCapabilities(contracts: [contract: features])
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: policy, allowedContracts: [contract]) }
            let writer = try db.write { try $0.createEpoch(descriptor()) }
            let original = try enrollment()
            let row = try StoredApprovalEnrollment(epoch: original.epoch, notificationTag: original.notificationTag,
                identityPublicKey: original.identityPublicKey, approval: ApprovalEnrollment(phoneID: original.approval.phoneID,
                    active: true, capabilities: policy, keys: original.approval.keys))
            _ = try db.write { try $0.addApprovalEnrollment(row, expectedTrustRevision: revision,
                eventID: id(40), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
            let peer = try XCTUnwrap(db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.first })
            XCTAssertEqual(peer.requests.first?.features, Set((1...64).map(UInt64.init)))
            let offer = try ChannelOffer(role: .mac, scope: peer.scope, nonce: id(60, count: 32),
                envelopeVersions: [1], requests: peer.requests, auditVersions: [])
            XCTAssertEqual(try ChannelOffer.decode(offer.encode()).requests.first?.features, Set((1...64).map(UInt64.init)))
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().authorityCapabilities.contracts[contract] }, features)
            XCTAssertEqual(try db.read { try $0.approvalEnrollments().first?.approval.capabilities.contracts[contract] }, features)
        }
    }

    func testPairingProofCommitsExactKeysAndCannotReplayAfterReopen() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        XCTAssertThrowsError(try attempt.commit(database: db, biometricProof: id(0, count: 64), writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)) {
            XCTAssertEqual($0 as? PairingEnrollmentError, .invalidProof)
        }
        XCTAssertTrue(try db.read { try $0.approvalEnrollments().isEmpty })
        let result = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        let row = try XCTUnwrap(db.read { try $0.approvalEnrollments().first })
        XCTAssertEqual(row.approval.phoneID, id(8)); XCTAssertEqual(row.epoch, id(10))
        XCTAssertEqual(row.identityPublicKey, attempt.transcript.transportKey.publicKey)
        XCTAssertEqual(row.approval.keys.first { $0.keyClass == .biometric }?.publicKey, key.publicKey.x963Representation)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, result.revision)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertThrowsError(try attempt.commit(database: reopened, biometricProof: proof, writer: writer,
            expectedAuditHead: 1, addEventID: id(41), receiptTimeMs: 1000, now: moment)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertEqual(try reopened.read { try $0.approvalEnrollments().count }, 1)
    }

    func testCommittedPairingSurvivesRestartButNotRevocation() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        let result = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        try db.close()
        let reopened = try open(fixture)
        let recovered = try XCTUnwrap(reopened.read {
            try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(8), authenticatedEnrollmentEpoch: id(10))
        })
        XCTAssertEqual(try recovered.encode(), try attempt.transcript.encode())
        let receipt = try rootKey.signature(for: recovered.signingInput(purpose: .macCommit)).rawRepresentation
        XCTAssertTrue(try attempt.transcript.verify(signature: receipt, publicKey: rootKey.publicKey.x963Representation, purpose: .macCommit))
        for (setup, phone, epoch) in [(31, 8, 10), (30, 9, 10), (30, 8, 11)] {
            XCTAssertNil(try reopened.read { try $0.committedPairing(setupID: id(UInt8(setup)),
                authenticatedPhoneID: id(UInt8(phone)), authenticatedEnrollmentEpoch: id(UInt8(epoch))) })
        }
        let restartedWriter = try reopened.write { try $0.createEpoch(descriptor(epoch: 70)) }
        _ = try reopened.write { try $0.revokeApprovalEnrollment(phoneID: id(8), epoch: id(10),
            expectedTrustRevision: result.revision, eventID: id(41), receiptTimeMs: 3000, writer: restartedWriter, expectedAuditHead: 0) }
        XCTAssertNil(try reopened.read { try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(8), authenticatedEnrollmentEpoch: id(10)) })
    }

    func testRecoveredPairingRejectsCanonicalCapabilityCorruption() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        guard case var .map(fields) = try DeterministicCBOR.decode(attempt.transcript.encode(), limits: limits),
              case var .map(offer) = try DeterministicCBOR.decode(attempt.transcript.phone.encode(), limits: limits) else {
            return XCTFail("Expected transcript and offer maps")
        }
        offer[5] = .array([.array([.unsigned(0), .unsigned(1), .unsigned(1), .array([.unsigned(42)])])])
        fields[3] = .bytes(try DeterministicCBOR.encode(.map(offer), limits: limits))
        let changed = try DeterministicCBOR.encode(.map(fields), limits: limits)
        _ = try PairingTranscript.decode(changed)
        let hex = changed.map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE pairing_commits_v1 SET transcript=x'\(hex)'")
        XCTAssertThrowsError(try db.read { try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(8), authenticatedEnrollmentEpoch: id(10)) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testRecoveredPairingAuthenticatesChallengeAndProof() throws {
        for alterProof in [false, true] {
            let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
            let (attempt, proof) = try pairing(db, biometric: key)
            _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
                expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
            if alterProof {
                try fixture.sql("UPDATE pairing_commits_v1 SET proof=zeroblob(64)")
            } else {
                guard case var .map(fields) = try DeterministicCBOR.decode(attempt.transcript.encode(), limits: limits) else {
                    return XCTFail("Expected transcript map")
                }
                fields[2] = .bytes(id(99, count: 32))
                let changed = try DeterministicCBOR.encode(.map(fields), limits: limits)
                _ = try PairingTranscript.decode(changed)
                let hex = changed.map { String(format: "%02x", $0) }.joined()
                try fixture.sql("UPDATE pairing_commits_v1 SET transcript=x'\(hex)'")
            }
            XCTAssertThrowsError(try db.read { try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(8), authenticatedEnrollmentEpoch: id(10)) }) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData)
            }
        }
    }

    func testPairingReceiptRecordRollsBackWithExpiredCommit() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        var calls = 0
        XCTAssertThrowsError(try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: {
                calls += 1
                return .init(epoch: self.clock, milliseconds: calls == 1 ? 110 : 1100)
            }))
        _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
        XCTAssertNotNil(try db.read { try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(8), authenticatedEnrollmentEpoch: id(10)) })
    }

    func testSchemaElevenMigrationDoesNotInventPairingReceipts() throws {
        let fixture = try Fixture(), (db, writer, revision) = try setup(fixture)
        _ = try add(db, writer: writer, revision: revision)
        try db.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; PRAGMA user_version=11")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 11)
        XCTAssertEqual(try migrated.read { try $0.approvalEnrollments().count }, 1)
        XCTAssertNil(try migrated.read { try $0.committedPairing(setupID: id(30), authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(9)) })
        try migrated.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testPairingReplacementFailureRollsBackRevocation() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let replacement = try PairingReplacement(phoneID: id(5), epoch: id(9))
        let (bad, badProof) = try pairing(db, biometric: key, replacement: replacement)
        XCTAssertThrowsError(try bad.commit(database: db, biometricProof: badProof, writer: writer,
            expectedAuditHead: 1, addEventID: id(42), removalEventID: id(41), receiptTimeMs: 1000, now: moment)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(5)])
        let (good, goodProof) = try pairing(db, biometric: P256.Signing.PrivateKey(), replacement: replacement)
        _ = try good.commit(database: db, biometricProof: goodProof, writer: writer,
            expectedAuditHead: 1, addEventID: id(42), removalEventID: id(41), receiptTimeMs: 1000, now: moment)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(8)])
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().count }, 2)
    }

    func testPairingReplacementMustMatchLocalAuthorization() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let selected = try PairingReplacement(phoneID: id(5), epoch: id(9))
        let otherPhone = try PairingReplacement(phoneID: id(6), epoch: id(9))
        let otherEpoch = try PairingReplacement(phoneID: id(5), epoch: id(7))
        let trusted = try db.read { try $0.approvalTrustSnapshot() }
        let mismatches: [(PairingReplacement?, PairingReplacement?)] = [
            (selected, nil), (nil, selected), (selected, otherPhone), (selected, otherEpoch),
        ]
        for (claimed, authorized) in mismatches {
            let (attempt, _) = try pairing(db, biometric: key, replacement: claimed)
            XCTAssertThrowsError(try PairingEnrollmentAttempt(transcript: attempt.transcript, trusted: trusted,
                authorizedReplacement: authorized, authorityPublicKey: rootKey.publicKey.x963Representation,
                transportPublicKey: attempt.transcript.macTransportKey, minimumEnvelopeVersion: 1,
                started: .init(epoch: clock, milliseconds: 100), startedAtUnixMillis: 1000, deadlineMilliseconds: 1100)) {
                XCTAssertEqual($0 as? PairingEnrollmentError, .wrongContext)
            }
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(5)])
    }

    func testPairingCannotSubstituteLocalAuthorityOrSecurityFloor() throws {
        let fixture = try Fixture(), (db, _, _) = try setup(fixture)
        let (attempt, _) = try pairing(db, biometric: key)
        let trusted = try db.read { try $0.approvalTrustSnapshot() }
        for wrongKey in [false, true] {
            XCTAssertThrowsError(try PairingEnrollmentAttempt(transcript: attempt.transcript, trusted: trusted, authorizedReplacement: nil,
                authorityPublicKey: wrongKey ? key.publicKey.x963Representation : rootKey.publicKey.x963Representation,
                transportPublicKey: attempt.transcript.macTransportKey, minimumEnvelopeVersion: wrongKey ? 1 : 2,
                started: .init(epoch: clock, milliseconds: 100), startedAtUnixMillis: 1000, deadlineMilliseconds: 1100)) {
                XCTAssertEqual($0 as? PairingEnrollmentError, .wrongContext)
            }
        }
    }

    func testPairingSignedValidityBoundsAdmissionAndElapsedLifetime() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (original, proof) = try pairing(db, biometric: key)
        let trusted = try db.read { try $0.approvalTrustSnapshot() }
        func admit(_ wallTime: UInt64) throws -> PairingEnrollmentAttempt {
            try PairingEnrollmentAttempt(transcript: original.transcript, trusted: trusted, authorizedReplacement: nil,
                authorityPublicKey: rootKey.publicKey.x963Representation,
                transportPublicKey: original.transcript.macTransportKey, minimumEnvelopeVersion: 1,
                started: .init(epoch: clock, milliseconds: 100), startedAtUnixMillis: wallTime, deadlineMilliseconds: 1100)
        }
        for wallTime: UInt64 in [999, 2000, 2001, UInt64.max] {
            XCTAssertThrowsError(try admit(wallTime)) { XCTAssertEqual($0 as? PairingEnrollmentError, .expired) }
        }
        let late = try admit(1990)
        XCTAssertThrowsError(try late.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 2000,
            now: { AuthorityMoment(epoch: self.clock, milliseconds: 110) })) {
            XCTAssertEqual($0 as? PairingEnrollmentError, .expired)
        }
        XCTAssertTrue(try db.read { try $0.approvalEnrollments().isEmpty })
        _ = try late.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1999,
            now: { AuthorityMoment(epoch: self.clock, milliseconds: 109) })
    }

    func testPairingExpiryBeforeCommitRollsBackKeysAndAudit() throws {
        let fixture = try Fixture(), (db, writer, revision) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        var reads = 0
        XCTAssertThrowsError(try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: {
                reads += 1
                return AuthorityMoment(epoch: self.clock, milliseconds: reads == 1 ? 110 : 1100)
            })) { XCTAssertEqual($0 as? PairingEnrollmentError, .expired) }
        XCTAssertTrue(try db.read { try $0.approvalEnrollments().isEmpty })
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        _ = try attempt.commit(database: db, biometricProof: proof, writer: writer,
            expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: moment)
    }

    func testPairingElapsedDeadlineAndClockEpochPreventCommit() throws {
        let fixture = try Fixture(), (db, writer, _) = try setup(fixture)
        let (attempt, proof) = try pairing(db, biometric: key)
        for now in [AuthorityMoment(epoch: clock, milliseconds: 1100), AuthorityMoment(epoch: clock, milliseconds: 99),
                    AuthorityMoment(epoch: UUID(), milliseconds: 110)] {
            XCTAssertThrowsError(try attempt.commit(database: db, biometricProof: proof, writer: writer,
                expectedAuditHead: 0, addEventID: id(40), receiptTimeMs: 1000, now: { now })) {
                XCTAssertEqual($0 as? PairingEnrollmentError, .expired)
            }
        }
        XCTAssertTrue(try db.read { try $0.approvalEnrollments().isEmpty })
    }

    func testPublicConsumptionRequiresStoredEnrollmentAndUsesItsKeys() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), writer = try db.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: UUID(), head: 0) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        let empty = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: empty, head: 0) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
        }
        let revision = try add(db, writer: writer, revision: empty)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: revision, head: 1, signingKey: P256.Signing.PrivateKey()) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .invalidSignature)
        }
        let receipt = try db.write { try consume($0, writer: writer, revision: revision, head: 1) }
        XCTAssertEqual(receipt.event.sequence, 2)
        XCTAssertEqual(receipt.decision.phoneID, id(5))
    }

    func testRemovalSerializesWithConsumptionAndPreservesOtherPhones() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture), other = P256.Signing.PrivateKey()
        let first = try add(db, writer: writer, revision: empty)
        let second = try add(db, writer: writer, revision: first, head: 1, phone: 8, epoch: 10, signingKey: other)
        let removed = try remove(db, writer: writer, revision: second, head: 2)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: second, head: 3) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: removed.revision, head: 3) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
        }
        XCTAssertNil(try db.read { try $0.consumption(requestID: id(4)) })
        let winner = try db.write { try consume($0, writer: writer, revision: removed.revision, head: 3, phone: 8, signingKey: other) }
        XCTAssertEqual(winner.decision.phoneID, id(8))
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().filter { !$0.approval.active }.count }, 1)
    }

    func testConsumedDecisionRemainsHistoricalAfterRemoval() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let winner = try db.write { try consume($0, writer: writer, revision: revision, head: 1) }
        _ = try remove(db, writer: writer, revision: revision, head: 2)
        XCTAssertEqual(try db.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 3)
    }

    func testEnrollmentAndRevocationSurviveRestartWithoutDerivingTrustFromAudit() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let removed = try remove(db, writer: writer, revision: revision)
        try db.close()
        let reopened = try open(fixture)
        let snapshot = try reopened.read { try $0.approvalTrustSnapshot() }
        XCTAssertEqual(snapshot.revision, removed.revision); XCTAssertTrue(snapshot.enrollments.isEmpty)
        let retained = try reopened.read { try $0.approvalEnrollments() }
        XCTAssertEqual(retained.count, 1); XCTAssertFalse(retained[0].approval.active)
        XCTAssertEqual(retained[0].epoch, id(9))
        XCTAssertThrowsError(try reopened.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .alreadyConfigured)
        }
    }

    func testReplacementAndItsAuditAreAtomicAndRetiredKeysCannotReturn() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        XCTAssertThrowsError(try db.write { tx in
            let removed = try tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            _ = try tx.addApprovalEnrollment(enrollment(epoch: 10), expectedTrustRevision: removed.revision,
                eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2)
        }) { XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity) }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
        try db.write { tx in
            let removed = try tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            _ = try tx.addApprovalEnrollment(enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey()), expectedTrustRevision: removed.revision,
                eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(8)])
        let events = try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        XCTAssertEqual(try events.map { try AuditEventMetadata.decode($0, limits: limits).kind }, [.enrollmentAdded, .enrollmentRevoked, .enrollmentAdded])
    }

    private func emptyGatewayHealthProof(registration: GatewayRegistrationIdentity) throws -> MachineUpdateConsumerHealthProof {
        let signer = MachineUpdateRoleChallengeTests.Fixture()
        let requirement = try signer.requirement(role: .notificationGateway, uid: 20001, mac: 1, account: 2)
        let now = moment()
        let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement, registration: registration,
            clock: { now }, verifyCurrent: {})
        let request = try session.makeRequest()
        let roleReply = try signer.answer(request, expected: requirement)
        let fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .unsigned(1),
            2: .bytes(try registration.encode()), 3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)),
            4: .unsigned(0), 5: .unsigned(0), 6: .bytes(Data()), 7: .bytes(Data())]
        let payload = try DeterministicCBOR.encode(.map(fields), limits: limits)
        let signature = try signer.key.signature(for: Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload).rawRepresentation
        let packet = try MachineUpdateConsumerHealthPacket(roleReply: roleReply,
            gatewayHead: .init(canonicalPayload: payload, signature: signature)).encoded
        return try session.accept(packet, authenticatePeer: { _ in })
    }

    func testGatewayHealthReconciliationInspectsTheExactHeadWithoutRecordingIt() throws {
        let fixture = try Fixture(), (db, _, _) = try setup(fixture)
        let registration = try identity()
        try db.write { try $0.configureGatewayAuthority(registration) }
        let proof = try emptyGatewayHealthProof(registration: registration)

        try db.read {
            try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: proof.role.requirement,
                registration: registration, transaction: $0)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(registration) }, 0)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(registration) })
    }

    func testGatewayHealthReconciliationRejectsAStaleSignedHead() throws {
        let fixture = try Fixture(), (db, writer, initial) = try setup(fixture)
        let registration = try identity()
        try db.write { try $0.configureGatewayAuthority(registration) }
        let proof = try emptyGatewayHealthProof(registration: registration)
        let revision = try add(db, writer: writer, revision: initial)
        _ = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval())

        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(registration) }, 1)
        XCTAssertThrowsError(try db.read {
            try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: proof.role.requirement,
                registration: registration, transaction: $0)
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .headMismatch) }
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(registration) })
    }

    func testGatewayHealthReconciliationRejectsMissingHeadOrForeignRegistration() throws {
        let fixture = try Fixture(), (db, _, _) = try setup(fixture)
        let registration = try identity()
        try db.write { try $0.configureGatewayAuthority(registration) }
        let proof = try emptyGatewayHealthProof(registration: registration)
        let missing = MachineUpdateConsumerHealthProof(role: proof.role, gatewayHead: nil)
        let foreign = try GatewayRegistrationIdentity(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: id(14), lifecycleEpoch: registration.lifecycleEpoch,
            rootPublicKey: registration.rootPublicKey)

        XCTAssertThrowsError(try db.read {
            try MachineUpdateGatewayHealthReconciliation.requireCurrent(missing, expected: proof.role.requirement,
                registration: registration, transaction: $0)
        }) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
        XCTAssertThrowsError(try db.read {
            try MachineUpdateGatewayHealthReconciliation.requireCurrent(proof, expected: proof.role.requirement,
                registration: foreign, transaction: $0)
        }) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
    }

    func testGatewayRemovalAndAuditCommitTogetherAndBadSignerRollsEverythingBack() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try remove(db, writer: writer, revision: revision)) { XCTAssertEqual($0 as? EnrollmentJournalError, .gatewayRequired) }
        XCTAssertThrowsError(try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(validSignature: false))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval())
        XCTAssertEqual(removed.gatewayControl?.kind, 3)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 1)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
    }

    func testStorageFaultsAndSwallowedErrorsCannotPartiallyCommitRemoval() throws {
        for trigger in ["BEFORE UPDATE ON approval_enrollments_v1", "BEFORE UPDATE ON approval_authority_v1", "BEFORE INSERT ON audit_records_v1"] {
            let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
            let revision = try add(db, writer: writer, revision: empty)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try db.write { tx in
                _ = try? tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                    eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
            XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try remove(db, writer: writer, revision: revision)
        }
    }

    func testReadOnlyExpiredAndCorruptStorageCannotSupplyTrust() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        XCTAssertThrowsError(try db.read { try $0.addApprovalEnrollment(enrollment(), expectedTrustRevision: empty,
            eventID: id(40), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.read { $0 }
        XCTAssertThrowsError(try escaped.approvalTrustSnapshot()) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        _ = try add(db, writer: writer, revision: empty)
        try fixture.sql("UPDATE approval_enrollments_v1 SET body=x'01'")
        XCTAssertThrowsError(try db.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testExplicitSchemaFiveMigrationKeepsAuditAndStartsUnconfigured() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try db.write { try $0.createEpoch(descriptor()) }; try db.close()
        try fixture.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; PRAGMA user_version=5")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 5)
        XCTAssertNotNil(try migrated.read { try $0.epoch(id(3)) })
        XCTAssertThrowsError(try migrated.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured) }
        try migrated.close()
        let reopened = try open(fixture)
        XCTAssertNotNil(try reopened.read { try $0.epoch(id(3)) })
    }

    func testSamePhoneCanReenrollWithFreshEpochAndKeys() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let removed = try remove(db, writer: writer, revision: revision)
        let material = try enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey())
        let replacement = try StoredApprovalEnrollment(epoch: material.epoch, notificationTag: material.notificationTag,
            identityPublicKey: material.identityPublicKey, approval: ApprovalEnrollment(phoneID: id(5), active: true,
                capabilities: material.approval.capabilities, keys: material.approval.keys))
        let fresh = try db.write { try $0.addApprovalEnrollment(replacement, expectedTrustRevision: removed.revision,
            eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(5)])
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().count }, 2)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: fresh, head: 3) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .wrongKey)
        }
    }

    func testMalformedPolicyAndPhoneMetadataRetireOwner() throws {
        for mutation in ["UPDATE approval_authority_v1 SET policy=x'7b7d'",
                         "UPDATE approval_enrollments_v1 SET phone=zeroblob(16)",
                         "UPDATE approval_enrollments_v1 SET epoch=zeroblob(16)"] {
            let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
            _ = try add(db, writer: writer, revision: empty)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try db.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
    }

    func testFailedSchemaFiveMigrationDoesNotResetExistingState() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        _ = try add(db, writer: writer, revision: empty); try db.close()
        try fixture.sql("PRAGMA user_version=5")
        XCTAssertThrowsError(try open(fixture, migrate: 5))
        try fixture.sql("PRAGMA user_version=12")
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.approvalEnrollments().count }, 1)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testInvalidEnrollmentKeysAndPolicyCannotConfigureAuthority() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        XCTAssertThrowsError(try db.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [:]), allowedContracts: []) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState)
        }
        let sameKey = try ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
            EnrolledApprovalKey(id: id(10), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
            EnrolledApprovalKey(id: id(11), keyClass: .decision, publicKey: key.publicKey.x963Representation),
        ])
        XCTAssertThrowsError(try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(5, count: 32),
            identityPublicKey: rootKey.publicKey.x963Representation, approval: sameKey)) { XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState) }
        let valid = try enrollment()
        XCTAssertThrowsError(try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(5, count: 32),
            identityPublicKey: id(4, count: 65), approval: valid.approval)) { XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState) }
        _ = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
    }

    private func tokenCandidate(_ db: JournalDatabase, revision: UUID, head: UInt64 = 0, epoch: UInt8 = 9) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(epoch),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: head,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }
    }
    private func signCandidate(_ value: GatewayTokenCandidate) throws -> Data {
        try rootKey.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: value.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func tokenProof(_ envelope: GatewayAuthorityEnvelope) throws -> Data {
        try GatewayTokenProof(binding: GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits).binding).encode(limits: limits)
    }
    private func activate(_ db: JournalDatabase, envelope: GatewayAuthorityEnvelope, revision: UUID, head: UInt64 = 1,
                          epoch: UInt8 = 9) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.consumeGatewayProof(canonicalProof: tokenProof(envelope), authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(epoch),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: head, nowUnixMillis: 1000, now: moment()) { value in
                try rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                    canonicalPayload: value.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
            } }
    }

    func testPublicGatewayCandidateAndProofUseStoredPhoneTagAndEpoch() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try tokenCandidate(db, revision: empty)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        let revision = try add(db, writer: writer, revision: empty)
        let envelope = try tokenCandidate(db, revision: revision)
        let value = try GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits)
        XCTAssertEqual(value.binding.enrollmentTag, id(5, count: 32)); XCTAssertEqual(value.binding.enrollmentEpoch, id(9))
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: envelope.operationID, phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, nowUnixMillis: 1000, now: moment()) }?.signature, envelope.signature)
        let activation = try activate(db, envelope: envelope, revision: revision)
        XCTAssertEqual(try GatewayMappingActivation.decode(activation.canonicalPayload, limits: limits).binding, value.binding)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 2)
    }

    func testPublicGatewayRemovalBlocksLateProofRenewalAndPendingControls() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let envelope = try tokenCandidate(db, revision: revision)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(head: 1))
        XCTAssertThrowsError(try activate(db, envelope: envelope, revision: revision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try activate(db, envelope: envelope, revision: removed.revision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.write { try $0.renewDesiredGatewayCandidate(phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: removed.revision, expectedHead: 2,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayControl(operationID: envelope.operationID, phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: removed.revision, nowUnixMillis: 1000, now: moment()) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 2)
    }

    func testPublicGatewayRejectsWrongPeerScopeAndInactiveRegistrationBeforeSigning() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let r = try identity()
        let wrongAccount = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: id(99), gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        let wrongKey = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        var signed = false
        for (phone, epoch, registration, active) in [(id(8), id(9), r, true), (id(5), id(10), r, true),
            (id(5), id(9), wrongAccount, true), (id(5), id(9), wrongKey, true), (id(5), id(9), r, false)] {
            XCTAssertThrowsError(try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token",
                authenticatedPhoneID: phone, authenticatedEnrollmentEpoch: epoch, registration: registration,
                registrationActive: active, expectedTrustRevision: revision, expectedHead: 0, nowUnixMillis: 1000, now: moment()) {
                    signed = true; return try signCandidate($0)
                } })
        }
        XCTAssertFalse(signed)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        _ = try tokenCandidate(db, revision: revision)
    }

    func testPublicGatewayRestartRenewalKeepsPairingAndUsesFreshChallenge() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let old = try tokenCandidate(db, revision: revision)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertThrowsError(try activate(reopened, envelope: old, revision: revision)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        let fresh = try reopened.write { try $0.renewDesiredGatewayCandidate(phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: 1,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }
        let first = try GatewayTokenCandidate.decode(old.canonicalPayload, limits: limits), next = try GatewayTokenCandidate.decode(fresh.canonicalPayload, limits: limits)
        XCTAssertNotEqual(first.binding.challenge, next.binding.challenge)
        XCTAssertEqual(next.binding.enrollmentEpoch, first.binding.enrollmentEpoch)
        XCTAssertEqual(next.binding.enrollmentTag, first.binding.enrollmentTag)
        _ = try activate(reopened, envelope: fresh, revision: revision, head: 2)
    }

    func testPublicGatewayNewEnrollmentCannotUseOldEpochProof() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let old = try tokenCandidate(db, revision: revision)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(head: 1))
        let material = try enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey())
        let replacement = try StoredApprovalEnrollment(epoch: material.epoch, notificationTag: material.notificationTag,
            identityPublicKey: material.identityPublicKey, approval: ApprovalEnrollment(phoneID: id(5), active: true,
                capabilities: material.approval.capabilities, keys: material.approval.keys))
        let nextRevision = try db.write { try $0.addApprovalEnrollment(replacement, expectedTrustRevision: removed.revision,
            eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertThrowsError(try activate(db, envelope: old, revision: nextRevision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        let fresh = try tokenCandidate(db, revision: nextRevision, head: 2, epoch: 10)
        XCTAssertThrowsError(try activate(db, envelope: old, revision: nextRevision, head: 3, epoch: 10)) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        _ = try activate(db, envelope: fresh, revision: nextRevision, head: 3, epoch: 10)
        XCTAssertEqual(try GatewayTokenCandidate.decode(fresh.canonicalPayload, limits: limits).binding.enrollmentTag, material.notificationTag)
    }

    func testPublicGatewayReadOnlyAndSwallowedEnrollmentFailureCannotWrite() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try db.read { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: revision,
            expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        XCTAssertThrowsError(try db.write { tx in
            _ = try? tx.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: empty,
                expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate)
            _ = try tx.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: revision,
                expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        _ = try tokenCandidate(db, revision: revision)
    }

    func testDeliveryTrustUsesCurrentDurableEnrollmentEpochs() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let request = try request(), session = try PendingRequestDelivery(request: request)
        let routing = PresenceRouting(destination: .phones, reason: .manualAway, detectionLimited: false)
        let before = try db.read { try $0.requestDeliveryTrust() }
        XCTAssertEqual(before.approval.revision, revision)
        let first = session.reconcile(current: request, routing: routing, trust: before, now: moment()) { _ in true }
        XCTAssertEqual(first.active.first?.recipient.enrollmentEpoch, id(9))
        let removed = try remove(db, writer: writer, revision: revision)
        let after = try db.read { try $0.requestDeliveryTrust() }
        XCTAssertEqual(after.approval.revision, removed.revision)
        XCTAssertFalse(try XCTUnwrap(after.enrollments.first).approval.active)
        let update = session.reconcile(current: request, routing: routing, trust: after, now: moment()) { _ in
            XCTFail("Revoked recipient must not enqueue"); return true
        }
        XCTAssertEqual(update.withdrawn, first.active)
        XCTAssertTrue(update.active.isEmpty)
    }

    private func recoveredRemoval(phone: UInt8 = 5, epoch: UInt8 = 9, operation: UInt8 = 70,
                                  registration: GatewayRegistrationIdentity? = nil) throws -> (Data, Data) {
        let r = try registration ?? identity()
        let binding = try GatewayPhoneEpochBinding(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, phoneID: id(phone), enrollmentEpoch: id(epoch))
        let value = try GatewayPhoneRevocation(binding: binding, revision: 99, operationID: id(operation),
            issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
        let payload = try value.encode(limits: limits)
        let signature = try rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return (payload, signature)
    }
    private func recoverRemoval(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 1,
                                evidence: (Data, Data)? = nil) throws -> UUID {
        let evidence = try evidence ?? recoveredRemoval()
        return try db.write { try $0.recoverGatewayRevocation(canonicalPayload: evidence.0, signature: evidence.1,
            registration: identity(), expectedTrustRevision: revision, eventID: id(UInt8(head + 100)), receiptTimeMs: 5000,
            writer: writer, expectedAuditHead: head) }
    }

    func testRecoveredExpiredRevocationDisablesDecisionsAndTokenProofsWithoutAdvancingCounter() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let candidate = try tokenCandidate(db, revision: revision)
        let next = try recoverRemoval(db, writer: writer, revision: revision)
        XCTAssertNotEqual(next, revision)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().count }, 1)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: next, head: 2) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
        }
        XCTAssertThrowsError(try activate(db, envelope: candidate, revision: next)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 1)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(identity()) })
        let trust = try GatewayAuthorityTrust(registration: identity(),
            enrollment: GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: true), active: true)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust) })
        let record = try db.read { try XCTUnwrap($0.page(epoch: id(3), after: 1, maximumRecords: 1, maximumBytes: 16384).canonicalRecords.first) }
        let event = try AuditEventMetadata.decode(record, limits: limits)
        XCTAssertEqual(event.kind, .recovery); XCTAssertEqual(event.authentication, .system)
        XCTAssertEqual(event.reason, .revoked); XCTAssertEqual(event.peerDeviceID, id(5))
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.approvalTrustSnapshot().revision }, next)
        XCTAssertTrue(try reopened.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust) })
    }

    func testRepeatedRecoveredRevocationDoesNotDuplicateAuditOrTrustChanges() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let next = try recoverRemoval(db, writer: writer, revision: revision)
        XCTAssertEqual(try recoverRemoval(db, writer: writer, revision: next, head: 2), next)
        let renewedEvidence = try recoveredRemoval(operation: 71)
        XCTAssertEqual(try recoverRemoval(db, writer: writer, revision: next, head: 2, evidence: renewedEvidence), next)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
    }

    func testRecoveryReusesNormalRevocationAtFullCapacityWithoutAuditOrRevisionChanges() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f, maximum: 2)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        _ = try tokenCandidate(db, revision: revision)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(head: 1))
        let evidence = try XCTUnwrap(removed.gatewayControl)
        let next = try recoverRemoval(db, writer: writer, revision: removed.revision, head: 2,
            evidence: (evidence.canonicalPayload, evidence.signature))
        XCTAssertEqual(next, removed.revision)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 2)
        XCTAssertEqual(try recoverRemoval(db, writer: writer, revision: next, head: 2), next)
    }

    func testKnownNormalRevocationStillDisablesAnActiveEnrollmentDuringRecovery() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let removal = try gatewayRemoval()
        let trusted = try GatewayAuthorityTrust(registration: identity(),
            enrollment: GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: false), active: true)
        let evidence = try db.write { try $0.revokeGatewayEnrollment(trust: trusted, expectedHead: 0,
            nowUnixMillis: 1000, now: moment(), sign: removal.sign) }
        let next = try recoverRemoval(db, writer: writer, revision: revision,
            evidence: (evidence.canonicalPayload, evidence.signature))
        XCTAssertNotEqual(next, revision)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 1)
    }

    func testRecoveredUnknownEpochCannotBeEnrolledAndDoesNotDisableNewerEpoch() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let restricted = try recoverRemoval(db, writer: writer, revision: empty, head: 0)
        XCTAssertThrowsError(try add(db, writer: writer, revision: restricted, head: 1)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity)
        }
        let current = try add(db, writer: writer, revision: restricted, head: 1, epoch: 10)
        let candidate = try tokenCandidate(db, revision: current, epoch: 10)
        XCTAssertEqual(try recoverRemoval(db, writer: writer, revision: current, head: 2), current)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.count }, 1)
        _ = try activate(db, envelope: candidate, revision: current, epoch: 10)
    }

    func testRecoveredRevocationPreservesAnotherPhoneAndWithdrawsOnlyRevokedDelivery() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), otherKey = P256.Signing.PrivateKey()
        let first = try add(db, writer: writer, revision: empty)
        let current = try add(db, writer: writer, revision: first, head: 1, phone: 8, epoch: 10, signingKey: otherKey)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let retained = try request(), pending = try PendingRequestDelivery(request: retained)
        let routing = PresenceRouting(destination: .phones, reason: .manualAway, detectionLimited: false)
        let before = pending.reconcile(current: retained, routing: routing, trust: try db.read { try $0.requestDeliveryTrust() }, now: moment()) { _ in true }
        XCTAssertEqual(before.active.count, 2)
        let next = try recoverRemoval(db, writer: writer, revision: current, head: 2)
        let after = pending.reconcile(current: retained, routing: routing, trust: try db.read { try $0.requestDeliveryTrust() }, now: moment()) { _ in
            XCTFail("No new recipient should be enqueued"); return true
        }
        XCTAssertEqual(after.withdrawn.count, 1); XCTAssertEqual(after.withdrawn.first?.recipient.phoneID, id(5))
        XCTAssertEqual(after.active.count, 1)
        let accepted = try db.write { try consume($0, writer: writer, revision: next, head: 3, phone: 8, signingKey: otherKey) }
        XCTAssertEqual(accepted.decision.phoneID, id(8))
    }

    func testRecoveredRevocationStorageFaultsRollbackRestrictionTokenRetirementAndAudit() throws {
        for trigger in ["BEFORE INSERT ON gateway_recovered_revocations_v1", "BEFORE DELETE ON gateway_desired_tokens_v1",
                        "BEFORE UPDATE ON gateway_root_candidates_v1", "BEFORE UPDATE ON approval_enrollments_v1",
                        "BEFORE UPDATE ON approval_authority_v1", "BEFORE INSERT ON audit_records_v1"] {
            let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
            try db.write { try $0.configureGatewayAuthority(identity()) }
            let candidate = try tokenCandidate(db, revision: revision)
            try f.sql("CREATE TRIGGER reject_recovery \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try recoverRemoval(db, writer: writer, revision: revision))
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
            XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
            XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: candidate.operationID, phoneID: id(5), enrollmentEpoch: id(9),
                registration: identity(), registrationActive: true, expectedTrustRevision: revision, nowUnixMillis: 1000, now: moment()) })
            try f.sql("DROP TRIGGER reject_recovery")
            _ = try recoverRemoval(db, writer: writer, revision: revision)
        }
    }

    func testRecoveredRevocationRequiresRootSignatureScopeAndCurrentTrust() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let evidence = try recoveredRemoval()
        XCTAssertThrowsError(try recoverRemoval(db, writer: writer, revision: UUID())) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try recoverRemoval(db, writer: writer, revision: revision, evidence: (evidence.0, id(0, count: 64)))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature)
        }
        let r = try identity(), wrong = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: id(99), rootPublicKey: r.rootPublicKey)
        XCTAssertThrowsError(try recoverRemoval(db, writer: writer, revision: revision, evidence: recoveredRemoval(registration: wrong))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope)
        }
        XCTAssertThrowsError(try db.read { try $0.recoverGatewayRevocation(canonicalPayload: evidence.0, signature: evidence.1,
            registration: identity(), expectedTrustRevision: revision, eventID: id(80), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testRecoveredRevocationCorruptionRetiresGatewayStorageOwner() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        _ = try recoverRemoval(db, writer: writer, revision: revision)
        try f.sql("UPDATE gateway_recovered_revocations_v1 SET signature=zeroblob(64)")
        let trust = try GatewayAuthorityTrust(registration: identity(),
            enrollment: GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: true), active: true)
        XCTAssertThrowsError(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testRecoveredRevocationsShareTheControlStorageBoundAndKeepIdempotentRetryAvailable() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f, maximum: 2)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let first = try recoverRemoval(db, writer: writer, revision: empty, head: 0)
        let second = try recoverRemoval(db, writer: writer, revision: first, head: 1,
            evidence: recoveredRemoval(phone: 6, epoch: 10, operation: 71))
        XCTAssertThrowsError(try recoverRemoval(db, writer: writer, revision: second, head: 2,
            evidence: recoveredRemoval(phone: 7, epoch: 11, operation: 72))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, second)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try recoverRemoval(db, writer: writer, revision: second, head: 2), second)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
    }

    func testSchemaNineMigrationPreservesEnrollmentAndStartsWithoutRecoveredRevocations() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.close()
        try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; DROP TABLE gateway_recovered_revocations_v1; PRAGMA user_version=9")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 9)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().enrollments.count }, 1)
        XCTAssertEqual(try migrated.read { try $0.epoch(id(3))?.head }, 1)
    }

    private func trustEvidence(kind: GatewayTrustEvidenceKind = .candidate, phone: UInt8 = 5, epoch: UInt8 = 10,
                               tag: UInt8 = 5, operation: UInt8 = 90, registration: GatewayRegistrationIdentity? = nil) throws -> (Data, Data) {
        let r = try registration ?? identity()
        let binding = try GatewayTokenBinding(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, phoneID: id(phone), enrollmentEpoch: id(epoch),
            candidateID: id(91), tokenDigest: id(92, count: 32), challenge: id(93, count: 32), enrollmentTag: id(tag, count: 32))
        switch kind {
        case .candidate:
            let value = try GatewayTokenCandidate(binding: binding, revision: 99, operationID: id(operation), issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
            return try (value.encode(limits: limits), signCandidate(value))
        case .activation:
            let value = try GatewayMappingActivation(binding: binding, revision: 99, operationID: id(operation), issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
            let payload = try value.encode(limits: limits)
            return try (payload, rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation)
        }
    }
    private func restrictTrust(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 1,
                               kind: GatewayTrustEvidenceKind = .candidate, evidence: (Data, Data)? = nil) throws -> GatewayTrustRestrictionResult {
        let evidence = try evidence ?? trustEvidence(kind: kind)
        return try db.write { try $0.restrictUnknownGatewayTrust(kind: kind, canonicalPayload: evidence.0, signature: evidence.1,
            registration: identity(), expectedTrustRevision: revision, eventID: id(UInt8(100 + head)), receiptTimeMs: 5000,
            writer: writer, expectedAuditHead: head) }
    }

    func testUnknownTrustRestrictionPreservesPairingButBlocksActionsTokensAndRoutingAfterRestart() throws {
        for kind in [GatewayTrustEvidenceKind.candidate, .activation] {
            let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
            try db.write { try $0.configureGatewayAuthority(identity()) }
            let old = try db.read { try XCTUnwrap($0.approvalEnrollments().first) }
            let candidate = try tokenCandidate(db, revision: revision)
            let result = try restrictTrust(db, writer: writer, revision: revision, kind: kind)
            XCTAssertEqual(result.disposition, .restricted); XCTAssertNotEqual(result.trustRevision, revision)
            XCTAssertEqual(try db.read { try $0.approvalTrustRestrictions() }, [id(5)])
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
            XCTAssertTrue(try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.isEmpty })
            let retained = try db.read { try XCTUnwrap($0.approvalEnrollments().first) }
            XCTAssertTrue(retained.approval.active)
            XCTAssertEqual(retained.identityPublicKey, old.identityPublicKey)
            XCTAssertEqual(retained.approval.keys.map(\.publicKey), old.approval.keys.map(\.publicKey))
            XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: result.trustRevision, head: 2) }) {
                XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
            }
            XCTAssertThrowsError(try activate(db, envelope: candidate, revision: result.trustRevision)) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired)
            }
            XCTAssertThrowsError(try tokenCandidate(db, revision: result.trustRevision, head: 1)) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired)
            }
            XCTAssertThrowsError(try db.write { try $0.issueRoutingChallenge(authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(9),
                expectedTrustRevision: result.trustRevision, expectedRoutingRevision: 0, nowUnixMillis: 1000, now: moment()) }) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired)
            }
            let stale = try GatewayAuthorityTrust(registration: identity(), enrollment:
                GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: true), active: true)
            XCTAssertThrowsError(try db.read { try $0.pendingGatewayControl(operationID: candidate.operationID,
                trust: stale, nowUnixMillis: 1000, now: moment()) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 1)
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(identity()) })
            let record = try db.read { try XCTUnwrap($0.page(epoch: id(3), after: 1, maximumRecords: 1, maximumBytes: 16384).canonicalRecords.first) }
            let event = try AuditEventMetadata.decode(record, limits: limits)
            XCTAssertEqual(event.kind, .recovery); XCTAssertEqual(event.authentication, .system)
            XCTAssertEqual(event.outcome, .unresolved); XCTAssertEqual(event.reason, .bindingMismatch)
            XCTAssertEqual(event.peerDeviceID, id(5))
            try db.close()
            let reopened = try open(f)
            XCTAssertEqual(try reopened.read { try $0.approvalTrustRestrictions() }, [id(5)])
            XCTAssertTrue(try reopened.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
            XCTAssertEqual(try reopened.read { try $0.approvalTrustSnapshot().revision }, result.trustRevision)
        }
    }

    func testKnownHistoryDoesNotRestrictAndReplayCannotClearUnknownTrustRestriction() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let known = try trustEvidence(epoch: 9)
        let result = try restrictTrust(db, writer: writer, revision: revision, evidence: known)
        XCTAssertEqual(result.disposition, .knownHistory); XCTAssertEqual(result.trustRevision, revision)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
        let changed = try restrictTrust(db, writer: writer, revision: revision, evidence: trustEvidence(epoch: 9, tag: 99))
        XCTAssertEqual(changed.disposition, .restricted)
        for evidence in [try trustEvidence(epoch: 9, tag: 99), known, try trustEvidence(operation: 94)] {
            let retry = try restrictTrust(db, writer: writer, revision: changed.trustRevision, head: 2, evidence: evidence)
            XCTAssertEqual(retry.disposition, .alreadyRestricted); XCTAssertEqual(retry.trustRevision, changed.trustRevision)
        }
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try db.read { try $0.approvalTrustRestrictions() }, [id(5)])
    }

    func testTrustRestrictionWithdrawsOnlyAffectedPhoneAndAllowsAnotherWinner() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), otherKey = P256.Signing.PrivateKey()
        let first = try add(db, writer: writer, revision: empty)
        let revision = try add(db, writer: writer, revision: first, head: 1, phone: 8, epoch: 11, signingKey: otherKey)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let request = try request(), pending = try PendingRequestDelivery(request: request)
        let routing = PresenceRouting(destination: .phones, reason: .manualAway, detectionLimited: false)
        XCTAssertEqual(pending.reconcile(current: request, routing: routing, trust: try db.read { try $0.requestDeliveryTrust() }, now: moment()) { _ in true }.active.count, 2)
        let prior = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024) }
        XCTAssertEqual(Set(prior.peers.map { $0.scope.phoneID }), [id(5), id(8)])
        let result = try restrictTrust(db, writer: writer, revision: revision, head: 2)
        let current = try db.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024) }
        XCTAssertEqual(current.peers.map { $0.scope.phoneID }, [id(8)])
        XCTAssertEqual(current.revision, result.trustRevision)
        let blocked = try XCTUnwrap(prior.peers.first { $0.scope.phoneID == id(5) })
        XCTAssertThrowsError(try db.read { try $0.requireDirectApprovalPeer(blocked, expectedTrustRevision: current.revision) })
        try db.read { try $0.requireDirectApprovalPeer(XCTUnwrap(current.peers.first), expectedTrustRevision: current.revision) }
        let update = pending.reconcile(current: request, routing: routing, trust: try db.read { try $0.requestDeliveryTrust() }, now: moment()) { _ in
            XCTFail("No new delivery"); return true
        }
        XCTAssertEqual(update.withdrawn.map { $0.recipient.phoneID }, [id(5)])
        XCTAssertEqual(update.active.map { $0.recipient.phoneID }, [id(8)])
        XCTAssertEqual(try db.write { try consume($0, writer: writer, revision: result.trustRevision, head: 3, phone: 8, signingKey: otherKey) }.decision.phoneID, id(8))
    }

    func testExplicitRemovalRemainsAvailableAndEnrollmentCannotBypassRestriction() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let restricted = try restrictTrust(db, writer: writer, revision: revision)
        let removed = try remove(db, writer: writer, revision: restricted.trustRevision, head: 2, gateway: gatewayRemoval())
        XCTAssertNotNil(removed.gatewayControl)
        XCTAssertFalse(try db.read { try XCTUnwrap($0.approvalEnrollments().first).approval.active })
        XCTAssertThrowsError(try add(db, writer: writer, revision: removed.revision, head: 3, epoch: 12, signingKey: P256.Signing.PrivateKey())) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustRestrictions() }, [id(5)])
    }

    func testUnknownPhoneEvidenceCannotEnrollOrConsumeAuthorityAndRetryWorksAtCapacity() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f, maximum: 2)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let first = try restrictTrust(db, writer: writer, revision: empty, head: 0)
        let second = try restrictTrust(db, writer: writer, revision: first.trustRevision, head: 1,
            evidence: trustEvidence(phone: 8, operation: 94))
        XCTAssertThrowsError(try restrictTrust(db, writer: writer, revision: second.trustRevision, head: 2,
            evidence: trustEvidence(phone: 9, operation: 95))) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertEqual(try restrictTrust(db, writer: writer, revision: second.trustRevision, head: 2).disposition, .alreadyRestricted)
        XCTAssertThrowsError(try add(db, writer: writer, revision: second.trustRevision, head: 2)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired)
        }
        XCTAssertTrue(try db.read { try $0.approvalEnrollments().isEmpty })
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
    }

    func testTrustRestrictionRejectsWrongSignaturesScopeRevisionAndReadOnlyCalls() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let evidence = try trustEvidence()
        XCTAssertThrowsError(try restrictTrust(db, writer: writer, revision: revision, evidence: (evidence.0, id(0, count: 64)))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature)
        }
        XCTAssertThrowsError(try restrictTrust(db, writer: writer, revision: empty)) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        let r = try identity(), wrong = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: id(99), rootPublicKey: r.rootPublicKey)
        XCTAssertThrowsError(try restrictTrust(db, writer: writer, revision: revision, evidence: trustEvidence(registration: wrong))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope)
        }
        XCTAssertThrowsError(try db.read { try $0.restrictUnknownGatewayTrust(kind: .candidate, canonicalPayload: evidence.0, signature: evidence.1,
            registration: identity(), expectedTrustRevision: revision, eventID: id(100), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        XCTAssertTrue(try db.read { try $0.approvalTrustRestrictions().isEmpty })
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
    }

    func testTrustRestrictionRollsBackMarkerCandidateRetirementRevisionAndAuditTogether() throws {
        for (table, operation) in [("gateway_trust_restrictions_v1", "INSERT"), ("gateway_root_candidates_v1", "UPDATE"),
                                   ("approval_authority_v1", "UPDATE"), ("audit_records_v1", "INSERT")] {
            let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
            try db.write { try $0.configureGatewayAuthority(identity()) }
            let candidate = try tokenCandidate(db, revision: revision)
            try f.sql("CREATE TRIGGER reject_restriction BEFORE \(operation) ON \(table) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try restrictTrust(db, writer: writer, revision: revision))
            XCTAssertTrue(try db.read { try $0.approvalTrustRestrictions().isEmpty })
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
            XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
            XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: candidate.operationID, phoneID: id(5), enrollmentEpoch: id(9),
                registration: identity(), registrationActive: true, expectedTrustRevision: revision, nowUnixMillis: 1000, now: moment()) })
            try f.sql("DROP TRIGGER reject_restriction")
            XCTAssertEqual(try restrictTrust(db, writer: writer, revision: revision).disposition, .restricted)
        }
    }

    func testKnownInactiveHistoryDoesNotCreateRestrictionAndStoredProofCorruptionCannotRestoreAuthority() throws {
        for corrupt in [false, true] {
            let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
            try db.write { try $0.configureGatewayAuthority(identity()) }
            if !corrupt {
                let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval())
                XCTAssertEqual(try restrictTrust(db, writer: writer, revision: removed.revision, head: 2, evidence: trustEvidence(epoch: 9)).disposition, .knownHistory)
                XCTAssertTrue(try db.read { try $0.approvalTrustRestrictions().isEmpty })
            } else {
                _ = try restrictTrust(db, writer: writer, revision: revision)
                let r = try identity(), wrong = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
                    gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
                let wrongTrust = try GatewayAuthorityTrust(registration: wrong, enrollment:
                    GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: true), active: true)
                XCTAssertThrowsError(try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                    authenticatedEnrollmentEpoch: id(9), trust: wrongTrust, expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) {
                    XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope)
                }
                try f.sql("UPDATE gateway_trust_restrictions_v1 SET signature=zeroblob(64)")
                XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
                let stale = try GatewayAuthorityTrust(registration: identity(), enrollment:
                    GatewayPhoneEnrollment(phoneID: id(5), epoch: id(9), tag: id(5, count: 32), active: true), active: true)
                XCTAssertThrowsError(try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                    authenticatedEnrollmentEpoch: id(9), trust: stale, expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) {
                    XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
                }
                XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
            }
        }
    }

    func testSchemaTenMigrationPreservesKeysAuditAndStartsWithoutRestrictions() throws {
        let f = try Fixture(), (db, writer, empty) = try setup(f), revision = try add(db, writer: writer, revision: empty)
        try db.close()
        try f.sql("DROP TABLE pairing_commits_v1; DROP TABLE gateway_trust_restrictions_v1; PRAGMA user_version=10")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 10)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().enrollments.count }, 1)
        XCTAssertEqual(try migrated.read { try $0.epoch(id(3))?.head }, 1)
        XCTAssertTrue(try migrated.read { try $0.approvalTrustRestrictions().isEmpty })
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
        func sql(_ sql: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
}
