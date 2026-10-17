import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

private func pushID(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
private final class PushSignCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}

final class AuthorityPhonePushRegistrationTests: XCTestCase {
    private enum Failure: Error { case injected }
    private final class Harness {
        let root: URL
        let key: P256.Signing.PrivateKey
        let clock = UUID()
        let db: JournalDatabase
        let writer: AuditEpochWriter
        let store: ContinuityStore
        let owner: ApprovalRequestCoordinator
        let binding: AuthorityPeerBinding
        let registration: GatewayRegistrationIdentity
        let provider: AuthorityPhonePushRegistration
        let signs = PushSignCount()
        let limits: CBORLimits
        init(configureGateway: Bool = true) throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            let root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            self.root = root
            for (directory, names) in [("store", ["writer.lock", "journal.sqlite"]), ("continuity", ["writer.lock", "continuity.sqlite"])] {
                let path = root.appendingPathComponent(directory)
                try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                for name in names {
                    let fd = Darwin.open(path.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
                }
            }
            key = P256.Signing.PrivateKey()
            limits = try .init(maxBytes: 4096, maxDepth: 12, maxItems: 256)
            let db = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: pushID(1), accountID: pushID(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: true,
                gatewayPolicy: GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: 30,
                    candidateLifetimeMillis: 1000, clockEpoch: clock))
            self.db = db
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let capabilities = ContractCapabilities(contracts: [contract: []])
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(pushID(1)), 2: .bytes(pushID(2)), 3: .bytes(pushID(3)), 4: .unsigned(3),
                5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }; self.writer = writer
            let identity = P256.Signing.PrivateKey()
            let enrollment = try StoredApprovalEnrollment(epoch: pushID(9), notificationTag: pushID(10, 32),
                identityPublicKey: identity.publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: pushID(5), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: pushID(6), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                    EnrolledApprovalKey(id: pushID(7), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)]))
            let enrolled = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
                eventID: pushID(30), receiptTimeMs: 900, writer: writer, expectedAuditHead: 0) }
            binding = try .init(scope: ChannelScope(macID: pushID(1), accountID: pushID(2), phoneID: pushID(5), enrollmentEpoch: pushID(9)),
                transportPublicKey: identity.publicKey.derRepresentation, revision: enrolled)
            let registration = try GatewayRegistrationIdentity(ownerID: pushID(40), macID: pushID(1), accountID: pushID(2),
                gatewayID: pushID(41), lifecycleEpoch: pushID(42), rootPublicKey: key.publicKey.x963Representation)
            self.registration = registration
            if configureGateway { try db.write { try $0.configureGatewayAuthority(registration) } }
            let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch, generation: 1, authorityGeneration: 3) }
            let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: pushID(1), accountID: pushID(2), initialize: initial)
            self.store = store
            owner = try ApprovalRequestCoordinator(database: db, continuity: store, writer: writer, clockEpoch: clock,
                maximumRequests: 8, maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits, decisionLimits: limits,
                signingLimits: limits, auditLimits: limits)
            let key = key, signs = signs
            provider = AuthorityPhonePushRegistration(policy: try .init(registration: registration, projectID: "project", senderID: "123", packageName: "dev.remozio.android"),
                signing: { bytes in signs.increment(); return try key.signature(for: bytes).rawRepresentation })
        }
        deinit { owner.close(); try? db.close(); store.close(); try? FileManager.default.removeItem(at: root) }
        func offer(project: String = "project") throws -> PhonePushRegistrationFrame {
            try .offer(correlationID: pushID(50), offer: PhonePushTokenOffer(token: "synthetic-token", projectID: project, senderID: "123", packageName: "dev.remozio.android"))
        }
        func exchange(_ frame: PhonePushRegistrationFrame, time: UInt64 = 100, binding: AuthorityPeerBinding? = nil,
                      validate: (JournalTransaction) throws -> Void = { _ in }) throws -> PhonePushRegistrationFrame {
            try owner.phonePushRegistration(frame, binding: binding ?? self.binding, provider: provider,
                now: .init(epoch: clock, milliseconds: time), wall: 900 + time, validateTransport: validate)
        }
        func candidate(_ metadata: PhonePushRegistrationMetadata) throws -> GatewayTokenCandidate {
            let envelope = try db.read { try $0.pendingGatewayControl(operationID: metadata.operationID, phoneID: pushID(5), enrollmentEpoch: pushID(9),
                registration: registration, registrationActive: true, expectedTrustRevision: binding.revision,
                nowUnixMillis: 1000, now: .init(epoch: clock, milliseconds: 100)) }
            return try GatewayTokenCandidate.decode(XCTUnwrap(envelope).canonicalPayload, limits: limits)
        }
        var head: UInt64 { get throws { try db.read { try $0.gatewayAuthorityHead(registration) } } }
        func assertCheckpoint() throws {
            let state = try store.read(); XCTAssertNil(state.pending)
            XCTAssertEqual(state.committed, try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch,
                generation: state.committed.generation, authorityGeneration: state.committed.authorityGeneration) })
        }
        func failCheckpoint(finalize: Bool) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent("continuity/continuity.sqlite").path, &connection) == SQLITE_OK, let connection else { throw Failure.injected }
            defer { sqlite3_close(connection) }
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            guard sqlite3_exec(connection, "CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
    private func prepared(_ reply: PhonePushRegistrationFrame) throws -> PhonePushRegistrationMetadata {
        guard case .prepared(let id, let metadata) = reply else { throw Failure.injected }
        XCTAssertEqual(id, pushID(50)); return metadata
    }
    private func proof(_ candidate: GatewayTokenCandidate) -> PhonePushRegistrationFrame {
        .proof(correlationID: pushID(51), proof: GatewayTokenProof(binding: candidate.binding))
    }
    func testReopenedAuthorityRetainsPairingAndTheCommittedMappingBoundary() throws {
        for committed in [false, true] {
        let h = try Harness(), metadata = try prepared(h.exchange(h.offer())), original = try h.candidate(metadata)
        if committed { _ = try h.exchange(proof(original), time: 101) }
        let before = try h.db.read { try $0.approvalTrustSnapshot().revision }
        h.owner.close(); try h.db.close(); h.store.close()
        let epoch = UUID(), root = h.root.path, limits = h.limits, provider = h.provider
        let storage = try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: root, relativeDirectory: "store", owner: getuid()),
                macID: pushID(1), accountID: pushID(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: false,
                gatewayPolicy: GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: 30,
                    candidateLifetimeMillis: 1000, clockEpoch: epoch))
        }, openContinuity: { _ in
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: root, relativeDirectory: "continuity", owner: getuid()),
                macID: pushID(1), accountID: pushID(2), initialize: nil)
        })
        let journal = try AuthorityJournal(storage: storage)
        defer { try? journal.close() }
        try journal.prepareRequests(clockEpoch: epoch, maximumPayloadBytes: 4096)
        try journal.withRequests { owner in
            let stale = try XCTUnwrap(owner.currentPhonePushRegistration(provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
                now: .init(epoch: epoch, milliseconds: 10), wall: 1001))
            XCTAssertTrue(stale.candidateExpired); XCTAssertEqual(stale.needsRenewal, !committed)
            let current = try XCTUnwrap(owner.renewExpiredPhonePushRegistration(provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
                now: .init(epoch: epoch, milliseconds: 11), wall: 1002))
            XCTAssertFalse(current.needsRenewal)
            let renewed = try GatewayTokenCandidate.decode(current.candidate.canonicalPayload, limits: limits)
            XCTAssertEqual(renewed.binding.enrollmentEpoch, original.binding.enrollmentEpoch)
            XCTAssertEqual(renewed.binding.enrollmentTag, original.binding.enrollmentTag)
            if committed {
                XCTAssertNotNil(current.activation)
                XCTAssertEqual(renewed.binding.challenge, original.binding.challenge)
                XCTAssertEqual(renewed.binding.candidateID, original.binding.candidateID)
            } else {
                XCTAssertNil(current.activation)
                XCTAssertNotEqual(renewed.binding.challenge, original.binding.challenge)
                XCTAssertNotEqual(renewed.binding.candidateID, original.binding.candidateID)
            }
        }
        XCTAssertEqual(try journal.read { try $0.approvalTrustSnapshot().revision }, before)
        }
    }
    func testCurrentTokenStateSeparatesAbsentCandidateProofAndExpiry() throws {
        let h = try Harness()
        func state(_ time: UInt64) throws -> GatewayCurrentTokenState? {
            try h.owner.currentPhonePushRegistration(h.provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
                now: .init(epoch: h.clock, milliseconds: time), wall: 900 + time)
        }
        XCTAssertNil(try state(99))
        let metadata = try prepared(h.exchange(h.offer()))
        let pending = try XCTUnwrap(state(101))
        XCTAssertFalse(pending.needsRenewal); XCTAssertNil(pending.activation)
        XCTAssertEqual(pending.candidate.operationID, metadata.operationID)
        XCTAssertEqual(String(describing: pending), "GatewayCurrentTokenState(redacted)")
        _ = try h.exchange(proof(GatewayTokenCandidate.decode(pending.candidate.canonicalPayload, limits: h.limits)), time: 102)
        let consumed = try XCTUnwrap(state(103))
        XCTAssertNotNil(consumed.activation); XCTAssertFalse(consumed.needsRenewal)
        let expired = try XCTUnwrap(state(1100))
        XCTAssertTrue(expired.candidateExpired); XCTAssertFalse(expired.needsRenewal); XCTAssertNotNil(expired.activation)
        XCTAssertEqual(expired.candidate.operationID, metadata.operationID)
        let before = try h.store.read()
        let retained = try XCTUnwrap(h.owner.renewExpiredPhonePushRegistration(h.provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
            now: .init(epoch: h.clock, milliseconds: 1101), wall: 2001))
        XCTAssertEqual(retained.activation?.operationID, consumed.activation?.operationID)
        XCTAssertEqual(try h.store.read(), before)

    }
    func testExpiredRenewalRetainsEnrollmentAndRequiresAFreshProviderProof() throws {
        let h = try Harness(), old = try prepared(h.exchange(h.offer())), oldCandidate = try h.candidate(old)
        let before = try h.store.read()
        let renewed = try XCTUnwrap(h.owner.renewExpiredPhonePushRegistration(h.provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
            now: .init(epoch: h.clock, milliseconds: 1101), wall: 2001))
        XCTAssertFalse(renewed.needsRenewal); XCTAssertNil(renewed.activation)
        let value = try GatewayTokenCandidate.decode(renewed.candidate.canonicalPayload, limits: h.limits)
        XCTAssertNotEqual(value.binding.candidateID, oldCandidate.binding.candidateID)
        XCTAssertNotEqual(value.binding.challenge, oldCandidate.binding.challenge)
        XCTAssertEqual(value.binding.phoneID, oldCandidate.binding.phoneID)
        XCTAssertEqual(value.binding.enrollmentEpoch, oldCandidate.binding.enrollmentEpoch)
        XCTAssertEqual(value.binding.tokenDigest, oldCandidate.binding.tokenDigest)
        XCTAssertEqual(value.binding.enrollmentTag, oldCandidate.binding.enrollmentTag)
        XCTAssertEqual(try h.store.read().committed.generation, before.committed.generation + 1)
        XCTAssertThrowsError(try h.exchange(proof(oldCandidate), time: 1102))
        _ = try h.exchange(proof(value), time: 1103)
        XCTAssertEqual(try h.head, 3)
    }
    func testLiveCandidateIsNotRenewedAndWrongEnrollmentCannotReadPrivateState() throws {
        let h = try Harness(), metadata = try prepared(h.exchange(h.offer())), before = try h.store.read()
        let current = try XCTUnwrap(h.owner.renewExpiredPhonePushRegistration(h.provider, phoneID: pushID(5), enrollmentEpoch: pushID(9),
            now: .init(epoch: h.clock, milliseconds: 101), wall: 1001))
        XCTAssertEqual(current.candidate.operationID, metadata.operationID)
        XCTAssertEqual(try h.store.read(), before)
        XCTAssertThrowsError(try h.owner.currentPhonePushRegistration(h.provider, phoneID: pushID(5), enrollmentEpoch: pushID(99),
            now: .init(epoch: h.clock, milliseconds: 102), wall: 1002))
        XCTAssertEqual(try h.store.read(), before)
        XCTAssertEqual(try h.head, 1)
    }
    func testProtectedStartupCheckpointFailureRetiresTheOwnerBeforeListenerStart() throws {
        for finalize in [false, true] {
            let h = try Harness(configureGateway: false), before = try h.store.read()
            try h.failCheckpoint(finalize: finalize)
            XCTAssertThrowsError(try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 100)))
            XCTAssertTrue(h.owner.retired)
            XCTAssertEqual(try h.store.read().committed, before.committed)
            XCTAssertEqual(try h.store.read().pending != nil, finalize)
            if finalize { XCTAssertEqual(try h.head, 0) } else { XCTAssertThrowsError(try h.head) }
            XCTAssertThrowsError(try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 101)))
        }
    }
    func testProtectedStartupRejectsADifferentAuthorityClockWithoutWriting() throws {
        let h = try Harness(configureGateway: false), before = try h.store.read()
        XCTAssertThrowsError(try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: UUID(), milliseconds: 100)))
        XCTAssertEqual(try h.store.read(), before)
        XCTAssertThrowsError(try h.head)
    }
    func testProtectedStartupConfiguresTheFixedIdentityThroughTheCheckpoint() throws {
        let h = try Harness(configureGateway: false)
        XCTAssertThrowsError(try h.head)
        try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 100))
        XCTAssertEqual(try h.head, 0)
        let first = try h.store.read()
        try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 101))
        XCTAssertEqual(try h.head, 0)
        XCTAssertGreaterThan(try h.store.read().committed.generation, first.committed.generation)
        guard case .prepared = try h.exchange(h.offer(), time: 102) else { return XCTFail() }
    }
    func testProtectedStartupRejectsAReplacementIdentityAndKeepsTheOriginalOwnerUsable() throws {
        let h = try Harness(), r = h.registration
        let changed = try GatewayRegistrationIdentity(ownerID: pushID(99), macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        let provider = AuthorityPhonePushRegistration(policy: try .init(registration: changed, projectID: "project", senderID: "123", packageName: "dev.remozio.android"),
            signing: { _ in throw Failure.injected })
        XCTAssertThrowsError(try h.owner.preparePhonePushRegistration(provider, now: .init(epoch: h.clock, milliseconds: 100)))
        XCTAssertEqual(try h.head, 0)
        guard case .prepared = try h.exchange(h.offer(), time: 101) else { return XCTFail() }
    }
    func testProtectedStartupValidatesRootBeforeCreatingGatewayState() throws {
        let h = try Harness(configureGateway: false)
        let provider = AuthorityPhonePushRegistration(policy: h.provider.policy, signing: { _ in throw Failure.injected },
            verifySelf: { _ in throw Failure.injected })
        XCTAssertThrowsError(try h.owner.preparePhonePushRegistration(provider, now: .init(epoch: h.clock, milliseconds: 100)))
        XCTAssertThrowsError(try h.head)
        try h.owner.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 101))
        XCTAssertEqual(try h.head, 0)
    }
    func testCandidateMetadataAndProofResultFollowCheckpointedCommits() throws {
        let f = try Harness(); let before = try f.store.read()
        let reply = try f.exchange(f.offer()), metadata = try prepared(reply)
        let candidate = try f.candidate(metadata)
        XCTAssertNil(try reply.encode().range(of: candidate.binding.challenge))
        XCTAssertEqual(try f.head, 1); XCTAssertEqual(try f.store.read().committed.generation, before.committed.generation + 1)
        try f.assertCheckpoint()
        guard case .outcome(let id, let result) = try f.exchange(proof(candidate), time: 110) else { return XCTFail("Missing proof result") }
        XCTAssertEqual(id, pushID(51)); XCTAssertEqual(result, .proofCommitted); XCTAssertNotEqual(result, .mappingConfirmed)
        XCTAssertEqual(try f.head, 2); XCTAssertEqual(f.signs.value, 2); try f.assertCheckpoint()
    }
    func testIncompatibleProviderDoesNotCreateCandidateOrSign() throws {
        let f = try Harness()
        guard case .outcome(_, let result) = try f.exchange(f.offer(project: "other")) else { return XCTFail("Missing compatibility result") }
        XCTAssertEqual(result, .incompatible); XCTAssertEqual(try f.head, 0); XCTAssertEqual(f.signs.value, 0)
        try f.assertCheckpoint()
    }
    func testTransportRejectionAndStaleBindingCannotReachTheSigner() throws {
        let f = try Harness(); let before = try f.store.read()
        XCTAssertThrowsError(try f.exchange(f.offer(), validate: { _ in throw Failure.injected }))
        let stale = try AuthorityPeerBinding(scope: f.binding.scope, transportPublicKey: f.binding.transportPublicKey, revision: UUID())
        XCTAssertThrowsError(try f.exchange(f.offer(), binding: stale))
        XCTAssertEqual(try f.store.read(), before); XCTAssertEqual(try f.head, 0); XCTAssertEqual(f.signs.value, 0)
        _ = try prepared(f.exchange(f.offer(), time: 110)); try f.assertCheckpoint()
    }
    func testDuplicateProofCannotCreateAnotherActivationOrRetireHealthyStorage() throws {
        let f = try Harness(); let candidate = try f.candidate(prepared(f.exchange(f.offer())))
        _ = try f.exchange(proof(candidate), time: 110); let before = try f.store.read()
        XCTAssertThrowsError(try f.exchange(proof(candidate), time: 120))
        XCTAssertEqual(try f.head, 2); XCTAssertEqual(f.signs.value, 2); XCTAssertEqual(try f.store.read(), before)
        _ = try prepared(f.exchange(f.offer(), time: 130)); XCTAssertEqual(try f.head, 3); try f.assertCheckpoint()
    }
    func testHostileResponseRolesNeverCreateControls() throws {
        let f = try Harness(); let before = try f.store.read()
        XCTAssertThrowsError(try f.exchange(.outcome(correlationID: pushID(50), outcome: .mappingConfirmed)))
        XCTAssertEqual(try f.store.read(), before); XCTAssertEqual(try f.head, 0); XCTAssertEqual(f.signs.value, 0)
    }
    func testCheckpointFailureWithholdsMetadataAndProofOutcomes() throws {
        for consume in [false, true] {
            for finalize in [false, true] {
                let f = try Harness()
                let request: PhonePushRegistrationFrame
                if consume { request = proof(try f.candidate(prepared(f.exchange(f.offer())))) }
                else { request = try f.offer() }
                let before = try f.store.read(), head = try f.head
                try f.failCheckpoint(finalize: finalize)
                XCTAssertThrowsError(try f.exchange(request, time: 110))
                XCTAssertTrue(f.owner.retired)
                XCTAssertEqual(try f.head, head + (finalize ? 1 : 0))
                XCTAssertEqual(try f.store.read().committed, before.committed)
                XCTAssertEqual(try f.store.read().pending != nil, finalize)
                XCTAssertThrowsError(try f.exchange(request, time: 120))
            }
        }
    }
}
