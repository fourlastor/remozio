import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class UpdateSchedulingVerifierTests: XCTestCase {
    private let decisionKey = P256.Signing.PrivateKey()
    private let biometricKey = P256.Signing.PrivateKey()
    private let identityKey = P256.Signing.PrivateKey()
    private let transportKey = P256.Signing.PrivateKey()
    private let clock = UUID()
    private let revision = UUID()
    private func id(_ value: UInt8, count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 8, maxItems: 64) } }
    private func moment(_ value: UInt64 = 100) -> AuthorityMoment { .init(epoch: clock, milliseconds: value) }
    private func control(_ action: UpdateSchedulingAction = .installWhenCurrentWorkFinishes) throws -> UpdateSchedulingControl {
        try .init(macID: id(1), accountID: id(2), phoneID: id(3), enrollmentEpoch: id(4), operationID: id(5),
            challenge: id(6, count: 32), keyID: id(7), updateID: id(8, count: 32), expectedGeneration: 10,
            expectedRevision: 20, issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000, action: action)
    }
    private func retained(_ control: UpdateSchedulingControl, revision: UUID? = nil) throws -> RetainedUpdateSchedulingChallenge {
        try .init(control: control, trustRevision: revision ?? self.revision, issuedAt: moment(), deadlineMilliseconds: 1100)
    }
    private func snapshot(_ control: UpdateSchedulingControl) throws -> UpdateSchedulingSnapshot {
        try .init(updateID: control.updateID, generation: control.expectedGeneration, revision: control.expectedRevision)
    }
    private func binding(mac: UInt8 = 1, account: UInt8 = 2, phone: UInt8 = 3, epoch: UInt8 = 4,
                         revision: UUID? = nil, transportPublicKey: Data? = nil) throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: id(mac), accountID: id(account), phoneID: id(phone), enrollmentEpoch: id(epoch)),
            transportPublicKey: transportPublicKey ?? identityKey.publicKey.derRepresentation, revision: revision ?? self.revision)
    }
    private func trust(mac: UInt8 = 1, account: UInt8 = 2, phone: UInt8 = 3, epoch: UInt8 = 4,
                       active: Bool = true, revision: UUID? = nil, decisionID: UInt8 = 7,
                       publicKey: Data? = nil, enrolled: Bool = true, restricted: Bool = false) throws -> RequestDeliveryTrust {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let approval = try ApprovalEnrollment(phoneID: id(phone), active: active, capabilities: capabilities, keys: [
            EnrolledApprovalKey(id: id(decisionID), keyClass: .decision, publicKey: publicKey ?? decisionKey.publicKey.x963Representation),
            EnrolledApprovalKey(id: id(9), keyClass: .biometric, publicKey: biometricKey.publicKey.x963Representation),
        ])
        let stored = try StoredApprovalEnrollment(epoch: id(epoch), notificationTag: id(10, count: 32),
            identityPublicKey: identityKey.publicKey.x963Representation, approval: approval)
        return try RequestDeliveryTrust(approval: ApprovalTrustSnapshot(macID: id(mac), accountID: id(account),
            revision: revision ?? self.revision, authorityCapabilities: capabilities, allowedContracts: [contract],
            enrollments: enrolled && !restricted ? [approval] : []), enrollments: enrolled ? [stored] : [])
    }
    private func sign(_ payload: Data, key: P256.Signing.PrivateKey? = nil) throws -> Data {
        let input = try UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: payload,
            payloadLimits: limits, inputLimits: limits)
        return try (key ?? decisionKey).signature(for: input).rawRepresentation
    }
    private func verify(_ control: UpdateSchedulingControl, retained: RetainedUpdateSchedulingChallenge? = nil,
                        current: UpdateSchedulingSnapshot? = nil, binding: AuthorityPeerBinding? = nil,
                        trust: RequestDeliveryTrust? = nil, now: AuthorityMoment? = nil, wall: UInt64 = 1500,
                        signature: Data? = nil) throws -> VerifiedUpdateSchedulingControl {
        let bytes = try control.encode(limits: limits)
        return try UpdateSchedulingVerifier.verify(canonicalControl: bytes, signature: signature ?? sign(bytes),
            retained: retained ?? self.retained(control), current: current ?? snapshot(control),
            binding: binding ?? self.binding(), trust: trust ?? self.trust(), now: now ?? moment(500),
            nowUnixMillis: wall, payloadLimits: limits, signingLimits: limits)
    }
    private func changed(_ control: UpdateSchedulingControl, field: UInt64, value: CBORValue) throws -> UpdateSchedulingControl {
        guard case .map(var fields) = try DeterministicCBOR.decode(control.encode(limits: limits), limits: limits) else {
            throw UpdateSchedulingVerificationError.invalidTrustedState
        }
        fields[field] = value
        return try UpdateSchedulingControl.decode(DeterministicCBOR.encode(.map(fields), limits: limits), limits: limits)
    }
    private func rejects(_ expected: UpdateSchedulingVerificationError, _ body: () throws -> Any,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(error as? UpdateSchedulingVerificationError, expected, file: file, line: line)
        }
    }

    func testEveryRetainedActionUsesCurrentDecisionKeyAndReturnsOnlyVerificationEvidence() throws {
        for action in UpdateSchedulingAction.allCases {
            let claim = try control(action), challenge = try retained(claim)
            let evidence = try verify(claim, retained: challenge)
            XCTAssertEqual(evidence.control, claim)
            XCTAssertEqual(evidence.trustRevision, revision)
            XCTAssertEqual(evidence.clockEpoch, clock)
            XCTAssertEqual(evidence.deadlineMilliseconds, 1100)
            // Reverification does not consume the operation. The future journal commit must consume it once.
            XCTAssertEqual(try verify(claim, retained: challenge).control, claim)
        }
    }
    func testAuthenticatedChannelAndCurrentAccountMustMatchEveryScopeField() throws {
        let claim = try control()
        for peer in [try binding(mac: 11), try binding(account: 11), try binding(phone: 11), try binding(epoch: 11)] {
            rejects(.wrongBinding) { try verify(claim, binding: peer) }
        }
        rejects(.wrongBinding) { try verify(claim, binding: binding(transportPublicKey: transportKey.publicKey.derRepresentation)) }
        for state in [try trust(mac: 11), try trust(account: 11)] {
            rejects(.wrongBinding) { try verify(claim, trust: state) }
        }
    }
    func testAnyTrustRevisionChangeInvalidatesTheIssuedChallengeAndListener() throws {
        let claim = try control(), fresh = UUID()
        rejects(.staleTrust) { try verify(claim, trust: trust(revision: fresh)) }
        rejects(.staleTrust) { try verify(claim, binding: binding(revision: fresh)) }
        rejects(.staleTrust) { try verify(claim, retained: retained(claim, revision: fresh)) }
        rejects(.staleTrust) { try verify(claim, binding: binding(revision: fresh), trust: trust(revision: fresh)) }
    }
    func testSignedAlterationsCannotReplaceAnyRetainedChallengeField() throws {
        let claim = try control(), challenge = try retained(claim)
        let alterations: [(UInt64, CBORValue)] = [
            (5, .bytes(id(11))), (6, .bytes(id(11, count: 32))), (7, .bytes(id(11))),
            (8, .bytes(id(11, count: 32))), (9, .unsigned(11)), (10, .unsigned(21)),
            (11, .unsigned(999)), (12, .unsigned(2001)), (13, .unsigned(2)),
        ]
        for (field, value) in alterations {
            let altered = try changed(claim, field: field, value: value)
            rejects(.wrongChallenge) { try verify(altered, retained: challenge) }
        }
    }
    func testReplacementOfferAndSchedulingChangeInvalidateOtherwiseValidSignature() throws {
        let claim = try control()
        for current in [
            try UpdateSchedulingSnapshot(updateID: id(11, count: 32), generation: 10, revision: 20),
            try UpdateSchedulingSnapshot(updateID: claim.updateID, generation: 11, revision: 20),
            try UpdateSchedulingSnapshot(updateID: claim.updateID, generation: 10, revision: 21),
        ] { rejects(.staleSchedulingState) { try verify(claim, current: current) } }
    }
    func testRevokedReenrolledAndMissingPhonesCannotUseAnOldDecisionKey() throws {
        let claim = try control()
        for current in [try trust(active: false), try trust(epoch: 11), try trust(phone: 11), try trust(enrolled: false), try trust(restricted: true)] {
            rejects(.unavailableEnrollment) { try verify(claim, trust: current) }
        }
        rejects(.wrongKey) { try verify(claim, trust: trust(decisionID: 11)) }
        rejects(.invalidSignature) { try verify(claim, trust: trust(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)) }
    }
    func testBiometricAndUnenrolledKeysCannotAuthorizeScheduling() throws {
        let claim = try control()
        let biometricClaim = try changed(claim, field: 7, value: .bytes(id(9)))
        rejects(.wrongKey) { try verify(biometricClaim, signature: sign(biometricClaim.encode(limits: limits), key: biometricKey)) }
        rejects(.invalidSignature) { try verify(claim, signature: sign(claim.encode(limits: limits), key: biometricKey)) }
        rejects(.invalidSignature) { try verify(claim, signature: Data(repeating: 0, count: 64)) }
        rejects(.invalidSignature) { try verify(claim, signature: Data()) }
    }
    func testMonotonicDeadlineCannotBeExtendedByWallClockOrRestart() throws {
        let claim = try control()
        _ = try verify(claim, now: moment(100), wall: 1000)
        _ = try verify(claim, now: moment(1099), wall: 1999)
        rejects(.expired) { try verify(claim, now: moment(1100), wall: 1000) }
        rejects(.expired) { try verify(claim, now: moment(UInt64.max), wall: 1500) }
        rejects(.invalidClock) { try verify(claim, now: moment(99)) }
        rejects(.invalidClock) { try verify(claim, now: .init(epoch: UUID(), milliseconds: 500)) }
        rejects(.expired) { try verify(claim, wall: 999) }
        rejects(.expired) { try verify(claim, wall: 2000) }
        rejects(.expired) { try verify(claim, wall: UInt64.max) }
    }
    func testRetainedLifetimeMustMatchTheWireLifetimeWithoutOverflow() throws {
        let claim = try control()
        for deadline: UInt64 in [0, 100, 1099, 1101, UInt64.max] {
            rejects(.invalidTrustedState) {
                try RetainedUpdateSchedulingChallenge(control: claim, trustRevision: revision, issuedAt: moment(), deadlineMilliseconds: deadline)
            }
        }
        let upper = try changed(changed(claim, field: 12, value: .unsigned(UInt64.max)),
            field: 11, value: .unsigned(UInt64.max - 1000))
        let challenge = try RetainedUpdateSchedulingChallenge(control: upper, trustRevision: revision,
            issuedAt: moment(UInt64.max - 1000), deadlineMilliseconds: UInt64.max)
        _ = try verify(upper, retained: challenge, now: moment(UInt64.max - 1), wall: UInt64.max - 1)
        rejects(.expired) { try verify(upper, retained: challenge, now: moment(UInt64.max), wall: UInt64.max - 1) }
        rejects(.invalidTrustedState) { try UpdateSchedulingSnapshot(updateID: id(8), generation: 1, revision: 0) }
        rejects(.invalidTrustedState) { try UpdateSchedulingSnapshot(updateID: id(8, count: 32), generation: 0, revision: 0) }
    }
    func testStrictCodecRejectsAnUnretainedFieldEvenWithACorrectDomainSignature() throws {
        let claim = try control(), bytes = try claim.encode(limits: limits)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { return XCTFail() }
        fields[14] = .text("artifact-selection-is-forbidden")
        let altered = try DeterministicCBOR.encode(.map(fields), limits: limits)
        let input = try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling"), 1: .unsigned(1), 2: .unsigned(1), 3: .unsigned(1), 4: .bytes(altered),
        ]), limits: limits)
        let signature = try decisionKey.signature(for: input).rawRepresentation
        XCTAssertThrowsError(try UpdateSchedulingVerifier.verify(canonicalControl: altered, signature: signature,
            retained: retained(claim), current: snapshot(claim), binding: binding(), trust: trust(), now: moment(500),
            nowUnixMillis: 1500, payloadLimits: limits, signingLimits: limits))
    }

    func testJournalVerificationReadsCurrentTrustWithoutChangingDurableState() throws {
        let fixture = try Fixture()
        let db = try JournalDatabase(lease: fixture.lease(), macID: id(1), accountID: id(2), recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 4, busyMilliseconds: 100, initialize: true)
        defer { try? db.close() }
        let trusted = try trust(), enrollment = try XCTUnwrap(trusted.enrollments.first)
        let configured = try db.write {
            try $0.configureApprovalAuthority(capabilities: trusted.approval.authorityCapabilities,
                allowedContracts: trusted.approval.allowedContracts)
        }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(12)),
            4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        let enrolledRevision = try db.write {
            try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: configured, eventID: id(13),
                receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0)
        }
        let claim = try control(), bytes = try claim.encode(limits: limits), signature = try sign(bytes)
        let challenge = try retained(claim, revision: enrolledRevision), peer = try binding(revision: enrolledRevision)
        let before = try db.read { try $0.continuityDigests() }
        var escaped: JournalTransaction?
        for _ in 0..<2 {
            let evidence = try db.read { tx in
                escaped = tx
                return try tx.verifyUpdateScheduling(canonicalControl: bytes, signature: signature, retained: challenge,
                    current: snapshot(claim), binding: peer, now: moment(500), nowUnixMillis: 1500,
                    payloadLimits: limits, signingLimits: limits)
            }
            XCTAssertEqual(evidence.control, claim)
        }
        XCTAssertEqual(try db.read { try $0.continuityDigests() }, before)
        XCTAssertThrowsError(try XCTUnwrap(escaped).verifyUpdateScheduling(canonicalControl: bytes, signature: signature,
            retained: challenge, current: snapshot(claim), binding: peer, now: moment(500), nowUnixMillis: 1500,
            payloadLimits: limits, signingLimits: limits))
        _ = try db.write {
            try $0.revokeApprovalEnrollment(phoneID: claim.phoneID, epoch: claim.enrollmentEpoch,
                expectedTrustRevision: enrolledRevision, eventID: id(17), receiptTimeMs: 1501,
                writer: writer, expectedAuditHead: 1)
        }
        rejects(.staleTrust) {
            try db.read { tx in
                try tx.verifyUpdateScheduling(canonicalControl: bytes, signature: signature, retained: challenge,
                    current: snapshot(claim), binding: peer, now: moment(500), nowUnixMillis: 1500,
                    payloadLimits: limits, signingLimits: limits)
            }
        }
    }

    private final class Fixture {
        let root: URL
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else {
                throw UpdateSchedulingVerificationError.invalidTrustedState
            }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let path = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(path + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw UpdateSchedulingVerificationError.invalidTrustedState }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
    }
}
