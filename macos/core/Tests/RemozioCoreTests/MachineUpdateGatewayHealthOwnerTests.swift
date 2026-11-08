import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateGatewayHealthOwnerTests: XCTestCase {
    private final class State<Value: Sendable>: Sendable {
        let value: Mutex<Value>
        init(_ value: Value) { self.value = Mutex(value) }
    }
    private enum Failure: Error { case changed }
    final class Fixture {
        let files: GatewayDatabaseTests.Fixture
        let root: P256.Signing.PrivateKey
        let key: P256.Signing.PrivateKey
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let configuration: GatewayServiceConfiguration
        let signer: GatewayReceiptSigner
        let database: GatewayDatabase
        init(ordinary: Bool = false, withHead: Bool = false) throws {
            let files = try GatewayDatabaseTests.Fixture(), root = P256.Signing.PrivateKey(), key = P256.Signing.PrivateKey()
            self.files = files; self.root = root; self.key = key
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16),
                accountID: Data(repeating: 3, count: 16), gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: root.publicKey.x963Representation)
            let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 1, minimumSendIntervalMillis: 1000),
                probe: .init(maximumAttempts: 1, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 60),
                wake: .init(maximumEntries: 8, maximumAttempts: 1, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 10000, maximumTTLSeconds: 60))
            configuration = try .init(registration: registration, receiptPublicKey: key.publicKey.x963Representation,
                directoryPath: files.directory, providerPath: files.root.appendingPathComponent("provider.json").path,
                receiptKeyPath: files.root.appendingPathComponent("receipt.cbor").path, serviceUID: 20000, ownerUID: 20001,
                serviceName: "dev.remozio.health.gateway", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.health.authority",
                authorityHashes: [Data(repeating: 7, count: 20)], project: "health-fixture", packageName: "dev.remozio.fixture", settings: settings)
            requirement = try MachineUpdateRoleChallengeTests.Fixture().requirement(role: .notificationGateway, uid: 20000,
                publicKey: key.publicKey.x963Representation)
            signer = try GatewayReceiptSigner(bytes: Self.keyBytes(key), expectedPublicKey: key.publicKey.x963Representation)
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128), epoch = UUID()
            func open(_ initialize: Bool, _ health: Bool) throws -> GatewayDatabase {
                try GatewayDatabase(lease: files.lease(), identity: registration, payloadLimits: limits, signingLimits: limits,
                    maximumOperations: 10, maximumPendingPerEnrollment: 2, maximumLifetimeMillis: 1000,
                    clockEpoch: epoch, busyMilliseconds: 100, initialize: initialize, readOnlyForUpdateHealth: health)
            }
            let initialized = try open(true, false)
            if withHead {
                let token = "synthetic-update-health-token", id: (UInt8) -> Data = { Data(repeating: $0, count: 16) }
                let candidate = try GatewayTokenCandidate(binding: .init(ownerID: id(1), macID: id(2), accountID: id(3),
                    gatewayID: id(4), lifecycleEpoch: id(5), phoneID: id(6), enrollmentEpoch: id(7), candidateID: id(8),
                    tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: Data(repeating: 9, count: 32),
                    enrollmentTag: Data(repeating: 6, count: 32)), revision: 1, operationID: id(10),
                    issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
                let payload = try candidate.encode(limits: limits)
                let signature = try root.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                    canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
                let trust = try GatewayCandidateTrust(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                    lifecycleEpoch: id(5), rootPublicKey: root.publicKey.x963Representation, active: true,
                    revision: UUID(), appliedControlRevision: 0,
                    enrollment: .init(phoneID: id(6), epoch: id(7), tag: Data(repeating: 6, count: 32), active: true))
                _ = try initialized.admitCandidate(canonicalPayload: payload, signature: signature, wireVersion: 1,
                    registrationToken: token, trust: trust, nowUnixMillis: 1000, now: .init(epoch: epoch, milliseconds: 100))
            }
            if ordinary { database = initialized }
            else { try initialized.close(); database = try open(false, true) }
        }
        static func keyBytes(_ key: P256.Signing.PrivateKey) throws -> Data {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-receipt-key"), 2: .bytes(key.x963Representation)]),
                limits: .init(maxBytes: 4096, maxDepth: 1, maxItems: 7))
        }
        func owner(requirement: MachineUpdateRestartHealthPlan.Requirement? = nil, signer: GatewayReceiptSigner? = nil, expectedRequest: Data? = nil,
            verifyCurrent: @escaping @Sendable () throws -> Void = {}, release: @escaping @Sendable () -> Void = {}) throws -> MachineUpdateGatewayHealthOwner {
            try .openOwned(database: database, configuration: configuration, requirement: requirement ?? self.requirement,
                signer: signer ?? self.signer, expectedRequest: expectedRequest, verifyCurrent: verifyCurrent, release: release)
        }
    }
    func testRetainedReceiptKeyAnswersWithoutChangingTheStore() throws {
        let fixture = try Fixture(), before = try Data(contentsOf: URL(fileURLWithPath: fixture.files.path))
        let session = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {})
        let owner = try fixture.owner(expectedRequest: session.request); defer { try? owner.close() }
        let reply = try owner.answer(session.request)
        XCTAssertEqual(try session.accept(reply, authenticatePeer: { _ in }).requirement, fixture.requirement)
        XCTAssertEqual(try owner.headEvidence().revision, 0)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.files.path)), before)
    }
    func testGatewayHealthPacketBindsTheSignedHeadWithoutChangingTheStore() throws {
        let fixture = try Fixture(withHead: true)
        let before = try Data(contentsOf: URL(fileURLWithPath: fixture.files.path))
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let session = try MachineUpdateConsumerHealthChallengeSession(requirement: fixture.requirement,
            registration: fixture.configuration.registration, clock: { moment }, verifyCurrent: {})
        let request = try session.makeRequest()
        let owner = try fixture.owner(expectedRequest: request)
        defer { try? owner.close() }

        let proof = try session.accept(owner.answerWithHead(request), authenticatePeer: { _ in })
        let head = try XCTUnwrap(proof.gatewayHead?.evidence)
        XCTAssertEqual(head.registration, fixture.configuration.registration)
        XCTAssertEqual(head.revision, 1)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.files.path)), before)
    }

    func testBoundRequestRejectsAnotherNonceAndRetiresTheSigner() throws {
        let fixture = try Fixture()
        let first = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {})
        let other = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {})
        let owner = try fixture.owner(expectedRequest: first.request); defer { try? owner.close() }
        XCTAssertThrowsError(try owner.answer(other.request))
        XCTAssertThrowsError(try owner.answer(first.request))
    }
    func testWrongRoleUIDAccountOrReceiptPinClosesTheStore() throws {
        for variant in 0..<4 {
            let fixture = try Fixture(), factory = MachineUpdateRoleChallengeTests.Fixture(), releases = State(0)
            let requirement = try factory.requirement(role: variant == 0 ? .transport : .notificationGateway,
                uid: variant == 1 ? 20002 : 20000, account: variant == 2 ? 9 : 3,
                publicKey: variant == 3 ? factory.key.publicKey.x963Representation : fixture.key.publicKey.x963Representation)
            XCTAssertThrowsError(try fixture.owner(requirement: requirement, release: { releases.value.withLock { $0 += 1 } }))
            XCTAssertEqual(releases.value.withLock { $0 }, 1)
            XCTAssertThrowsError(try fixture.database.head())
            let lease = try fixture.files.lease(); lease.close()
        }
    }
    func testOrdinaryDatabaseCannotBecomeAnUpdateHealthOwner() throws {
        let fixture = try Fixture(ordinary: true)
        XCTAssertThrowsError(try fixture.owner()) { XCTAssertEqual($0 as? GatewayDatabaseError, .invalidConfiguration) }
    }
    func testCorruptHeadRetiresTheOwnerWithoutRepairOrRevival() throws {
        let fixture = try Fixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let request = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {}).request
        try fixture.files.sql("UPDATE gateway_identity_v1 SET head=x'0000000000000001'")
        let corrupt = try Data(contentsOf: URL(fileURLWithPath: fixture.files.path))
        XCTAssertThrowsError(try owner.answer(request))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.files.path)), corrupt)
        try fixture.files.sql("UPDATE gateway_identity_v1 SET head=x'0000000000000000'")
        XCTAssertThrowsError(try owner.answer(request))
        XCTAssertThrowsError(try owner.headEvidence())
    }
    func testChangedPublicationCannotBeRevivedByRestoringTheFlag() throws {
        let fixture = try Fixture(), valid = State(true)
        let owner = try fixture.owner(verifyCurrent: { guard valid.value.withLock({ $0 }) else { throw Failure.changed } })
        defer { try? owner.close() }
        let request = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {}).request
        valid.value.withLock { $0 = false }; XCTAssertThrowsError(try owner.answer(request))
        valid.value.withLock { $0 = true }; XCTAssertThrowsError(try owner.answer(request))
    }
    func testCloseReleasesTheLeaseOnlyOnceAndStopsSigning() throws {
        let fixture = try Fixture(), releases = State(0), owner = try fixture.owner(release: { releases.value.withLock { $0 += 1 } })
        let request = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {}).request
        try owner.close(); try owner.close(); XCTAssertThrowsError(try owner.answer(request))
        XCTAssertEqual(releases.value.withLock { $0 }, 1)
        let lease = try fixture.files.lease(); lease.close()
    }
    func testCloseDuringValidationCannotReturnASignedReply() throws {
        let fixture = try Fixture(), reference = State<MachineUpdateGatewayHealthOwner?>(nil)
        let owner = try fixture.owner(verifyCurrent: { try reference.value.withLock { $0 }?.close() })
        reference.value.withLock { $0 = owner }
        defer { reference.value.withLock { $0 = nil }; try? owner.close() }
        let request = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {}).request
        XCTAssertThrowsError(try owner.answer(request))
    }
    func testOwnerRejectsASignerThatDoesNotMatchTheReceiptPin() throws {
        let fixture = try Fixture(), other = P256.Signing.PrivateKey(), releases = State(0)
        let signer = try GatewayReceiptSigner(bytes: Fixture.keyBytes(other), expectedPublicKey: other.publicKey.x963Representation)
        XCTAssertThrowsError(try fixture.owner(signer: signer,
            verifyCurrent: { XCTFail("A mismatched signer cannot use the health owner") },
            release: { releases.value.withLock { $0 += 1 } })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
        }
        XCTAssertEqual(releases.value.withLock { $0 }, 1)
        let lease = try fixture.files.lease(); lease.close()
    }
}
