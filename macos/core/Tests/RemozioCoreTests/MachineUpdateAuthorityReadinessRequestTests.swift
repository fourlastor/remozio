import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Software keys exercise the exchange codec and signatures.
final class MachineUpdateAuthorityReadinessRequestTests: XCTestCase {
    private struct Fixture {
        let root: MachineUpdateRestartHealthPlan.Requirement
        let gateway: MachineUpdateAuthorityReadinessGateway
        let signing: MachineUpdateRoleChallengeTests.Fixture
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 1)

        init() throws {
            let roles = MachineUpdateRoleChallengeTests.Fixture()
            let signing = MachineUpdateRoleChallengeTests.Fixture()
            self.signing = signing
            root = try roles.requirement()
            let requirement = try roles.requirement(role: .notificationGateway, uid: 20001,
                publicKey: signing.key.publicKey.x963Representation)
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 1, count: 16),
                macID: requirement.binding.macID, accountID: requirement.binding.accountID,
                gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: root.publicKey)
            gateway = try .init(requirement: requirement, registration: registration)
        }

        func rootRequest() throws -> Data {
            try MachineUpdateRoleChallengeSession(requirement: root, verifyCurrent: {}).request
        }

        func exchange(rootRequest: Data) throws -> MachineUpdateConsumerHealthExchange {
            let requirement = gateway.requirement
            let session = try MachineUpdateRoleChallengeSession(requirement: requirement,
                authorityReadinessRequest: rootRequest, verifyCurrent: {})
            let request = try session.request
            let reply = try signing.answer(request, expected: requirement)
            let fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .unsigned(1),
                2: .bytes(try gateway.registration.encode()), 3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)),
                4: .unsigned(0), 5: .unsigned(0), 6: .bytes(Data()), 7: .bytes(Data())]
            let payload = try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 70_000, maxDepth: 4, maxItems: 32))
            let signature = try signing.key.signature(for: Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload).rawRepresentation
            let packet = try MachineUpdateConsumerHealthPacket(roleReply: reply,
                gatewayHead: .init(canonicalPayload: payload, signature: signature)).encoded
            return .init(request: request, response: packet)
        }
    }

    func testCanonicalEnvelopeRoundTripsBothGatewaySignatures() throws {
        let fixture = try Fixture()
        let root = try fixture.rootRequest()
        let exchange = try fixture.exchange(rootRequest: root)
        let bytes = try MachineUpdateAuthorityReadinessRequest(challenge: root, gateway: exchange).encoded
        let decoded = try MachineUpdateAuthorityReadinessRequest.decode(bytes)

        XCTAssertEqual(try decoded.encoded, bytes)
        let proof = try XCTUnwrap(decoded.gatewayProof(expected: fixture.gateway, now: fixture.moment))
        XCTAssertEqual(proof.role.requirement, fixture.gateway.requirement)
        XCTAssertEqual(proof.gatewayHead?.evidence.registration, fixture.gateway.registration)
        XCTAssertEqual(proof.gatewayHead?.evidence.revision, 0)
    }

    func testGatewayExchangeCannotBeSplicedIntoAnotherRootChallenge() throws {
        let fixture = try Fixture()
        let first = try fixture.rootRequest()
        let second = try fixture.rootRequest()
        let exchange = try fixture.exchange(rootRequest: first)

        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest(challenge: second, gateway: exchange))
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest(challenge: exchange.request, gateway: nil))
    }

    func testGatewayEvidenceMustMatchTheProtectedSelection() throws {
        let fixture = try Fixture()
        let root = try fixture.rootRequest()
        let missing = try MachineUpdateAuthorityReadinessRequest(challenge: root, gateway: nil)
        let exchange = try fixture.exchange(rootRequest: root)
        let extra = try MachineUpdateAuthorityReadinessRequest(challenge: root, gateway: exchange)

        XCTAssertNil(try missing.gatewayProof(expected: nil, now: fixture.moment))
        XCTAssertThrowsError(try missing.gatewayProof(expected: fixture.gateway, now: fixture.moment))
        XCTAssertThrowsError(try extra.gatewayProof(expected: nil, now: fixture.moment))
        let registered = fixture.gateway.registration
        let foreign = try GatewayRegistrationIdentity(ownerID: registered.ownerID, macID: registered.macID,
            accountID: registered.accountID, gatewayID: registered.gatewayID, lifecycleEpoch: registered.lifecycleEpoch,
            rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let selected = try MachineUpdateAuthorityReadinessGateway(requirement: fixture.gateway.requirement, registration: foreign)
        XCTAssertThrowsError(try extra.gatewayProof(expected: selected, now: fixture.moment))
    }

    func testGatewayProofRejectsEitherDamagedSignature() throws {
        let fixture = try Fixture()
        let root = try fixture.rootRequest()
        let exchange = try fixture.exchange(rootRequest: root)
        let packet = try MachineUpdateConsumerHealthPacket.decode(exchange.response)
        let head = try XCTUnwrap(packet.gatewayHead)
        for damageHead in [true, false] {
            var roleReply = packet.roleReply, headSignature = head.signature
            if damageHead { headSignature[headSignature.count - 1] ^= 1 }
            else { roleReply[roleReply.count - 1] ^= 1 }
            let damaged = try MachineUpdateConsumerHealthPacket(roleReply: roleReply,
                gatewayHead: .init(canonicalPayload: head.canonicalPayload, signature: headSignature)).encoded
            let request = try MachineUpdateAuthorityReadinessRequest(challenge: root,
                gateway: .init(request: exchange.request, response: damaged))
            XCTAssertThrowsError(try request.gatewayProof(expected: fixture.gateway, now: fixture.moment)) {
                if damageHead { XCTAssertEqual($0 as? GatewayHeadReplyError, .invalidSignature) }
                else { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature) }
            }
        }
    }

    func testDecoderRejectsExtraFieldsTrailingBytesAndPartialGatewayPairs() throws {
        let fixture = try Fixture()
        let bytes = try MachineUpdateAuthorityReadinessRequest(challenge: fixture.rootRequest(), gateway: nil).encoded
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest.decode(bytes + Data([0])))
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest.decode(Data(count: 140_001)))

        let limits = try CBORLimits(maxBytes: 140_000, maxDepth: 1, maxItems: 13)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { return XCTFail() }
        fields[5] = .null
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        fields.removeValue(forKey: 5)
        fields[3] = .bytes(Data())
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessRequest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }

    func testInstalledReadinessPeerAuthenticatesBeforeItParsesAndRetiresOnRefusal() throws {
        let fixture = try Fixture()
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: fixture.root, authorityInstalledReadiness: true,
            authenticateInvocation: { throw AdmissionFailure.refused },
            verifyPeer: { XCTFail("Peer verification ran after authentication failed") }, verifyCurrent: {})

        XCTAssertThrowsError(try peer.accept(Data())) { XCTAssertEqual($0 as? AdmissionFailure, .refused) }
        XCTAssertThrowsError(try peer.accept(Data())) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable) }
    }

    func testInstalledReadinessPeerClaimsTheExactEnvelopeOnce() throws {
        let fixture = try Fixture()
        let root = try fixture.rootRequest()
        let exchange = try fixture.exchange(rootRequest: root)
        let envelope = try MachineUpdateAuthorityReadinessRequest(challenge: root, gateway: exchange).encoded
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: fixture.root, authorityInstalledReadiness: true,
            authenticateInvocation: {}, verifyPeer: {}, verifyCurrent: {})

        let request = try peer.accept(envelope)
        XCTAssertEqual(request.requirement, fixture.root)
        XCTAssertEqual(request.bytes, root)
        XCTAssertEqual(try request.authorityReadiness?.encoded, envelope)
        try request.claim()
        XCTAssertThrowsError(try request.claim())
        peer.close()
        XCTAssertThrowsError(try request.validate())
    }

    func testRawRoleAndInstalledReadinessPeersRejectEachOthersWireFormats() throws {
        let fixture = try Fixture()
        let root = try fixture.rootRequest()
        let envelope = try MachineUpdateAuthorityReadinessRequest(challenge: root, gateway: nil).encoded
        let installed = MachineUpdateConsumerHealthPeer.owned(expected: fixture.root, authorityInstalledReadiness: true,
            authenticateInvocation: {}, verifyPeer: {}, verifyCurrent: {})
        let raw = MachineUpdateConsumerHealthPeer.owned(expected: fixture.root,
            authenticateInvocation: {}, verifyPeer: {}, verifyCurrent: {})

        XCTAssertThrowsError(try installed.accept(root))
        XCTAssertThrowsError(try raw.accept(envelope))
    }

    private enum AdmissionFailure: Error { case refused }
}
