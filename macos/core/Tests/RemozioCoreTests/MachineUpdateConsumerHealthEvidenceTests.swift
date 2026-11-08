import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateConsumerHealthEvidenceTests: XCTestCase {
    private struct Fixture {
        let signing = MachineUpdateRoleChallengeTests.Fixture()
        let registration: GatewayRegistrationIdentity
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let epoch = UUID()

        init() throws {
            requirement = try signing.requirement(role: .notificationGateway, uid: 20001)
            registration = try .init(ownerID: Data(repeating: 11, count: 16), macID: requirement.binding.macID,
                accountID: requirement.binding.accountID, gatewayID: Data(repeating: 12, count: 16),
                lifecycleEpoch: Data(repeating: 13, count: 16),
                rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        }

        func session() throws -> MachineUpdateConsumerHealthChallengeSession {
            let moment = AuthorityMoment(epoch: epoch, milliseconds: 100)
            return try .init(requirement: requirement, registration: registration, clock: { moment }, verifyCurrent: {})
        }

        func packet(_ request: Data, headRequest: Data? = nil) throws -> Data {
            let role = try signing.answer(request, expected: requirement)
            let fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .unsigned(1),
                2: .bytes(try registration.encode()), 3: .bytes(MachineUpdateGatewayHealthQuery.nonce(headRequest ?? request)),
                4: .unsigned(0), 5: .unsigned(0), 6: .bytes(Data()), 7: .bytes(Data())]
            let payload = try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 70000, maxDepth: 4, maxItems: 32))
            let signature = try signing.key.signature(for: Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload).rawRepresentation
            return try MachineUpdateConsumerHealthPacket(roleReply: role,
                gatewayHead: .init(canonicalPayload: payload, signature: signature)).encoded
        }
    }

    func testTransportAuthenticatesOnePacketWithoutGatewayEvidence() throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let requirement = try fixture.requirement(role: .transport, uid: 20000)
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement, registration: nil,
            clock: { moment }, verifyCurrent: {})
        let request = try session.makeRequest(), role = try fixture.answer(request, expected: requirement)
        let packet = try MachineUpdateConsumerHealthPacket(roleReply: role, gatewayHead: nil).encoded
        let proof = try session.accept(packet, authenticatePeer: { XCTAssertEqual($0, requirement) })
        XCTAssertEqual(proof.role.requirement, requirement)
        XCTAssertNil(proof.gatewayHead)
        XCTAssertThrowsError(try session.accept(packet, authenticatePeer: { _ in }))
    }

    func testGatewayHeadCannotBeSplicedAcrossChallenges() throws {
        let fixture = try Fixture()
        let first = try fixture.session(), second = try fixture.session()
        let a = try first.makeRequest(), b = try second.makeRequest()
        XCTAssertNotEqual(a, b)
        let mixed = try fixture.packet(a, headRequest: b)
        XCTAssertThrowsError(try first.accept(mixed, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? GatewayHeadReplyError, .unknownQuery)
        }
        XCTAssertThrowsError(try first.accept(fixture.packet(a), authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
        let verified = try second.accept(fixture.packet(b), authenticatePeer: { _ in })
        XCTAssertEqual(verified.gatewayHead?.evidence.registration, fixture.registration)
        XCTAssertEqual(verified.gatewayHead?.evidence.revision, 0)
    }

    func testBoundHeadQueryCannotRenewItsNonceAfterExpiration() throws {
        let fixture = try Fixture(), session = try fixture.session()
        let request = try session.makeRequest()
        let key = fixture.requirement.publicKey
        let query = try GatewayHeadQueryOwner(registration: fixture.registration,
            gatewayPublicKey: key, clockEpoch: fixture.epoch, lifetimeMillis: 1000)
        let bytes = try query.makeUpdateHealthQuery(request: request, now: .init(epoch: fixture.epoch, milliseconds: 100))
        XCTAssertEqual(bytes, try MachineUpdateGatewayHealthQuery.make(request: request,
            registration: fixture.registration, gatewayPublicKey: key))
        XCTAssertThrowsError(try query.makeUpdateHealthQuery(request: request,
            now: .init(epoch: fixture.epoch, milliseconds: 1100)))
        query.invalidate()
    }

    func testPeerAuthenticationRejectsMalformedBytesBeforeDecode() throws {
        enum AuthenticationError: Error { case denied }
        let fixture = try Fixture(), session = try fixture.session()
        let request = try session.makeRequest()
        XCTAssertThrowsError(try session.accept(Data([0]), authenticatePeer: { [requirement = fixture.requirement] in
            XCTAssertEqual($0, requirement)
            throw AuthenticationError.denied
        })) {
            XCTAssertEqual($0 as? AuthenticationError, .denied)
        }
        XCTAssertThrowsError(try session.accept(fixture.packet(request), authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
    }

    func testPacketRejectsTrailingBytesAndOversizedOperands() throws {
        let fixture = try Fixture(), session = try fixture.session()
        let request = try session.makeRequest(), bytes = try fixture.packet(request)
        XCTAssertThrowsError(try MachineUpdateConsumerHealthPacket.decode(bytes + Data([0])))
        XCTAssertThrowsError(try MachineUpdateConsumerHealthPacket(roleReply: Data(count: 16641), gatewayHead: nil).encoded)
        XCTAssertThrowsError(try MachineUpdateConsumerHealthPacket(roleReply: Data([0]),
            gatewayHead: .init(canonicalPayload: Data(count: 70001), signature: Data(count: 64))).encoded)
        XCTAssertThrowsError(try session.accept(bytes + Data([0]), authenticatePeer: { _ in }))
        XCTAssertThrowsError(try session.accept(bytes, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
    }
}
