import CryptoKit
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateRoleChallengeTests: XCTestCase {
    private enum Failure: Error { case changed }
    private final class State<Value: Sendable>: Sendable {
        let value: Mutex<Value>
        init(_ value: Value) { self.value = Mutex(value) }
    }
    struct Fixture {
        let key = P256.Signing.PrivateKey()
        let configurationID = UUID(), configurationRevision = UUID(), backendID = UUID(), backendRevision = UUID()
        func requirement(role: AuthorityCodeRole = .authority, uid: UInt32 = 0, mac: UInt8 = 2, account: UInt8 = 3,
                         configurationID: UUID? = nil, configurationRevision: UUID? = nil,
                         backendID: UUID? = nil, backendRevision: UUID? = nil, hash: UInt8 = 7,
                         publicKey: Data? = nil) throws -> MachineUpdateRestartHealthPlan.Requirement {
            let digest = Data(repeating: 8, count: 32).base64EncodedString()
            let identity = Data(repeating: mac, count: 16).base64EncodedString()
            var fields: [String: Any] = ["formatVersion": 2, "activationAttempt": "11111111-1111-4111-8111-111111111111",
                "macID": identity, "installationID": identity, "accountID": Data(repeating: account, count: 16).base64EncodedString(),
                "sourcePolicyRevision": "22222222-2222-4222-8222-222222222222"]
            for name in ["candidateDigest", "sourceInventoryDigest", "admissionDigest", "sourceAccountDigest", "runtimeReferenceDigest",
                "sourcePolicyDigest", "previousInstalledReleaseDigest", "installedReleaseDigest", "updateID", "startupPolicyDigest", "completionPolicyDigest"] {
                fields[name] = digest
            }
            let bytes = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
            let binding = try RuntimeReleaseBinding.decode(bytes)
            let code = try AuthorityCodeEntry(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.health-\(role.rawValue)",
                installedGeneration: 3, minimumGeneration: 2, codeDirectoryHash: Data(repeating: hash, count: 20), active: true)
            return .init(binding: binding, configurationEpoch: configurationID ?? self.configurationID,
                configurationRevision: configurationRevision ?? self.configurationRevision,
                backendEpoch: backendID ?? self.backendID, backendRevision: backendRevision ?? self.backendRevision,
                role: role, executionUID: uid, code: code, publicKey: publicKey ?? key.publicKey.x963Representation)
        }
        func answer(_ request: Data, expected: MachineUpdateRestartHealthPlan.Requirement) throws -> Data {
            try MachineUpdateRoleChallengeSession.answer(request, expected: expected, verifyCurrent: {},
                sign: { try key.signature(for: $0).rawRepresentation })
        }
    }
    func testAuthenticatedReplyRequiresTheExactRoleKeyCodeAndEpochScope() throws {
        let fixture = Fixture()
        for (role, uid) in [(AuthorityCodeRole.authority, UInt32(0)), (.transport, 20000), (.notificationGateway, 20001)] {
            let requirement = try fixture.requirement(role: role, uid: uid)
            let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
            let request = try session.request, reply = try fixture.answer(request, expected: requirement)
            let result = try session.accept(reply, authenticatePeer: { XCTAssertEqual($0, requirement) })
            XCTAssertEqual(result.requirement, requirement)
            XCTAssertEqual(result.challengeDigest, MachineUpdateActivationRecord.digest(request))
            XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in })) {
                XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
            }
        }
    }
    func testFreshSessionRejectsAnEarlierSignedReply() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let first = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let second = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        XCTAssertNotEqual(try first.request, try second.request)
        let reply = try fixture.answer(first.request, expected: requirement)
        XCTAssertThrowsError(try second.accept(reply, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
        XCTAssertThrowsError(try second.accept(fixture.answer(second.request, expected: requirement), authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
        _ = try first.accept(reply, authenticatePeer: { _ in })
    }
    func testAnswerRejectsChangedAccountRoleUIDCodeKeyAndEitherEpochRevision() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let request = try session.request
        let variants = try [fixture.requirement(account: 4), fixture.requirement(role: .transport, uid: 20000),
            fixture.requirement(uid: 1), fixture.requirement(configurationID: UUID()), fixture.requirement(configurationRevision: UUID()),
            fixture.requirement(backendID: UUID()), fixture.requirement(backendRevision: UUID()), fixture.requirement(hash: 9),
            fixture.requirement(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)]
        for changed in variants {
            XCTAssertThrowsError(try fixture.answer(request, expected: changed))
        }
        _ = try session.accept(fixture.answer(request, expected: requirement), authenticatePeer: { _ in })
    }
    func testWrongSigningKeyConsumesTheChallengeWithoutAnAuthenticatedResult() throws {
        let fixture = Fixture(), requirement = try fixture.requirement(), other = P256.Signing.PrivateKey()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let reply = try MachineUpdateRoleChallengeSession.answer(session.request, expected: requirement,
            verifyCurrent: {}, sign: { try other.signature(for: $0).rawRepresentation })
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature)
        }
        XCTAssertThrowsError(try session.accept(fixture.answer(session.request, expected: requirement), authenticatePeer: { _ in }))
    }
    func testReplySignatureUsesADistinctDomain() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let request = try session.request
        let reply = try MachineUpdateRoleChallengeSession.answer(request, expected: requirement, verifyCurrent: {},
            sign: { _ in try fixture.key.signature(for: request).rawRepresentation })
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature)
        }
    }
    func testChangedOwnerAfterPeerAuthenticationCannotProduceAnAuthenticatedResult() throws {
        let fixture = Fixture(), requirement = try fixture.requirement(), valid = State(true)
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {
            guard valid.value.withLock({ $0 }) else { throw Failure.changed }
        })
        let reply = try fixture.answer(session.request, expected: requirement)
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in valid.value.withLock { $0 = false } })) {
            XCTAssertTrue($0 is Failure)
        }
        valid.value.withLock { $0 = true }
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in }))
    }
    func testClosingDuringPeerAuthenticationRejectsTheInFlightReply() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let reply = try fixture.answer(session.request, expected: requirement)
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in session.close() })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in }))
    }
    func testPeerAuthenticationFailureConsumesEvenACorrectlySignedReply() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let reply = try fixture.answer(session.request, expected: requirement)
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in throw Failure.changed })) {
            XCTAssertTrue($0 is Failure)
        }
        XCTAssertThrowsError(try session.accept(reply, authenticatePeer: { _ in })) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
    }
    func testConcurrentRepliesProduceExactlyOneAuthenticatedResult() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let reply = try fixture.answer(session.request, expected: requirement), counts = State((passed: 0, failed: 0))
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            do { _ = try session.accept(reply, authenticatePeer: { _ in }); counts.value.withLock { $0.passed += 1 } }
            catch { counts.value.withLock { $0.failed += 1 } }
        }
        XCTAssertEqual(counts.value.withLock { $0.passed }, 1); XCTAssertEqual(counts.value.withLock { $0.failed }, 7)
    }
    func testReentrantVerificationRejectsOnlyTheNestedAttempt() throws {
        let fixture = Fixture(), requirement = try fixture.requirement(), nested = State(0)
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let reply = try fixture.answer(session.request, expected: requirement)
        _ = try session.accept(reply, authenticatePeer: { _ in
            do { _ = try session.accept(reply, authenticatePeer: { _ in }) }
            catch MachineUpdateRoleChallengeError.unavailable { nested.value.withLock { $0 += 1 } }
        })
        XCTAssertEqual(nested.value.withLock { $0 }, 1)
    }
    func testOwnerChangeDuringSigningDoesNotReturnAReply() throws {
        let fixture = Fixture(), requirement = try fixture.requirement(), valid = State(true)
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.answer(session.request, expected: requirement,
            verifyCurrent: { guard valid.value.withLock({ $0 }) else { throw Failure.changed } }, sign: {
                let signature = try fixture.key.signature(for: $0).rawRepresentation
                valid.value.withLock { $0 = false }; return signature
            }))
    }
    func testChallengeAndReplyRejectTrailingBytesAndCapacityOverflow() throws {
        let fixture = Fixture(), requirement = try fixture.requirement()
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let request = try session.request
        XCTAssertThrowsError(try fixture.answer(request + Data([0]), expected: requirement))
        let reply = try fixture.answer(request, expected: requirement)
        XCTAssertThrowsError(try session.accept(reply + Data([0]), authenticatePeer: { _ in }))
        let other = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        XCTAssertThrowsError(try other.accept(Data(repeating: 0, count: 16641), authenticatePeer: { _ in }))
    }
    func testSessionRejectsAnUnregisteredRoleAndWrongExecutionUID() throws {
        let fixture = Fixture()
        for requirement in try [fixture.requirement(role: .app, uid: 501), fixture.requirement(role: .transport, uid: 0),
            fixture.requirement(role: .transport, uid: UInt32.max), fixture.requirement(uid: 501)] {
            XCTAssertThrowsError(try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {}))
        }
    }

    func testGatewayProofIsBoundToTheExactRootRequest() throws {
        let fixture = Fixture()
        let root = try fixture.requirement(), gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let first = try MachineUpdateRoleChallengeSession(requirement: root, verifyCurrent: {})
        let other = try MachineUpdateRoleChallengeSession(requirement: root, verifyCurrent: {})
        let firstRequest = try first.request
        let session = try MachineUpdateRoleChallengeSession(requirement: gateway, authorityReadinessRequest: firstRequest, verifyCurrent: {})
        let request = try session.request
        let reply = try fixture.answer(request, expected: gateway)
        let proof = try MachineUpdateRoleChallengeSession.verifyGatewayReply(request: request, response: reply,
            expected: gateway, boundTo: firstRequest)
        XCTAssertEqual(proof.requirement, gateway)
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.verifyGatewayReply(request: request,
            response: reply, expected: gateway, boundTo: other.request))
    }

    func testInventoryRejectsMissingDuplicateAndForeignAuthenticatedReplies() throws {
        let fixture = Fixture(), authority = try fixture.requirement()
        let transport = try fixture.requirement(role: .transport, uid: 20000)
        let foreign = try fixture.requirement(role: .transport, uid: 20000, account: 8)
        let inventory = try MachineUpdateHealthInventory(requirements: [authority, transport], preservedAccounts: [])
        func reply(_ requirement: MachineUpdateRestartHealthPlan.Requirement) throws -> MachineUpdateAuthenticatedRoleReply {
            let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
            return try session.accept(fixture.answer(session.request, expected: requirement), authenticatePeer: { _ in })
        }
        let a = try reply(authority), t = try reply(transport), other = try reply(foreign)
        try inventory.requireReplies([t, a], accountID: authority.binding.accountID)
        for replies in [[a], [a, a], [a, other]] {
            XCTAssertThrowsError(try inventory.requireReplies(replies, accountID: authority.binding.accountID)) {
                XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .incompleteHealth)
            }
        }
    }
}
