import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Checks individual rejection paths with owned keys. It creates no live readiness or startup proof.
final class RetainedSetupHealthGuardTests: XCTestCase {
    typealias Evidence = MachineUpdateRetainedSetupHealthEvidence
    typealias Fixture = RetainedSetupHealthTranscriptTests.Fixture
    private func challenge(_ f: Fixture, requirement: Evidence.Requirement, nonce: UInt8 = 8) throws -> Data {
        try f.encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
            2: .bytes(Data(repeating: nonce, count: 32)), 3: .bytes(requirement.encoded)])
    }
    private func joint(_ f: Fixture, request: Data, digest: Data, key: P256.Signing.PrivateKey) throws -> Data {
        let signed = Data("Remozio/RetainedSetupJointRootReply/v1\0".utf8) + digest + request
        let signature = try key.signature(for: signed)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: signed))
        return try f.encode([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
            2: .bytes(request), 3: .bytes(digest), 4: .bytes(signature.rawRepresentation)])
    }
    private func copy(_ scope: Evidence.Requirement, role: AuthorityCodeRole? = nil, uid: UInt32? = nil,
        code: AuthorityCodeEntry? = nil) -> Evidence.Requirement {
        .init(binding: scope.binding, activationPlanDigest: scope.activationPlanDigest, inventoryDigest: scope.inventoryDigest,
            role: role ?? scope.role, executionUID: uid ?? scope.executionUID, code: code ?? scope.code,
            publicKey: scope.publicKey, completionBoundaryDigest: scope.completionBoundaryDigest, promotionDigest: scope.promotionDigest)
    }
    private func code(_ value: AuthorityCodeEntry, role: AuthorityCodeRole? = nil, generation: UInt64? = nil,
        active: Bool = true) throws -> AuthorityCodeEntry {
        try .init(role: role ?? value.role, teamID: value.teamID, identifier: value.identifier,
            installedGeneration: generation ?? value.installedGeneration, minimumGeneration: value.minimumGeneration,
            codeDirectoryHash: value.codeDirectoryHash, active: active)
    }
    func testJointRootRequiresExpectedScopeExactRequestAuthorityRoleAndDigestLength() throws {
        let f = try Fixture(), pair = try f.exchange()
        let digest = try MachineUpdateRetainedSetupJointHealthPacket.transportDigest(request: pair.1.transportRequest, reply: pair.1.transportReply)
        XCTAssertNoThrow(try Evidence.verifyJointRootReply(request: pair.0, response: pair.1.rootReply, expected: pair.2, transportDigest: digest))
        let other = try copy(pair.2, code: code(pair.2.code, generation: 2))
        XCTAssertNoThrow(try other.validate()); XCTAssertEqual(other.publicKey, pair.2.publicKey)
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: pair.1.rootReply, expected: other, transportDigest: digest)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
        // The request echo and canonical reply reconstruction both reject this case.
        let anotherRequest = try challenge(f, requirement: pair.2, nonce: 7)
        let anotherReply = try joint(f, request: anotherRequest, digest: digest, key: f.rootKey)
        XCTAssertNoThrow(try Evidence.verifyJointRootReply(request: anotherRequest, response: anotherReply, expected: pair.2, transportDigest: digest))
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: anotherReply, expected: pair.2, transportDigest: digest)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
        let transportRequest = try challenge(f, requirement: pair.3)
        let transportReply = try joint(f, request: transportRequest, digest: digest, key: f.transportKey)
        XCTAssertNoThrow(try pair.3.validate()); XCTAssertEqual(pair.3.publicKey, f.transportKey.publicKey.x963Representation)
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: transportRequest, response: transportReply, expected: pair.3, transportDigest: digest)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
        let shortDigest = Data(repeating: 2, count: 31)
        let shortReply = try joint(f, request: pair.0, digest: shortDigest, key: f.rootKey)
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: shortReply, expected: pair.2, transportDigest: shortDigest)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
    }
    func testJointReplyRejectsAValidSignatureFromTheOtherDomain() throws {
        let f = try Fixture(), pair = try f.exchange()
        let digest = try MachineUpdateRetainedSetupJointHealthPacket.transportDigest(request: pair.1.transportRequest, reply: pair.1.transportReply)
        XCTAssertNoThrow(try Evidence.verifyJointRootReply(request: pair.0, response: pair.1.rootReply, expected: pair.2, transportDigest: digest))
        let wrongDomain = Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + digest + pair.0
        let signature = try f.rootKey.signature(for: wrongDomain)
        XCTAssertTrue(f.rootKey.publicKey.isValidSignature(signature, for: wrongDomain))
        let reply = try f.encode([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
            2: .bytes(pair.0), 3: .bytes(digest), 4: .bytes(signature.rawRepresentation)])
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: reply, expected: pair.2, transportDigest: digest)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature)
        }
    }
    func testRequirementDirectValidationRejectsUnsupportedRoleMismatchedCodeAndInactiveCode() throws {
        let f = try Fixture(), pair = try f.exchange()
        XCTAssertNoThrow(try pair.2.validate()); XCTAssertNoThrow(try pair.3.validate())
        let setupCode = try code(pair.2.code, role: .setupController)
        let unsupported = copy(pair.2, role: .setupController, uid: 20000, code: setupCode)
        let mismatched = copy(pair.3, code: pair.2.code)
        let inactive = try copy(pair.2, code: code(pair.2.code, active: false))
        for value in [unsupported, mismatched, inactive] {
            XCTAssertThrowsError(try value.validate()) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
        }
    }
    func testTransportScopeRejectsWrongParentAndChildRolesWithValidSignatures() throws {
        let f = try Fixture(), pair = try f.exchange()
        XCTAssertNoThrow(try Evidence.verifyTransportReply(request: pair.1.transportRequest, response: pair.1.transportReply, expected: pair.3, boundTo: pair.0))
        // After validation, the parent authority role and UID zero are equivalent. This case covers the pair.
        for (parent, child, key) in [(pair.3, pair.3, f.transportKey), (pair.2, pair.2, f.rootKey)] {
            XCTAssertNoThrow(try parent.validate()); XCTAssertNoThrow(try child.validate())
            let root = try challenge(f, requirement: parent)
            let nonce = MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupTransportNonce/v1\0".utf8) + root)
            let request = try f.encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"), 2: .bytes(nonce), 3: .bytes(child.encoded)])
            let signed = Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + request
            let signature = try key.signature(for: signed)
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: signed)); XCTAssertEqual(child.publicKey, key.publicKey.x963Representation)
            let reply = try f.encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"), 2: .bytes(request), 3: .bytes(signature.rawRepresentation)])
            XCTAssertThrowsError(try Evidence.verifyTransportReply(request: request, response: reply, expected: child, boundTo: root)) {
                XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
            }
        }
    }
}
