import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned keys and historical metadata. These tests prove no current peer, freshness, writer, or startup authority.
final class RetainedSetupHealthTranscriptTests: XCTestCase {
    typealias Evidence = MachineUpdateRetainedSetupHealthEvidence
    typealias Packet = MachineUpdateRetainedSetupJointHealthPacket
    struct Fixture {
        let rootKey = P256.Signing.PrivateKey(), transportKey = P256.Signing.PrivateKey()
        let binding: Data
        let limits = try! CBORLimits(maxBytes: 131072, maxDepth: 4, maxItems: 4096)
        init() throws {
            let source = try RetainedSetupConsumerHostArchiveTests.Fixture()
            binding = try source.json(source.startup)
        }
        func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
        func scope(_ role: AuthorityCodeRole, version: UInt64 = 3) throws -> [UInt64: CBORValue] {
            let code = try AuthorityCodeEntry(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.fixture.\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 7, count: 20), active: true)
            var fields: [UInt64: CBORValue] = [0: .unsigned(version), 1: .text("retained-setup-health-scope"), 2: .bytes(binding),
                3: .bytes(Data(repeating: 3, count: 32)), 4: .bytes(Data(repeating: 4, count: 32)),
                5: .unsigned(role.rawValue), 6: .unsigned(role == .authority ? 0 : 20000),
                7: .bytes(try AuthorityCodePolicy(entries: [code]).bytes),
                8: .bytes((role == .authority ? rootKey : transportKey).publicKey.x963Representation)]
            if version >= 2 { fields[9] = .bytes(Data(repeating: 9, count: 32)) }
            if version >= 3 { fields[10] = .bytes(Data(repeating: 10, count: 32)) }
            return fields
        }
        func exchange(version: UInt64 = 3, child: [UInt64: CBORValue]? = nil, nonce: Data? = nil,
            wrongRoot: Bool = false, wrongTransport: Bool = false) throws -> (Data, Packet, Evidence.Requirement, Evidence.Requirement) {
            let rootScope = try scope(.authority, version: version), childScope = try child ?? scope(.transport, version: version)
            let root = try Evidence.Requirement.decode(encode(rootScope)), transport = try Evidence.Requirement.decode(encode(childScope))
            let request = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
                2: .bytes(Data(repeating: 8, count: 32)), 3: .bytes(try encode(rootScope))])
            let childNonce = nonce ?? MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupTransportNonce/v1\0".utf8) + request)
            let childRequest = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
                2: .bytes(childNonce), 3: .bytes(try encode(childScope))])
            let childSignature = try (wrongTransport ? P256.Signing.PrivateKey() : transportKey)
                .signature(for: Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + childRequest).rawRepresentation
            let childReply = try encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"),
                2: .bytes(childRequest), 3: .bytes(childSignature)])
            let digest = MachineUpdateActivationRecord.digest(try encode([0: .unsigned(1),
                1: .text("retained-setup-joint-transport-proof"), 2: .bytes(childRequest), 3: .bytes(childReply)]))
            let signature = try (wrongRoot ? P256.Signing.PrivateKey() : rootKey)
                .signature(for: Data("Remozio/RetainedSetupJointRootReply/v1\0".utf8) + digest + request).rawRepresentation
            let rootReply = try encode([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
                2: .bytes(request), 3: .bytes(digest), 4: .bytes(signature)])
            return (request, Packet(rootReply: rootReply, transportRequest: childRequest, transportReply: childReply), root, transport)
        }
    }
    private func verifyRoot(_ pair: (Data, Packet, Evidence.Requirement, Evidence.Requirement)) throws {
        try Evidence.verifyJointRootReply(request: pair.0, response: pair.1.rootReply, expected: pair.2,
            transportDigest: Packet.transportDigest(request: pair.1.transportRequest, reply: pair.1.transportReply))
    }
    private func verifyTransport(_ pair: (Data, Packet, Evidence.Requirement, Evidence.Requirement)) throws {
        try Evidence.verifyTransportReply(request: pair.1.transportRequest, response: pair.1.transportReply, expected: pair.3, boundTo: pair.0)
    }
    func testSourceDerivedVersionsAndJointSignaturesRoundTrip() throws {
        let f = try Fixture()
        for version in UInt64(1)...3 {
            let pair = try f.exchange(version: version)
            XCTAssertNoThrow(try verifyRoot(pair)); XCTAssertNoThrow(try verifyTransport(pair))
            XCTAssertEqual(try Packet.decode(pair.1.encoded).encoded, try pair.1.encoded)
            XCTAssertEqual(try Evidence.decodeRequestedRequirement(pair.0), pair.2)
        }
        XCTAssertFalse(PreparationIntentStore.supportedSchemaVersions.contains(28))
    }
    func testEachSignatureFailureKeepsTheOtherSignatureValid() throws {
        let f = try Fixture(), valid = try f.exchange()
        XCTAssertNoThrow(try verifyRoot(valid)); XCTAssertNoThrow(try verifyTransport(valid))
        let wrongRoot = try f.exchange(wrongRoot: true)
        XCTAssertNoThrow(try verifyTransport(wrongRoot))
        XCTAssertThrowsError(try verifyRoot(wrongRoot)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature) }
        let wrongTransport = try f.exchange(wrongTransport: true)
        XCTAssertNoThrow(try verifyRoot(wrongTransport))
        XCTAssertThrowsError(try verifyTransport(wrongTransport)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidSignature) }
    }
    func testChildNonceAndEachSharedScopeFieldRejectWithValidSignatures() throws {
        let f = try Fixture(), valid = try f.exchange(); XCTAssertNoThrow(try verifyTransport(valid))
        let nonce = try f.exchange(nonce: Data(repeating: 5, count: 32))
        XCTAssertNoThrow(try verifyRoot(nonce))
        XCTAssertThrowsError(try verifyTransport(nonce)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
        for key in [UInt64(3), 4, 9, 10] {
            var child = try f.scope(.transport); child[key] = .bytes(Data(repeating: 42, count: 32))
            let pair = try f.exchange(child: child)
            XCTAssertNoThrow(try verifyRoot(pair))
            XCTAssertThrowsError(try verifyTransport(pair)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
        }
    }
    func testRequirementValidationRejectsEachInvalidOperand() throws {
        let f = try Fixture(), valid = try f.scope(.authority)
        XCTAssertNoThrow(try Evidence.Requirement.decode(f.encode(valid)))
        for (key, value): (UInt64, CBORValue) in [(3, .bytes(Data(repeating: 1, count: 31))),
            (4, .bytes(Data(repeating: 1, count: 31))), (6, .unsigned(1)),
            (8, .bytes(Data(repeating: 0, count: 64))), (8, .bytes(Data(repeating: 0, count: 65))),
            (9, .bytes(Data(repeating: 1, count: 31))), (10, .bytes(Data(repeating: 1, count: 31)))] {
            var fields = valid; fields[key] = value
            XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(fields)))
        }
        for uid in [UInt64(0), UInt64(UInt32.max)] {
            var child = try f.scope(.transport); child[6] = .unsigned(uid)
            XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(child)))
        }
        let root = try Evidence.Requirement.decode(f.encode(valid))
        let incomplete = Evidence.Requirement(binding: root.binding, activationPlanDigest: root.activationPlanDigest,
            inventoryDigest: root.inventoryDigest, role: root.role, executionUID: root.executionUID, code: root.code,
            publicKey: root.publicKey, completionBoundaryDigest: nil, promotionDigest: root.promotionDigest)
        XCTAssertThrowsError(try incomplete.validate()) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
    }
    func testScopeDecodersRejectEachMissingUnknownAndNoncanonicalField() throws {
        let f = try Fixture(), valid = try f.scope(.authority)
        for version in UInt64(1)...3 {
            let selected = try f.scope(.authority, version: version)
            for key in selected.keys {
                var fields = selected; fields[key] = nil
                XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(fields)))
            }
            var unknown = selected; unknown[11] = .null
            XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(unknown)))
        }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(4)), (1, .text("other")), (11, .null), (5, .unsigned(UInt64.max))] {
            var fields = valid; fields[key] = value
            XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(fields)))
        }
        XCTAssertThrowsError(try Evidence.Requirement.decode(f.encode(valid) + Data([0])))
    }
    func testStandaloneRootPurposeCannotReplaceTheJointReply() throws {
        let f = try Fixture(), pair = try f.exchange(); XCTAssertNoThrow(try verifyRoot(pair))
        let signature = try f.rootKey.signature(for: Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + pair.0).rawRepresentation
        let reply = try f.encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"), 2: .bytes(pair.0), 3: .bytes(signature)])
        XCTAssertNoThrow(try verifyTransport(pair))
        XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: reply, expected: pair.2,
            transportDigest: Packet.transportDigest(request: pair.1.transportRequest, reply: pair.1.transportReply))) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
    }
    func testChallengeAndReplyFramingRejectWithValidControls() throws {
        let f = try Fixture(), pair = try f.exchange(); XCTAssertNoThrow(try verifyRoot(pair)); XCTAssertNoThrow(try verifyTransport(pair))
        func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: f.limits) else { throw RuntimeActivationError.invalidPlan }; return fields
        }
        let challenge = try map(pair.0)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other")), (2, .bytes(Data(repeating: 1, count: 31))), (4, .null)] {
            var fields = challenge; fields[key] = value
            XCTAssertThrowsError(try Evidence.decodeRequestedRequirement(f.encode(fields)))
        }
        let rootReply = try map(pair.1.rootReply)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other")), (3, .bytes(Data(repeating: 1, count: 32))), (4, .bytes(Data(repeating: 1, count: 63)))] {
            var fields = rootReply; fields[key] = value
            XCTAssertThrowsError(try Evidence.verifyJointRootReply(request: pair.0, response: f.encode(fields), expected: pair.2,
                transportDigest: Packet.transportDigest(request: pair.1.transportRequest, reply: pair.1.transportReply)))
        }
        let reply = try map(pair.1.transportReply)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other")), (2, .bytes(pair.0)), (3, .bytes(Data(repeating: 1, count: 63)))] {
            var fields = reply; fields[key] = value
            XCTAssertThrowsError(try Evidence.verifyTransportReply(request: pair.1.transportRequest, response: f.encode(fields), expected: pair.3, boundTo: pair.0))
        }
        var packet = try map(pair.1.encoded); packet[5] = .null
        XCTAssertThrowsError(try Packet.decode(f.encode(packet)))
    }
    func testExpectedScopeMismatchDoesNotDependOnSignatureFailure() throws {
        let f = try Fixture(), pair = try f.exchange(); XCTAssertNoThrow(try verifyRoot(pair)); XCTAssertNoThrow(try verifyTransport(pair))
        let other = Evidence.Requirement(binding: pair.3.binding, activationPlanDigest: pair.3.activationPlanDigest,
            inventoryDigest: pair.3.inventoryDigest, role: pair.3.role, executionUID: pair.3.executionUID + 1, code: pair.3.code,
            publicKey: pair.3.publicKey, completionBoundaryDigest: pair.3.completionBoundaryDigest, promotionDigest: pair.3.promotionDigest)
        XCTAssertNoThrow(try other.validate())
        XCTAssertThrowsError(try Evidence.verifyTransportReply(request: pair.1.transportRequest, response: pair.1.transportReply,
            expected: other, boundTo: pair.0)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
        var child = try f.scope(.transport); child[2] = .bytes(try Fixture().binding)
        let foreign = try f.exchange(child: child); XCTAssertNoThrow(try verifyRoot(foreign))
        XCTAssertThrowsError(try verifyTransport(foreign)) { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
    }
    func testPacketBoundsRejectOnlyTheChangedOuterOperand() throws {
        let f = try Fixture(), pair = try f.exchange(); XCTAssertNoThrow(try pair.1.encoded)
        for root in [Data(), Data(repeating: 0, count: 16769)] {
            XCTAssertThrowsError(try Packet(rootReply: root, transportRequest: pair.1.transportRequest, transportReply: pair.1.transportReply).encoded)
        }
        for child in [Data(), Data(repeating: 0, count: 16513)] {
            XCTAssertThrowsError(try Packet(rootReply: pair.1.rootReply, transportRequest: child, transportReply: pair.1.transportReply).encoded)
        }
        for reply in [Data(), Data(repeating: 0, count: 16705)] {
            XCTAssertThrowsError(try Packet(rootReply: pair.1.rootReply, transportRequest: pair.1.transportRequest, transportReply: reply).encoded)
        }
    }
}
