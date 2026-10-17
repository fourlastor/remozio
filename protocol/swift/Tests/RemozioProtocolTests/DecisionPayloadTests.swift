#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class DecisionPayloadTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 64) } }
    private let choices: [ActionChoice] = [.decline, .cancelTarget, .execute, .approveAccess, .unlockVault,
                                          .allowOnce, .denyOnce, .allowRule, .denyRule, .removeRule]
    private struct Row: Decodable { let name: String; let hex: String; let choice: Int?; let scope: Int?; let seconds: String? }
    private struct Vectors: Decodable { let bindings: [String: String]; let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/decision-payload-v1.json")))
    }

    func testSharedCanonicalDecisionsAndExactBindings() throws {
        let vectors = try vectors()
        XCTAssertEqual(vectors.valid.count, 13)
        XCTAssertEqual(Set(choices), Set(ActionChoice.allCases))
        for row in vectors.valid {
            let encoded = hex(row.hex)
            let payload = try DecisionPayload.decode(encoded, limits: limits)
            let actual = [payload.macID, payload.accountID, payload.requestID, payload.requestDigest,
                          payload.challenge, payload.phoneID, payload.keyID]
            for (index, value) in actual.enumerated() { XCTAssertEqual(value, hex(vectors.bindings[String(index + 1)]!)) }
            XCTAssertEqual(payload.action.choice, choices[row.choice!], row.name)
            let scope: ActionScope
            switch row.scope! {
            case 0: scope = .currentRequest
            case 1: scope = .session
            case 2: scope = .timed(seconds: UInt64(row.seconds!)!)
            default: scope = .forever
            }
            XCTAssertEqual(payload.action.scope, scope, row.name)
            XCTAssertEqual(try payload.encode(limits: limits), encoded, row.name)
        }
    }

    func testRejectsMalformedAndUnknownFields() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 48)
        for row in rows {
            XCTAssertThrowsError(try DecisionPayload.decode(hex(row.hex), limits: limits), row.name)
        }
    }

    func testLimitsApplyToPayloadInBothDirections() throws {
        let bytes = hex(try vectors().valid[0].hex)
        let payload = try DecisionPayload.decode(bytes, limits: limits)
        let exact = try CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 64)
        XCTAssertEqual(try payload.encode(limits: exact), bytes)
        let small = try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try payload.encode(limits: small))
        XCTAssertThrowsError(try DecisionPayload.decode(bytes, limits: small))
    }

    func testConstructionRetainsValueBytesAndRejectsInvalidLengths() throws {
        var identifier = Data(repeating: 1, count: 16)
        let digest = Data(repeating: 2, count: 32)
        let action = CapturedAction(choice: .execute, scope: .currentRequest)
        let payload = try DecisionPayload(macID: identifier, accountID: identifier, requestID: identifier,
            requestDigest: digest, challenge: digest, phoneID: identifier, keyID: identifier, action: action)
        identifier[0] = 9
        XCTAssertEqual(payload.macID[0], 1)
        XCTAssertThrowsError(try DecisionPayload(macID: Data(), accountID: identifier, requestID: identifier,
            requestDigest: digest, challenge: digest, phoneID: identifier, keyID: identifier, action: action))
        XCTAssertThrowsError(try DecisionPayload(macID: identifier, accountID: identifier, requestID: identifier,
            requestDigest: digest, challenge: digest, phoneID: identifier, keyID: identifier,
            action: CapturedAction(choice: .allowRule, scope: .timed(seconds: 0))))
    }

    func testParsingDoesNotReplaceRetainedActionPolicy() throws {
        let id = Data(repeating: 1, count: 16), digest = Data(repeating: 2, count: 32)
        let action = CapturedAction(choice: .allowRule, scope: .currentRequest)
        let payload = try DecisionPayload(macID: id, accountID: id, requestID: id, requestDigest: digest,
            challenge: digest, phoneID: id, keyID: id, action: action)
        let decoded = try DecisionPayload.decode(payload.encode(limits: limits), limits: limits)
        XCTAssertThrowsError(try ActionPolicy.requirement(for: decoded.action, requestKind: .littleSnitch,
            retainedPermittedActions: [action]))
    }

    func testSignatureBindsEveryIdentityAndSelectedAction() throws {
        let payload = hex(try vectors().valid[5].hex)
        let key = P256.Signing.PrivateKey()
        let input = try SigningInput.make(wireVersion: 1, messageType: .decision, purpose: .oneTimeUI,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        let signature = try key.signature(for: input).rawRepresentation
        func verify(_ bytes: Data, purpose: SigningPurpose = .oneTimeUI) throws -> Bool {
            try ApprovalSignature.verify(signature: signature, publicKey: key.publicKey.x963Representation,
                wireVersion: 1, messageType: .decision, purpose: purpose, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits)
        }
        XCTAssertTrue(try verify(payload))
        XCTAssertFalse(try verify(payload, purpose: .biometricAuthorization))
        guard case let .map(original) = try DeterministicCBOR.decode(payload, limits: limits) else { return XCTFail() }
        for field in UInt64(1)...7 {
            var changed = original
            guard case var .bytes(value) = changed[field] else { return XCTFail() }
            value[value.startIndex] ^= 1
            changed[field] = .bytes(value)
            XCTAssertFalse(try verify(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var changed = original
        changed[8] = .map([0: .unsigned(7), 1: .unsigned(3)])
        XCTAssertFalse(try verify(DeterministicCBOR.encode(.map(changed), limits: limits)))
    }

    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
}
