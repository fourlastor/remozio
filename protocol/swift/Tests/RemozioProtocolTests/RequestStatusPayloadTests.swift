#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class RequestStatusPayloadTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 64) } }
    private let phases: [RequestPhase] = [.queued, .presented, .authorized, .executing, .succeeded, .failed,
                                          .unknown, .declined, .cancelled, .expired]
    private struct Row: Decodable {
        let name: String; let hex: String; let phase: Int?; let reason: UInt64?; let revision: String?
        let age: String?; let remaining: String?; let estimate: String?; let late: Bool?; let terminal: String?; let phone: Bool?
    }
    private struct Vectors: Decodable { let bindings: [String: String]; let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/request-status-v1.json")))
    }

    func testSharedStatusFieldsAndExactRoundTrips() throws {
        let vectors = try vectors()
        XCTAssertEqual(vectors.valid.count, 19)
        XCTAssertEqual(Set(phases), Set(RequestPhase.allCases))
        for row in vectors.valid {
            let bytes = hex(row.hex)
            let status = try RequestStatusPayload.decode(bytes, limits: limits)
            let bindings = [1: status.macID, 2: status.accountID, 3: status.requestID,
                4: status.requestDigest, 5: status.challenge, 9: status.observationID]
            for (key, value) in bindings { XCTAssertEqual(value, hex(vectors.bindings[String(key)]!)) }
            XCTAssertEqual(status.phase, phases[row.phase!])
            XCTAssertEqual(status.reason.rawValue, row.reason)
            XCTAssertEqual(status.revision, row.revision.flatMap(UInt64.init))
            XCTAssertEqual(status.observedAgeMs, row.age.flatMap(UInt64.init))
            XCTAssertEqual(status.authorizationRemainingMs, row.remaining.flatMap(UInt64.init))
            XCTAssertEqual(status.estimatedLifetimeMs, row.estimate.flatMap(UInt64.init))
            XCTAssertEqual(status.terminalAgeMs, row.terminal.flatMap(UInt64.init))
            XCTAssertEqual(status.lateObservation, row.late)
            XCTAssertEqual(status.decisionPhoneID, row.phone! ? hex(vectors.bindings["15"]!) : nil)
            XCTAssertEqual(try status.encode(limits: limits), bytes, row.name)
        }
    }

    func testRejectsUnknownFieldsAndInconsistentStateOrTiming() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 174)
        for row in rows { XCTAssertThrowsError(try RequestStatusPayload.decode(hex(row.hex), limits: limits), row.name) }
    }

    func testElapsedEstimateAndZeroRemainingDoNotProveExpiry() throws {
        let row = try XCTUnwrap(vectors().valid.first { $0.name == "elapsed-estimate-is-still-pending" })
        let status = try RequestStatusPayload.decode(hex(row.hex), limits: limits)
        XCTAssertEqual(status.observedAgeMs, 70_000)
        XCTAssertEqual(status.estimatedLifetimeMs, 60_000)
        XCTAssertEqual(status.authorizationRemainingMs, 0)
        XCTAssertFalse(status.phase.isTerminal)
    }

    func testLimitsApplyInBothDirections() throws {
        let bytes = hex(try vectors().valid[0].hex)
        let status = try RequestStatusPayload.decode(bytes, limits: limits)
        XCTAssertEqual(try status.encode(limits: CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 64)), bytes)
        let small = try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try status.encode(limits: small))
        XCTAssertThrowsError(try RequestStatusPayload.decode(bytes, limits: small))
        XCTAssertThrowsError(try RequestStatusPayload.decode(bytes, limits: CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 1)))
    }

    func testConstructorRetainsBindingsAndEnforcesInvariants() throws {
        var id = Data(repeating: 1, count: 16), digest = Data(repeating: 2, count: 32)
        func construct(revision: UInt64 = 1, phase: RequestPhase = .authorized, reason: RequestStatusReason = .none,
                       remaining: UInt64? = nil, estimate: UInt64? = 60_000, terminal: UInt64? = nil,
                       phone: Data? = Data(repeating: 3, count: 16)) throws -> RequestStatusPayload {
            try RequestStatusPayload(macID: id, accountID: id, requestID: id, requestDigest: digest, challenge: digest,
                revision: revision, phase: phase, reason: reason, observationID: id, observedAgeMs: 1000,
                authorizationRemainingMs: remaining, estimatedLifetimeMs: estimate, lateObservation: false,
                terminalAgeMs: terminal, decisionPhoneID: phone)
        }
        let status = try construct()
        let encoded = try status.encode(limits: limits)
        id[0] = 9; digest[0] = 9
        XCTAssertEqual(try status.encode(limits: limits), encoded)
        XCTAssertThrowsError(try construct(revision: 0))
        XCTAssertThrowsError(try construct(phase: .queued, remaining: 1))
        XCTAssertThrowsError(try construct(estimate: 0))
        XCTAssertThrowsError(try construct(phase: .expired, reason: .targetTimedOut, terminal: 1001))
        XCTAssertThrowsError(try construct(phone: Data()))
    }

    func testStatusSignatureBindsAllFieldsAndDomain() throws {
        let payload = hex(try vectors().valid[0].hex)
        let key = P256.Signing.PrivateKey()
        let input = try SigningInput.make(wireVersion: 1, messageType: .status, purpose: .status,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        let signature = try key.signature(for: input).rawRepresentation
        func verify(_ bytes: Data, type: ApprovalMessageType = .status, purpose: SigningPurpose = .status) throws -> Bool {
            try ApprovalSignature.verify(signature: signature, publicKey: key.publicKey.x963Representation,
                wireVersion: 1, messageType: type, purpose: purpose, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits)
        }
        XCTAssertTrue(try verify(payload))
        XCTAssertFalse(try verify(payload, type: .request, purpose: .issuedRequest))
        guard case let .map(original) = try DeterministicCBOR.decode(payload, limits: limits) else { return XCTFail() }
        for field in UInt64(0)...15 {
            var changed = original
            switch changed[field]! {
            case var .bytes(value): value[value.startIndex] ^= 1; changed[field] = .bytes(value)
            case let .unsigned(value): changed[field] = .unsigned(value + 1)
            case let .boolean(value): changed[field] = .boolean(!value)
            case .null: changed[field] = .unsigned(0)
            default: return XCTFail("Unexpected fixture type")
            }
            XCTAssertFalse(try verify(DeterministicCBOR.encode(.map(changed), limits: limits)), "field \(field)")
        }
    }

    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
}
