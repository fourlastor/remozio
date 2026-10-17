import Foundation
import XCTest
@testable import RemozioProtocol

final class PhonePushRecoveryFrameTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let applicationProtocol: String; let valid: [Row]; let invalid: [Row] }
    private func vectors(_ name: String = "phone-push-recovery-v2.json") throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/" + name)))
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func binding() throws -> GatewayTokenBinding {
        try .init(ownerID: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16),
            accountID: Data(repeating: 3, count: 16), gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
            phoneID: Data(repeating: 6, count: 16), enrollmentEpoch: Data(repeating: 7, count: 16), candidateID: Data(repeating: 8, count: 16),
            tokenDigest: Data(repeating: 9, count: 32), challenge: Data(repeating: 170, count: 32), enrollmentTag: Data(repeating: 11, count: 32))
    }
    private func metadata() throws -> PhonePushRegistrationMetadata {
        try .init(.init(binding: binding(), revision: 7, operationID: Data(repeating: 12, count: 16), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000))
    }
    func testSharedVectorsKeepRolesAndCanonicalBytes() throws {
        let values = try vectors(); XCTAssertEqual(values.applicationProtocol, PhonePushRecoveryFrame.applicationProtocol)
        for row in values.valid {
            let bytes = hex(row.hex), frame = try PhonePushRecoveryFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes, row.name)
            XCTAssertEqual(frame.correlationID, Data(0..<16))
            XCTAssertEqual(String(reflecting: frame), "PhonePushRecoveryFrame(redacted)")
            switch (row.name, frame) {
            case ("probe", .probe), ("ready", .ready): break
            case ("resume", .resume(_, let offer)): XCTAssertEqual(offer.token, "synthetic-token")
            case (let name, .state(_, let state)):
                XCTAssertEqual(state.metadata, try metadata())
                let phase: PhonePushRecoveryPhase = name == "awaiting-proof" ? .awaitingProviderProof : name == "proof-committed" ? .proofCommitted : .mappingObserved
                XCTAssertEqual(state.phase, phase)
                XCTAssertEqual(state.observationAgeMilliseconds, name == "mapping-observed-new" ? 0 : name == "mapping-observed-boundary" ? 4999 : nil)
            case (let name, .outcome(_, let failure)): XCTAssertEqual(UInt64(name.replacingOccurrences(of: "failure-", with: "")), failure.rawValue)
            default: XCTFail(row.name)
            }
        }
    }
    func testReadinessContainsOnlyCorrelationAndFixedCapabilityFields() throws {
        let probe = try PhonePushRecoveryFrame.probe(correlationID: Data(0..<16)).encode()
        let ready = try PhonePushRecoveryFrame.ready(correlationID: Data(0..<16)).encode()
        let limits = try CBORLimits(maxBytes: 8192, maxDepth: 4, maxItems: 64)
        guard case .map(let probeFields) = try DeterministicCBOR.decode(probe, limits: limits),
              case .map(let readyFields) = try DeterministicCBOR.decode(ready, limits: limits) else { return XCTFail("Missing readiness fields") }
        XCTAssertEqual(probeFields[4], .null); XCTAssertEqual(readyFields[4], .unsigned(2))
        XCTAssertEqual(probeFields[3], .bytes(Data(0..<16))); XCTAssertEqual(readyFields[3], probeFields[3])
    }
    func testHostileVersionsRolesAndAgesFail() throws {
        for row in try vectors().invalid { XCTAssertThrowsError(try PhonePushRecoveryFrame.decode(hex(row.hex)), row.name) }
    }
    func testVersion1BytesRemainSeparateAndUnchanged() throws {
        for row in try vectors("phone-push-registration-v1.json").valid {
            let bytes = hex(row.hex)
            XCTAssertEqual(try PhonePushRegistrationFrame.decode(bytes).encode(), bytes)
            XCTAssertThrowsError(try PhonePushRecoveryFrame.decode(bytes))
        }
        for row in try vectors().valid { XCTAssertThrowsError(try PhonePushRegistrationFrame.decode(hex(row.hex))) }
    }
    func testCommittedMappingKeepsHistoricalProofExpiry() throws {
        let state = try PhonePushRecoveryState(metadata: metadata(), phase: .mappingObserved, observationAgeMilliseconds: 0)
        let bytes = try PhonePushRecoveryFrame.state(correlationID: Data(0..<16), state: state).encode()
        guard case .state(_, let decoded) = try PhonePushRecoveryFrame.decode(bytes) else { return XCTFail("Wrong recovery role") }
        XCTAssertEqual(decoded.metadata.expiresAtUnixMillis, 2000)
        XCTAssertEqual(decoded.phase, .mappingObserved)
        XCTAssertEqual(decoded.observationAgeMilliseconds, 0)
    }
    func testStateExcludesChallengeAndRedactsDescriptions() throws {
        let state = try PhonePushRecoveryState(metadata: metadata(), phase: .proofCommitted)
        let frame = PhonePushRecoveryFrame.state(correlationID: Data(0..<16), state: state)
        XCTAssertNil(try frame.encode().range(of: binding().challenge))
        XCTAssertEqual(String(reflecting: state), "PhonePushRecoveryState(redacted)")
        let offer = try PhonePushTokenOffer(token: "private-provider-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android")
        XCTAssertFalse(String(reflecting: PhonePushRecoveryFrame.resume(correlationID: Data(0..<16), offer: offer)).contains(offer.token))
    }
    func testInvalidStateAgesAndCorrelationsFailBeforeEncoding() throws {
        for phase in [PhonePushRecoveryPhase.awaitingProviderProof, .proofCommitted] {
            XCTAssertThrowsError(try PhonePushRecoveryState(metadata: metadata(), phase: phase, observationAgeMilliseconds: 0))
        }
        XCTAssertThrowsError(try PhonePushRecoveryState(metadata: metadata(), phase: .mappingObserved))
        XCTAssertThrowsError(try PhonePushRecoveryState(metadata: metadata(), phase: .mappingObserved, observationAgeMilliseconds: 5000))
        XCTAssertThrowsError(try PhonePushRecoveryFrame.outcome(correlationID: Data(count: 15), failure: .unavailable).encode())
        XCTAssertNotEqual(PhonePushRecoveryPhase.proofCommitted, .mappingObserved)
    }
}
