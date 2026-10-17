import Foundation
import XCTest
@testable import RemozioProtocol

final class PhonePushRegistrationFrameTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let applicationProtocol: String; let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/phone-push-registration-v1.json")))
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
    func testSharedVectorsRetainTheirRolesAndCanonicalBytes() throws {
        let values = try vectors(); XCTAssertEqual(values.applicationProtocol, PhonePushRegistrationFrame.applicationProtocol)
        for row in values.valid {
            let bytes = hex(row.hex); let frame = try PhonePushRegistrationFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes)
            XCTAssertEqual(String(reflecting: frame), "PhonePushRegistrationFrame(redacted)")
            switch (row.name, frame) {
            case ("offer", .offer(let id, let offer)): XCTAssertEqual(id, Data(0..<16)); XCTAssertEqual(offer.token, "synthetic-token")
            case ("prepared", .prepared(let id, let m)): XCTAssertEqual(id, Data(0..<16)); XCTAssertEqual(m.tokenDigest, try binding().tokenDigest)
            case ("proof", .proof(let id, let proof)): XCTAssertEqual(id, Data(0..<16)); XCTAssertEqual(proof.binding, try binding())
            case (let name, .outcome(let id, let outcome)):
                XCTAssertEqual(id, Data(0..<16)); XCTAssertEqual(UInt64(name.replacingOccurrences(of: "outcome-", with: "")), outcome.rawValue)
            default: XCTFail(row.name)
            }
        }
    }
    func testHostileAndConfusedContractsFail() throws {
        for row in try vectors().invalid { XCTAssertThrowsError(try PhonePushRegistrationFrame.decode(hex(row.hex)), row.name) }
    }
    func testFetchableMetadataCannotRevealProviderChallenge() throws {
        let m = try metadata(); let b = try binding()
        let encoded = try PhonePushRegistrationFrame.prepared(correlationID: Data(0..<16), metadata: m).encode()
        XCTAssertNil(encoded.range(of: b.challenge))
        XCTAssertEqual(try m.proof(.init(candidateID: b.candidateID, challenge: b.challenge, enrollmentTag: b.enrollmentTag)).binding, b)
        XCTAssertThrowsError(try m.proof(.init(candidateID: Data(count: 16), challenge: b.challenge, enrollmentTag: b.enrollmentTag)))
        XCTAssertThrowsError(try m.proof(.init(candidateID: b.candidateID, challenge: b.challenge, enrollmentTag: Data(count: 32))))
        XCTAssertEqual(String(reflecting: m), "PhonePushRegistrationMetadata(redacted)")
    }
    func testProviderRoutingHintsAreBoundedAndRedacted() throws {
        for token in ["", "space token", "newline\n", String(repeating: "x", count: 4097)] {
            XCTAssertThrowsError(try PhonePushTokenOffer(token: token, projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
        }
        let offer = try PhonePushTokenOffer(token: "secret-provider-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android")
        XCTAssertEqual(String(reflecting: offer), "PhonePushTokenOffer(redacted)")
        XCTAssertThrowsError(try PhonePushRegistrationFrame.offer(correlationID: Data(count: 15), offer: offer).encode())
        XCTAssertNotEqual(PhonePushRegistrationOutcome.proofCommitted.rawValue, PhonePushRegistrationOutcome.mappingConfirmed.rawValue)
    }
}
