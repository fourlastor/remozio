import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RelayRunCredentialTransportTests: XCTestCase, @unchecked Sendable {
    private typealias Fixture = RelayRunCredentialPublicationTests.Fixture
    private let limits = try! CBORLimits(maxBytes: 32_768, maxDepth: 1, maxItems: 64)
    private func fixture() throws -> Fixture { try RelayRunCredentialPublicationTests().fixture() }
    private func read(_ bytes: Data, _ f: Fixture, port: UInt16? = nil) throws -> RelayRunCredentialReference {
        try .decodeForTransport(bytes, runtime: f.runtime, relayPort: port ?? f.plan.port)
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case let .map(value) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimePreparationError.invalidRecord
        }
        return value
    }
    private func changed(_ original: [UInt64: CBORValue], _ key: UInt64, _ value: CBORValue?) throws -> Data {
        var result = original; result[key] = value
        return try DeterministicCBOR.encode(.map(result), limits: limits)
    }
    private func different(_ value: Data) -> Data {
        var result = value; result[0] ^= 0xff; return result
    }
    func testTransportReadsTheSameReferenceWithoutAnyPrivateMaterial() throws {
        let f = try fixture(), material = try f.material(), reference = try material.reference
        XCTAssertEqual(try read(reference.encoded, f), reference)
        try material.withCredentialBytes { XCTAssertNil(try reference.encoded.range(of: $0)) }
        XCTAssertEqual(RelayRunCredentialReference.supportedVersions, [1])
    }
    func testAnotherRuntimeOrLocalPortCannotUseTheReference() throws {
        let f = try fixture(), other = try fixture(), reference = try f.material().reference
        XCTAssertThrowsError(try RelayRunCredentialReference.decodeForTransport(reference.encoded,
            runtime: other.runtime, relayPort: f.plan.port))
        XCTAssertThrowsError(try read(reference.encoded, f, port: f.plan.port == 65_535 ? 65_534 : f.plan.port + 1))
        for port: UInt16 in [0, 1, 1023] { XCTAssertThrowsError(try read(reference.encoded, f, port: port)) }
    }
    func testReferenceSchemaPurposeIdentityAndDigestBoundsAreClosed() throws {
        let f = try fixture(), original = try fields(f.material().reference.encoded)
        let cases: [(UInt64, CBORValue?)] = [(0, .unsigned(2)), (1, .text("wrong-purpose")),
            (2, .bytes(Data())), (3, .bytes(Data())), (4, .bytes(Data())), (5, .bytes(Data())),
            (6, .text("invalid-account")), (7, .text("invalid-tunnel")),
            (8, .text("wrong-name")), (9, .bytes(Data())), (10, .bytes(Data())), (11, .null), (4, nil)]
        for (key, value) in cases {
            XCTAssertThrowsError(try read(changed(original, key, value), f), "Accepted changed reference field \(key)")
        }
        XCTAssertThrowsError(try read(Data(repeating: 0, count: 16_385), f))
    }
    func testEveryLocalPlanScopeFieldAndItsSchemaAreChecked() throws {
        let f = try fixture(), original = try fields(f.material().reference.encoded)
        let plan = try fields(f.plan.bytes)
        let cases: [(UInt64, CBORValue?)] = [(0, .unsigned(2)), (1, .text("wrong-purpose")),
            (2, .bytes(different(f.runtime.services.macID))), (3, .bytes(different(f.runtime.services.installationID))),
            (4, .bytes(different(f.runtime.services.releaseDigest))), (5, .bytes(different(f.runtime.services.accountID))),
            (6, .unsigned(UInt64(f.runtime.services.ownerUID) + 1)), (7, .bytes(Data())),
            (8, .bytes(Data())), (8, .bytes(different(f.expected.operationID))), (9, .bytes(Data())),
            (10, .unsigned(0)), (11, .text(String(repeating: "b", count: 32))),
            (12, .text("invalid-zone")), (13, .text("invalid/path")), (14, .null), (7, nil)]
        for (key, value) in cases {
            let changedPlan = try changed(plan, key, value)
            XCTAssertThrowsError(try read(changed(original, 3, .bytes(changedPlan)), f), "Accepted changed plan field \(key)")
        }
    }
    func testCanonicalTunnelIdentifierAndExactPlanNameAreRequired() throws {
        let f = try fixture(), original = try fields(f.material().reference.encoded)
        for value in ["ABCDEF12-1111-4111-8111-111111111111", "{11111111-1111-4111-8111-111111111111}", ""] {
            XCTAssertThrowsError(try read(changed(original, 7, .text(value)), f))
        }
        for name in ["", f.plan.tunnelName + "-other", "../other"] {
            XCTAssertThrowsError(try read(changed(original, 8, .text(name)), f))
        }
        XCTAssertThrowsError(try read(changed(original, 6, .text(String(repeating: "b", count: 32))), f))
    }
}
