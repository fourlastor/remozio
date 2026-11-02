import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityRequestStartupConfigurationTests: XCTestCase {
    private func service(continuity: Bool = true, maximumPayloadBytes: Int = 4096) throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: "/Library/Application Support/Remozio/journal", serviceName: "dev.sebastiano.remozio.macos.authority",
            teamID: "ABCDEFGHIJ", transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: 3, count: 20)],
            transportUID: 502, maximumPayloadBytes: maximumPayloadBytes,
            continuityDirectory: continuity ? "/Library/Application Support/Remozio/continuity" : nil)
    }
    private func inputs() throws -> AuthorityRequestStartupConfiguration {
        try AuthorityRequestStartupConfiguration(service: service(), keyRecordPath: "/Library/Application Support/Remozio/keys/authority.cbor",
            authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, maintenanceIntervalMilliseconds: 250)
    }
    func testRoundTripPreservesProtectedScopePinAndRuntimeLimits() throws {
        let original = try inputs(), decoded = try AuthorityRequestStartupConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.service.canonicalBytes, original.service.canonicalBytes)
        XCTAssertEqual(decoded.keyRecordPath, original.keyRecordPath)
        XCTAssertEqual(decoded.authorityPublicKey, original.authorityPublicKey)
        XCTAssertEqual(decoded.maintenanceIntervalMilliseconds, 250)
        XCTAssertEqual(decoded.description, "AuthorityRequestStartupConfiguration(redacted)")
    }
    func testRequiresPairedRecoveryAndSpaceForSignedCarrier() throws {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertThrowsError(try AuthorityRequestStartupConfiguration(service: service(continuity: false),
            keyRecordPath: "/keys/authority.cbor", authorityPublicKey: key))
        for budget in [1, 127, 128] {
            XCTAssertThrowsError(try AuthorityRequestStartupConfiguration(service: service(maximumPayloadBytes: budget),
                keyRecordPath: "/keys/authority.cbor", authorityPublicKey: key))
        }
        XCTAssertNoThrow(try AuthorityRequestStartupConfiguration(service: service(maximumPayloadBytes: 129),
            keyRecordPath: "/keys/authority.cbor", authorityPublicKey: key))
    }
    func testRejectsAmbiguousRecordPathsAndInvalidPins() throws {
        let configuration = try service(), key = P256.Signing.PrivateKey().publicKey.x963Representation
        for path in ["", "/", "relative", "/keys//authority", "/keys/../authority", "/keys/./authority", "/keys/authority/",
                     "/keys/a\0", "/" + String(repeating: "a", count: 256), "/" + String(repeating: "a/", count: Int(PATH_MAX))] {
            XCTAssertThrowsError(try AuthorityRequestStartupConfiguration(service: configuration, keyRecordPath: path, authorityPublicKey: key))
        }
        for pin in [Data(), Data(repeating: 4, count: 65), key.dropLast(), Data(repeating: 2, count: 33)] {
            XCTAssertThrowsError(try AuthorityRequestStartupConfiguration(service: configuration,
                keyRecordPath: "/keys/authority", authorityPublicKey: pin))
        }
        XCTAssertNoThrow(try AuthorityRequestStartupConfiguration(service: configuration,
            keyRecordPath: "/" + String(repeating: "a", count: 255), authorityPublicKey: key))
    }
    func testMaintenanceIntervalsStayWithinExistingRuntimeBounds() throws {
        let value = try inputs()
        for interval in [Int.min, -1, 0, 99, 60_001, Int.max] {
            XCTAssertThrowsError(try AuthorityRequestStartupConfiguration(service: value.service,
                keyRecordPath: value.keyRecordPath, authorityPublicKey: value.authorityPublicKey, maintenanceIntervalMilliseconds: interval))
        }
        for interval in [100, 60_000] {
            let boundary = try AuthorityRequestStartupConfiguration(service: value.service,
                keyRecordPath: value.keyRecordPath, authorityPublicKey: value.authorityPublicKey, maintenanceIntervalMilliseconds: interval)
            XCTAssertEqual(try AuthorityRequestStartupConfiguration.decode(boundary.canonicalBytes).maintenanceIntervalMilliseconds, interval)
        }
    }
    func testRejectsUnknownMissingAndMistypedFieldsWithoutLegacyFallback() throws {
        let value = try inputs(), limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else { return XCTFail("Expected map") }
        let changes: [(UInt64, CBORValue?)] = [
            (0, .unsigned(2)), (0, nil), (1, .bytes(try service(continuity: false).canonicalBytes)),
            (1, .text("service")), (2, nil), (2, .bytes(Data())), (3, .null),
            (4, .unsigned(UInt64.max)), (4, .unsigned(0)), (5, .unsigned(1)),
        ]
        for (field, replacement) in changes {
            var changed = fields; changed[field] = replacement
            XCTAssertThrowsError(try AuthorityRequestStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        XCTAssertThrowsError(try AuthorityRequestStartupConfiguration.decode(value.service.canonicalBytes))
        XCTAssertThrowsError(try AuthorityServiceConfiguration.decode(value.canonicalBytes))
        XCTAssertThrowsError(try AuthorityRequestStartupConfiguration.decode(value.canonicalBytes + Data([0])))
        XCTAssertThrowsError(try AuthorityRequestStartupConfiguration.decode(Data(count: 65_537)))
    }
    func testProtectedLoaderRejectsNormalUserBeforeReadingAnyInput() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        XCTAssertThrowsError(try AuthorityRequestStartupConfiguration.load(path: "/Library/Application Support/Remozio/request-startup.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
