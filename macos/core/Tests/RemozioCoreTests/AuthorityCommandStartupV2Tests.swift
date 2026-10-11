import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore
final class AuthorityCommandStartupV2Tests: XCTestCase {
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func presence() throws -> AuthorityPresenceStartupConfiguration {
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32)).publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.remozio.authority", teamID: "TEAMID1234", transportIdentifier: "dev.remozio.transport",
            transportHashes: [id(3, 20)], transportUID: 401, maximumPayloadBytes: 262_144, continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/key.cbor", authorityPublicKey: key)
        let registration = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key)
        let wake = try AuthorityWakeStartupConfiguration(request: request, registration: registration,
            gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402, teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [id(4, 20)])
        return try .init(wake: wake, ownerUID: 501, appServiceName: "dev.remozio.presence", teamID: "TEAMID1234",
            appIdentifier: "dev.remozio.mac", appHashes: [id(6, 20)], policy: .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000))
    }
    private func config(service: String = "dev.remozio.command", path: String = "/Library/Remozio/elevation.cbor",
                        environment: [CapturedEnvironmentEntry] = [], captureBytes: Int = 65_536,
                        ancestry: Int = 16, lifetime: UInt64 = 60_000) throws -> AuthorityCommandStartupConfiguration {
        try .init(presence: presence(), serviceName: service, policyPath: path, environment: environment,
            submissionLimits: .init(maxBytes: 8192, maxDepth: 8, maxItems: 1024),
            captureLimits: .init(maxBytes: captureBytes, maxDepth: 8, maxItems: 4096),
            maximumAncestryEntries: ancestry, approvalLifetimeMilliseconds: lifetime)
    }
    func testVersionOneKeepsLegacyBytesAndDoesNotEnableExecution() throws {
        let current = try config()
        let legacyBytes = try XCTUnwrap(Data(base64Encoded: """
            rQABAVkCoKoAAQFZAj2rAAEBWQExpQABAVjHsAACAVABAQEBAQEBAQEBAQEBAQEBAlACAgICAgICAgICAgICAgICA3gYL0xp
            YnJhcnkvUmVtb3ppby9qb3VybmFsBHVkZXYucmVtb3ppby5hdXRob3JpdHkFalRFQU1JRDEyMzQGdWRldi5yZW1vemlvLnRy
            YW5zcG9ydAeBVAMDAwMDAwMDAwMDAwMDAwMDAwMDCBkBkQkaAAQAAAoBC4AMCA0ZE4gOCA94Gy9MaWJyYXJ5L1JlbW96aW8v
            Y29udGludWl0eQJ4GS9MaWJyYXJ5L1JlbW96aW8va2V5LmNib3IDWEEEcTX6T9k6Cdzpi79oG0v89Q58DWNU5ir7C/8qNClh
            eGXtTB8C3bkCPuVqVX5RXWqdxmwR8iCWDeWUM031iHdnJAQZA+gCWJ+mAFADAwMDAwMDAwMDAwMDAwMDAVABAQEBAQEBAQEB
            AQEBAQEBAlACAgICAgICAgICAgICAgICA1AEBAQEBAQEBAQEBAQEBAQEBFAFBQUFBQUFBQUFBQUFBQUFBVhBBHE1+k/ZOgnc
            6Yu/aBtL/PUOfA1jVOYq+wv/KjQpYXhl7UwfAt25Aj7lalV+UV1qncZsEfIglg3llDNN9Yh3ZyQDeBhkZXYucmVtb3ppby5n
            YXRld2F5LnJvb3QEGQGSBWpURUFNSUQxMjM0BnNkZXYucmVtb3ppby5nYXRld2F5B4FUBAQEBAQEBAQEBAQEBAQEBAQEBAQI
            GScQCRkD6AoZE4gCGQH1A3RkZXYucmVtb3ppby5wcmVzZW5jZQRqVEVBTUlEMTIzNAVvZGV2LnJlbW96aW8ubWFjBoFUBgYG
            BgYGBgYGBgYGBgYGBgYGBgYHGgAB1MAIGROICRkD6AJzZGV2LnJlbW96aW8uY29tbWFuZAN4Hy9MaWJyYXJ5L1JlbW96aW8v
            ZWxldmF0aW9uLmNib3IEgAWjABkgAAEIAhkEAAajABoAAQAAAQgCGRAABxggCBj6CRkTiAoQCxnqYAwD
            """, options: .ignoreUnknownCharacters))
        XCTAssertEqual(current.canonicalBytes, legacyBytes)
        XCTAssertNil(current.execution)
        XCTAssertNil(try AuthorityCommandStartupConfiguration.decode(legacyBytes).execution)
    }

    func testVersionTwoRequiresItsExactExecutorInputsAndNeverFallsBack() throws {
        let legacy = try config()
        let execution = try AuthorityCommandExecutionConfiguration(monitorPath: "/Applications/Remozio.app/Contents/Helpers/monitor",
            childPath: "/Applications/Remozio.app/Contents/Helpers/child")
        let modern = try AuthorityCommandStartupConfiguration(presence: legacy.presence, serviceName: legacy.serviceName,
            policyPath: legacy.policyPath, environment: legacy.environment, submissionLimits: legacy.submissionLimits,
            captureLimits: legacy.captureLimits, execution: execution)
        XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(modern.canonicalBytes).execution, execution)
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 4, maxItems: 1024)
        guard case .map(let fields) = try DeterministicCBOR.decode(modern.canonicalBytes, limits: limits) else { return XCTFail() }
        XCTAssertEqual(fields[0], .unsigned(2))
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(1)), (0, .unsigned(3)), (13, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var missing = fields; missing.removeValue(forKey: 13)
        XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(missing), limits: limits)))
    }
}
