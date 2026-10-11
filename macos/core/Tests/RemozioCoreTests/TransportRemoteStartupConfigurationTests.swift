import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class TransportRemoteStartupConfigurationTests: XCTestCase {
    private func transport() throws -> ApprovalTransportConfiguration {
        try .init(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            ownerUID: 501, serviceUID: 401, authorityServiceName: "dev.remozio.authority",
            teamID: "TEAMID1234", authorityIdentifier: "dev.remozio.authority", authorityHashes: [Data(repeating: 3, count: 20)],
            identityReference: Data([1]), identityPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
    }
    private func wake(_ transport: ApprovalTransportConfiguration) throws -> TransportWakeStartupConfiguration {
        let signer = try GatewayWakeSignerConfiguration(binding: .init(ownerID: Data(repeating: 3, count: 16),
            macID: transport.macID, accountID: transport.accountID, gatewayID: Data(repeating: 4, count: 16),
            lifecycleEpoch: Data(repeating: 5, count: 16)), credentialID: Data(repeating: 6, count: 16),
            transportUID: 401, ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake",
            teamID: "TEAMID1234", gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating: 4, count: 20)],
            custody: .protectedFile, keyRecordPath: "/Library/Remozio/transport/wake.cbor",
            publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        return try .init(transport: transport, wake: signer)
    }
    func testRoundTripWithAndWithoutWakeRetainsExactIdentityAndScope() throws {
        let transport = try transport()
        for wake in [nil, try wake(transport)] {
            let original = try TransportRemoteStartupConfiguration(transport: transport, wake: wake, relayPort: 9090)
            let decoded = try TransportRemoteStartupConfiguration.decode(original.canonicalBytes)
            XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
            XCTAssertEqual(decoded.transport.canonicalBytes, transport.canonicalBytes)
            XCTAssertEqual(decoded.wake?.canonicalBytes, wake?.canonicalBytes)
            XCTAssertEqual(decoded.relayPort, 9090)
            XCTAssertEqual(decoded.description, "TransportRemoteStartupConfiguration(redacted)")
        }
    }
    func testRejectsAnotherTransportIdentityInTheWakeConfiguration() throws {
        let transport = try transport()
        XCTAssertThrowsError(try TransportRemoteStartupConfiguration(transport: transport, wake: wake(self.transport()), relayPort: 9090))
        XCTAssertThrowsError(try TransportRemoteStartupConfiguration(transport: transport, relayPort: 0))
    }
    func testRejectsUnknownVersionsFieldsMalformedWakeAndPorts() throws {
        let original = try TransportRemoteStartupConfiguration(transport: transport(), relayPort: 9090)
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 16)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (2, .text("wake")), (3, .unsigned(0)),
            (3, .unsigned(65536)), (4, .null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try TransportRemoteStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testNormalOwnerCannotUseProtectedRemoteStartup() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires an ordinary account") }
        let configuration = try TransportRemoteStartupConfiguration(transport: transport(), relayPort: 9090)
        XCTAssertThrowsError(try configuration.transport.requireProcess(realUID: 501, effectiveUID: 501))
        XCTAssertThrowsError(try TransportRemoteStartupConfiguration.load(path: "/Library/Remozio/transport/remote.cbor"))
    }
}
