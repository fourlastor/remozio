import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushStartupConfigurationTests: XCTestCase {
    private func configuration(key: Data? = nil) throws -> AuthorityPhonePushStartupConfiguration {
        try .init(projectID: "project", senderID: "123", packageName: "dev.remozio.android",
            gatewayReceiptPublicKey: key ?? P256.Signing.PrivateKey().publicKey.x963Representation,
            maximumControls: 17, candidateLifetimeMilliseconds: 42_000)
    }
    private func wake(_ push: AuthorityPhonePushStartupConfiguration? = nil) throws -> AuthorityWakeStartupConfiguration {
        let id = Data(repeating: 1, count: 16), key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id, accountID: id, journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.remozio.authority", teamID: "TEAMID1234", transportIdentifier: "dev.remozio.transport",
            transportHashes: [Data(repeating: 3, count: 20)], transportUID: 401, maximumPayloadBytes: 4096,
            continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/root/key.cbor", authorityPublicKey: key)
        return try .init(request: request, registration: GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id,
                gatewayID: id, lifecycleEpoch: id, rootPublicKey: key), gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402,
            teamID: "TEAMID1234", gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating: 4, count: 20)], phonePush: push)
    }
    func testOptInRoundTripPreservesProviderAndClockPolicy() throws {
        let config = try configuration(), epoch = UUID(), policy = try config.journalPolicy(clockEpoch: epoch)
        XCTAssertEqual(try AuthorityPhonePushStartupConfiguration.decode(config.canonicalBytes).canonicalBytes, config.canonicalBytes)
        XCTAssertEqual(policy.clockEpoch, epoch); XCTAssertEqual(policy.maximumControls, 17)
        XCTAssertEqual(policy.candidateLifetimeMillis, 42_000)
        let original = try wake(config), decoded = try AuthorityWakeStartupConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.phonePush?.canonicalBytes, config.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
    }
    func testDisabledFormatKeepsVersionOneAndRejectsAnInjectedOption() throws {
        let original = try wake(), limits = try CBORLimits(maxBytes: 65_536, maxDepth: 2, maxItems: 48)
        guard case .map(var fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        XCTAssertEqual(fields[0], .unsigned(1)); XCTAssertNil(fields[11])
        XCTAssertNil(try AuthorityWakeStartupConfiguration.decode(original.canonicalBytes).phonePush)
        fields[11] = .bytes(try configuration().canonicalBytes)
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        fields[0] = .unsigned(2); fields.removeValue(forKey: 11)
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testMalformedClosedConfigurationAndResourceBoundsAreRejected() throws {
        let original = try configuration(), limits = try CBORLimits(maxBytes: 4096, maxDepth: 2, maxItems: 32)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0,.unsigned(2)),(1,.text("bad project")),(2,.text("123x")),
            (3,.text("invalid")),(4,.bytes(Data(repeating:0,count:65))),(5,.unsigned(1)),(5,.unsigned(100_001)),
            (6,.unsigned(0)),(6,.unsigned(86_400_001)),(7,.null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityPhonePushStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testReceiptKeyCannotBeTheRootAuthorityKey() throws {
        let original = try wake(), config = try configuration(key: original.registration.rootPublicKey)
        XCTAssertThrowsError(try config.registrationPolicy(original.registration))
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration(request: original.request, registration: original.registration,
            gatewayServiceName: original.gatewayServiceName, gatewayUID: 402, teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating:4,count:20)], phonePush: config))
    }
}
