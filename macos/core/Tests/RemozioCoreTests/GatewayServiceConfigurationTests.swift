import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayServiceConfigurationTests: XCTestCase {
    private let root = P256.Signing.PrivateKey()
    private let receipt = P256.Signing.PrivateKey()
    private var uid: uid_t { getuid() == 401 ? 402 : 401 }

    private func settings(maximumOperations: Int = 8, lease: UInt64 = 15000) throws -> GatewayServiceSettings {
        try GatewayServiceSettings(delivery: GatewayDeliveryPolicy(maximumFlights: 4, minimumSendIntervalMillis: 1000),
            probe: GatewayProbePolicy(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: GatewayWakePolicy(maximumEntries: 128, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                maximumLifetimeMillis: 300000, maximumTTLSeconds: 300), maximumOperations: maximumOperations, authorityLeaseMillis: lease)
    }
    private func configuration(receiptKey: Data? = nil, providerPath: String = "/Library/Remozio/provider.json",
                               ownerUID: uid_t = 501, serviceUID: uid_t? = nil, wakeEndpoint: GatewayWakeEndpointConfiguration? = nil) throws -> GatewayServiceConfiguration {
        let id = Data(repeating: 1, count: 16)
        return try GatewayServiceConfiguration(registration: GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id,
                gatewayID: id, lifecycleEpoch: id, rootPublicKey: root.publicKey.x963Representation),
            receiptPublicKey: receiptKey ?? receipt.publicKey.x963Representation, directoryPath: "/Library/Remozio/gateway",
            providerPath: providerPath, receiptKeyPath: "/Library/Remozio/receipt.cbor", serviceUID: serviceUID ?? uid, ownerUID: ownerUID,
            serviceName: "dev.remozio.gateway", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.authority",
            authorityHashes: [Data(repeating: 1, count: 20), Data(repeating: 2, count: 20)],
            project: "fixture-project", packageName: "dev.remozio.android", settings: settings(), wakeEndpoint: wakeEndpoint)
    }
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 65536, maxDepth: 4, maxItems: 128) } }


    func testNativeProcessValidationPrecedesPrivateAccessAndMapsLookupFailure() throws {
        let own = getuid(), other: uid_t = own == 601 ? 602 : 601
        guard own > 0 else { throw XCTSkip("Ordinary-user fixture") }
        let value = try configuration(ownerUID: other, serviceUID: own)
        var calls = 0
        try value.requireNativeProcess { service, owner in
            calls += 1; XCTAssertEqual(service, own); XCTAssertEqual(owner, other)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertThrowsError(try value.requireNativeProcess { _, _ in throw DedicatedServiceAccountError.unsafeAccount }) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
        XCTAssertThrowsError(try value.requireNativeProcess()) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
    }
    func testRoundTripPinsRootScopeAndServicePolicyWithoutEmbeddingSecrets() throws {
        let original = try configuration(), decoded = try GatewayServiceConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.registration, original.registration)
        XCTAssertEqual(decoded.authorityPolicy.expectedUserID, 0)
        XCTAssertEqual(decoded.authorityPolicy.requirement, original.authorityPolicy.requirement)
        XCTAssertEqual(decoded.receiptPublicKey, receipt.publicKey.x963Representation)
        XCTAssertEqual(decoded.settings.authorityLeaseMillis, 15000)
        XCTAssertFalse(original.canonicalBytes.range(of: receipt.x963Representation) != nil)
        XCTAssertFalse(original.canonicalBytes.range(of: root.x963Representation) != nil)
        XCTAssertEqual(decoded.settings.delivery.maximumRetryBackoffMillis, 60000)
    }

    func testRejectsRootKeyReuseAndUnsafeCredentialPlacement() throws {
        XCTAssertThrowsError(try configuration(receiptKey: root.publicKey.x963Representation))
        XCTAssertThrowsError(try configuration(ownerUID: uid))
        for path in ["relative", "/", "/Library//provider", "/Library/../provider", "/Library/Remozio/gateway/provider",
                     "/Library/Remozio/receipt.cbor", "/Library/provi\0der"] {
            XCTAssertThrowsError(try configuration(providerPath: path))
        }
        XCTAssertThrowsError(try settings(maximumOperations: 0))
        XCTAssertThrowsError(try settings(lease: 0))
        XCTAssertThrowsError(try settings(lease: 60001))
    }

    func testRequiresBothProcessUIDsBeforePrivateCredentialAccess() throws {
        let config = try configuration()
        try config.requireProcess(realUID: uid, effectiveUID: uid)
        for pair: (uid_t, uid_t) in [(0, uid), (uid, 0), (501, uid), (uid, 501)] {
            XCTAssertThrowsError(try config.requireProcess(realUID: pair.0, effectiveUID: pair.1)) {
                XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
            }
        }
        XCTAssertThrowsError(try GatewayServiceCredentials.load(configuration: config)) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
    }

    func testRejectsUnknownVersionsFieldsAndDuplicateOrUnsortedPins() throws {
        guard case .map(let original) = try DeterministicCBOR.decode(configuration().canonicalBytes, limits: limits) else { return XCTFail() }
        func reject(_ fields: [UInt64: CBORValue]) throws {
            XCTAssertThrowsError(try GatewayServiceConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        for (key, value): (UInt64, CBORValue?) in [(0, .unsigned(2)), (0, .unsigned(0)), (6, .unsigned(0)),
            (7, .unsigned(UInt64(uid))), (10, nil), (13, .null)] {
            var changed = original; changed[key] = value; try reject(changed)
        }
        for hashes in [[Data(repeating: 1, count: 20), Data(repeating: 1, count: 20)],
                       [Data(repeating: 2, count: 20), Data(repeating: 1, count: 20)]] {
            var changed = original
            changed[9] = .array([.text("ABCDEFGHIJ"), .text("dev.remozio.authority"), .array(hashes.map(CBORValue.bytes))])
            try reject(changed)
        }
        var changed = original
        guard case .map(var policy) = changed[10] else { return XCTFail() }
        policy[3] = .unsigned(UInt64.max); changed[10] = .map(policy); try reject(changed)
    }

    func testRestrictedEndpointUsesExplicitSchemaAndIndependentAccountPolicy() throws {
        let endpoint = try GatewayWakeEndpointConfiguration(serviceName: "dev.remozio.gateway.wake", transportUID: 410,
            teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.transport", approvedCodeDirectoryHashes: [Data(repeating: 3, count: 20)])
        let config = try configuration(wakeEndpoint: endpoint), decoded = try GatewayServiceConfiguration.decode(config.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, config.canonicalBytes)
        XCTAssertEqual(decoded.wakeEndpoint?.policy.expectedUserID, 410)
        XCTAssertEqual(decoded.wakeEndpoint?.policy.requirement, endpoint.policy.requirement)
        XCTAssertEqual(decoded.authorityPolicy.expectedUserID, 0)
        guard case .map(let original) = try DeterministicCBOR.decode(config.canonicalBytes, limits: limits) else { return XCTFail() }
        XCTAssertEqual(original[0], .unsigned(2))
        for version: UInt64 in [0, 1, 3] {
            var changed = original; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try GatewayServiceConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var missing = original; missing.removeValue(forKey: 13)
        XCTAssertThrowsError(try GatewayServiceConfiguration.decode(DeterministicCBOR.encode(.map(missing), limits: limits)))
        for account in [uid_t(0), uid, uid_t(501)] {
            XCTAssertThrowsError(try configuration(wakeEndpoint: GatewayWakeEndpointConfiguration(serviceName: endpoint.serviceName,
                transportUID: account, teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.transport",
                approvedCodeDirectoryHashes: [Data(repeating: 3, count: 20)])))
        }
        for (name, team, component) in [("dev.remozio.gateway", "ABCDEFGHIJ", "dev.remozio.transport"),
            (endpoint.serviceName, "KLMNOPQRST", "dev.remozio.transport"),
            (endpoint.serviceName, "ABCDEFGHIJ", "dev.remozio.authority")] {
            XCTAssertThrowsError(try configuration(wakeEndpoint: GatewayWakeEndpointConfiguration(serviceName: name,
                transportUID: 410, teamID: team, componentIdentifier: component, approvedCodeDirectoryHashes: [Data(repeating: 3, count: 20)])))
        }
        XCTAssertThrowsError(try GatewayWakeEndpointConfiguration(serviceName: "other.service", transportUID: 410,
            teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.transport", approvedCodeDirectoryHashes: [Data(repeating: 3, count: 20)]))
    }

    func testReceiptSignerChecksPurposeCanonicalPrivateKeyAndPinnedPublicKey() throws {
        func encoded(role: String = "remozio-gateway-receipt-key", key: Data? = nil) throws -> Data {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(role), 2: .bytes(key ?? receipt.x963Representation)]), limits: limits)
        }
        let signer = try GatewayReceiptSigner(bytes: encoded(), expectedPublicKey: receipt.publicKey.x963Representation)
        let input = Data("disposable typed gateway receipt".utf8)
        XCTAssertTrue(try receipt.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signer.sign(input)), for: input))
        XCTAssertThrowsError(try GatewayReceiptSigner(bytes: encoded(), expectedPublicKey: root.publicKey.x963Representation))
        XCTAssertThrowsError(try GatewayReceiptSigner(bytes: encoded(role: "remozio-transport-identity"), expectedPublicKey: receipt.publicKey.x963Representation))
        XCTAssertThrowsError(try GatewayReceiptSigner(bytes: encoded(key: receipt.rawRepresentation), expectedPublicKey: receipt.publicKey.x963Representation))
        var inconsistent = receipt.x963Representation
        inconsistent.replaceSubrange(0..<65, with: root.publicKey.x963Representation)
        XCTAssertThrowsError(try GatewayReceiptSigner(bytes: encoded(key: inconsistent), expectedPublicKey: root.publicKey.x963Representation))
    }
}
