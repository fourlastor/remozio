import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class WakeStartupConfigurationTests: XCTestCase {
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func root() throws -> AuthorityWakeStartupConfiguration {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.sebastiano.remozio.macos.authority", teamID: "TEAMID1234", transportIdentifier: "dev.sebastiano.remozio.macos.transport",
            transportHashes: [id(3, count: 20)], transportUID: 401, maximumPayloadBytes: 4096, continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/root/key.cbor", authorityPublicKey: key)
        let registration = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key)
        return try .init(request: request, registration: registration, gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402,
            teamID: "TEAMID1234", gatewayIdentifier: "dev.sebastiano.remozio.macos.gateway", gatewayHashes: [id(4, count: 20)])
    }
    private func transport(owner: UInt32 = 501, mac: UInt8 = 1) throws -> ApprovalTransportConfiguration {
        try .init(macID: id(mac), accountID: id(2), ownerUID: owner, serviceUID: 401, authorityServiceName: "dev.sebastiano.remozio.macos.authority",
            teamID: "TEAMID1234", authorityIdentifier: "dev.sebastiano.remozio.macos.authority", authorityHashes: [id(3, count: 20)],
            identityReference: Data([1]), identityPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
    }
    private func wake() throws -> GatewayWakeSignerConfiguration {
        try .init(binding: GatewaySubmissionBinding(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4), lifecycleEpoch: id(5)),
            credentialID: id(6), transportUID: 401, ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.sebastiano.remozio.macos.gateway", gatewayHashes: [id(4, count: 20)], custody: .protectedFile,
            keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
    }
    func testRootCanonicalConfigurationPinsHardwareIdentityScopeAndBoundedLease() throws {
        let original = try root(), decoded = try AuthorityWakeStartupConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.registration.rootPublicKey, decoded.request.authorityPublicKey)
        XCTAssertEqual(decoded.gatewayPolicy.expectedUserID, 402)
        XCTAssertEqual(decoded.leaseMilliseconds, 10_000); XCTAssertEqual(decoded.pollMilliseconds, 1000)
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (4, .unsigned(401)), (8, .unsigned(0)),
            (8, .unsigned(60_001)), (9, .unsigned(5001)), (10, .unsigned(5001)), (11, .null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        let other = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4), lifecycleEpoch: id(5),
            rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        var changed = fields; changed[2] = .bytes(try other.encode())
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
    }
    func testTransportCanonicalCompositionRejectsWrongMachineOrAccountOwner() throws {
        let transport = try transport(), wake = try wake(), original = try TransportWakeStartupConfiguration(transport: transport, wake: wake, pollMilliseconds: 250)
        XCTAssertEqual(try TransportWakeStartupConfiguration.decode(original.canonicalBytes).canonicalBytes, original.canonicalBytes)
        XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: self.transport(mac: 9), wake: wake))
        XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: self.transport(owner: 502), wake: wake))
        for interval: UInt64 in [0, 99, 60_001, UInt64.max] {
            XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: transport, wake: wake, pollMilliseconds: interval))
        }
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(var fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        fields[4] = .unsigned(1)
        XCTAssertThrowsError(try TransportWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testPresenceConfigurationRejectsInvalidScopeAccountAndRecoveryIntervals() throws {
        let policy = try PresenceConfiguration(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 200)
        for uid: UInt32 in [0, UInt32.max] {
            XCTAssertThrowsError(try AuthorityAccountPresenceConfiguration(macID: id(1), accountID: id(2), ownerUID: uid, policy: policy))
        }
        XCTAssertThrowsError(try AuthorityAccountPresenceConfiguration(macID: id(1, count: 15), accountID: id(2), ownerUID: 501, policy: policy))
        for tooLarge in [try PresenceConfiguration(observationLifetimeMilliseconds: 60_001, unavailableGraceMilliseconds: 200),
                         try PresenceConfiguration(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 60_001)] {
            XCTAssertThrowsError(try AuthorityAccountPresenceConfiguration(macID: id(1), accountID: id(2), ownerUID: 501, policy: tooLarge))
        }
    }
    func testPresenceStartupRoundTripKeepsDistinctAccountAndServices() throws {
        let wake = try root()
        let original = try AuthorityPresenceStartupConfiguration(wake: wake, ownerUID: 501, appServiceName: "dev.sebastiano.remozio.macos.presence",
            teamID: "TEAMID1234", appIdentifier: "dev.sebastiano.remozio.macos", appHashes: [id(7, count: 20)],
            policy: .init(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000))
        let decoded = try AuthorityPresenceStartupConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.presence.ownerUID, 501); XCTAssertEqual(decoded.presence.macID, wake.request.service.macID)
        XCTAssertEqual(decoded.presence.policy.idleMilliseconds, 120_000)
        XCTAssertEqual(decoded.endpoint.appPolicy.expectedUserID, 501)
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (2, .unsigned(0)), (2, .unsigned(401)), (2, .unsigned(402)),
            (2, .unsigned(UInt64(UInt32.max))), (3, .text(wake.request.service.serviceName)), (3, .text(wake.gatewayServiceName)),
            (7, .unsigned(0)), (8, .unsigned(60_001)), (9, .unsigned(60_001)), (10, .null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityPresenceStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testPublicPresenceClientConfigurationPinsRootAndRejectsMalformedMetadata() throws {
        let original = try AuthorityPresenceClientConfiguration(macID: id(1), accountID: id(2), ownerUID: 501,
            serviceName: "dev.sebastiano.remozio.macos.presence", teamID: "TEAMID1234", rootIdentifier: "dev.sebastiano.remozio.macos.authority", rootHashes: [id(7, count: 20)])
        let decoded = try AuthorityPresenceClientConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes); XCTAssertEqual(decoded.rootPolicy.expectedUserID, 0)
        XCTAssertEqual(decoded.ownerUID, 501)
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .bytes(id(1, count: 15))), (2, .bytes(id(2, count: 17))),
            (3, .unsigned(0)), (3, .unsigned(UInt64(UInt32.max))), (4, .text("other.presence")),
            (7, .array([.bytes(id(7, count: 20)), .bytes(id(7, count: 20))])), (8, .unsigned(0)), (8, .unsigned(60_001)), (9, .null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityPresenceClientConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }

    func testNormalAccountCannotOpenRootServiceOrReadPrivateStartupInputs() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Requires an unprivileged fixture") }
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.load(path: "/Library/Remozio/root/startup.cbor"))
        let presence = try AuthorityAccountPresenceConfiguration(macID: id(1), accountID: id(2), ownerUID: 501,
            policy: PresenceConfiguration(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 200))
        XCTAssertThrowsError(try AuthorityWakeService.open(configuration: root(), accountPresence: presence,
            appEndpoint: .init(serviceName: "dev.remozio.presence.test", appPolicy: .init(teamID: "ABCDEFGHIJ",
                componentIdentifier: "dev.remozio.app", approvedCodeDirectoryHashes: [Data(repeating: 8, count: 20)], expectedUserID: presence.ownerUID)),
            reconcileExpired: { _ in XCTFail("Wrong account reached presence cleanup") })) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
        XCTAssertThrowsError(try AuthorityWakeService.open(configuration: root(), routing: {
            XCTFail("Wrong account reached presence")
            throw AuthorityWakePublisherError.closed
        }, reconcileExpired: { _ in XCTFail("Wrong account reached request cleanup") })) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
    }
}
