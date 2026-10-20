import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class TransportSettingsHostConfigurationTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 32)
    private func configuration(_ f: ConsumerHostMetadataFixture, host: GatewaySettingsConsumerHostConfiguration? = nil) throws -> TransportPairingStartupConfiguration {
        let base = f.f.plan.transport
        return try .init(transport: base.transport, control: base.control, relayPort: 52432, settingsHost: host)
    }
    func testLegacyCanonicalBytesStayExactAndTheNewHostRoundTripsSeparately() throws {
        let f = try ConsumerHostMetadataFixture(), legacy = try configuration(f), host = try f.host()
        let expected = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(legacy.transport.canonicalBytes),
            2: .null, 3: .unsigned(52432), 4: .bytes(legacy.control.canonicalBytes)]), limits: limits)
        XCTAssertEqual(legacy.canonicalBytes, expected); XCTAssertNoThrow(try legacy.requireLegacyStartup())
        let current = try configuration(f, host: host), restored = try TransportPairingStartupConfiguration.decode(current.canonicalBytes)
        XCTAssertEqual(restored.canonicalBytes, current.canonicalBytes); XCTAssertEqual(restored.settingsHost, host)
        XCTAssertEqual(restored.relayPort, 52432); XCTAssertNil(restored.wake)
        XCTAssertEqual(restored.transport.canonicalBytes, legacy.transport.canonicalBytes)
        XCTAssertEqual(restored.control.canonicalBytes, legacy.control.canonicalBytes)
        XCTAssertThrowsError(try current.requireLegacyStartup()) { XCTAssertEqual($0 as? TransportPairingControlError, .unsupportedVersion) }
    }
    func testHostCannotCrossRolesAccountsOrTransportKeys() throws {
        let f = try ConsumerHostMetadataFixture(), other = try ConsumerHostMetadataFixture()
        XCTAssertThrowsError(try configuration(f, host: f.host(.gateway)))
        XCTAssertThrowsError(try configuration(f, host: other.host()))
        let now = Date(), different = try RuntimePreparationMaterial.create(services: f.f.services,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600), serviceActivity: f.reference().serviceActivity)
        XCTAssertThrowsError(try configuration(f, host: f.host(runtime: different.reference)))
    }
    func testMissingNullMalformedAndDowngradedHostCannotFallBackToLegacy() throws {
        let f = try ConsumerHostMetadataFixture(), current = try configuration(f, host: f.host())
        guard case .map(let fields) = try DeterministicCBOR.decode(current.canonicalBytes, limits: limits) else { return XCTFail() }
        var variants: [[UInt64: CBORValue]] = []
        var changed = fields; changed[0] = .unsigned(1); variants.append(changed)
        changed = fields; changed[5] = nil; variants.append(changed)
        changed = fields; changed[5] = .null; variants.append(changed)
        changed = fields; changed[5] = .bytes(Data()); variants.append(changed)
        changed = fields; changed[6] = .null; variants.append(changed)
        changed = fields; changed[0] = .unsigned(3); variants.append(changed)
        for values in variants { XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(DeterministicCBOR.encode(.map(values), limits: limits))) }
    }
    func testWakeProposalsKeepTheImmutableHostAndForegroundRoutes() throws {
        let ready = try GatewaySettingsConsumerControlFixture(), runtime = ready.ready.fixture.runtime
        let activity = try ServiceReleaseActivityReference(services: runtime.services, identities: [
            .transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        let material = try RuntimePreparationMaterial(materialID: runtime.material.materialID, services: runtime.services,
            transportIdentity: runtime.material.transportIdentity, transportPublicKeyInfo: runtime.material.transportPublicKeyInfo,
            gateway: runtime.material.gateway, serviceActivity: activity)
        let host = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: material.reference,
            bundlePath: runtime.plan.bundlePath, codePolicy: runtime.plan.host.codePolicy)
        let base = runtime.plan.transport
        let initial = try TransportPairingStartupConfiguration(transport: base.transport, control: base.control, relayPort: 52432, settingsHost: host)
        let selected = try initial.replacingWake(XCTUnwrap(ready.plan.pair.transport.wake))
        XCTAssertEqual(selected.settingsHost, host); XCTAssertEqual(selected.relayPort, initial.relayPort)
        XCTAssertEqual(selected.transport.canonicalBytes, initial.transport.canonicalBytes)
        XCTAssertEqual(selected.control.canonicalBytes, initial.control.canonicalBytes)
        XCTAssertEqual(selected.wake?.canonicalBytes, ready.plan.pair.transport.wake?.canonicalBytes)
        XCTAssertEqual(try TransportPairingStartupConfiguration.decode(selected.canonicalBytes).settingsHost, host)
        XCTAssertThrowsError(try selected.requireLegacyStartup())
    }
}
