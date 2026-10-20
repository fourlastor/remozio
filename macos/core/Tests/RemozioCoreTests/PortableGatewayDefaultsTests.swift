import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PortableGatewayDefaultsTests: XCTestCase {
    private var limits: CBORLimits { get throws { try .init(maxBytes: 65_536, maxDepth: 4, maxItems: 128) } }
    private func legacy() throws -> SharedSetupDefaults {
        try .init(presence: .init(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000),
            wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60),
            delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 100))
    }
    private func selection() throws -> GatewayRuntimeSettingsSelection {
        let base = try legacy()
        return try .init(service: .init(delivery: base.delivery,
            probe: .init(maximumAttempts: 5, minimumRetryDelayMillis: 1234, maximumTTLSeconds: 40), wake: base.wake,
            maximumOperations: 11, handshakeTimeoutMillis: 3456, authorityLeaseMillis: 9999,
            providerTimeoutSeconds: 44, schedulerRetryMillis: 2222, maximumStoredControls: 123,
            maximumPendingPerEnrollment: 7, maximumCandidateLifetimeMillis: 7777, databaseBusyMillis: 987),
            activation: .init(wakePollMilliseconds: 4321, wakeTimeoutMilliseconds: 6789),
            maximumWakeConnections: 13, maximumWakeOperations: 17, wakeChallengeLifetimeMilliseconds: 7999)
    }
    private func expanded() throws -> PortableSetup {
        try .init(defaults: .init(presence: legacy().presence, gateway: selection()))
    }
    private func fields(_ setup: PortableSetup) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(setup.canonicalBytes(), limits: limits) else {
            throw PortableSetupError.rejected
        }
        return fields
    }
    private func reject(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: bytes), file: file, line: line)
    }
    func testLegacySettingsKeepTheExactVersionOneFixtureAndDoNotInventMissingDefaults() throws {
        let setup = try PortableSetup(defaults: legacy())
        let hex = "a4000101a300831a0001d4c019138819753001851820031903e819ea60183c02840418641903e819ea6002f603f6"
        let chars = Array(hex)
        let expected = Data(stride(from: 0, to: chars.count, by: 2).map {
            UInt8(String(chars[$0...($0 + 1)]), radix: 16)!
        })
        XCTAssertEqual(try setup.canonicalBytes(), expected)
        let restored = try PortableSetup(canonicalBytes: expected)
        XCTAssertEqual(try restored.canonicalBytes(), expected); XCTAssertNil(restored.defaults.gateway)
        XCTAssertEqual(restored.preview.categories, [.sharedDefaults])
    }
    func testVersionTwoEncryptedRoundTripPreservesAllOperationalValuesAndPreviewsTheirScope() throws {
        let original = try expanded(), selected = try selection()
        let file = try original.encryptedFile(password: "synthetic settings export password")
        let restored = try PortableSetup(encryptedFile: file, password: "synthetic settings export password")
        XCTAssertEqual(try restored.defaults.gateway?.bytes, try selected.bytes)
        XCTAssertEqual(try restored.canonicalBytes(), try original.canonicalBytes())
        XCTAssertEqual(try fields(restored)[0], .unsigned(2))
        XCTAssertEqual(restored.preview.categories, [.sharedDefaults, .gatewayOperationalDefaults])
        XCTAssertNil(restored.fcm); XCTAssertNil(restored.cloudflare)
        XCTAssertThrowsError(try PortableSetup(encryptedFile: file, password: "different synthetic password"))
    }
    func testConflictingLegacyAndExpandedDefaultsCannotChooseDifferentEffectiveValues() throws {
        for key: UInt64 in [1, 2] {
            var root = try fields(expanded())
            guard case .map(var settings) = root[1], case .array(var numbers) = settings[key] else {
                return XCTFail("Fixture settings missing")
            }
            numbers[0] = .unsigned(key == 1 ? 33 : 2)
            settings[key] = .array(numbers); root[1] = .map(settings); try reject(root)
        }
    }
    func testVersionsCannotAcquireOrSilentlyDropTheExpandedSettingsField() throws {
        var root = try fields(expanded()); root[0] = .unsigned(1); try reject(root)
        root = try fields(expanded()); root[0] = .unsigned(3); try reject(root)
        root = try fields(expanded())
        guard case .map(var settings) = root[1] else { return XCTFail() }
        settings.removeValue(forKey: 3); root[1] = .map(settings); try reject(root)
        settings[3] = .null; root[1] = .map(settings); try reject(root)
    }
    func testExpandedSettingsRejectForeignPurposesAndEmbeddedDeviceState() throws {
        var root = try fields(expanded())
        guard case .map(var settings) = root[1] else { return XCTFail() }
        settings[3] = .bytes(try GatewayRuntimeActivationSettings().bytes); root[1] = .map(settings); try reject(root)
        let selected = try selection()
        guard case .map(var fields) = try DeterministicCBOR.decode(selected.bytes, limits: limits) else { return XCTFail() }
        fields[99] = .text("device-specific approval or bridge grant")
        settings[3] = .bytes(try DeterministicCBOR.encode(.map(fields), limits: limits)); root[1] = .map(settings)
        try reject(root)
    }
}
