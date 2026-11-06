import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeReleaseConfigurationSourceTests: XCTestCase {
    private final class Fixture {
        let runtime: RuntimeActivationFixture
        let source: RuntimeReleaseConfigurationSource
        init() throws {
            runtime = try .init(nativeConsumerHosts: true)
            let initial = try XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID))
            let inventory = try XCTUnwrap(runtime.machine.inventory())
            let bundle = try runtime.plan.configurationBundle(account: runtime.account,
                initialization: initial, inventory: inventory)
            source = .init(host: runtime.plan.host, transport: runtime.plan.transport,
                gateway: try XCTUnwrap(runtime.plan.gatewaySettingsHost),
                clients: .init(presence: bundle.presenceClient, pairing: bundle.pairingClient,
                    frontend: bundle.frontendClient))
        }
    }
    private let limits = try! CBORLimits(maxBytes: 524288, maxDepth: 2, maxItems: 64)
    private func outer(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimeActivationError.invalidPlan
        }
        return fields
    }
    private func content(_ source: RuntimeReleaseConfigurationSource) throws -> [UInt64: CBORValue] {
        let fields = try outer(source.encoded)
        guard case .bytes(let bytes) = fields[2] else { throw RuntimeActivationError.invalidPlan }
        return try outer(bytes)
    }
    private func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private func wrapped(_ fields: [UInt64: CBORValue]) throws -> Data {
        try encode([0: .unsigned(1), 1: .text(RuntimeReleaseConfigurationSource.formatName),
            2: .bytes(encode(fields))])
    }
    func testRoundTripPreservesAllSixOriginalConfigurationPayloads() throws {
        let fixture = try Fixture(), source = fixture.source
        let decoded = try RuntimeReleaseConfigurationSource.decode(source.encoded)
        XCTAssertEqual(decoded.host.canonicalBytes, source.host.canonicalBytes)
        XCTAssertEqual(decoded.transport.canonicalBytes, source.transport.canonicalBytes)
        XCTAssertEqual(try decoded.gateway.encoded, try source.gateway.encoded)
        XCTAssertEqual(decoded.clients.presence.canonicalBytes, source.clients.presence.canonicalBytes)
        XCTAssertEqual(decoded.clients.pairing.canonicalBytes, source.clients.pairing.canonicalBytes)
        XCTAssertEqual(decoded.clients.frontend.canonicalBytes, source.clients.frontend.canonicalBytes)
        XCTAssertEqual(try decoded.encoded, try source.encoded)
        XCTAssertEqual(try decoded.digest, try source.digest)
    }
    func testDigestUsesTheOriginalDomainAndExactContentBytes() throws {
        let fixture = try Fixture(), source = fixture.source
        let bytes = try encode(content(source))
        let expected = MachineUpdateActivationRecord.digest(
            Data("Remozio/RuntimeReleaseConfigurationSource/v1\0".utf8) + bytes)
        XCTAssertEqual(try source.digest, expected)
        XCTAssertNotEqual(try source.digest, MachineUpdateActivationRecord.digest(try source.encoded))
    }
    func testChangingAnyOfTheSixPayloadsChangesTheDigest() throws {
        let first = try Fixture(), second = try Fixture()
        let a = first.source, b = second.source
        let changed: [RuntimeReleaseConfigurationSource] = [
            .init(host: b.host, transport: a.transport, gateway: a.gateway, clients: a.clients),
            .init(host: a.host, transport: b.transport, gateway: a.gateway, clients: a.clients),
            .init(host: a.host, transport: a.transport, gateway: b.gateway, clients: a.clients),
            .init(host: a.host, transport: a.transport, gateway: a.gateway,
                clients: .init(presence: b.clients.presence, pairing: a.clients.pairing, frontend: a.clients.frontend)),
            .init(host: a.host, transport: a.transport, gateway: a.gateway,
                clients: .init(presence: a.clients.presence, pairing: b.clients.pairing, frontend: a.clients.frontend)),
            .init(host: a.host, transport: a.transport, gateway: a.gateway,
                clients: .init(presence: a.clients.presence, pairing: a.clients.pairing, frontend: b.clients.frontend))
        ]
        for value in changed { XCTAssertNotEqual(try value.digest, try a.digest) }
    }
    func testMissingAndUnknownOuterFieldsAreRejected() throws {
        let fixture = try Fixture(), fields = try outer(fixture.source.encoded)
        for key in fields.keys {
            var missing = fields; missing.removeValue(forKey: key)
            XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(encode(missing)))
        }
        var unknown = fields; unknown[3] = .null
        XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(encode(unknown)))
    }
    func testWrongVersionsAndNamesAreRejected() throws {
        let fixture = try Fixture(), fields = try outer(fixture.source.encoded)
        for version in [UInt64(0), 2, UInt64.max] {
            var changed = fields; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(encode(changed)))
        }
        var changed = fields; changed[1] = .text("runtime.release-configuration")
        XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(encode(changed)))
    }
    func testMissingAndUnknownContentFieldsAreRejected() throws {
        let fixture = try Fixture(), fields = try content(fixture.source)
        for key in fields.keys {
            var missing = fields; missing.removeValue(forKey: key)
            XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(wrapped(missing)))
        }
        var unknown = fields; unknown[6] = .bytes(Data([1]))
        XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(wrapped(unknown)))
    }
    func testEveryContentFieldMustContainAConfigurationPayload() throws {
        let fixture = try Fixture(), fields = try content(fixture.source)
        for key in fields.keys {
            for replacement in [CBORValue.null, .unsigned(1), .text("configuration")] {
                var changed = fields; changed[key] = replacement
                XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(wrapped(changed)))
            }
        }
    }
    func testMalformedNestedConfigurationsAreRejected() throws {
        let fixture = try Fixture(), fields = try content(fixture.source)
        for key in fields.keys {
            var changed = fields; changed[key] = .bytes(Data([0xff]))
            XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(wrapped(changed)))
        }
    }
    func testEmptyTrailingAndOversizedRecordsAreRejected() throws {
        let fixture = try Fixture()
        for bytes in [Data(), try fixture.source.encoded + Data([0]),
            Data(repeating: 0, count: RuntimeReleaseConfigurationSource.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeReleaseConfigurationSource.decode(bytes))
        }
    }
    func testReadsAndRoundTripsLeaveTheRetainedSourceUnchanged() throws {
        let fixture = try Fixture(), source = fixture.source
        let before = try source.encoded, digest = try source.digest
        for _ in 0..<3 {
            _ = try RuntimeReleaseConfigurationSource.decode(source.encoded)
            XCTAssertEqual(try source.encoded, before)
            XCTAssertEqual(try source.digest, digest)
        }
    }
}
