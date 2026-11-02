import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned SQLite and synthetic releases exercise admission. They do not prove installed service health.
final class RuntimeActivationCapabilityTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 32)

    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimeActivationError.invalidPlan
        }
        return fields
    }

    private func encoded(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: limits)
    }

    func testLegacyPlansKeepTheirExactFieldsAndBytes() throws {
        for native in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: native)
            var expected: [UInt64: CBORValue] = [0: .unsigned(native ? 2 : 1),
                1: .bytes(try f.material.reference.encoded), 2: .text(f.plan.bundlePath),
                3: .bytes(f.plan.host.canonicalBytes), 4: .bytes(f.plan.transport.canonicalBytes)]
            if let gateway = f.plan.gatewaySettingsHost { expected[5] = .bytes(try gateway.encoded) }
            let bytes = try f.plan.encoded
            XCTAssertEqual(bytes, try encoded(expected))
            XCTAssertEqual(try RuntimeActivationPlan.decode(bytes).encoded, bytes)
            XCTAssertNil(f.plan.phoneRoutingVersion)
            XCTAssertNil(f.plan.phoneAuditVersion)
            XCTAssertEqual(f.plan.host.command.presence.wake.request.service.auditVersions, [])
        }
    }

    func testRoutingSelectionRetainsSchemaThreeAndExactCodecVersion() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true)
        let bytes = try f.plan.encoded, record = try fields(bytes)
        XCTAssertEqual(f.plan.formatVersion, 3)
        XCTAssertEqual(Set(record.keys), Set(UInt64(0)...6))
        XCTAssertEqual(record[6], .unsigned(1))
        XCTAssertEqual(f.plan.phoneRoutingVersion, 1)
        XCTAssertNil(f.plan.phoneAuditVersion)
        XCTAssertEqual(try RuntimeActivationPlan.decode(bytes).encoded, bytes)
    }

    func testAuditCodecSelectionDoesNotAdmitDelivery() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true)
        let bytes = try f.plan.encoded, record = try fields(bytes)
        XCTAssertEqual(f.plan.formatVersion, 4)
        XCTAssertEqual(Set(record.keys), Set(UInt64(0)...7))
        XCTAssertEqual(record[6], .null)
        XCTAssertEqual(record[7], .unsigned(1))
        XCTAssertNil(f.material.auditDeliveryVersion)
        XCTAssertEqual(f.plan.host.command.presence.wake.request.service.auditVersions, [])
        XCTAssertEqual(try RuntimeActivationPlan.decode(bytes).encoded, bytes)
    }

    func testSelectedDeliveryRebuildsTheSameAdmittedConfiguration() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true)
        let decoded = try RuntimeActivationPlan.decode(f.plan.encoded)
        let bundle = try decoded.configurationBundle(account: f.account,
            initialization: XCTUnwrap(f.machine.initialization(accountID: f.account.accountID)),
            inventory: XCTUnwrap(f.machine.inventory()))
        XCTAssertEqual(decoded.phoneAuditVersion, 1)
        XCTAssertEqual(decoded.reference.auditDeliveryVersion, 1)
        XCTAssertEqual(decoded.host.command.presence.wake.request.service.auditVersions, [1])
        XCTAssertEqual(bundle.command.canonicalBytes, decoded.host.command.canonicalBytes)
        XCTAssertEqual(bundle.transport.canonicalBytes, decoded.transport.canonicalBytes)
        XCTAssertEqual(try decoded.encoded, try f.plan.encoded)
    }

    func testCombinedSelectionKeepsBothVersionsAcrossSQLiteReopen() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true, auditDelivery: true)
        let bytes = try f.plan.encoded
        try f.machine.retainRuntimeActivation(f.plan)
        try f.machine.close()
        let reopened = try f.f.open()
        defer { try? reopened.close() }
        let state = try reopened.runtimeActivation(accountID: f.account.accountID)
        let retained = try XCTUnwrap(state.plan)
        XCTAssertFalse(state.jobsRegistered)
        XCTAssertEqual(retained.formatVersion, 4)
        XCTAssertEqual(retained.phoneRoutingVersion, 1)
        XCTAssertEqual(retained.phoneAuditVersion, 1)
        XCTAssertEqual(try retained.encoded, bytes)
        XCTAssertEqual(retained.authorityJob.declaration, f.plan.authorityJob.declaration)
        XCTAssertEqual(retained.transportJob.declaration, f.plan.transportJob.declaration)
    }

    func testUnknownVersionsMissingFieldsAndExtraFieldsFailClosed() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true)
        let original = try fields(f.plan.encoded)
        for version in [UInt64(0), 5, 6, 7, UInt64.max] {
            var changed = original; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(changed)))
        }
        for key in [UInt64(5), 6, 7] {
            var changed = original; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(changed)))
        }
        var extra = original; extra[8] = .null
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(extra)))
    }

    func testRoutingAndAuditVersionsCannotBeZeroLaterOrWronglyTyped() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true)
        let original = try fields(f.plan.encoded)
        for key in [UInt64(6), 7] {
            for value in [CBORValue.unsigned(0), .unsigned(2), .text("1"), .bytes(Data([1]))] {
                var changed = original; changed[key] = value
                XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(changed)))
            }
        }
        var missingAudit = original; missingAudit[7] = .null
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(missingAudit)))
        let routing = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true)
        var missingRouting = try fields(routing.plan.encoded); missingRouting[6] = .null
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(missingRouting)))
    }

    func testRetainedDeliveryCannotDecodeAsALegacyOrRoutingOnlyPlan() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true, auditDelivery: true)
        var record = try fields(f.plan.encoded)
        record[0] = .unsigned(3); record.removeValue(forKey: 7)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(record)))
        record[0] = .unsigned(2); record.removeValue(forKey: 6)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(record)))
    }

    func testNewSchemasCannotBorrowTheLegacyHostConfiguration() throws {
        let legacy = try RuntimeActivationFixture()
        let native = try RuntimeActivationFixture(nativeConsumerHosts: true)
        var record = try fields(legacy.plan.encoded)
        record[0] = .unsigned(3)
        record[5] = .bytes(try XCTUnwrap(native.plan.gatewaySettingsHost).encoded)
        record[6] = .unsigned(1)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(record)))
        record[0] = .unsigned(4); record[6] = .null; record[7] = .unsigned(1)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(encoded(record)))
    }

    func testDeliveryNeedsBothAuditCodecsAndMaterialCapabilities() throws {
        XCTAssertThrowsError(try RuntimeActivationFixture(nativeConsumerHosts: true,
            auditDelivery: true, materialAuditDelivery: true))
        XCTAssertThrowsError(try RuntimeActivationFixture(nativeConsumerHosts: true,
            phoneAudit: true, materialAuditDelivery: true))
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertThrowsError(try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
                auditDelivery: true, releaseEdit: { component in
                    guard component.role == role else { return component }
                    let formats = try component.formats.map { format in
                        guard format.name == RuntimeActivationPlan.formatName else { return format }
                        return try ReleaseFormat(name: format.name, readers: format.readers.subtracting([4]),
                            writers: format.writers.subtracting([4]))
                    }
                    return try .init(role: component.role, identifier: component.identifier,
                        generation: component.generation, relativePath: component.relativePath,
                        codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                        teamID: component.teamID, formats: formats, requests: component.requests)
                }))
        }
    }
}
