import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// In-memory material only. No fixture here migrates a retained SQLite reference, publishes files or restarts a service.
final class RuntimeAuditMaterialUpgradeTests: XCTestCase {
    private func legacy(_ f: AuditMaterialUpgradeFixture, native: Bool = true) throws -> RuntimePreparationMaterial {
        try .init(materialID: f.material.materialID, services: f.services, transportIdentity: f.material.transportIdentity,
            transportPublicKeyInfo: f.material.transportPublicKeyInfo, gateway: f.material.gateway,
            serviceActivity: native ? f.material.serviceActivity : nil)
    }
    private func upgrade(_ f: AuditMaterialUpgradeFixture, _ source: RuntimePreparationMaterial,
                         expected: RuntimeMaterialReference? = nil, activity: ServiceReleaseActivityReference? = nil,
                         release: SignedReleaseEvidence? = nil, policy: AuthorityCodePolicy? = nil,
                         budget: Int = AuthorityServiceConfiguration.defaultMaximumPayloadBytes) throws -> RuntimePreparationMaterial {
        try RuntimeAuditMaterialUpgrade.prepare(material: source, expected: expected ?? source.reference,
            account: f.account, activity: activity ?? XCTUnwrap(f.material.serviceActivity),
            installedRelease: release ?? XCTUnwrap(f.nativeRelease), policy: policy ?? f.policy, maximumPayloadBytes: budget)
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: .init(maxBytes: 65536, maxDepth: 1, maxItems: 32)) else {
            throw RuntimePreparationError.invalidRecord
        }
        return fields
    }
    func testBothLegacySchemasUpgradeWithoutReplacingAnyKeyOrIdentity() throws {
        let f = try AuditMaterialUpgradeFixture()
        for native in [false, true] {
            let original = try legacy(f, native: native), before = try original.encoded
            let target = try upgrade(f, original)
            XCTAssertEqual(target.formatVersion, 3); XCTAssertEqual(target.auditDeliveryVersion, 1)
            XCTAssertEqual(target.materialID, original.materialID); XCTAssertEqual(target.services, original.services)
            XCTAssertEqual(target.transportIdentity, original.transportIdentity)
            XCTAssertEqual(target.transportPublicKeyInfo, original.transportPublicKeyInfo)
            XCTAssertEqual(target.gateway, original.gateway)
            XCTAssertEqual(target.serviceActivity, f.material.serviceActivity)
            var expectedFields = try fields(before)
            expectedFields[0] = .unsigned(3); expectedFields[7] = .bytes(try XCTUnwrap(f.material.serviceActivity).encoded)
            expectedFields[8] = .unsigned(1)
            XCTAssertEqual(try fields(target.encoded), expectedFields)
            XCTAssertEqual(try original.encoded, before)
            XCTAssertEqual(try RuntimePreparationMaterial.decode(target.encoded).reference, try target.reference)
            XCTAssertNotEqual(try target.reference.materialDigest, try original.reference.materialDigest)
        }
    }
    func testAlreadySelectedMaterialIsByteIdenticalButStillNeedsCurrentCapabilities() throws {
        let f = try AuditMaterialUpgradeFixture()
        XCTAssertEqual(try upgrade(f, f.material).encoded, try f.material.encoded)
        XCTAssertThrowsError(try upgrade(f, f.material, budget: PhoneAuditFrame.overheadBytes))
    }
    func testWrongRetainedReferenceOrAccountCannotProduceAMigration() throws {
        let f = try AuditMaterialUpgradeFixture()
        let other = try AuditMaterialUpgradeFixture()
        let source = try legacy(f)
        XCTAssertThrowsError(try upgrade(f, source, expected: f.material.reference)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
        }
        XCTAssertThrowsError(try upgrade(f, source, expected: other.material.reference))
        XCTAssertThrowsError(try RuntimeAuditMaterialUpgrade.prepare(material: source, expected: source.reference,
            account: other.account, activity: XCTUnwrap(f.material.serviceActivity), installedRelease: XCTUnwrap(f.nativeRelease),
            policy: f.policy))
    }
    func testExistingActivityCannotBeReplacedAndForeignServiceClaimsCannotBeIntroduced() throws {
        let f = try AuditMaterialUpgradeFixture()
        let source = try legacy(f)
        let changed = try ServiceReleaseActivityReference(services: f.services,
            identities: [.transport: .init(device: 1, inode: 200), .gateway: .init(device: 1, inode: 201)])
        XCTAssertThrowsError(try upgrade(f, source, activity: changed)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
        }
        let other = try AuditMaterialUpgradeFixture()
        XCTAssertThrowsError(try upgrade(f, legacy(f, native: false), activity: other.material.serviceActivity))
    }
    func testChangedReleaseMetadataCannotBorrowAnInstalledPolicy() throws {
        let f = try AuditMaterialUpgradeFixture()
        let changed = try AuditMaterialUpgradeFixture { c in
            try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: "changed", teamID: c.teamID, formats: c.formats, requests: c.requests)
        }
        XCTAssertThrowsError(try upgrade(f, legacy(f), release: changed.nativeRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }
    func testCodecOnlyAndPartialWriterReleasesDoNotEnableLegacyMaterial() throws {
        let codec = try AuditMaterialUpgradeFixture(delivery: false)
        XCTAssertThrowsError(try upgrade(codec, codec.material)) { XCTAssertEqual($0 as? RuntimePreparationError, .incomplete) }
        let partial = try AuditMaterialUpgradeFixture(delivery: false, edit: { c in
            guard c.role == .setupController else { return c }
            let formats = try c.formats.map { value in
                guard value.name == RuntimeMaterialReference.formatName else { return value }
                return try ReleaseFormat(name: value.name, readers: value.readers.union([3]), writers: value.writers.union([3]))
            }
            return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
        })
        XCTAssertThrowsError(try upgrade(partial, partial.material))
    }
    func testCurrentSecurityFloorsCannotFallBackToTheAccountInitialPolicy() throws {
        let f = try AuditMaterialUpgradeFixture()
        let current = try AuthorityCodePolicy(entries: f.policy.entries.map { entry in
            try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                installedGeneration: 2, minimumGeneration: 2, codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
        })
        XCTAssertThrowsError(try upgrade(f, legacy(f), policy: current)) {
            guard case ReleaseGenerationPreflightError.rollback = $0 else { return XCTFail("Current floors must reject the retained older release") }
        }
    }
    func testUnavailableCapacityDoesNotChangeTheOriginalMaterial() throws {
        let f = try AuditMaterialUpgradeFixture()
        let source = try legacy(f), before = try source.encoded
        for budget in [0, PhoneAuditFrame.overheadBytes] {
            XCTAssertThrowsError(try upgrade(f, source, budget: budget)) { XCTAssertEqual($0 as? RuntimePreparationError, .incomplete) }
        }
        XCTAssertEqual(try source.encoded, before)
        XCTAssertNil(source.auditDeliveryVersion)
        XCTAssertEqual(String(describing: try upgrade(f, source)), "RuntimePreparationMaterial(redacted)")
    }
}
