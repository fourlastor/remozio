import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeCodecTests: XCTestCase {
    private let envelopeLimits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 17)

    private func target(_ f: RuntimeActivationFixture, digest: Data = Data(repeating: 91, count: 32),
                        materialID: Data? = nil, key: Data? = nil) throws -> RuntimeMaterialReference {
        let source = try f.material.reference
        let activity = try source.serviceActivity ?? ServiceReleaseActivityReference(services: source.services,
            identities: [.transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        return try .init(materialID: materialID ?? source.materialID, services: source.services,
            materialDigest: digest, transportPublicKeyInfo: key ?? source.transportPublicKeyInfo,
            gateway: source.gateway, serviceActivity: activity, auditDeliveryVersion: 1)
    }

    private func intent(_ f: RuntimeActivationFixture) throws -> RuntimeAuditUpgradeIntent {
        try .init(source: f.material.reference, target: target(f), policy: f.plan.host.codePolicy)
    }

    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let value) = try DeterministicCBOR.decode(bytes, limits: envelopeLimits) else {
            throw RuntimePreparationError.invalidRecord
        }
        return value
    }

    func testBothLegacySourcesRoundTripWithoutChangingRetainedMaterial() throws {
        for native in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: native)
            let before = try f.material.reference.encoded, value = try intent(f)
            XCTAssertEqual(try RuntimeAuditUpgradeIntent.decode(value.encoded), value)
            XCTAssertEqual(try f.material.reference.encoded, before)
            XCTAssertNil(f.material.auditDeliveryVersion)
            XCTAssertEqual(value.target.auditDeliveryVersion, 1)
            XCTAssertEqual(value.source.services, value.target.services)
        }
    }

    func testEveryRecordPhaseRoundTripsWithPublicMetadataOnly() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), value = try intent(f)
        for phase in [RuntimeAuditUpgradeRecord.Phase.retained, .materialStaged] {
            let record = try RuntimeAuditUpgradeRecord(intent: value, phase: phase)
            let bytes = try record.encoded
            XCTAssertEqual(try RuntimeAuditUpgradeRecord.decode(bytes), record)
            XCTAssertNil(bytes.range(of: f.material.transportIdentity))
            XCTAssertEqual(String(describing: record), "RuntimeAuditUpgradeRecord(redacted)")
            XCTAssertEqual(String(reflecting: record), "RuntimeAuditUpgradeRecord(redacted)")
            XCTAssertEqual(String(describing: value), "RuntimeAuditUpgradeIntent(redacted)")
            XCTAssertEqual(String(reflecting: value), "RuntimeAuditUpgradeIntent(redacted)")
        }
    }

    func testPolicyDigestBindsExactPolicyBytes() throws {
        let f = try RuntimeActivationFixture(), value = try intent(f), policy = f.plan.host.codePolicy
        XCTAssertEqual(value.policyDigest, Data(SHA256.hash(data:
            Data("Remozio audit upgrade policy v1\0".utf8) + (try policy.bytes))))
        XCTAssertNoThrow(try value.validate(policy: policy))
        let changed = try AuthorityCodePolicy(entries: policy.entries.map { entry in
            try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                installedGeneration: 2, minimumGeneration: 2,
                codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
        })
        XCTAssertThrowsError(try value.validate(policy: changed)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testUpgradeRejectsAnAuditSourceOrAnUnchangedTarget() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let source = try f.material.reference, audit = try target(f)
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(source: audit, target: audit, policy: f.plan.host.codePolicy))
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(source: source, target: source, policy: f.plan.host.codePolicy))
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(source: source,
            target: target(f, digest: source.materialDigest), policy: f.plan.host.codePolicy))
    }

    func testUpgradeRejectsChangedMaterialAndTransportIdentity() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let source = try f.material.reference
        let other = try RuntimePreparationMaterial.create(services: source.services,
            notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(600),
            serviceActivity: source.serviceActivity)
        for changed in [try target(f, materialID: AccountPreparationIntent.randomID()),
                        try target(f, key: other.transportPublicKeyInfo)] {
            XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(source: source,
                target: changed, policy: f.plan.host.codePolicy))
        }
        let second = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(source: source,
            target: target(second), policy: f.plan.host.codePolicy))
    }

    func testIntentRejectsMalformedFieldsAndIdentifierLengths() throws {
        let f = try RuntimeActivationFixture(), value = try intent(f), original = try fields(value.encoded)
        for (key, replacement): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other")),
            (2, .bytes(Data())), (2, .bytes(Data(repeating: 1, count: 17))),
            (3, .bytes(Data())), (4, .bytes(Data())), (5, .bytes(Data(repeating: 1, count: 31))), (5, .null)] {
            var changed = original
            changed[key] = replacement
            XCTAssertThrowsError(try RuntimeAuditUpgradeIntent.decode(
                DeterministicCBOR.encode(.map(changed), limits: envelopeLimits)))
        }
        for key in original.keys {
            var missing = original
            missing.removeValue(forKey: key)
            XCTAssertThrowsError(try RuntimeAuditUpgradeIntent.decode(
                DeterministicCBOR.encode(.map(missing), limits: envelopeLimits)))
        }
        var extra = original
        extra[6] = .null
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent.decode(
            DeterministicCBOR.encode(.map(extra), limits: envelopeLimits)))
    }

    func testRecordRejectsUnknownPhasesVersionsAndRevisionLengths() throws {
        let f = try RuntimeActivationFixture(), value = try intent(f)
        let original = try fields(RuntimeAuditUpgradeRecord(intent: value, phase: .retained).encoded)
        for (key, replacement): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .bytes(Data())),
            (2, .unsigned(0)), (2, .unsigned(3)), (2, .null),
            (3, .bytes(Data())), (3, .bytes(Data(repeating: 1, count: 17)))] {
            var changed = original
            changed[key] = replacement
            XCTAssertThrowsError(try RuntimeAuditUpgradeRecord.decode(
                DeterministicCBOR.encode(.map(changed), limits: envelopeLimits)))
        }
        for key in original.keys {
            var missing = original
            missing.removeValue(forKey: key)
            XCTAssertThrowsError(try RuntimeAuditUpgradeRecord.decode(
                DeterministicCBOR.encode(.map(missing), limits: envelopeLimits)))
        }
        var extra = original
        extra[4] = .null
        XCTAssertThrowsError(try RuntimeAuditUpgradeRecord.decode(
            DeterministicCBOR.encode(.map(extra), limits: envelopeLimits)))
    }

    func testDecodersRejectTrailingBytesAndOversizedInput() throws {
        let f = try RuntimeActivationFixture(), value = try intent(f)
        let record = try RuntimeAuditUpgradeRecord(intent: value, phase: .retained)
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent.decode(value.encoded + Data([0])))
        XCTAssertThrowsError(try RuntimeAuditUpgradeRecord.decode(record.encoded + Data([0])))
        XCTAssertThrowsError(try RuntimeAuditUpgradeIntent.decode(Data(repeating: 0, count: 20481)))
        XCTAssertThrowsError(try RuntimeAuditUpgradeRecord.decode(Data(repeating: 0, count: 24577)))
    }

    func testIntentAndRevisionRejectInvalidDirectConstruction() throws {
        let f = try RuntimeActivationFixture(), value = try intent(f)
        for count in [0, 15, 17, 32] {
            XCTAssertThrowsError(try RuntimeAuditUpgradeIntent(id: Data(repeating: 1, count: count),
                source: value.source, target: value.target, policy: f.plan.host.codePolicy))
            XCTAssertThrowsError(try RuntimeAuditUpgradeRecord(intent: value, phase: .retained,
                revision: Data(repeating: 1, count: count)))
        }
    }
}
