import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeMaterialAuditCodecTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 64)

    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let value) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimePreparationError.invalidRecord
        }
        return value
    }

    private func fixture(native: Bool = true, audit: UInt64? = nil,
        _ body: (AccountPreparationFixture, PreparationIntentStore, RuntimePreparationMaterial, AuthorityCodePolicy, SignedReleaseEvidence) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner metadata fixture") }
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway,
            .commandFrontend, .commandMonitor, .commandChild, .setupController]
        let policy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        let release = try NativeHostReleaseFixture.make(policy: policy)
        let f = try AccountPreparationFixture(policy: policy, releaseDigest: InstallationInventory.digest(release))
        let machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
        try machine.retainServiceAccountPlan(services)
        try machine.completeServiceAccountPlan(services)
        let activity: ServiceReleaseActivityReference? = native ? try .init(services: services,
            identities: [.transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)]) : nil
        let now = Date()
        let material = try RuntimePreparationMaterial.create(services: services,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
            serviceActivity: activity, auditDeliveryVersion: audit)
        try machine.retainRuntimeMaterial(material.reference)
        try machine.completeRuntimePublication(material.reference)
        try body(f, machine, material, policy, release)
    }

    func testLegacyVersionsRoundTripWithoutSelectingAuditDelivery() throws {
        for native in [false, true] {
            try fixture(native: native) { _, _, material, _, _ in
                let version: UInt64 = native ? 2 : 1
                let reference = try material.reference
                XCTAssertEqual(material.formatVersion, version)
                XCTAssertEqual(reference.formatVersion, version)
                XCTAssertNil(material.auditDeliveryVersion)
                XCTAssertNil(reference.auditDeliveryVersion)
                XCTAssertEqual(try fields(material.encoded)[0], .unsigned(version))
                XCTAssertEqual(try fields(reference.encoded)[0], .unsigned(version))
                XCTAssertEqual(try RuntimePreparationMaterial.decode(material.encoded).encoded, try material.encoded)
                XCTAssertEqual(try RuntimeMaterialReference.decode(reference.encoded), reference)
            }
        }
    }

    func testVersionThreeRoundTripsAndKeepsPrivateIdentityOutOfTheReference() throws {
        try fixture(audit: 1) { _, _, material, _, _ in
            let reference = try material.reference
            XCTAssertEqual(material.formatVersion, 3)
            XCTAssertEqual(reference.formatVersion, 3)
            XCTAssertEqual(try RuntimePreparationMaterial.decode(material.encoded).reference, reference)
            XCTAssertEqual(try RuntimeMaterialReference.decode(reference.encoded), reference)
            XCTAssertEqual(reference.materialDigest, Data(SHA256.hash(data: try material.encoded)))
            XCTAssertNil(try reference.encoded.range(of: material.transportIdentity))
            XCTAssertEqual(String(reflecting: material), "RuntimePreparationMaterial(redacted)")
            XCTAssertEqual(String(reflecting: reference), "RuntimeMaterialReference(redacted)")
            XCTAssertEqual(try fields(material.encoded)[8], .unsigned(1))
            XCTAssertEqual(try fields(reference.encoded)[7], .unsigned(1))
        }
    }

    func testAuditSelectionRequiresActivityAndRejectsOtherVersions() throws {
        try fixture { _, _, material, _, _ in
            for selection in [UInt64(0), 2, .max] {
                XCTAssertThrowsError(try RuntimeMaterialReference(materialID: material.materialID,
                    services: material.services, materialDigest: Data(repeating: 1, count: 32),
                    transportPublicKeyInfo: material.transportPublicKeyInfo, gateway: material.gateway,
                    serviceActivity: material.serviceActivity, auditDeliveryVersion: selection))
                XCTAssertThrowsError(try RuntimePreparationMaterial(materialID: material.materialID,
                    services: material.services, transportIdentity: material.transportIdentity,
                    transportPublicKeyInfo: material.transportPublicKeyInfo, gateway: material.gateway,
                    serviceActivity: material.serviceActivity, auditDeliveryVersion: selection))
            }
            XCTAssertThrowsError(try RuntimeMaterialReference(materialID: material.materialID,
                services: material.services, materialDigest: Data(repeating: 1, count: 32),
                transportPublicKeyInfo: material.transportPublicKeyInfo, gateway: material.gateway,
                auditDeliveryVersion: 1))
            XCTAssertThrowsError(try RuntimePreparationMaterial(materialID: material.materialID,
                services: material.services, transportIdentity: material.transportIdentity,
                transportPublicKeyInfo: material.transportPublicKeyInfo, gateway: material.gateway,
                auditDeliveryVersion: 1))
        }
    }

    func testVersionThreeRejectsUnknownMissingAndNoncanonicalFields() throws {
        try fixture(audit: 1) { _, _, material, _, _ in
            for secret in [false, true] {
                let bytes = try secret ? material.encoded : material.reference.encoded
                let selection: UInt64 = secret ? 8 : 7
                let original = try fields(bytes)
                let decode: (Data) throws -> Void = { bytes in
                    if secret { _ = try RuntimePreparationMaterial.decode(bytes) }
                    else { _ = try RuntimeMaterialReference.decode(bytes) }
                }
                var missing = original
                missing.removeValue(forKey: selection)
                XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(missing), limits: limits)))
                var noActivity = original
                noActivity.removeValue(forKey: selection - 1)
                XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(noActivity), limits: limits)))
                for (key, value): (UInt64, CBORValue) in [(0, .unsigned(4)), (selection, .unsigned(0)),
                    (selection, .unsigned(2)), (selection, .null), (selection + 1, .null)] {
                    var changed = original
                    changed[key] = value
                    XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
                }
                XCTAssertThrowsError(try decode(bytes + Data([0])))
            }
        }
    }

    func testRetainedAuditMaterialRequiresVersionThreeReaders() throws {
        try fixture(audit: 1) { _, machine, _, policy, release in
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
            XCTAssertThrowsError(try snapshot.validate(release, policy: policy, machine: machine)) {
                XCTAssertEqual($0 as? ReleaseCompatibilityError,
                    .missingReader(.authority, RuntimePreparationMaterial.formatName, 3))
            }
            let names = Set([RuntimeMaterialReference.formatName, RuntimePreparationMaterial.formatName])
            let current = try NativeHostReleaseFixture.make(policy: policy) { component in
                let formats = try component.formats.map { format in
                    guard names.contains(format.name) else { return format }
                    return try ReleaseFormat(name: format.name, readers: format.readers.union([3]),
                        writers: component.role == .setupController ? format.writers.union([3]) : format.writers)
                }
                return try .init(role: component.role, identifier: component.identifier,
                    generation: component.generation, relativePath: component.relativePath,
                    codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: formats, requests: component.requests)
            }
            XCTAssertNoThrow(try snapshot.validate(current, policy: policy, machine: machine))
        }
    }

    func testReopenedAuditMaterialKeepsTransportConfigurationAtVersionTwo() throws {
        try fixture(audit: 1) { f, machine, material, _, _ in
            let reference = try material.reference
            try machine.close()
            let reopened = try f.open()
            defer { try? reopened.close() }
            XCTAssertEqual(try reopened.runtimePreparation(accountID: material.services.accountID).reference, reference)
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: reopened)
            for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
                let format = try XCTUnwrap(snapshot.requirements.formats.first {
                    $0.role == role && $0.name == RuntimeMaterialReference.formatName
                })
                XCTAssertTrue(format.readVersions.contains(3))
            }
            for role in [AuthorityCodeRole.transport, .setupController] {
                let format = try XCTUnwrap(snapshot.requirements.formats.first {
                    $0.role == role && $0.name == "transport.pairing-config"
                })
                XCTAssertEqual(format.readVersions, [2])
            }
        }
    }
}
