import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

struct ConsumerHostMetadataFixture {
    let f: RuntimeActivationFixture
    init() throws { f = try .init() }
    func reference(services: ServiceAccountPlan? = nil) throws -> RuntimeMaterialReference {
        let services = services ?? f.services
        let activity = try ServiceReleaseActivityReference(services: services, identities: [
            .transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        return try RuntimePreparationMaterial(materialID: f.material.materialID, services: services,
            transportIdentity: f.material.transportIdentity, transportPublicKeyInfo: f.material.transportPublicKeyInfo,
            gateway: f.material.gateway, serviceActivity: activity).reference
    }
    func host(_ role: GatewaySettingsConsumerRole = .transport, runtime: RuntimeMaterialReference? = nil,
              policy: AuthorityCodePolicy? = nil, path: String? = nil) throws -> GatewaySettingsConsumerHostConfiguration {
        try .init(role: role, runtime: runtime ?? reference(), bundlePath: path ?? f.plan.bundlePath,
            codePolicy: policy ?? f.plan.host.codePolicy)
    }
    func release(edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let components = try f.plan.host.codePolicy.entries.map { entry in
            var formats: [ReleaseFormat] = []
            for role in GatewaySettingsConsumerRole.allCases where entry.role == role.codeRole || entry.role == .setupController {
                formats.append(try .init(name: role.formatName, readers: [1], writers: [1]))
            }
            if [.transport, .notificationGateway, .setupController].contains(entry.role) {
                let fenceWriters: Set<UInt64> = entry.role == .setupController ? GatewayRuntimeSettingsFence.supportedVersions : []
                formats.append(try .init(name: GatewayRuntimeSettingsFence.formatName,
                    readers: GatewayRuntimeSettingsFence.supportedVersions, writers: fenceWriters))
                formats.append(try .init(name: GatewaySettingsConsumerHostConfiguration.formatName,
                    readers: [1], writers: entry.role == .setupController ? [1] : []))
            }
            return try edit(.init(role: entry.role, identifier: entry.identifier, generation: entry.installedGeneration,
                relativePath: "Contents/Helpers/role-\(entry.role.rawValue)", codeDirectoryHash: entry.role == .app ? nil : entry.codeDirectoryHash,
                build: "1", teamID: entry.teamID, formats: formats))
        }
        return .init(manifest: try .init(release: "0.1.0", build: "1", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: components.map { c in
                (c.role, c.codeDirectoryHash ?? f.plan.host.codePolicy.entries.first { $0.role == c.role }!.codeDirectoryHash)
            }))
    }
    // Synthetic signature evidence checks format and scope decisions. It is not native Developer ID inspection.
    func host(_ role: GatewaySettingsConsumerRole, release: SignedReleaseEvidence) throws -> GatewaySettingsConsumerHostConfiguration {
        guard case .map(var fields) = try DeterministicCBOR.decode(f.services.encoded, limits: ServiceAccountPlan.limits) else {
            throw RuntimePreparationError.invalidRecord
        }
        fields[5] = .bytes(try InstallationInventory.digest(release))
        let services = try ServiceAccountPlan.decode(DeterministicCBOR.encode(.map(fields), limits: ServiceAccountPlan.limits))
        return try host(role, runtime: reference(services: services))
    }
}

final class GatewaySettingsConsumerHostConfigurationTests: XCTestCase {
    private let loose = try! CBORLimits(maxBytes: 65536, maxDepth: 5, maxItems: 128)
    private func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: loose) else { throw GatewayPreparationError.invalidRecord }; return fields
    }
    func testBothImmutableRoleRecordsRoundTripWithoutProviderSettingsOrSecrets() throws {
        let f = try ConsumerHostMetadataFixture()
        for role in GatewaySettingsConsumerRole.allCases {
            let host = try f.host(role), bytes = try host.encoded
            XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decode(bytes), host)
            XCTAssertEqual(host.activity.services, f.f.services)
            XCTAssertEqual(host.serviceUID, role == .transport ? 20000 : 20001)
            XCTAssertEqual(try host.serviceName, try role.serviceName(accountID: f.f.account.accountID))
            XCTAssertEqual(host.consumerCode.role, role.codeRole); XCTAssertEqual(host.setupCode.role, .setupController)
            XCTAssertNil(bytes.range(of: f.f.material.transportIdentity))
            XCTAssertEqual(String(reflecting: host), "GatewaySettingsConsumerHostConfiguration(redacted)")
            XCTAssertNoThrow(try host.validate(account: f.f.account, inventory: XCTUnwrap(f.f.machine.inventory())))
        }
        XCTAssertNotEqual(try f.host(.gateway).encoded, try f.host(.transport).encoded)
    }
    func testLegacyReferencesMissingSetupCodeAndUnsafeBundlePathsCannotClaimParticipation() throws {
        let f = try ConsumerHostMetadataFixture()
        XCTAssertThrowsError(try f.host(runtime: f.f.material.reference))
        let noSetup = try AuthorityCodePolicy(entries: f.f.plan.host.codePolicy.entries.filter { $0.role != .setupController })
        XCTAssertThrowsError(try f.host(policy: noSetup))
        for path in ["relative.app", "/Library/../Remozio.app", "/Library//Remozio.app", "/Library/Remozio.app/", "/Library/R\0.app"] {
            XCTAssertThrowsError(try f.host(path: path))
        }
    }
    func testMetadataIsClosedBoundedAndRejectsWrongPurposeVersionAndRole() throws {
        let f = try ConsumerHostMetadataFixture(), host = try f.host(), fields = try map(host.encoded)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("remozio-gateway-settings-consumer-binding")),
            (2, .unsigned(3)), (3, .bytes(Data())), (4, .text("relative.app")), (5, .bytes(Data())), (6, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: loose)))
        }
        for key in fields.keys {
            var changed = fields; changed[key] = nil
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: loose)))
        }
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(host.encoded + Data([0])))
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(Data(repeating: 0, count: 32769)))
    }
    func testRetainedAccountInstallationAndPolicyMustMatchBeforePublication() throws {
        let f = try ConsumerHostMetadataFixture(), other = try ConsumerHostMetadataFixture(), host = try f.host()
        XCTAssertThrowsError(try host.validate(account: other.f.account, inventory: XCTUnwrap(f.f.machine.inventory())))
        let original = try XCTUnwrap(f.f.machine.inventory())
        for changedInstallation in [true, false] {
            let changed = try InstallationInventory(macID: original.macID,
                installationID: changedInstallation ? Data(repeating: 99, count: 16) : original.installationID,
                revision: original.revision, bundlePath: original.bundlePath,
                releaseDigest: changedInstallation ? original.releaseDigest : Data(repeating: 99, count: 32),
                accounts: original.accounts, services: original.services, formatVersion: original.formatVersion)
            XCTAssertThrowsError(try host.validate(account: f.f.account, inventory: changed))
        }
        let alteredPolicy = try AuthorityCodePolicy(entries: f.f.plan.host.codePolicy.entries.map { code in
            try .init(role: code.role, teamID: code.teamID, identifier: code.identifier, installedGeneration: code.installedGeneration,
                minimumGeneration: code.minimumGeneration, codeDirectoryHash: code.role == .setupController ? Data(repeating: 99, count: 20) : code.codeDirectoryHash,
                active: code.active)
        })
        XCTAssertThrowsError(try f.host(policy: alteredPolicy).validate(account: f.f.account, inventory: original))
        let moved = try f.host(path: "/Library/Other.app")
        XCTAssertThrowsError(try moved.validate(account: f.f.account, inventory: XCTUnwrap(f.f.machine.inventory())))
    }
    func testExactReleaseRequiresTheRoleControlAndMetadataReaderAndSetupWriter() throws {
        let f = try ConsumerHostMetadataFixture(), release = try f.release()
        for role in GatewaySettingsConsumerRole.allCases {
            XCTAssertNoThrow(try f.host(role, release: release).validateRelease(release))
            for code in [role.codeRole, .setupController] {
                for mode in 0..<4 {
                    let changed = try f.release { component in
                        guard component.role == code else { return component }
                        let formats = try component.formats.compactMap { format -> ReleaseFormat? in
                            if mode == 0, format.name == role.formatName { return nil }
                            guard format.name == GatewaySettingsConsumerHostConfiguration.formatName else { return format }
                            if mode == 1 { return nil }
                            if mode == 2 { return try .init(name: format.name, readers: [2], writers: code == .setupController ? [2] : []) }
                            if mode == 3, code == .setupController { return try .init(name: format.name, readers: [1], writers: []) }
                            return format
                        }
                        return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                            relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                            build: component.build, teamID: component.teamID, formats: formats)
                    }
                    if mode == 3 && code != .setupController { continue }
                    let host = try f.host(role, release: changed)
                    XCTAssertThrowsError(try host.validateRelease(changed), "Missing role codec or metadata reader/writer must block native selection")
                }
            }
        }
    }
    func testReleaseDigestAndActualInspectedHashesCannotBeSubstituted() throws {
        let f = try ConsumerHostMetadataFixture(), release = try f.release()
        for role in GatewaySettingsConsumerRole.allCases {
            XCTAssertThrowsError(try f.host(role).validateRelease(release))
            let host = try f.host(role, release: release)
            var hashes = release.codeDirectoryHashes; hashes[role.codeRole] = Data(repeating: 99, count: 20)
            XCTAssertThrowsError(try host.validateRelease(.init(manifest: release.manifest, codeDirectoryHashes: hashes)))
            hashes = release.codeDirectoryHashes; hashes[.app] = nil
            XCTAssertThrowsError(try host.validateRelease(.init(manifest: release.manifest, codeDirectoryHashes: hashes)))
        }
    }
}
