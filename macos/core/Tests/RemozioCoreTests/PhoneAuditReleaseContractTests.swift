import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PhoneAuditReleaseContractTests: XCTestCase {
    private func replacing(_ component: ReleaseComponent, formats: [ReleaseFormat]? = nil,
                           path: String? = nil) throws -> ReleaseComponent {
        try .init(role: component.role, identifier: component.identifier, generation: component.generation,
            relativePath: path ?? component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
            build: component.build, teamID: component.teamID, formats: formats ?? component.formats,
            requests: component.requests)
    }

    private func release(_ fixture: RuntimeActivationFixture, delivery: Bool = true,
                         edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let requirements = try PhoneAuditReleaseContract.requirements
            + (delivery ? PhoneAuditReleaseContract.deliveryRequirements : [])
        return try NativeHostReleaseFixture.make(policy: fixture.plan.host.codePolicy) { component in
            var formats = component.formats
            for required in requirements where required.role == component.role {
                if let index = formats.firstIndex(where: { $0.name == required.name }) {
                    let old = formats[index]
                    formats[index] = try .init(name: old.name, readers: old.readers.union(required.readVersions),
                        writers: old.writers.union(required.writeVersions))
                } else {
                    formats.append(try .init(name: required.name, readers: required.readVersions,
                        writers: required.writeVersions))
                }
            }
            return try edit(replacing(component, formats: formats))
        }
    }

    private func selectedReference(_ fixture: RuntimeActivationFixture) throws -> RuntimeMaterialReference {
        let old = try fixture.material.reference
        return try .init(materialID: old.materialID, services: old.services, materialDigest: old.materialDigest,
            transportPublicKeyInfo: old.transportPublicKeyInfo, gateway: old.gateway,
            serviceActivity: old.serviceActivity, auditDeliveryVersion: 1)
    }

    func testCompleteDeclarationsSelectFreshMaterialWithoutChangingAnExistingLegacySelection() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let candidate = try release(fixture), policy = fixture.plan.host.codePolicy
        XCTAssertEqual(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: candidate, policy: policy), 1)
        let selected = try selectedReference(fixture)
        XCTAssertEqual(try RuntimeAuditDeliverySupport.selectedVersion(reference: selected, release: candidate, policy: policy), 1)
        for native in [false, true] {
            let legacy = try RuntimeActivationFixture(nativeConsumerHosts: native).material.reference
            let before = try legacy.encoded
            XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: legacy, release: candidate, policy: policy))
            XCTAssertEqual(try legacy.encoded, before)
        }
    }

    func testCodecOnlyAndReaderOnlyReleasesKeepFreshMaterialDisabled() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let codecs = try release(fixture, delivery: false)
        XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: codecs, policy: policy))
        let readerOnly = try release(fixture) { component in
            guard component.role == .setupController else { return component }
            return try self.replacing(component, formats: component.formats.map { format in
                guard [RuntimeMaterialReference.formatName, RuntimePreparationMaterial.formatName].contains(format.name) else { return format }
                return try .init(name: format.name, readers: format.readers, writers: format.writers.subtracting([3]))
            })
        }
        XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: readerOnly, policy: policy))
        XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: selectedReference(fixture), release: readerOnly, policy: policy))
    }

    func testEveryRequiredReaderAndWriterMustSupportTheExactSelectedVersion() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        for required in try PhoneAuditReleaseContract.requirements + PhoneAuditReleaseContract.deliveryRequirements {
            for missingWriter in [false, true] {
                if missingWriter && required.writeVersions.isEmpty { continue }
                let candidate = try release(fixture) { component in
                    guard component.role == required.role else { return component }
                    return try self.replacing(component, formats: component.formats.map { format in
                        guard format.name == required.name else { return format }
                        let later: Set<UInt64> = [required.readVersions.max()! + 1]
                        return try .init(name: format.name,
                            readers: missingWriter ? format.readers : later,
                            writers: missingWriter ? format.writers.subtracting(required.writeVersions) : format.writers.isEmpty ? [] : later)
                    })
                }
                XCTAssertThrowsError(try PhoneAuditReleaseContract.validateDelivery(candidate, policy: policy), "\(required.role):\(required.name)")
            }
        }
    }

    func testEachMissingCodecAndPlanDeclarationBlocksTheContract() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        for required in try PhoneAuditReleaseContract.requirements {
            let candidate = try release(fixture) { component in
                guard component.role == required.role else { return component }
                return try self.replacing(component, formats: component.formats.filter { $0.name != required.name })
            }
            XCTAssertThrowsError(try PhoneAuditReleaseContract.validate(candidate, policy: policy))
        }
    }

    func testUnexpectedExecutablePathsCannotSatisfyTheContract() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        for role in [AuthorityCodeRole.authority, .transport] {
            let candidate = try release(fixture) { component in
                component.role == role ? try self.replacing(component, path: "Contents/Helpers/UnexpectedAuditHost") : component
            }
            XCTAssertThrowsError(try PhoneAuditReleaseContract.validate(candidate, policy: policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testInsufficientCapacityCannotDowngradeAnEstablishedSelection() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let candidate = try release(fixture), selected = try selectedReference(fixture)
        for budget in [0, PhoneAuditFrame.overheadBytes] {
            XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: candidate, policy: policy, maximumPayloadBytes: budget))
            XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: selected, release: candidate, policy: policy, maximumPayloadBytes: budget)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
        XCTAssertNil(try PhoneAuditReleaseContract.selectedVersion(in: candidate, policy: policy, nativeHosts: false, maximumPayloadBytes: 1024))
        XCTAssertEqual(try PhoneAuditReleaseContract.selectedVersion(in: candidate, policy: policy, nativeHosts: true, maximumPayloadBytes: 1024), 1)
    }

    func testChangedInstalledCodeCannotChooseTheLegacyFallback() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let original = try release(fixture), changedHash = Data(repeating: 99, count: 20)
        let components = try original.manifest.components.map { component in
            try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.role == .transport ? changedHash : component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: component.formats, requests: component.requests)
        }
        var hashes = original.codeDirectoryHashes
        hashes[.transport] = changedHash
        let changed = try SignedReleaseEvidence(manifest: .init(release: "0.1.0", build: "1", components: components), codeDirectoryHashes: hashes)
        XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: changed, policy: policy))
        XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: fixture.material.reference, release: changed, policy: policy))
    }

    func testMissingNativeHostFamilyCannotSelectFreshOrEstablishedAuditMaterial() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let names = Set([RuntimeActivationPlan.formatName, GatewaySettingsConsumerHostConfiguration.formatName,
            GatewayRuntimeSettingsFenceReleaseValidation.formatName] + GatewaySettingsConsumerRole.allCases.map(\.formatName))
        let legacy = try release(fixture) { component in
            try self.replacing(component, formats: component.formats.filter { !names.contains($0.name) })
        }
        XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: legacy, policy: policy))
        XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: selectedReference(fixture), release: legacy, policy: policy))
    }

    func testPartialFreshWritersCannotUpgradeLegacyMaterial() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let legacy = try fixture.material.reference, before = try legacy.encoded
        for missing in [RuntimeMaterialReference.formatName, RuntimePreparationMaterial.formatName] {
            let partial = try release(fixture) { component in
                guard component.role == .setupController else { return component }
                return try self.replacing(component, formats: component.formats.map { format in
                    guard format.name == missing else { return format }
                    return try .init(name: format.name, readers: format.readers, writers: format.writers.subtracting([3]))
                })
            }
            XCTAssertThrowsError(try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: partial, policy: policy))
            XCTAssertNil(try RuntimeAuditDeliverySupport.selectedVersion(reference: legacy, release: partial, policy: policy))
            XCTAssertEqual(try legacy.encoded, before)
        }
    }
}
