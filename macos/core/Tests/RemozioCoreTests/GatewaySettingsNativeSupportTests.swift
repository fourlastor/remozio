import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySettingsNativeSupportTests: XCTestCase {
    private func legacy(_ f: RuntimeActivationFixture, activationOne: Bool = false) throws -> SignedReleaseEvidence {
        let names = Set([RuntimeActivationPlan.formatName, GatewaySettingsConsumerHostConfiguration.formatName,
            GatewayRuntimeSettingsFenceReleaseValidation.formatName] + GatewaySettingsConsumerRole.allCases.map(\.formatName))
        return try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy) { c in
            var formats = c.formats.filter { !names.contains($0.name) }
            if activationOne && [.authority, .setupController].contains(c.role) {
                formats.append(try .init(name: RuntimeActivationPlan.formatName, readers: [1], writers: [1]))
            }
            return try .init(role: c.role, identifier: c.identifier, generation: c.generation,
                relativePath: c.relativePath, codeDirectoryHash: c.codeDirectoryHash,
                build: c.build, teamID: c.teamID, formats: formats)
        }
    }
    func testCompleteNativeFamilySelectsActivityOnlyForFreshOrAlreadyNativeMaterial() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), old = try RuntimeActivationFixture()
        let release = try XCTUnwrap(f.nativeRelease), mode = try GatewaySettingsNativeSupport.mode(release: release, policy: f.plan.host.codePolicy)
        XCTAssertEqual(mode, .native)
        XCTAssertTrue(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: nil, mode: mode))
        XCTAssertTrue(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: f.material.reference, mode: mode))
        XCTAssertFalse(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: old.material.reference, mode: mode))
        XCTAssertEqual(try old.plan.encoded, try RuntimeActivationPlan.decode(old.plan.encoded).encoded)
    }
    func testLegacyAndActivationOneDeclarationsKeepTheirExistingModeWithoutImplicitParticipation() throws {
        let f = try RuntimeActivationFixture()
        for one in [false, true] {
            let mode = try GatewaySettingsNativeSupport.mode(release: legacy(f, activationOne: one), policy: f.plan.host.codePolicy)
            XCTAssertEqual(mode, .legacy)
            XCTAssertFalse(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: nil, mode: mode))
            XCTAssertFalse(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: f.material.reference, mode: mode))
        }
    }
    func testEveryPartialNativeMarkerFailsInsteadOfSelectingLegacyMode() throws {
        let f = try RuntimeActivationFixture()
        let markers = [GatewaySettingsConsumerHostConfiguration.formatName, RuntimeActivationPlan.formatName,
            GatewayRuntimeSettingsFenceReleaseValidation.formatName] + GatewaySettingsConsumerRole.allCases.map(\.formatName)
        let base = try legacy(f)
        for marker in markers {
            let components = try base.manifest.components.map { c in
                guard c.role == .authority else { return c }
                let version: UInt64 = marker == GatewaySettingsConsumerHostConfiguration.formatName ? 1 : 2
                return try ReleaseComponent(role: c.role, identifier: c.identifier, generation: c.generation,
                    relativePath: c.relativePath, codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID,
                    formats: c.formats + [.init(name: marker, readers: [version], writers: [version])])
            }
            let release = try SignedReleaseEvidence(manifest: .init(release: "0.1.0", build: "1", components: components),
                codeDirectoryHashes: base.codeDirectoryHashes)
            XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: release, policy: f.plan.host.codePolicy), marker)
        }
    }
    func testCurrentCodeHashesAndInstalledGenerationsRemainRequiredEvenForLegacySelection() throws {
        let f = try RuntimeActivationFixture(), base = try legacy(f)
        var hashes = base.codeDirectoryHashes; hashes[.transport] = Data(repeating: 99, count: 20)
        XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: .init(manifest: base.manifest, codeDirectoryHashes: hashes),
            policy: f.plan.host.codePolicy))
        let components = try base.manifest.components.map { c in
            try ReleaseComponent(role: c.role, identifier: c.identifier, generation: c.role == .transport ? 2 : c.generation,
                relativePath: c.relativePath, codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: c.formats)
        }
        let changed = try SignedReleaseEvidence(manifest: .init(release: "0.1.0", build: "1", components: components), codeDirectoryHashes: base.codeDirectoryHashes)
        XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: changed, policy: f.plan.host.codePolicy))
    }
    func testNativeMaterialCannotBeDowngradedByALegacyReleaseAndWrongRolePathsCannotSelectNativeMode() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertThrowsError(try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: f.material.reference, mode: .legacy))
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            let changed = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy) { c in
                guard c.role == role else { return c }
                return try .init(role: c.role, identifier: c.identifier, generation: c.generation,
                    relativePath: "Contents/Helpers/wrong", codeDirectoryHash: c.codeDirectoryHash,
                    build: c.build, teamID: c.teamID, formats: c.formats)
            }
            XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: changed, policy: f.plan.host.codePolicy))
        }
    }
    func testNativeModeRequiresAllFiveActiveProtocolParticipantsInTheRetainedPolicy() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), release = try XCTUnwrap(f.nativeRelease)
        for role in [AuthorityCodeRole.app, .authority, .transport, .notificationGateway, .setupController] {
            let missing = try AuthorityCodePolicy(entries: f.plan.host.codePolicy.entries.filter { $0.role != role })
            XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: release, policy: missing))
            let inactive = try AuthorityCodePolicy(entries: f.plan.host.codePolicy.entries.map { value in
                try .init(role: value.role, teamID: value.teamID, identifier: value.identifier,
                    installedGeneration: value.installedGeneration, minimumGeneration: value.minimumGeneration,
                    codeDirectoryHash: value.codeDirectoryHash, active: value.role == role ? false : value.active)
            })
            XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: release, policy: inactive))
        }
    }

}
