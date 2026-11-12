import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeActivationCompatibilityProjectionTests: XCTestCase {
    func testOrdinaryVersionsKeepTheirExactBytesAndRequirements() throws {
        for version in UInt64(1)...5 {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: version >= 2,
                phoneRouting: version == 3, phoneAudit: version == 4, phoneUpdateScheduling: version == 5)
            let plan = f.plan, bytes = try plan.encoded
            let projection = try RuntimeActivationCompatibilityProjection.decode(bytes)
            guard case .ordinary = projection else { return XCTFail("Ordinary plans must keep their type") }
            XCTAssertEqual(projection.formatVersion, version)
            XCTAssertEqual(try projection.encoded, bytes)
            XCTAssertEqual(projection.reference, plan.reference)
            XCTAssertEqual(projection.host.canonicalBytes, plan.host.canonicalBytes)
            XCTAssertEqual(projection.phoneRoutingVersion, plan.phoneRoutingVersion)
            XCTAssertEqual(projection.phoneAuditVersion, plan.phoneAuditVersion)
            XCTAssertEqual(projection.phoneUpdateSchedulingVersion, plan.phoneUpdateSchedulingVersion)
            try f.machine.retainRuntimeActivation(plan)
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
            for role in [AuthorityCodeRole.authority, .setupController] {
                let activation = try XCTUnwrap(snapshot.requirements.formats.first {
                    $0.role == role && $0.name == RuntimeActivationPlan.formatName
                })
                XCTAssertTrue(activation.readVersions.contains(version))
                XCTAssertTrue(role != .setupController || activation.writeVersions.contains(version))
                let host = try XCTUnwrap(snapshot.requirements.formats.first {
                    $0.role == role && $0.name == "authority.command-host-config"
                })
                XCTAssertEqual(host.readVersions, [version >= 2 ? 3 : 2])
            }
        }
    }

    func testTypedV6KeepsEveryPhoneChoiceAndActualHostRequirement() throws {
        let f = try RetainedSetupActivationArchiveTests.Fixture()
        for mask in 0..<8 {
            var fields = f.fields
            for bit in 0..<3 { fields[UInt64(6 + bit)] = mask & (1 << bit) == 0 ? .null : .unsigned(1) }
            let bytes = try f.bytes(fields), plan = try RuntimeRetainedSetupActivationPlan.decode(bytes)
            let projection = try RuntimeActivationCompatibilityProjection.decode(bytes)
            guard case .retained = projection else { return XCTFail("V6 must keep its retained type") }
            XCTAssertEqual(try projection.encoded, bytes)
            XCTAssertEqual(projection.reference, plan.reference)
            XCTAssertEqual(projection.host.canonicalBytes, plan.host.canonicalBytes)
            XCTAssertEqual(projection.phoneRoutingVersion, plan.phoneRoutingVersion)
            XCTAssertEqual(projection.phoneAuditVersion, plan.phoneAuditVersion)
            XCTAssertEqual(projection.phoneUpdateSchedulingVersion, plan.phoneUpdateSchedulingVersion)
            let inputs = RuntimeReleaseCompatibilitySnapshot.Inputs(schemaVersion: 7,
                macID: plan.reference.services.macID, inventory: plan.retainedSetupInventory.canonicalBytes,
                runtimes: [.init(reference: plan.reference, configurationPublished: true,
                    activationRecord: bytes, jobsRegistered: false)], gateways: [])
            let formats = try RuntimeReleaseCompatibilitySnapshot.describe(inputs: inputs).requirements.formats
            for requirement in try RuntimeRetainedSetupReleaseBinding.requirements {
                let actual = try XCTUnwrap(formats.first { $0.role == requirement.role && $0.name == requirement.name })
                XCTAssertTrue(requirement.readVersions.isSubset(of: actual.readVersions))
                XCTAssertTrue(requirement.writeVersions.isSubset(of: actual.writeVersions))
            }
            let selected = [(mask & 1 != 0, try PhoneRoutingReleaseContract.requirements),
                (mask & 2 != 0, try PhoneAuditReleaseContract.requirements),
                (mask & 4 != 0, try PhoneUpdateSchedulingReleaseContract.requirements)]
            let baseline = try GatewaySettingsNativeHostPlan.releaseRequirements.formats +
                RuntimeRetainedSetupReleaseBinding.requirements + MachineUpdatePreflightCompatibility.retainedSetupActivationRequirements
            let expectedFormats = baseline + selected.filter { $0.0 }.flatMap { $0.1 }
            for role in [AuthorityCodeRole.authority, .setupController] {
                let expected = expectedFormats.filter { $0.role == role && $0.name == RuntimeActivationPlan.formatName }
                let actual = try XCTUnwrap(formats.first { $0.role == role && $0.name == RuntimeActivationPlan.formatName })
                XCTAssertTrue(actual.readVersions.contains(RuntimeRetainedSetupActivationArchive.formatVersion))
                XCTAssertEqual(actual.readVersions, Set(expected.flatMap { $0.readVersions }))
                XCTAssertEqual(actual.writeVersions, Set(expected.flatMap { $0.writeVersions }))
                XCTAssertEqual(formats.first { $0.role == role && $0.name == "authority.command-host-config" }?.readVersions,
                    [plan.host.formatVersion])
            }
            for (enabled, requirements) in selected where enabled {
                for requirement in requirements {
                    let actual = try XCTUnwrap(formats.first { $0.role == requirement.role && $0.name == requirement.name })
                    XCTAssertTrue(requirement.readVersions.isSubset(of: actual.readVersions))
                    XCTAssertTrue(requirement.writeVersions.isSubset(of: actual.writeVersions))
                }
            }
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(bytes))
            XCTAssertThrowsError(try RuntimeActivationState.Plan(encoded: bytes))
            XCTAssertFalse(formats.contains { $0.name == MachineUpdateAuthorityReadinessDeclaration.formatName })
        }
        let original = f.host
        let host = try InstalledAuthorityCommandConfiguration(machineDirectory: original.machineDirectory,
            installationID: original.installationID, releaseDigest: original.releaseDigest, codePolicy: original.codePolicy,
            command: original.command, label: original.label, plistName: original.plistName, jobPlacement: original.jobPlacement,
            gatewaySettingsControlEnabled: true, installedReadinessEnabled: true)
        let archive = try RuntimeRetainedSetupActivationArchive(reference: f.source.reference, bundlePath: f.gateway.bundlePath,
            host: host, transport: f.transport, gatewaySettingsHost: f.gateway, phoneRoutingVersion: nil,
            phoneAuditVersion: nil, phoneUpdateSchedulingVersion: nil, binding: f.binding, inventory: f.inventory)
        let bytes = try archive.encoded
        XCTAssertEqual(try RuntimeActivationCompatibilityProjection.decode(bytes).host.formatVersion, 4)
        let inputs = RuntimeReleaseCompatibilitySnapshot.Inputs(schemaVersion: 7, macID: archive.reference.services.macID,
            inventory: archive.inventory.canonicalBytes, runtimes: [.init(reference: archive.reference,
                configurationPublished: true, activationRecord: bytes, jobsRegistered: false)], gateways: [])
        let formats = try RuntimeReleaseCompatibilitySnapshot.describe(inputs: inputs).requirements.formats
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertEqual(formats.first { $0.role == role && $0.name == "authority.command-host-config" }?.readVersions, [3, 4])
        }
        let readiness = try XCTUnwrap(formats.first {
            $0.role == .authority && $0.name == MachineUpdateAuthorityReadinessDeclaration.formatName
        })
        XCTAssertEqual(readiness.readVersions, [MachineUpdateAuthorityReadinessDeclaration.version])
        XCTAssertEqual(readiness.writeVersions, [MachineUpdateAuthorityReadinessDeclaration.version])
    }

    func testProjectionRejectsUnknownMalformedAndNoncanonicalRecords() throws {
        let f = try RetainedSetupActivationArchiveTests.Fixture(), valid = try f.bytes()
        XCTAssertNoThrow(try RuntimeActivationCompatibilityProjection.decode(valid))
        for version in [UInt64(0), 7, UInt64.max] {
            var fields = f.fields; fields[0] = .unsigned(version)
            XCTAssertThrowsError(try RuntimeActivationCompatibilityProjection.decode(f.bytes(fields)))
        }
        for key in f.fields.keys {
            var fields = f.fields; fields[key] = nil
            XCTAssertThrowsError(try RuntimeActivationCompatibilityProjection.decode(f.bytes(fields)))
        }
        for bytes in [Data(), valid + Data([0]), Data(repeating: 0, count: RuntimeRetainedSetupActivationPlan.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeActivationCompatibilityProjection.decode(bytes))
        }
    }
}
