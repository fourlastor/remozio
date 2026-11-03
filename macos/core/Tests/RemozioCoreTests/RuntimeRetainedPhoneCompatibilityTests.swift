import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeRetainedPhoneCompatibilityTests: XCTestCase {
    func testCompatibilityRetainsTheActualActivationFormatWithoutAPendingUpgrade() throws {
        for audit in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: !audit, phoneAudit: audit)
            try f.machine.retainRuntimeActivation(f.plan)
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
            for role in [AuthorityCodeRole.authority, .setupController] {
                let format = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == RuntimeActivationPlan.formatName })
                XCTAssertTrue(format.readVersions.contains(f.plan.formatVersion))
            }
            try snapshot.validate(XCTUnwrap(f.nativeRelease), policy: f.plan.host.codePolicy, machine: f.machine)
            let missing = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneRouting: !audit, phoneAudit: audit) { component in
                guard component.role == .authority else { return component }
                let formats = try component.formats.map { format in
                    guard format.name == RuntimeActivationPlan.formatName else { return format }
                    return try ReleaseFormat(name: format.name, readers: format.readers.subtracting([f.plan.formatVersion]),
                        writers: format.writers.subtracting([f.plan.formatVersion]))
                }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
            }
            XCTAssertThrowsError(try snapshot.validate(missing, policy: f.plan.host.codePolicy, machine: f.machine)) {
                XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingReader(.authority, RuntimeActivationPlan.formatName, f.plan.formatVersion))
            }
        }
    }
    func testCompatibilityRetainsPhoneReadersWithoutAPendingUpgrade() throws {
        for audit in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: !audit, phoneAudit: audit)
            try f.machine.retainRuntimeActivation(f.plan)
            let contract = try audit ? PhoneAuditReleaseContract.requirements : PhoneRoutingReleaseContract.requirements
            let required = try XCTUnwrap(contract.first { $0.role == .transport && $0.name != RuntimeMaterialReference.formatName })
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
            let missing = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneRouting: !audit, phoneAudit: audit) { component in
                guard component.role == required.role else { return component }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: component.formats.filter { $0.name != required.name },
                    requests: component.requests)
            }
            XCTAssertThrowsError(try snapshot.validate(missing, policy: f.plan.host.codePolicy, machine: f.machine))
        }
    }
}
