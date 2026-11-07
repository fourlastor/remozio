import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimePhoneUpdateSchedulingCompatibilityTests: XCTestCase {
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let value) = try DeterministicCBOR.decode(bytes, limits: RuntimeActivationPlan.limits) else {
            throw RuntimeActivationError.invalidPlan
        }
        return value
    }
    private func release(_ f: RuntimeActivationFixture, edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneRouting: f.plan.phoneRoutingVersion != nil,
            phoneAudit: f.plan.phoneAuditVersion != nil, phoneUpdateScheduling: true, edit: edit)
    }
    private func replacing(_ component: ReleaseComponent, formats: [ReleaseFormat]? = nil, path: String? = nil) throws -> ReleaseComponent {
        try .init(role: component.role, identifier: component.identifier, generation: component.generation,
            relativePath: path ?? component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
            build: component.build, teamID: component.teamID, formats: formats ?? component.formats, requests: component.requests)
    }
    func testVersionFiveRetainsEachOptionalCodecWithoutChangingLegacyBytesOrJobs() throws {
        for routing in [false, true] {
            for audit in [false, true] {
                let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: routing, phoneAudit: audit, phoneUpdateScheduling: true)
                let bytes = try f.plan.encoded, decoded = try RuntimeActivationPlan.decode(bytes)
                XCTAssertEqual(decoded.formatVersion, 5); XCTAssertEqual(decoded.phoneUpdateSchedulingVersion, 1)
                XCTAssertEqual(try fields(bytes)[6], routing ? .unsigned(1) : .null)
                XCTAssertEqual(try fields(bytes)[7], audit ? .unsigned(1) : .null)
                XCTAssertEqual(try fields(bytes)[8], .unsigned(1)); XCTAssertEqual(try decoded.encoded, bytes)
                XCTAssertEqual(decoded.authorityJob.bytes, f.plan.authorityJob.bytes)
                XCTAssertEqual(decoded.transportJob.bytes, f.plan.transportJob.bytes)
                var legacy = try fields(bytes); legacy.removeValue(forKey: 8)
                legacy[0] = .unsigned(audit ? 4 : routing ? 3 : 2)
                if !audit { legacy.removeValue(forKey: 7) }
                if !audit && !routing { legacy.removeValue(forKey: 6) }
                let oldBytes = try DeterministicCBOR.encode(.map(legacy), limits: RuntimeActivationPlan.limits)
                let old = try RuntimeActivationPlan.decode(oldBytes)
                XCTAssertNil(old.phoneUpdateSchedulingVersion); XCTAssertEqual(try old.encoded, oldBytes)
                XCTAssertEqual(old.authorityJob.bytes, decoded.authorityJob.bytes)
                XCTAssertEqual(old.transportJob.bytes, decoded.transportJob.bytes)
                XCTAssertNil(bytes.range(of: f.material.transportIdentity))
            }
        }
    }
    func testProtectedReopenRetainsTheExactWireStorageAndPlanRequirements() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        try f.machine.retainRuntimeActivation(f.plan); try f.machine.close()
        let reopened = try f.f.open(); defer { try? reopened.close() }
        let retained = try reopened.runtimeActivation(accountID: f.account.accountID)
        XCTAssertEqual(retained.plan?.phoneUpdateSchedulingVersion, 1); XCTAssertFalse(retained.jobsRegistered)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: reopened)
        for required in try PhoneUpdateSchedulingReleaseContract.requirements {
            let actual = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == required.role && $0.name == required.name })
            XCTAssertTrue(required.readVersions.isSubset(of: actual.readVersions))
            XCTAssertTrue(required.writeVersions.isSubset(of: actual.writeVersions))
        }
        try snapshot.validate(release(f), policy: f.plan.host.codePolicy, machine: reopened)
    }
    func testEachMissingRequiredCodecPreventsUpdateAndLeavesRetainedStateUnchanged() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        try f.machine.retainRuntimeActivation(f.plan)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        for required in try PhoneUpdateSchedulingReleaseContract.requirements {
            let candidate = try release(f) { component in
                if component.role != required.role { return component }
                return try self.replacing(component, formats: component.formats.filter { $0.name != required.name })
            }
            XCTAssertThrowsError(try snapshot.validate(candidate, policy: f.plan.host.codePolicy, machine: f.machine))
            try snapshot.requireCurrent(machine: f.machine)
            XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
        }
    }
    func testLaterOnlyReadersAndMissingWritersCannotReplaceTheRetainedContract() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        try f.machine.retainRuntimeActivation(f.plan)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        for required in try PhoneUpdateSchedulingReleaseContract.requirements {
            for missingWriter in [false, true] {
                if missingWriter && required.writeVersions.isEmpty { continue }
                let candidate = try release(f) { component in
                    if component.role != required.role { return component }
                    return try self.replacing(component, formats: component.formats.map { old in
                        if old.name != required.name { return old }
                        return try ReleaseFormat(name: old.name,
                            readers: missingWriter ? old.readers : [required.readVersions.max()! + 1],
                            writers: missingWriter || old.writers.isEmpty ? [] : [required.readVersions.max()! + 1])
                    })
                }
                XCTAssertThrowsError(try snapshot.validate(candidate, policy: f.plan.host.codePolicy, machine: f.machine))
            }
        }
    }
    func testPartialDeclarationsAndUnexpectedExecutablePathsCannotSelectSupport() throws {
        XCTAssertThrowsError(try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true, releaseEdit: { component in
            if component.role != .transport { return component }
            return try self.replacing(component, formats: component.formats.filter { $0.name != "phone.update-scheduling-frame" })
        })) { XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingFormat(.transport, "phone.update-scheduling-frame")) }
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        for role: AuthorityCodeRole in [.authority, .transport] {
            let candidate = try release(f) { component in
                if component.role != role { return component }
                return try self.replacing(component, path: "Contents/Helpers/UnexpectedUpdateHost")
            }
            XCTAssertThrowsError(try PhoneUpdateSchedulingReleaseContract.validate(candidate, policy: f.plan.host.codePolicy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }
    func testBudgetAndLegacyPlansDoNotInferSchedulingAuthorityOrCodecs() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let signed = try XCTUnwrap(f.nativeRelease)
        for budget in [0, PhoneUpdateSchedulingFrame.maximumBytes - 1] {
            XCTAssertNil(try PhoneUpdateSchedulingReleaseContract.selectedVersion(in: signed, policy: f.plan.host.codePolicy,
                nativeHosts: true, maximumPayloadBytes: budget))
        }
        XCTAssertNil(try PhoneUpdateSchedulingReleaseContract.selectedVersion(in: signed, policy: f.plan.host.codePolicy,
            nativeHosts: false, maximumPayloadBytes: PhoneUpdateSchedulingFrame.maximumBytes))
        for (native, routing, audit) in [(false, false, false), (true, false, false), (true, true, false), (true, false, true)] {
            let old = try RuntimeActivationFixture(nativeConsumerHosts: native, phoneRouting: routing, phoneAudit: audit)
            XCTAssertNil(old.plan.phoneUpdateSchedulingVersion)
            try old.machine.retainRuntimeActivation(old.plan)
            let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: old.machine)
            XCTAssertFalse(snapshot.requirements.formats.contains { PhoneUpdateSchedulingReleaseContract.names.contains($0.name) })
        }
    }
    func testVersionFiveRejectsUnknownSelectorsMissingSlotsAndAdditionalFields() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let valid = try fields(f.plan.encoded)
        for slot: UInt64 in [6, 7, 8] {
            for invalid: CBORValue in [.unsigned(0), .unsigned(2), .bytes(Data()), .text("unknown")] {
                var value = valid; value[slot] = invalid
                XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(value), limits: RuntimeActivationPlan.limits)))
            }
            var missing = valid; missing.removeValue(forKey: slot)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(missing), limits: RuntimeActivationPlan.limits)))
        }
        var absent = valid; absent[8] = .null
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(absent), limits: RuntimeActivationPlan.limits)))
        var extra = valid; extra[9] = .unsigned(1)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(extra), limits: .init(maxBytes: 262144, maxDepth: 1, maxItems: 21))))
    }
}
