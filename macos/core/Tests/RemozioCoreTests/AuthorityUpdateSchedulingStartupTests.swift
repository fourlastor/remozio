import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityUpdateSchedulingStartupTests: XCTestCase {
    private struct Failed: Error {}
    private func selection(_ f: RuntimeActivationFixture, plan: RuntimeActivationPlan? = nil,
        configuration: InstalledAuthorityCommandConfiguration? = nil, release: SignedReleaseEvidence? = nil,
        bundlePath: String? = nil) throws -> AuthorityUpdateSchedulingStartupSelection? {
        try .capture(plan: plan ?? f.plan, configuration: configuration ?? f.plan.host,
            release: release ?? XCTUnwrap(f.nativeRelease), bundlePath: bundlePath ?? f.plan.bundlePath)
    }
    func testCompiledDeclarationsDoNotEnableAnUnselectedOrMissingRetainedPlan() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertNil(try selection(f))
        XCTAssertNil(try AuthorityUpdateSchedulingStartupSelection.capture(plan: nil, configuration: f.plan.host,
            release: XCTUnwrap(f.nativeRelease), bundlePath: f.plan.bundlePath))
    }
    func testSelectedPlanBindsTheFullRetainedBytesAndCurrentInstalledRelease() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let selected = try XCTUnwrap(selection(f))
        try selected.requireCurrent(plan: f.plan, configuration: f.plan.host, release: XCTUnwrap(f.nativeRelease), bundlePath: f.plan.bundlePath)
        XCTAssertEqual(try selection(f), selected)
        try f.machine.retainRuntimeActivation(f.plan)
        XCTAssertEqual(try selection(f, plan: f.machine.runtimeActivation(accountID: f.account.accountID).plan), selected)
    }
    func testForeignBundleOrHostCannotEnableOrReuseTheStartupSelection() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let other = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        XCTAssertThrowsError(try selection(f, bundlePath: f.plan.bundlePath + ".other"))
        XCTAssertThrowsError(try selection(f, configuration: other.plan.host))
        let selected = try XCTUnwrap(selection(f))
        XCTAssertThrowsError(try selected.requireCurrent(plan: other.plan, configuration: other.plan.host,
            release: XCTUnwrap(other.nativeRelease), bundlePath: other.plan.bundlePath))
    }
    func testPartialSignedCodecDeclarationsCannotEnableTheStartupSelection() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let release = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneUpdateScheduling: true) { c in
            try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID,
                formats: c.formats.filter { $0.name != "update.scheduling-control" }, requests: c.requests)
        }
        XCTAssertThrowsError(try selection(f, release: release))
    }
    func testRetainedPlanReplacementCannotReuseThePriorStartupSelection() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let selected = try XCTUnwrap(selection(f))
        guard case .map(var fields) = try DeterministicCBOR.decode(f.plan.encoded, limits: RuntimeActivationPlan.limits) else { return XCTFail() }
        fields.removeValue(forKey: 8); fields.removeValue(forKey: 7); fields.removeValue(forKey: 6); fields[0] = .unsigned(2)
        let legacy = try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(fields), limits: RuntimeActivationPlan.limits))
        XCTAssertThrowsError(try selected.requireCurrent(plan: legacy, configuration: f.plan.host,
            release: XCTUnwrap(f.nativeRelease), bundlePath: f.plan.bundlePath))
    }
    func testUnavailableStartupStateStaysDistinctFromUnsupportedAndSelected() throws {
        let unsupported = AuthorityUpdateSchedulingStartupSnapshot { nil }
        let unavailable = AuthorityUpdateSchedulingStartupSnapshot { throw Failed() }
        XCTAssertEqual(unsupported, .unsupported); XCTAssertEqual(unavailable, .unavailable)
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneUpdateScheduling: true)
        let selected = try XCTUnwrap(selection(f))
        XCTAssertEqual(AuthorityUpdateSchedulingStartupSnapshot { selected }, .selected(selected))
    }
}
