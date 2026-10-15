import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeActivationStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private func fixture() throws -> RuntimeActivationFixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner SQLite fixture") }
        return try .init()
    }
    func testIntentEnrollmentAndRegistrationAreSeparateMonotonicTransitions() throws {
        let f = try fixture(), original = try XCTUnwrap(f.machine.inventory())
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
        XCTAssertNil(try f.machine.runtimeActivation(accountID: f.account.accountID).plan)
        try f.machine.retainRuntimeActivation(f.plan)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 7)
        XCTAssertEqual(try f.machine.inventory(), original)
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
        XCTAssertThrowsError(try f.machine.markRuntimeJobsRegistered(f.plan))
        let enrolled = try f.machine.enrollRuntimeActivation(f.plan)
        XCTAssertNotEqual(enrolled.revision, original.revision)
        XCTAssertEqual(try f.machine.enrollRuntimeActivation(f.plan), enrolled)
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
        try f.machine.markRuntimeJobsRegistered(f.plan); try f.machine.retainRuntimeActivation(f.plan)
        try f.machine.markRuntimeJobsRegistered(f.plan)
        let done = try f.machine.runtimeActivation(accountID: f.account.accountID)
        XCTAssertTrue(done.jobsRegistered); XCTAssertEqual(try done.plan?.encoded, try f.plan.encoded)
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID).reference, f.plan.reference)
        XCTAssertEqual(try f.machine.inventory(), enrolled)
    }
    func testInventoryEnrollmentCannotRunWithoutRetainedIntent() throws {
        let f = try fixture(), original = try f.machine.inventory()
        XCTAssertThrowsError(try f.machine.enrollRuntimeActivation(f.plan))
        XCTAssertEqual(try f.machine.inventory(), original); XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
    }
    func testAChangedPlanCannotReplaceTheEstablishedIntentOrEnrollment() throws {
        let f = try fixture()
        try f.machine.retainRuntimeActivation(f.plan)
        // Same account, identity and release, but a different installation path is not a repair choice.
        let original = try XCTUnwrap(f.machine.inventory())
        let changed = try InstallationInventory(macID: original.macID, installationID: original.installationID,
            revision: original.revision, bundlePath: "/Library/Other.app", releaseDigest: original.releaseDigest,
            accounts: original.accounts, services: original.services, formatVersion: original.formatVersion)
        _ = try f.machine.writeInventory(changed, expectedRevision: original.revision)
        XCTAssertThrowsError(try f.machine.retainRuntimeActivation(f.plan)) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
        XCTAssertThrowsError(try f.machine.enrollRuntimeActivation(f.plan))
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
    }
    func testLostCommitRepliesRetainIntentEnrollmentAndRegistrationOnReopen() throws {
        for stage in 0...2 {
            let f = try fixture()
            if stage > 0 { try f.machine.retainRuntimeActivation(f.plan) }
            if stage > 1 { _ = try f.machine.enrollRuntimeActivation(f.plan) }
            try f.machine.close()
            var armed = false
            let writer = try f.f.open(hook: { if armed { throw Interrupted() } }); armed = true
            XCTAssertThrowsError(try {
                switch stage {
                case 0: try writer.retainRuntimeActivation(f.plan)
                case 1: _ = try writer.enrollRuntimeActivation(f.plan)
                default: try writer.markRuntimeJobsRegistered(f.plan)
                }
            }()) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertThrowsError(try writer.runtimeActivation(accountID: f.account.accountID)); try writer.close()
            let restored = try f.f.open(); defer { try? restored.close() }
            let result = try restored.runtimeActivation(accountID: f.account.accountID)
            XCTAssertEqual(try result.plan?.encoded, try f.plan.encoded); XCTAssertEqual(result.jobsRegistered, stage == 2)
            XCTAssertEqual(try XCTUnwrap(restored.inventory()).accounts.isEmpty, stage == 0)
            try restored.retainRuntimeActivation(f.plan)
            _ = try restored.enrollRuntimeActivation(f.plan); try restored.markRuntimeJobsRegistered(f.plan)
            XCTAssertTrue(try restored.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
        }
    }
    func testCorruptRecordsAndMismatchedIndexesRetireTheConnection() throws {
        for change in ["UPDATE runtime_activation_v1 SET record=x'00'", "UPDATE runtime_activation_v1 SET digest=zeroblob(32)",
                       "UPDATE runtime_activation_v1 SET material=zeroblob(16)"] {
            let f = try fixture(); try f.machine.retainRuntimeActivation(f.plan); _ = try f.f.sql(change)
            XCTAssertThrowsError(try f.machine.runtimeActivation(accountID: f.account.accountID)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            XCTAssertThrowsError(try f.machine.runtimeActivation(accountID: f.account.accountID)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertEqual(try f.f.sql("SELECT COUNT(*) FROM runtime_activation_v1"), 1)
        }
    }
}
