import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateRestartSharedActivityTests: XCTestCase {
    private func directory(_ f: UpdateAdmissionTestFixture) throws -> ReleaseDestinationLease {
        try .init(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
    }
    private func restart(_ f: UpdateAdmissionTestFixture) throws -> UpdateRestartAdmissionLease {
        let owner = try UpdateActivationAdmission(anchor: f.activity.root.path,
            relativeDirectory: "Machine", owner: getuid(), expected: f.identity)
        return try XCTUnwrap(owner.automatic()).releaseActivityForRestart()
    }
    private func assertClosed(_ f: UpdateAdmissionTestFixture) {
        XCTAssertThrowsError(try f.open().acquireAdmission()) {
            XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
        }
    }
    private func assertReleased(_ f: UpdateAdmissionTestFixture) throws {
        let admission = try f.open().acquireAdmission()
        let activity = try f.activity.open().acquireExclusive()
        try admission.validate(); try activity.validateExclusive()
        activity.close(); admission.close()
    }
    func testClosingTheParentRevokesTheLoanButRetainsAdmissionUntilActualCleanup() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try restart(f), target = try directory(f)
        defer { target.close(); owner.close() }
        let loan = try owner.acquireSharedActivity(activity: f.activity.open(), directory: target, expected: f.identity)
        try loan.validate(); owner.close()
        XCTAssertThrowsError(try owner.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try loan.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        assertClosed(f)
        XCTAssertThrowsError(try f.activity.open().acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        loan.close(); loan.close()
        try assertReleased(f)
    }
    func testClosingDuringSharedReadinessRetainsBothLocksThroughTheCallback() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try restart(f), target = try directory(f)
        defer { target.close(); owner.close() }
        let loan = try owner.acquireSharedActivity(activity: f.activity.open(), directory: target, expected: f.identity)
        XCTAssertThrowsError(try loan.withClosedAdmission {
            owner.close(); loan.close(); assertClosed(f)
            XCTAssertThrowsError(try f.activity.open().acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
            return "not healthy"
        }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try assertReleased(f)
    }
    func testAForeignDirectoryCannotAcquireALoanOrLeakItsAdmissionCount() throws {
        let f = try UpdateAdmissionTestFixture(), other = try UpdateAdmissionTestFixture()
        let owner = try restart(f), foreign = try directory(other)
        defer { foreign.close(); owner.close() }
        XCTAssertThrowsError(try owner.acquireSharedActivity(activity: other.activity.open(), directory: foreign, expected: f.identity))
        try owner.withClosedAdmission { assertClosed(f) }
        owner.close(); try assertReleased(f)
        let otherActivity = try other.activity.open().acquireExclusive(); otherActivity.close()
    }
    func testEverySharedLoanMustCloseBeforeTheParentCanBorrowExclusiveActivity() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try restart(f), target = try directory(f)
        defer { target.close(); owner.close() }
        let one = try owner.acquireSharedActivity(activity: f.activity.open(), directory: target, expected: f.identity)
        let two = try owner.acquireSharedActivity(activity: f.activity.open(), directory: target, expected: f.identity)
        XCTAssertThrowsError(try owner.withClosedAdmission {}) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        one.close(); try two.validate(); assertClosed(f)
        XCTAssertThrowsError(try owner.withClosedAdmission {}) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        two.close()
        try owner.withExclusiveActivity(activity: f.activity.open(), directory: target, expected: f.identity) { token in
            try token.validateExclusive(in: target); assertClosed(f)
        }
        owner.close(); try assertReleased(f)
    }
}
