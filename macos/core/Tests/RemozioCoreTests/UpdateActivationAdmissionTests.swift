import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateActivationAdmissionTests: XCTestCase {
    private func coordinator(_ f: UpdateAdmissionTestFixture) throws -> UpdateActivationAdmission {
        try .init(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid(), expected: f.identity)
    }

    func testNativeEntryRefusesOrdinaryIdentityBeforeOpeningPaths() throws {
        XCTAssertNotEqual(getuid(), 0)
        XCTAssertThrowsError(try UpdateActivationAdmission.open(machineDirectory: "/missing", expected: .init(device: 1, inode: 1))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }

    func testAutomaticBusyWorkLeavesAdmissionOpenWithoutCancellingWork() throws {
        let f = try UpdateAdmissionTestFixture(), worker = try f.activity.open()
        let pending = try worker.acquireShared(), updater = try coordinator(f)
        XCTAssertNil(try updater.automatic())
        let next = try f.open().acquireAdmission(), moreWork = try worker.acquireShared()
        try pending.validate(); try moreWork.validate(); try next.validate()
        next.close(); moreWork.close(); pending.close()
        let ready = try XCTUnwrap(updater.automatic())
        try ready.validate(); ready.close()
    }

    func testAutomaticInflightAdmissionReleasesTheTemporaryActivityExclusion() throws {
        let f = try UpdateAdmissionTestFixture(), account = try f.open()
        let inflight = try account.acquireAdmission()
        XCTAssertNil(try coordinator(f).automatic())
        let work = try f.activity.open().acquireShared()
        try work.validate(); try inflight.validate()
        let concurrent = try account.acquireAdmission()
        concurrent.close(); inflight.close(); work.close()
    }

    func testAutomaticIdleBoundaryExcludesBothIndependentOwnersUntilClose() throws {
        let f = try UpdateAdmissionTestFixture()
        let ready = try XCTUnwrap(coordinator(f).automatic())
        try ready.validate()
        XCTAssertThrowsError(try f.activity.open().acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertThrowsError(try f.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        ready.close(); ready.close()
        XCTAssertThrowsError(try ready.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let admission = try f.open().acquireAdmission(), work = try f.activity.open().acquireShared()
        try admission.validate(); try work.validate(); admission.close(); work.close()
    }

    func testExplicitDrainPreservesEveryExistingReferenceAndTransfersBothLocks() throws {
        let f = try UpdateAdmissionTestFixture(), worker = try f.activity.open()
        let one = try worker.acquireShared(), two = try worker.acquireShared(), other = try f.activity.open().acquireShared()
        let drain = try coordinator(f).beginDrain()
        XCTAssertNil(try drain.acquireQuiescence())
        XCTAssertThrowsError(try f.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        try one.validate(); try two.validate(); try other.validate()
        one.close(); other.close(); XCTAssertNil(try drain.acquireQuiescence())
        try two.validate(); two.close()
        let ready = try XCTUnwrap(drain.acquireQuiescence())
        drain.close()
        XCTAssertThrowsError(try drain.acquireQuiescence()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try f.open().acquireAdmission())
        XCTAssertThrowsError(try f.activity.open().acquireShared())
        try ready.validate(); ready.close()
        let resumed = try f.open().acquireAdmission(); resumed.close()
    }

    func testCancelDrainResumesAdmissionWhileTheOriginalWorkContinues() throws {
        let f = try UpdateAdmissionTestFixture(), work = try f.activity.open().acquireShared()
        let drain = try coordinator(f).beginDrain()
        XCTAssertNil(try drain.acquireQuiescence()); drain.close(); drain.close()
        let next = try f.open().acquireAdmission()
        try work.validate(); try next.validate(); next.close(); work.close()
    }

    func testActivityReplacementNeverCountsAsQuiescenceOrDropsTheDrain() throws {
        let f = try UpdateAdmissionTestFixture()
        let drain = try coordinator(f).beginDrain()
        let path = f.activity.directory.appendingPathComponent(ReleaseActivityBarrier.fileName).path
        XCTAssertEqual(rename(path, path + ".old"), 0)
        let replacement = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
        XCTAssertThrowsError(try drain.acquireQuiescence()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try f.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        drain.close()
        let next = try f.open().acquireAdmission(); next.close()
    }

    func testCloseDuringAnActivationCallbackRetainsBothLocksThroughItsActualReturn() throws {
        let f = try UpdateAdmissionTestFixture()
        let ready = try XCTUnwrap(coordinator(f).automatic())
        try ready.withExclusiveActivity { activity in
            try activity.validateExclusive(); ready.close()
            XCTAssertThrowsError(try ready.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try f.activity.open().acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
            XCTAssertThrowsError(try f.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            try activity.validateExclusive()
        }
        let admitted = try f.open().acquireAdmission(), work = try f.activity.open().acquireShared()
        admitted.close(); work.close()
    }

    func testFailedCallbackReleasesOnCloseAndCannotLendTheBoundaryTwice() throws {
        enum Fault: Error { case expected }
        let f = try UpdateAdmissionTestFixture()
        let ready = try XCTUnwrap(coordinator(f).automatic())
        XCTAssertThrowsError(try ready.withExclusiveActivity { _ in
            XCTAssertThrowsError(try ready.withExclusiveActivity { _ in XCTFail("Concurrent activation borrowed the boundary") }) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            ready.close(); throw Fault.expected
        }) { XCTAssertTrue($0 is Fault) }
        let admitted = try f.open().acquireAdmission(), work = try f.activity.open().acquireShared()
        admitted.close(); work.close()
    }

    func testMetadataReplacementDuringCallbackCannotReturnSuccessOrDropItsLocks() throws {
        let f = try UpdateAdmissionTestFixture(), otherActivity = try f.activity.open()
        let ready = try XCTUnwrap(coordinator(f).automatic())
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertThrowsError(try ready.withExclusiveActivity { _ in
            XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
            let replacement = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
            return "success"
        }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try otherActivity.acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        ready.close()
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), 0)
        let work = try otherActivity.acquireShared(); work.close()
    }
}
