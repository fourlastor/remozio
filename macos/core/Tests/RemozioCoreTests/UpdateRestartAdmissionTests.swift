import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateRestartAdmissionTests: XCTestCase {
    private func quiescence(_ f: UpdateAdmissionTestFixture) throws -> UpdateQuiescenceLease {
        let coordinator = try UpdateActivationAdmission(anchor: f.activity.root.path,
            relativeDirectory: "Machine", owner: getuid(), expected: f.identity)
        return try XCTUnwrap(coordinator.automatic())
    }

    private func admissionIsClosed(_ f: UpdateAdmissionTestFixture) {
        XCTAssertThrowsError(try f.open().acquireAdmission()) {
            XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
        }
    }

    func testHandoffAllowsStartupActivityWithoutOpeningRequestAdmission() throws {
        let f = try UpdateAdmissionTestFixture(), ready = try quiescence(f)
        let restart = try ready.releaseActivityForRestart()
        let startup = try f.activity.open().acquireShared(), recovery = try f.activity.open().acquireShared()
        try startup.validate(); try recovery.validate(); try restart.validate()
        admissionIsClosed(f)
        XCTAssertThrowsError(try ready.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        ready.close(); ready.close(); admissionIsClosed(f)
        restart.close(); restart.close()
        let admitted = try f.open().acquireAdmission()
        try admitted.validate(); try startup.validate(); try recovery.validate()
        admitted.close(); startup.close(); recovery.close()
        XCTAssertThrowsError(try restart.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    func testOldOwnerDeinitializationCannotCloseTheTransferredDrain() throws {
        let f = try UpdateAdmissionTestFixture()
        var ready: UpdateQuiescenceLease? = try quiescence(f)
        let restart = try XCTUnwrap(ready).releaseActivityForRestart()
        ready = nil
        try restart.validate(); admissionIsClosed(f)
        restart.close()
        let admitted = try f.open().acquireAdmission(); admitted.close()
    }

    func testAnotherUpdaterCannotStartActivationDuringTheRestartPhase() throws {
        let f = try UpdateAdmissionTestFixture(), restart = try quiescence(f).releaseActivityForRestart()
        let other = try UpdateActivationAdmission(anchor: f.activity.root.path,
            relativeDirectory: "Machine", owner: getuid(), expected: f.identity)
        XCTAssertNil(try other.automatic())
        XCTAssertThrowsError(try other.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        let startup = try f.activity.open().acquireShared(); try startup.validate(); startup.close()
        try restart.validate(); admissionIsClosed(f); restart.close()
    }

    func testTheRestartDrainCannotBeTransferredTwiceOrBorrowExclusiveActivity() throws {
        let f = try UpdateAdmissionTestFixture(), ready = try quiescence(f)
        let restart = try ready.releaseActivityForRestart()
        XCTAssertThrowsError(try ready.releaseActivityForRestart()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try ready.withExclusiveActivity { _ in XCTFail("The old owner lent released activity") }) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
        }
        try restart.validate(); admissionIsClosed(f); restart.close()
    }

    func testActiveCutoverCallbackPreventsHandoffWithoutReleasingEitherLock() throws {
        let f = try UpdateAdmissionTestFixture(), ready = try quiescence(f)
        try ready.withExclusiveActivity { activity in
            XCTAssertThrowsError(try ready.releaseActivityForRestart()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            try activity.validateExclusive(); admissionIsClosed(f)
            XCTAssertThrowsError(try f.activity.open().acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        }
        let restart = try ready.releaseActivityForRestart()
        let startup = try f.activity.open().acquireShared(); startup.close()
        admissionIsClosed(f); restart.close()
    }

    func testCancelledCutoverCannotTransferItsDeferredCloseToRestart() throws {
        let f = try UpdateAdmissionTestFixture(), ready = try quiescence(f)
        try ready.withExclusiveActivity { _ in
            ready.close()
            XCTAssertThrowsError(try ready.releaseActivityForRestart()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            admissionIsClosed(f)
            XCTAssertThrowsError(try f.activity.open().acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        }
        let admitted = try f.open().acquireAdmission(), startup = try f.activity.open().acquireShared()
        admitted.close(); startup.close()
    }

    func testCloseDuringRestartChecksKeepsAdmissionClosedThroughTheCallback() throws {
        let f = try UpdateAdmissionTestFixture(), restart = try quiescence(f).releaseActivityForRestart()
        let result = try restart.withClosedAdmission {
            restart.close(); admissionIsClosed(f)
            let startup = try f.activity.open().acquireShared(); try startup.validate(); startup.close()
            XCTAssertThrowsError(try restart.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            return "checked"
        }
        XCTAssertEqual(result, "checked")
        let admitted = try f.open().acquireAdmission(); admitted.close()
    }

    func testFailedRestartCheckKeepsAdmissionClosedUntilTheOwnerCloses() throws {
        enum Fault: Error { case expected }
        let f = try UpdateAdmissionTestFixture(), restart = try quiescence(f).releaseActivityForRestart()
        XCTAssertThrowsError(try restart.withClosedAdmission { throw Fault.expected }) { XCTAssertTrue($0 is Fault) }
        try restart.validate(); admissionIsClosed(f)
        try restart.withClosedAdmission {
            XCTAssertThrowsError(try restart.withClosedAdmission { XCTFail("Concurrent restart check entered") }) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            admissionIsClosed(f)
        }
        restart.close()
    }

    func testThrowingRestartCheckDefersItsRequestedCloseThroughTheCallback() throws {
        enum Fault: Error { case expected }
        let f = try UpdateAdmissionTestFixture(), restart = try quiescence(f).releaseActivityForRestart()
        XCTAssertThrowsError(try restart.withClosedAdmission {
            restart.close(); admissionIsClosed(f)
            throw Fault.expected
        }) { XCTAssertTrue($0 is Fault) }
        let admitted = try f.open().acquireAdmission(); admitted.close()
    }

    func testAdmissionReplacementBeforeHandoffRetainsBothOriginalLocks() throws {
        let f = try UpdateAdmissionTestFixture(), ready = try quiescence(f)
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
        let replacement = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
        XCTAssertThrowsError(try ready.releaseActivityForRestart()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try f.activity.open().acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        ready.close()
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), 0)
        let startup = try f.activity.open().acquireShared(); startup.close()
    }

    func testReplacementDuringRestartChecksCannotReturnHealthSuccessOrDropTheDrain() throws {
        let f = try UpdateAdmissionTestFixture(), restart = try quiescence(f).releaseActivityForRestart()
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertThrowsError(try restart.withClosedAdmission {
            XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
            let replacement = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
            return "healthy"
        }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        let startup = try f.activity.open().acquireShared(); startup.close()
        restart.close()
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), 0)
    }

    func testRestartOwnerDeinitializationReopensAdmission() throws {
        let f = try UpdateAdmissionTestFixture()
        var restart: UpdateRestartAdmissionLease? = try quiescence(f).releaseActivityForRestart()
        try XCTUnwrap(restart).validate(); admissionIsClosed(f); restart = nil
        let admitted = try f.open().acquireAdmission(); admitted.close()
    }
}
