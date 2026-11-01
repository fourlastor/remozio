import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateOrdinaryAdmissionTests: XCTestCase {
    private enum Fault: Error { case injected }
    private func directory(_ f: UpdateAdmissionTestFixture) throws -> ReleaseDestinationLease {
        try .init(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
    }
    private func lease(_ f: UpdateAdmissionTestFixture) throws -> UpdateOrdinaryAdmissionLease {
        try .init(activity: f.activity.open(), admission: f.open(), directory: directory(f), expected: f.identity)
    }
    func testNativeOrdinaryEntryRefusesUnprivilegedIdentityBeforeOpeningAPath() throws {
        guard getuid() != 0 || geteuid() != 0 else { throw XCTSkip("This control requires an unprivileged caller.") }
        XCTAssertThrowsError(try UpdateOrdinaryAdmissionLease.open(machineDirectory: "/unused", expected: .init(device: 1, inode: 1))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testOrdinaryLeasePinsBothBoundariesAndItsEscapedScopeExpires() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f), target = try directory(f)
        defer { owner.close(); target.close() }
        let escaped = try owner.withMachineAdmission { scope in
            try scope.validateMachineBoundary(directory: target, expected: f.identity)
            XCTAssertThrowsError(try f.open().beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            XCTAssertThrowsError(try f.activity.open().acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
            let otherAdmission = try f.open().acquireAdmission(), otherActivity = try f.activity.open().acquireShared()
            try otherAdmission.validate(); try otherActivity.validate(); otherAdmission.close(); otherActivity.close()
            return scope
        }
        XCTAssertThrowsError(try escaped.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try escaped.validateMachineBoundary(directory: target, expected: f.identity))
        try owner.validate(); owner.close()
        let drain = try f.open().beginDrain(), exclusive = try f.activity.open().acquireExclusive(); drain.close(); exclusive.close()
    }
    func testCloseDuringBorrowRetainsActualLocksUntilTheCallbackReturns() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f)
        try owner.withMachineAdmission { scope in
            owner.close()
            XCTAssertThrowsError(try owner.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try f.open().beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            XCTAssertThrowsError(try f.activity.open().acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
            try scope.validate()
        }
        let drain = try f.open().beginDrain(), exclusive = try f.activity.open().acquireExclusive(); drain.close(); exclusive.close()
        XCTAssertThrowsError(try owner.withMachineAdmission { _ in XCTFail("A closed lease lent admission.") })
    }
    func testFailedAndNestedCallbacksCannotLendTwiceOrReleaseBeforeSettlement() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f)
        XCTAssertThrowsError(try owner.withMachineAdmission { scope in
            XCTAssertThrowsError(try owner.withMachineAdmission { _ in XCTFail("A nested borrower entered.") }) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            owner.close(); try scope.validate()
            XCTAssertThrowsError(try f.open().beginDrain())
            throw Fault.injected
        }) { XCTAssertTrue($0 is Fault) }
        let drain = try f.open().beginDrain(), exclusive = try f.activity.open().acquireExclusive(); drain.close(); exclusive.close()
    }
    func testDoubleCloseAndDeinitReleaseOnlyTheOwnedReferences() throws {
        let f = try UpdateAdmissionTestFixture(), first = try lease(f)
        var second: UpdateOrdinaryAdmissionLease? = try lease(f)
        first.close(); first.close()
        XCTAssertThrowsError(try f.open().beginDrain()); XCTAssertThrowsError(try f.activity.open().acquireExclusive())
        try second?.validate(); second = nil
        let drain = try f.open().beginDrain(), exclusive = try f.activity.open().acquireExclusive(); drain.close(); exclusive.close()
    }
    func testCrossedDirectoriesAndWrongIdentitiesCannotAuthorizeAMachineBoundary() throws {
        let f = try UpdateAdmissionTestFixture(), other = try UpdateAdmissionTestFixture()
        let target = try directory(f), foreign = try directory(other); defer { target.close(); foreign.close() }
        XCTAssertThrowsError(try UpdateOrdinaryAdmissionLease(activity: other.activity.open(), admission: f.open(), directory: target, expected: f.identity))
        let freeActivity = try other.activity.open().acquireExclusive(), freeAdmission = try f.open().beginDrain(); freeActivity.close(); freeAdmission.close()
        let owner = try lease(f); defer { owner.close() }
        try owner.withMachineAdmission { scope in
            XCTAssertThrowsError(try scope.validateMachineBoundary(directory: foreign, expected: f.identity))
            XCTAssertThrowsError(try scope.validateMachineBoundary(directory: target, expected: .init(device: f.identity.device, inode: f.identity.inode ^ 1))) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
            }
            try scope.validateMachineBoundary(directory: target, expected: f.identity)
        }
    }
    func testAccountAdmissionCannotSubstituteForTheMachineFile() throws {
        let f = try UpdateAdmissionTestFixture(), scope = UpdateAdmissionScope.account(Data(repeating: 7, count: 16))
        let path = f.activity.directory.appendingPathComponent(try scope.fileName).path
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0); guard fd >= 0 else { return }; defer { Darwin.close(fd) }
        var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
        let identity = PreparationFileIdentity(device: UInt32(bitPattern: info.st_dev), inode: info.st_ino)
        let account = try UpdateAdmissionBarrier(directory: directory(f), owner: getuid(), expected: identity, scope: scope)
        let token = try account.acquireAdmission(), target = try directory(f); defer { token.close(); target.close() }
        XCTAssertThrowsError(try token.validateMachineBoundary(directory: target, expected: identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        XCTAssertThrowsError(try UpdateOrdinaryAdmissionLease(activity: f.activity.open(), admission: account, directory: target, expected: identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        try token.validate(); let machine = try f.open().beginDrain(); machine.close()
    }
    func testAdmissionReplacementDuringBorrowRefusesSuccessAndRetainsTheOldLockUntilClose() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f)
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC); XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertThrowsError(try owner.withMachineAdmission { _ in
            XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
            let fd = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600); XCTAssertGreaterThanOrEqual(fd, 0); Darwin.close(fd)
            return "success"
        }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        XCTAssertThrowsError(try f.activity.open().acquireExclusive())
        owner.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
        let exclusive = try f.activity.open().acquireExclusive(); exclusive.close()
    }
    func testActivityReplacementDuringBorrowKeepsMachineAdmissionHeldUntilClose() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f)
        let path = f.activity.directory.appendingPathComponent(ReleaseActivityBarrier.fileName).path
        let observer = Darwin.open(path, O_RDWR | O_CLOEXEC); XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertThrowsError(try owner.withMachineAdmission { _ in
            XCTAssertEqual(rename(path, path + ".old"), 0)
            let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600); XCTAssertGreaterThanOrEqual(fd, 0); Darwin.close(fd)
        }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        XCTAssertThrowsError(try f.open().beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        owner.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
        let drain = try f.open().beginDrain(); drain.close()
    }
    func testDirectMachineBoundaryValidationDoesNotCreateANestedWriterLoan() throws {
        let f = try UpdateAdmissionTestFixture(), owner = try lease(f), target = try directory(f)
        defer { owner.close(); target.close() }
        try owner.validateMachineBoundary(directory: target, expected: f.identity)
        try owner.withMachineAdmission { scope in
            try owner.validateMachineBoundary(directory: target, expected: f.identity); try scope.validate()
        }
        let other = try UpdateAdmissionTestFixture(), foreign = try directory(other); defer { foreign.close() }
        XCTAssertThrowsError(try owner.validateMachineBoundary(directory: foreign, expected: f.identity))
        owner.close(); XCTAssertThrowsError(try owner.validateMachineBoundary(directory: target, expected: f.identity))
    }
    func testAccountBoundaryRequiresItsExactAccountFileAndDirectory() throws {
        let f = try UpdateAdmissionTestFixture(), first = Data(repeating: 51, count: 16), second = Data(repeating: 52, count: 16)
        let target = try directory(f); defer { target.close() }
        func account(_ id: Data) throws -> (barrier: UpdateAdmissionBarrier, identity: PreparationFileIdentity) {
            let scope = UpdateAdmissionScope.account(id), path = f.activity.directory.appendingPathComponent(try scope.fileName).path
            let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }; defer { Darwin.close(fd) }
            var value = stat(); guard fstat(fd, &value) == 0 else { throw JournalLeaseError.system(errno) }
            let identity = PreparationFileIdentity(device: UInt32(bitPattern: value.st_dev), inode: value.st_ino)
            return (try UpdateAdmissionBarrier(directory: directory(f), owner: getuid(), expected: identity, scope: scope), identity)
        }
        let a = try account(first), b = try account(second), one = try a.barrier.acquireAdmission(), two = try b.barrier.acquireAdmission()
        defer { one.close(); two.close() }
        try one.validateAccountBoundary(directory: target, accountID: first, expected: a.identity)
        XCTAssertThrowsError(try one.validateAccountBoundary(directory: target, accountID: second, expected: a.identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        let machine = try f.open().acquireAdmission(); defer { machine.close() }
        XCTAssertThrowsError(try machine.validateAccountBoundary(directory: target, accountID: first, expected: f.identity))
        let other = try UpdateAdmissionTestFixture(), foreign = try directory(other); defer { foreign.close() }
        XCTAssertThrowsError(try one.validateAccountBoundary(directory: foreign, accountID: first, expected: a.identity))
        one.close(); XCTAssertThrowsError(try one.validateAccountBoundary(directory: target, accountID: first, expected: a.identity))
        let drain = try a.barrier.beginDrain(); drain.close(); try two.validate()
        XCTAssertThrowsError(try b.barrier.beginDrain())
    }

}
