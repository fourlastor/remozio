import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Real temporary locks test the loan lifetime. They establish no installed Root identity or native readiness.
final class MachineUpdateRestartSharedActivityTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private final class BorrowGate: Sendable {
        let continuation = Mutex<CheckedContinuation<Void, Never>?>(nil)
    }
    private final class Fixture: @unchecked Sendable {
        let files: UpdateAdmissionTestFixture
        let directory: ReleaseDestinationLease
        let restart: UpdateRestartAdmissionLease
        let access: MachineUpdateRestartSharedActivity
        let macID: Data, installationID: Data
        let attempt: UUID
        init() throws {
            let files = try UpdateAdmissionTestFixture(); self.files = files
            let directory = try ReleaseDestinationLease(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            self.directory = directory
            let updater = try UpdateActivationAdmission(anchor: files.activity.root.path,
                relativeDirectory: "Machine", owner: getuid(), expected: files.identity)
            let ready = try XCTUnwrap(updater.automatic()), restart = try ready.releaseActivityForRestart(); self.restart = restart
            let macID = Data(repeating: 1, count: 16), installationID = Data(repeating: 2, count: 16), attempt = UUID()
            self.macID = macID; self.installationID = installationID; self.attempt = attempt
            access = try .init(restart: restart, activity: files.activity.open(), directory: directory,
                expectedMachine: files.identity, macID: macID, installationID: installationID, activationAttempt: attempt)
        }
        deinit { access.close(); restart.close(); directory.close() }
        func requireClosedAdmission() {
            XCTAssertThrowsError(try files.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        }
        func requireNoExclusiveActivity() {
            XCTAssertThrowsError(try files.activity.open().acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        }
        func requireOpenAdmission() throws { let admitted = try files.open().acquireAdmission(); admitted.close() }
    }
    func testSeveralSharedLoansRetainAdmissionAndPermitOrdinarySharedActivity() throws {
        let f = try Fixture(), first = try f.access.acquireShared(), second = try f.access.acquireShared()
        try first.validate(); try second.validate(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        let ordinary = try f.files.activity.open().acquireShared(); try ordinary.validate(); ordinary.close()
        XCTAssertThrowsError(try f.restart.withClosedAdmission { XCTFail("Exclusive callback entered") })
        first.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity(); try second.validate()
        second.close(); f.requireClosedAdmission()
        try f.restart.withClosedAdmission {}
        f.restart.close(); try f.requireOpenAdmission()
    }
    func testClosingTheParentRevokesLoansButKeepsTheDrainUntilTheLastClose() throws {
        let f = try Fixture(), first = try f.access.acquireShared(), second = try f.access.acquireShared()
        f.restart.close()
        XCTAssertThrowsError(try first.validate()); XCTAssertThrowsError(try second.validate())
        XCTAssertThrowsError(try f.access.acquireShared())
        f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        first.close(); first.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        second.close(); try f.requireOpenAdmission()
        let exclusive = try f.files.activity.open().acquireExclusive(); exclusive.close()
    }
    func testClosingAccessRetainsBothActualLocksUntilItsBorrowerCloses() throws {
        let f = try Fixture(), loan = try f.access.acquireShared()
        f.access.close(); XCTAssertThrowsError(try loan.validate()); XCTAssertThrowsError(try f.access.acquireShared())
        f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        f.restart.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        loan.close(); try f.requireOpenAdmission()
    }
    func testFailedSharedAcquisitionRollsBackItsAdmissionCount() throws {
        let f = try Fixture(), exclusive = try f.files.activity.open().acquireExclusive()
        XCTAssertThrowsError(try f.access.acquireShared()); f.requireClosedAdmission()
        try f.restart.withClosedAdmission {}
        exclusive.close()
        let next = try f.access.acquireShared(); try next.validate(); next.close()
        f.restart.close(); try f.requireOpenAdmission()
    }
    func testAnActivityTokenFromAnotherDirectoryFailsAndReleasesItsRealLock() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try f.restart.acquireSharedActivity(activity: other.files.activity.open(),
            directory: f.directory, expected: f.files.identity))
        f.requireClosedAdmission(); try f.restart.withClosedAdmission {}
        let exclusive = try other.files.activity.open().acquireExclusive(); exclusive.close()
        f.restart.close(); try f.requireOpenAdmission()
    }
    func testSharedTokensValidateTheirModeAndExactDirectory() throws {
        let f = try Fixture(), other = try Fixture(), token = try f.files.activity.open().acquireShared()
        XCTAssertNoThrow(try token.validateShared(in: f.directory))
        XCTAssertThrowsError(try token.validateExclusive(in: f.directory))
        XCTAssertThrowsError(try token.validateShared(in: other.directory))
        token.close(); XCTAssertThrowsError(try token.validateShared(in: f.directory))
        f.requireClosedAdmission()
    }
    func testTheAccessRejectsAnotherMachineFileAndEveryChangedScope() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try MachineUpdateRestartSharedActivity(restart: f.restart, activity: f.files.activity.open(),
            directory: f.directory, expectedMachine: other.files.identity, macID: f.macID,
            installationID: f.installationID, activationAttempt: f.attempt))
        XCTAssertNoThrow(try f.access.requireScope(macID: f.macID, installationID: f.installationID, activationAttempt: f.attempt))
        XCTAssertThrowsError(try f.access.requireScope(macID: Data(count: 16), installationID: f.installationID, activationAttempt: f.attempt))
        XCTAssertThrowsError(try f.access.requireScope(macID: f.macID, installationID: Data(count: 16), activationAttempt: f.attempt))
        XCTAssertThrowsError(try f.access.requireScope(macID: f.macID, installationID: f.installationID, activationAttempt: UUID()))
        f.requireClosedAdmission()
    }
    func testAParentCloseDuringASynchronousLoanKeepsTheDrainUntilActualReturn() throws {
        let f = try Fixture()
        let value = try f.restart.withClosedAdmission {
            XCTAssertThrowsError(try f.access.acquireShared()) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            f.restart.close(); f.requireClosedAdmission()
            XCTAssertThrowsError(try f.restart.validate()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            return 7
        }
        XCTAssertEqual(value, 7)
        try f.requireOpenAdmission()
        XCTAssertThrowsError(try f.access.acquireShared()) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
        }
    }
    func testAReadinessLoanCanReadWhileOtherSharedLoansRemainHeld() throws {
        let f = try Fixture(), first = try f.access.acquireShared(), second = try f.access.acquireShared()
        let value = try first.withClosedAdmission {
            try first.validate(); try second.validate(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
            XCTAssertThrowsError(try first.withClosedAdmission { XCTFail("Nested loan entered") })
            XCTAssertThrowsError(try second.withClosedAdmission { XCTFail("Second owner entered") })
            XCTAssertThrowsError(try f.access.acquireShared())
            return 7
        }
        XCTAssertEqual(value, 7); try second.validate()
        first.close(); second.close(); f.restart.close(); try f.requireOpenAdmission()
    }
    func testClosingTheActiveLoanKeepsItsActualTokenUntilTheCallbackReturns() throws {
        let f = try Fixture(), loan = try f.access.acquireShared()
        XCTAssertThrowsError(try loan.withClosedAdmission {
            loan.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
            XCTAssertThrowsError(try loan.validate())
        })
        let exclusive = try f.files.activity.open().acquireExclusive(); exclusive.close()
        f.requireClosedAdmission(); f.restart.close(); try f.requireOpenAdmission()
    }
    func testClosingTheParentInAReadinessCallbackWaitsForEveryActualLoan() throws {
        let f = try Fixture(), first = try f.access.acquireShared(), second = try f.access.acquireShared()
        XCTAssertThrowsError(try first.withClosedAdmission {
            f.restart.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        })
        f.requireClosedAdmission(); first.close(); f.requireClosedAdmission()
        second.close(); try f.requireOpenAdmission()
    }
    func testAThrowingReadinessCallbackRetainsItsLoanAndTheNextCallbackCanRun() throws {
        let f = try Fixture(), loan = try f.access.acquireShared()
        XCTAssertThrowsError(try loan.withClosedAdmission { throw Refused() })
        f.requireClosedAdmission(); try loan.validate()
        try loan.withClosedAdmission { try loan.validate(); f.requireNoExclusiveActivity() }
        loan.close(); f.restart.close(); try f.requireOpenAdmission()
    }
    func testAnAsyncBorrowRetainsAdmissionUntilItsTaskReleasesTheLoan() async throws {
        let f = try Fixture(), loan = try f.access.acquireShared(), gate = BorrowGate()
        let task = Task {
            await withCheckedContinuation { continuation in gate.continuation.withLock { $0 = continuation } }
            XCTAssertThrowsError(try loan.validate()); f.requireClosedAdmission(); loan.close()
        }
        let end = ContinuousClock.now.advanced(by: .seconds(4))
        while gate.continuation.withLock({ $0 == nil }) {
            guard ContinuousClock.now < end else { throw Refused() }
            try await Task.sleep(for: .milliseconds(2))
        }
        f.restart.close(); f.requireClosedAdmission(); f.requireNoExclusiveActivity()
        gate.continuation.withLock { value in let saved = value; value = nil; return saved }?.resume()
        try await task.value; try f.requireOpenAdmission()
    }
}
