import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

private enum RecoveryScopeTestFailure: Error { case timeout }
private final class RecoveryScopeHarness: @unchecked Sendable {
    let activity: ReleaseActivityFixture
    let owner: SetupAccountOwner
    let placement: ReleaseDestinationLease
    let processLease: SetupProcessLease
    let shutdown: AdministrativeSetupShutdown
    init(_ fixture: RetainedMaterialWriterFixture) throws {
        activity = try ReleaseActivityFixture()
        owner = try .init(machine: fixture.machine(), expectedReleaseDigest: InstallationInventory.digest(fixture.candidate),
            resume: { _, value in value }, releaseActivity: activity.open())
        placement = try .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
        processLease = try .openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
        shutdown = .init(owner: owner, placement: placement, processLease: processLease)
    }
    func acquireProcess() throws -> SetupProcessLease {
        try .openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
    }
}

private final class RecoveryScopeCompletion: Sendable {
    let value = Mutex<Result<Void, any Error>?>(nil)
}
private final class RecoveryScopeCounter: Sendable { let value = Mutex(0) }
private final class RecoveryScopeBoolean: Sendable { let value = Mutex(false) }
private final class RecoveryScopeGate: Sendable {
    let entered = Mutex(false)
    let resume = DispatchSemaphore(value: 0)
}

final class SetupMaintenanceRecoveryScopeTests: XCTestCase {
    private func runAsync(_ body: @escaping @Sendable () async throws -> Void) throws {
        let done = DispatchSemaphore(value: 0), result = RecoveryScopeCompletion()
        Task { @Sendable [body, done, result] in
            do { try await body(); result.value.withLock { $0 = .success(()) } }
            catch { result.value.withLock { $0 = .failure(error) } }
            done.signal()
        }
        guard done.wait(timeout: .now() + 30) == .success else { throw RecoveryScopeTestFailure.timeout }
        try XCTUnwrap(result.value.withLock { $0 }).get()
    }
    private static func retryingSupervisor(owner: SetupAccountOwner,
        custody: SetupMaintenanceRecoveryNativeAdapter.Custody, count: RecoveryScopeCounter) throws -> SetupMaintenanceRecoverySupervisor {
        let native = SetupMaintenanceRecoveryNativeAdapter.driver(owner: owner, custody: custody)
        return try .openOwned(custody: custody, driver: .init(acquire: { request, deadline in
            let result = try await native.acquire(request, deadline)
            guard case .busyBeforeOwner = result else { throw RecoveryScopeTestFailure.timeout }
            count.value.withLock { $0 += 1 }; return result
        }))
    }
    private static func retryRequest() throws -> SetupMaintenanceRecoverySupervisor.Request {
        try .init(accountID: Data(repeating: 1, count: 16), windowID: Data(repeating: 2, count: 16),
            revision: Data(repeating: 3, count: 16))
    }
    private func withScope(_ body: @escaping @Sendable (RecoveryScopeHarness) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { fixture in
            let h = try RecoveryScopeHarness(fixture), done = DispatchSemaphore(value: 0)
            let result = RecoveryScopeCompletion()
            Task { @Sendable [h, done, result, body] in
                do { try await body(h); result.value.withLock { $0 = .success(()) } }
                catch { result.value.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + 10) == .success else { throw RecoveryScopeTestFailure.timeout }
            try XCTUnwrap(result.value.withLock { $0 }).get()
        }
    }
    private static func eventually(for timeout: Duration = .seconds(3), _ check: @escaping @Sendable () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while !check() {
            guard ContinuousClock.now < deadline else { throw RecoveryScopeTestFailure.timeout }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
    }
    func testScopePinsStatusAndRefusesBothAdmissionsUntilClose() throws {
        try withScope { h in
            let installer = try h.activity.open(), scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            defer { scope.close(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            XCTAssertEqual(h.owner.statusLaneCheck(), .pinned)
            XCTAssertThrowsError(try h.owner.verifyCurrent())
            XCTAssertThrowsError(try h.owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)) {
                XCTAssertTrue($0 is SetupAccountOwner.MaintenanceRecoveryAdmissionError)
            }
            XCTAssertThrowsError(try installer.acquireExclusive())
            scope.close(); scope.close()
            XCTAssertEqual(h.owner.statusLaneCheck(), .verified)
            let reply = try h.owner.acquireSetupReplyAdmission(); reply.close()
            XCTAssertNoThrow(try h.owner.verifyCurrent())
            let exclusive = try installer.acquireExclusive(); exclusive.close()
        }
    }
    func testBusyRecoveryAndValidationCannotStealTheAdmittedWorkersExecutor() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let phases = h.owner.maintenanceRecoveryPhases(), entered = RecoveryScopeBoolean(), resume = DispatchSemaphore(value: 0)
            let work = Task { @Sendable [phases, entered, resume] in
                try await phases.acquire {
                    entered.value.withLock { $0 = true }
                    guard resume.wait(timeout: .now() + 5) == .success else { throw RecoveryScopeTestFailure.timeout }
                }
            }
            defer { resume.signal(); work.cancel(); scope.close(); custody.releaseAfterJoining() }
            try await Self.eventually { entered.value.withLock { $0 } }
            let start = ContinuousClock.now, valid = await custody.validateForRecovery()
            XCTAssertTrue(valid); XCTAssertLessThan(start.duration(to: .now), .milliseconds(500))
            let attempts = try h.owner.observeMaintenanceRecoveryExecutorOwned(), before = try attempts.countOwned()
            let driver = SetupMaintenanceRecoveryNativeAdapter.driver(owner: h.owner, custody: custody)
            let request = try SetupMaintenanceRecoverySupervisor.Request(accountID: Data(repeating: 1, count: 16),
                windowID: Data(repeating: 2, count: 16), revision: Data(repeating: 3, count: 16))
            for _ in 0..<3 {
                guard case .busyBeforeOwner = try await driver.acquire(request, .now.advanced(by: .seconds(5))) else {
                    return XCTFail("Recovery borrowed the active admission")
                }
            }
            XCTAssertEqual(try attempts.countOwned(), before, "The driver must refuse before attempting the executor")
            resume.signal(); try await work.value
            try await phases.acquire { XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes) }
            scope.close(); custody.releaseAfterJoining(); try await h.shutdown.close()
        }
    }
    func testBoundShutdownRefusesDirectCloseAndRetriesAfterTheScopeJoins() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            defer { scope.close(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            do { try await h.shutdown.close(); XCTFail("Direct shutdown bypassed its recovery binding") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            let pending = await custody.closeAfterJoiningResult(); XCTAssertEqual(pending, .pending)
            XCTAssertNoThrow(try h.processLease.validate()); XCTAssertNoThrow(try h.placement.validate())
            XCTAssertThrowsError(try h.acquireProcess()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            scope.close()
            let closed = await custody.closeAfterJoiningResult(); XCTAssertEqual(closed, .closed)
            XCTAssertThrowsError(try h.processLease.validate())
            let replacement = try h.acquireProcess(); replacement.close()
        }
    }
    func testFailedOwnerCleanupHasATypedFailureAndRetainsTheProcessLease() throws {
        try withScope { h in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown), id = UUID()
            defer { custody.joined(id); custody.releaseAfterJoining(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            custody.retain(id, id: id); custody.cleanupFailed(id)
            let result = await custody.closeAfterJoiningResult(); XCTAssertEqual(result, .failed)
            XCTAssertNoThrow(try h.processLease.validate())
            XCTAssertThrowsError(try h.acquireProcess()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            custody.joined(id)
            let settled = await custody.closeAfterJoiningResult(); XCTAssertEqual(settled, .closed)
            let replacement = try h.acquireProcess(); replacement.close()
        }
    }
    func testNativeFactoryRefusesTheOrdinaryCallerBeforeBindingShutdown() throws {
        try withScope { h in
            XCTAssertThrowsError(try SetupMaintenanceRecoverySupervisor.openNative(owner: h.owner, shutdown: h.shutdown)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            custody.releaseAfterJoining(); try await h.shutdown.close()
        }
    }
    func testOwnedCloseWaitCannotExtendTheNativeFiveSecondLimit() throws {
        XCTAssertThrowsError(try SetupMaintenanceRecoveryNativeAdapter.OwnedCloseWait(shorteningTo: .seconds(6))) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try SetupMaintenanceRecoveryNativeAdapter.OwnedCloseWait(shorteningTo: .zero))
        let wait = try SetupMaintenanceRecoveryNativeAdapter.OwnedCloseWait(shorteningTo: .seconds(5))
        XCTAssertEqual(wait.maximum, .seconds(5))
    }
    func testTimedOutSupervisorRetainsItsActualCloseAndRefusesEarlyDisposal() throws {
        try retainedFinalClose(cancelWaiter: false)
    }
    func testCancelledCustodyWaiterReturnsTimedOutWithoutCancellingItsActualClose() throws {
        try retainedFinalClose(cancelWaiter: true)
    }
    private func retainedFinalClose(cancelWaiter: Bool) throws {
        let fixture = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try fixture.owner()
        fixture.quiescenceCloseFails = true
        let expected = try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid()))
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let invocation = try SetupAuditUpgradeInvocation.openOwned(owner: owner, expected: expected,
            authorization: grant, openOperation: fixture.operation(scope:))
        XCTAssertThrowsError(try invocation.run { _ in XCTFail("Cleanup failure must not report a completed audit") })
        XCTAssertFalse(owner.settleAuditUpgradeInvocation(invocation))
        let quiescence = try XCTUnwrap(fixture.q), gate = RecoveryScopeGate(), releases = RecoveryScopeCounter()
        quiescence.closeFails = false
        quiescence.beforeClose = {
            releases.value.withLock { $0 += 1 }; gate.entered.withLock { $0 = true }
            guard gate.resume.wait(timeout: .now() + 20) == .success else { throw RecoveryScopeTestFailure.timeout }
        }
        let placement = try ReleaseDestinationLease(anchor: fixture.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let lease = try SetupProcessLease.openOwned(directory: .init(anchor: fixture.activity.root.path,
            relativeDirectory: "Machine", owner: getuid()))
        let shutdown = AdministrativeSetupShutdown(owner: owner, placement: placement, processLease: lease)
        let wait = try SetupMaintenanceRecoveryNativeAdapter.OwnedCloseWait(
            shorteningTo: cancelWaiter ? .seconds(5) : .milliseconds(25))
        let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: owner, shutdown: shutdown, ownedCloseWait: wait)
        defer { gate.resume.signal(); custody.releaseAfterJoining(); try? owner.close(); placement.close(); lease.close() }
        try runAsync { @Sendable [owner, shutdown, custody, gate, releases, lease, cancelWaiter] in
            let released = RecoveryScopeBoolean()
            let supervisor = try SetupMaintenanceRecoverySupervisor.openOwned(custody: custody,
                driver: .init(acquire: { _, _ in
                    XCTFail("An idle shutdown must not acquire recovery work"); return .terminal(.noWindow)
                }))
            var cancelledWaiterID: UUID?
            if cancelWaiter {
                let started = ContinuousClock.now
                let waiter = Task { @Sendable [custody] in await custody.closeAfterJoiningResult() }
                waiter.cancel()
                let cancelled = await waiter.value; XCTAssertEqual(cancelled, .timedOut)
                XCTAssertLessThan(started.duration(to: .now), .seconds(1))
                cancelledWaiterID = try XCTUnwrap(custody.closeAttemptIDOwned())
            }
            await supervisor.retire()
            try await Self.eventually { gate.entered.withLock { $0 } }
            let firstResult = await supervisor.closureResult, firstExit = await supervisor.shouldExit
            XCTAssertEqual(firstResult, .timedOut); XCTAssertFalse(firstExit)
            let firstID = try XCTUnwrap(custody.closeAttemptIDOwned())
            if let cancelledWaiterID { XCTAssertEqual(cancelledWaiterID, firstID) }
            XCTAssertNoThrow(try lease.validate()); XCTAssertThrowsError(try owner.close())
            let disposing = Task { @Sendable [custody, released] in
                custody.releaseAfterJoining(); released.value.withLock { $0 = true }
            }
            try await Self.eventually(for: .milliseconds(500)) { released.value.withLock { $0 } }
            await disposing.value
            XCTAssertThrowsError(try shutdown.reserveRecoverySupervisor()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            XCTAssertEqual(try custody.closeAttemptIDOwned(), firstID)
            await supervisor.retire()
            let secondResult = await supervisor.closureResult, secondExit = await supervisor.shouldExit
            XCTAssertEqual(secondResult, .timedOut); XCTAssertFalse(secondExit)
            XCTAssertEqual(try custody.closeAttemptIDOwned(), firstID); XCTAssertEqual(releases.value.withLock { $0 }, 1)
            XCTAssertNoThrow(try lease.validate())
            gate.resume.signal()
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while !(await supervisor.shouldExit) {
                guard ContinuousClock.now < deadline else { throw RecoveryScopeTestFailure.timeout }
                await supervisor.retire()
            }
            let completed = await supervisor.closureResult
            XCTAssertEqual(completed, .closed); XCTAssertNil(try custody.closeAttemptIDOwned())
            XCTAssertEqual(releases.value.withLock { $0 }, 1); XCTAssertThrowsError(try lease.validate())
        }
        let replacement = try SetupProcessLease.openOwned(directory: .init(anchor: fixture.activity.root.path,
            relativeDirectory: "Machine", owner: getuid())); replacement.close()
    }
    func testSupervisorRetriesDoNotStealTheRealAuditUpgradeWorkersExecutor() throws {
        let fixture = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try fixture.owner()
        let placement = try ReleaseDestinationLease(anchor: fixture.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let lease = try SetupProcessLease.openOwned(directory: .init(anchor: fixture.activity.root.path,
            relativeDirectory: "Machine", owner: getuid()))
        let shutdown = AdministrativeSetupShutdown(owner: owner, placement: placement, processLease: lease)
        let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: owner, shutdown: shutdown)
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let gate = RecoveryScopeGate(), count = RecoveryScopeCounter(), attempts = try owner.observeMaintenanceRecoveryExecutorOwned()
        defer { gate.resume.signal(); custody.releaseAfterJoining(); grant.close(); try? owner.close(); placement.close(); lease.close() }
        try runAsync { @Sendable [owner, custody, grant, gate, count, attempts, lease] in
            let actual = Task { @Sendable [owner, grant, gate] in
                try await owner.performAuditUpgradeWork(authorization: grant) { token in
                    let scope = try owner.acquireAuditUpgradeScope(authorization: grant)
                    do {
                        try scope.validateLifetime(); gate.entered.withLock { $0 = true }
                        guard gate.resume.wait(timeout: .now() + 20) == .success else { throw RecoveryScopeTestFailure.timeout }
                        try token.check(); try scope.close(); return 7
                    } catch { try? scope.close(); throw error }
                }
            }
            try await Self.eventually { gate.entered.withLock { $0 } }
            let before = try attempts.countOwned()
            let supervisor = try Self.retryingSupervisor(owner: owner, custody: custody, count: count)
            let request = try Self.retryRequest(), accepted = await supervisor.schedule(request); XCTAssertTrue(accepted)
            try await Self.eventually(for: .seconds(10)) { count.value.withLock { $0 >= 3 } }
            XCTAssertEqual(try attempts.countOwned(), before, "Recovery must refuse before entering the audit executor")
            let valid = await custody.validateForRecovery(); XCTAssertTrue(valid); XCTAssertEqual(try attempts.countOwned(), before)
            await supervisor.close()
            XCTAssertEqual(try attempts.countOwned(), before); XCTAssertNoThrow(try lease.validate())
            gate.resume.signal(); let returned = try await actual.value; XCTAssertEqual(returned, 7)
            let closed = await custody.closeAfterJoiningResult(); XCTAssertEqual(closed, .closed)
        }
    }
    func testSupervisorRetriesCannotTurnTheRealSealedLedgerJoinIntoJoinFailed() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { material in
            let activity = try ReleaseActivityFixture(), frame = try SetupRetainedOrphanClaimTests.Frame(material, activity: activity)
            let owner = frame.owner
            let placement = try ReleaseDestinationLease(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
            let lease = try SetupProcessLease.openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
            let shutdown = AdministrativeSetupShutdown(owner: owner, placement: placement, processLease: lease)
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: owner, shutdown: shutdown)
            let gate = RecoveryScopeGate(), count = RecoveryScopeCounter(), attempts = try owner.observeMaintenanceRecoveryExecutorOwned()
            defer { gate.resume.signal(); custody.releaseAfterJoining(); try? owner.close(); placement.close(); lease.close() }
            var invocation: SetupRetainedInvocation? = try frame.invocation(captured: false)
            try invocation?.retainCleanup {
                gate.entered.withLock { $0 = true }
                guard gate.resume.wait(timeout: .now() + 20) == .success else { throw RecoveryScopeTestFailure.timeout }
            }
            try frame.lose(&invocation)
            let claim = try frame.claim()
            try runAsync { @Sendable [frame, owner, custody, gate, count, attempts, claim] in
                let beforeJoin = try attempts.countOwned()
                let supervisor = try Self.retryingSupervisor(owner: owner, custody: custody, count: count)
                let request = try Self.retryRequest(), accepted = await supervisor.schedule(request); XCTAssertTrue(accepted)
                try await Self.eventually(for: .seconds(10)) { count.value.withLock { $0 >= 3 } }
                XCTAssertEqual(try attempts.countOwned(), beforeJoin, "Retrying recovery must leave the idle ledger executor untouched")
                let actual = Task { @Sendable [claim] in try await claim.join() }
                try await Self.eventually { gate.entered.withLock { $0 } }
                let duringJoin = try attempts.countOwned(), retries = count.value.withLock { $0 }
                try await Self.eventually(for: .seconds(10)) { count.value.withLock { $0 >= retries + 3 } }
                XCTAssertEqual(try attempts.countOwned(), duringJoin, "Recovery must not enter the active ledger executor")
                XCTAssertEqual(frame.status.cleanup, .observed(.joining))
                await supervisor.close(); gate.resume.signal()
                let joined = try await actual.value
                XCTAssertEqual(joined.evidence.cleanupRegistered, 1); XCTAssertEqual(joined.evidence.cleanupReturned, 1)
                XCTAssertEqual(frame.status.cleanup, .observed(.joined))
                XCTAssertTrue(try joined.releaseIfWindowFree())
                let closed = await custody.closeAfterJoiningResult(); XCTAssertEqual(closed, .closed)
            }
        }
    }

}
