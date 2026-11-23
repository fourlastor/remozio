import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

private enum RecoveryScopeTestFailure: Error { case timeout }
private final class RecoveryScopeHarness: @unchecked Sendable {
    let activity: ReleaseActivityFixture
    let account: AccountPreparationIntent
    let identity: LocalAccountIdentity
    let owner: SetupAccountOwner
    let placement: ReleaseDestinationLease
    let processLease: SetupProcessLease
    let shutdown: AdministrativeSetupShutdown
    init(_ fixture: RetainedMaterialWriterFixture) throws {
        identity = fixture.owner
        account = try XCTUnwrap(fixture.machine().accountPreparation(ownerUID: fixture.owner.uid))
        XCTAssertEqual(account.accountID, fixture.material.services.accountID)
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

private final class RecoveryScopeForeignOwner: @unchecked Sendable {
    let harness: RuntimeAuditUpgradeOperationTests.Harness
    let owner: SetupAccountOwner
    init() throws {
        harness = try .init()
        owner = try harness.owner()
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

private final class RecoveryCleanupClock: Sendable {
    private let instant = Mutex(ContinuousClock.now)
    func now() -> ContinuousClock.Instant { instant.withLock { $0 } }
    func advance(_ delay: Duration) { instant.withLock { $0 = $0.advanced(by: delay) } }
}

private final class RecoveryCleanupOwner: SetupMaintenanceRecoveryOwnerCleanup, Sendable {
    let id = UUID()
    let runs = Mutex(0), attempts = Mutex(0)
    private let scope: SetupAccountOwner.MaintenanceRecoveryScope
    private let cleanup: @Sendable (Int) async -> Bool
    private let didJoin: @Sendable () -> Void
    private let didFailCleanup: @Sendable () -> Void

    init(scope: SetupAccountOwner.MaintenanceRecoveryScope, custody: SetupMaintenanceRecoveryNativeAdapter.Custody,
         cleanup: @escaping @Sendable (Int) async -> Bool) {
        let id = self.id
        self.scope = scope; self.cleanup = cleanup
        didJoin = { [weak custody] in custody?.joined(id) }
        didFailCleanup = { [weak custody] in custody?.cleanupFailed(id) }
    }
    func run() -> SetupMaintenanceRecoverySupervisor.Observation {
        runs.withLock { $0 += 1 }
        return .noWindow
    }
    func join() async {
        let attempt = attempts.withLock { $0 += 1; return $0 }
        guard await cleanup(attempt) else { didFailCleanup(); return }
        scope.close(); didJoin()
    }
    func releaseFixture() { scope.close(); didJoin() }
}

private final class RetirementScopeCustody: SetupMaintenanceRecoveryProcessCustody, Sendable {
    let native: SetupMaintenanceRecoveryNativeAdapter.Custody
    private let admissionClosed = DispatchSemaphore(value: 0)
    let driverRejected = DispatchSemaphore(value: 0)
    let finalCloses = Mutex(0)

    init(native: SetupMaintenanceRecoveryNativeAdapter.Custody) {
        self.native = native
    }

    func validate() throws { try native.validate() }
    func validateForRecovery() async -> Bool { await native.validateForRecovery() }
    func joinRecoverySessions() async { await native.joinRecoverySessions() }
    func observeRecoverySessionsForDisposal() async { await native.observeRecoverySessionsForDisposal() }
    func retainSupervisorDisposal(_ actual: Task<Void, Never>) { native.retainSupervisorDisposal(actual) }
    func releaseAfterJoining() { native.releaseAfterJoining() }
    func closeAfterJoining() async { _ = await closeAfterJoiningResult() }
    func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
        finalCloses.withLock { $0 += 1 }
        return await native.closeAfterJoiningResult()
    }

    func closeAdmission() {
        native.closeAdmission()
        admissionClosed.signal()
        if driverRejected.wait(timeout: .now() + 3) != .success {
            XCTFail("The recovery driver did not observe the closed admission")
        }
    }

    func waitForAdmissionClose() async throws {
        // The fixture must reach the real scope call even when the supervisor cancels the entry.
        let closed = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(returning: self.admissionClosed.wait(timeout: .now() + 3) == .success)
            }
        }
        guard closed else {
            XCTFail("Retirement did not close admission")
            throw RecoveryScopeTestFailure.timeout
        }
    }
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
    func testRetirementCancelsBeforeTheOwnerRefusesRecoveryScope() throws {
        try withScope { h in
            let native = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let custody = RetirementScopeCustody(native: native)
            let entered = Mutex(false), cancelledAtRejection = Mutex<Bool?>(nil)
            let attempts = try h.owner.observeMaintenanceRecoveryExecutorOwned()
            let before = try attempts.countOwned()
            let supervisor = try SetupMaintenanceRecoverySupervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                entered.withLock { $0 = true }
                try await custody.waitForAdmissionClose()
                defer { custody.driverRejected.signal() }
                do {
                    let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
                    scope.close()
                    XCTFail("Recovery acquired a scope after retirement closed admission")
                    throw RecoveryScopeTestFailure.timeout
                } catch AdministrativeSetupError.unavailable {
                    try h.processLease.validate()
                    cancelledAtRejection.withLock { $0 = Task.isCancelled }
                    throw AdministrativeSetupError.unavailable
                }
            }))
            native.bindSupervisor(supervisor)
            let request = try Self.retryRequest()
            let scheduled = await supervisor.schedule(request)
            XCTAssertTrue(scheduled)
            try await Self.eventually { entered.withLock { $0 } }
            await supervisor.retire()

            XCTAssertEqual(cancelledAtRejection.withLock { $0 }, true, "The rejected entry was still running without cancellation")
            let observation = await supervisor.observation(for: request.key)
            switch observation {
            case .cancelled?: break
            case .failed(.serviceUnavailable)?: XCTFail("Retirement published failed(serviceUnavailable)")
            default: XCTFail("Retirement did not publish cancelled")
            }
            XCTAssertEqual(try attempts.countOwned(), before)
            XCTAssertEqual(custody.finalCloses.withLock { $0 }, 1)
            let nextProcess = try h.acquireProcess()
            nextProcess.close()
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
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope), entered = RecoveryScopeBoolean(), resume = DispatchSemaphore(value: 0)
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
    func testBoundDirectCloseWaitsForTheSupervisorBeforeReportingPendingScopeCleanup() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let supervisor = try SetupMaintenanceRecoverySupervisor.openOwned(custody: custody,
                driver: .init(acquire: { _, _ in .terminal(.noWindow) }))
            let session = try h.shutdown.registerRecoverySession(owner: h.owner)
            XCTAssertTrue(session.reservePublication())
            let released = RecoveryScopeBoolean(), closing = RecoveryScopeBoolean(), returned = RecoveryScopeBoolean()
            session.bindEndpointClose { closing.value.withLock { $0 = true } }
            let actual = Task {
                let deadline = ContinuousClock.now.advanced(by: .seconds(5))
                while !released.value.withLock({ $0 }) {
                    guard ContinuousClock.now < deadline else {
                        XCTFail("Session did not receive its bounded async release"); return
                    }
                    await withCheckedContinuation { continuation in
                        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(1)) {
                            continuation.resume()
                        }
                    }
                }
            }
            session.publish(actual)
            defer { released.value.withLock { $0 = true }; scope.close(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            let close = Task {
                do { try await h.shutdown.close(); XCTFail("Pending account scope reported closed") }
                catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
                returned.value.withLock { $0 = true }
            }
            try await Self.eventually { closing.value.withLock { $0 } }
            XCTAssertFalse(returned.value.withLock { $0 })
            XCTAssertTrue(h.shutdown.belongs(to: h.owner))
            XCTAssertNoThrow(try h.processLease.validate()); XCTAssertNoThrow(try h.placement.validate())
            released.value.withLock { $0 = true }; await close.value
            let closedSupervisor = await supervisor.isClosed, pending = await supervisor.closureResult
            XCTAssertTrue(closedSupervisor); XCTAssertEqual(pending, .pending)
            XCTAssertNoThrow(try h.processLease.validate())
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
    private static func scheduleCleanupFailure(_ h: RecoveryScopeHarness, clock: RecoveryCleanupClock,
        closeWait: SetupMaintenanceRecoveryNativeAdapter.OwnedCloseWait? = nil,
        cleanup: @escaping @Sendable (Int) async -> Bool
    ) async throws -> (SetupMaintenanceRecoverySupervisor, SetupMaintenanceRecoveryNativeAdapter.Custody, RecoveryCleanupOwner) {
        let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown,
            ownedCloseWait: closeWait, ownedRetryNow: { clock.now() })
        let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
        let owner = RecoveryCleanupOwner(scope: scope, custody: custody, cleanup: cleanup)
        custody.retain(owner, id: owner.id)
        let supervisor = try SetupMaintenanceRecoverySupervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in owner.run() }, join: { await owner.join() }))
        }))
        let request = try retryRequest()
        let scheduled = await supervisor.schedule(request)
        XCTAssertTrue(scheduled)
        await supervisor.waitForInitialAttempt(request.key)
        XCTAssertEqual(owner.runs.withLock { $0 }, 1)
        XCTAssertEqual(owner.attempts.withLock { $0 }, 1)
        await supervisor.retire()
        let result = await supervisor.closureResult, exit = await supervisor.shouldExit
        XCTAssertEqual(result, .failed)
        XCTAssertFalse(exit)
        XCTAssertNoThrow(try h.processLease.validate())
        XCTAssertNoThrow(try h.placement.validate())
        return (supervisor, custody, owner)
    }

    func testLaterRetirementRetriesNativeOwnerCleanupAndReleasesBothLeases() throws {
        try withScope { h in
            let clock = RecoveryCleanupClock()
            let (supervisor, custody, owner) = try await Self.scheduleCleanupFailure(h, clock: clock) { $0 == 2 }
            defer { owner.releaseFixture(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            XCTAssertThrowsError(try h.acquireProcess()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            clock.advance(.seconds(1))
            await supervisor.retire()
            let result = await supervisor.closureResult, exit = await supervisor.shouldExit
            XCTAssertEqual(owner.runs.withLock { $0 }, 1)
            XCTAssertEqual(owner.attempts.withLock { $0 }, 2)
            XCTAssertEqual(result, .closed)
            XCTAssertTrue(exit)
            XCTAssertThrowsError(try h.processLease.validate())
            XCTAssertThrowsError(try h.placement.validate())
            if exit {
                let replacement = try h.acquireProcess(); replacement.close()
            }
        }
    }

    func testDirectCloseWaitsForAnActiveRetirementRetry() throws {
        try withScope { h in
            let clock = RecoveryCleanupClock(), releaseCleanup = AsyncStream<Void>.makeStream()
            let (supervisor, custody, owner) = try await Self.scheduleCleanupFailure(h, clock: clock) { attempt in
                guard attempt == 2 else { return false }
                for await _ in releaseCleanup.stream {}
                return true
            }
            defer {
                releaseCleanup.continuation.finish(); owner.releaseFixture(); custody.releaseAfterJoining()
                h.placement.close(); h.processLease.close()
            }

            clock.advance(.seconds(1))
            let retirement = Task { await supervisor.retire() }
            try await Self.eventually { owner.attempts.withLock { $0 } == 2 }
            let closeOutcome = RecoveryScopeCompletion(), closeStarted = RecoveryScopeBoolean()
            let close = Task {
                closeStarted.value.withLock { $0 = true }
                do { try await h.shutdown.close(); closeOutcome.value.withLock { $0 = .success(()) } }
                catch { closeOutcome.value.withLock { $0 = .failure(error) } }
            }
            try await Self.eventually { closeStarted.value.withLock { $0 } }
            do {
                try await Self.eventually(for: .milliseconds(300)) { closeOutcome.value.withLock { $0 != nil } }
                XCTFail("Direct close returned while the retirement retry was held")
            } catch RecoveryScopeTestFailure.timeout {}
            XCTAssertNoThrow(try h.processLease.validate())
            XCTAssertNoThrow(try h.placement.validate())

            releaseCleanup.continuation.finish()
            await retirement.value
            await close.value
            try XCTUnwrap(closeOutcome.value.withLock { $0 }).get()
            let result = await supervisor.closureResult
            XCTAssertEqual(result, .closed)
            XCTAssertEqual(owner.attempts.withLock { $0 }, 2)
            XCTAssertEqual(owner.runs.withLock { $0 }, 1)
            XCTAssertThrowsError(try h.processLease.validate())
            XCTAssertThrowsError(try h.placement.validate())
            let replacement = try h.acquireProcess()
            replacement.close()
        }
    }

    func testCleanupRetryCoalescesRetirementCallsInsideBackoff() throws {
        try withScope { h in
            let clock = RecoveryCleanupClock()
            let (supervisor, custody, owner) = try await Self.scheduleCleanupFailure(h, clock: clock) { _ in false }
            defer { owner.releaseFixture(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            clock.advance(.seconds(1))
            await supervisor.retire()
            await supervisor.retire()
            XCTAssertEqual(owner.attempts.withLock { $0 }, 2)
            XCTAssertEqual(owner.runs.withLock { $0 }, 1)
            let result = await supervisor.closureResult, exit = await supervisor.shouldExit
            XCTAssertEqual(result, .failed)
            XCTAssertFalse(exit)
            XCTAssertNoThrow(try h.processLease.validate())
            XCTAssertNoThrow(try h.placement.validate())
        }
    }

    func testPersistentOwnerCleanupUsesBackoffCappedAtThirtySeconds() throws {
        try withScope { h in
            let clock = RecoveryCleanupClock()
            let (supervisor, custody, owner) = try await Self.scheduleCleanupFailure(h, clock: clock) { _ in false }
            defer { owner.releaseFixture(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            for (index, delay) in [1, 2, 4, 8, 16, 30, 30].enumerated() {
                clock.advance(.seconds(delay) - .milliseconds(1))
                await supervisor.close()
                XCTAssertEqual(owner.attempts.withLock { $0 }, index + 1)
                clock.advance(.milliseconds(1))
                await supervisor.close()
                XCTAssertEqual(owner.attempts.withLock { $0 }, index + 2)
                let result = await supervisor.closureResult, exit = await supervisor.shouldExit
                XCTAssertEqual(result, .failed)
                XCTAssertFalse(exit)
                XCTAssertNoThrow(try h.processLease.validate())
                XCTAssertNoThrow(try h.placement.validate())
            }
            XCTAssertEqual(owner.runs.withLock { $0 }, 1)
        }
    }

    func testCancelledAndTimedOutCloseWaitersKeepTheSameCleanupAttempt() throws {
        try withScope { h in
            let clock = RecoveryCleanupClock()
            let gate = AsyncStream<Void>.makeStream()
            let (supervisor, custody, owner) = try await Self.scheduleCleanupFailure(h, clock: clock,
                closeWait: .init(shorteningTo: .seconds(1))) { attempt in
                guard attempt == 2 else { return false }
                for await _ in gate.stream {}
                return true
            }
            defer {
                gate.continuation.finish(); owner.releaseFixture(); custody.releaseAfterJoining()
                h.placement.close(); h.processLease.close()
            }
            clock.advance(.seconds(1))
            let retire = Task { await supervisor.retire() }
            try await Self.eventually { owner.attempts.withLock { $0 } == 2 }
            let identity = try XCTUnwrap(custody.closeAttemptIDOwned())
            retire.cancel(); await retire.value
            let cancelled = await supervisor.closureResult
            XCTAssertEqual(cancelled, .timedOut)
            XCTAssertEqual(try custody.closeAttemptIDOwned(), identity)

            clock.advance(.seconds(30))
            await supervisor.close()
            let timedOut = await supervisor.closureResult
            XCTAssertEqual(timedOut, .timedOut)
            XCTAssertEqual(try custody.closeAttemptIDOwned(), identity)
            XCTAssertEqual(owner.attempts.withLock { $0 }, 2)
            XCTAssertNoThrow(try h.processLease.validate())
            XCTAssertNoThrow(try h.placement.validate())

            gate.continuation.finish()
            await supervisor.close()
            let result = await supervisor.closureResult, exit = await supervisor.shouldExit
            XCTAssertEqual(result, .closed)
            XCTAssertTrue(exit)
            XCTAssertEqual(owner.runs.withLock { $0 }, 1)
            XCTAssertEqual(owner.attempts.withLock { $0 }, 2)
            XCTAssertThrowsError(try h.processLease.validate())
            XCTAssertThrowsError(try h.placement.validate())
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
            XCTAssertThrowsError(try shutdown.reserveRecoverySupervisor(expectsPublication: false)) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
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
                try await owner.performAuditUpgradeWork(authorization: grant) { token, admission in
                    let scope = try owner.acquireAuditUpgradeScope(authorization: grant, admission: admission)
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

    func testRecoveryPermitRefusesAScopeFromAnotherOwner() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            defer { scope.close(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let other = try await SetupExecutorAdmissionTestFixture.make { try RecoveryScopeForeignOwner() }
            defer { try? other.owner.close() }
            XCTAssertThrowsError(try other.owner.maintenanceRecoveryPhases(scope: scope))
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope)
            try await phases.acquire { XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes) }
        }
    }
    func testClosedRecoveryScopeCannotMintOrStartEarlierPhases() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            defer { scope.close(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope), writes = RecoveryScopeCounter()
            let attempts = try h.owner.observeMaintenanceRecoveryExecutorOwned()
            scope.close()
            XCTAssertThrowsError(try h.owner.maintenanceRecoveryPhases(scope: scope))
            for operation in 0..<4 {
                do {
                    if operation == 0 { try await phases.acquire { writes.value.withLock { $0 += 1 } } }
                    else if operation == 1 { try await phases.run { writes.value.withLock { $0 += 1 } } }
                    else if operation == 2 { try await phases.cleanup { writes.value.withLock { $0 += 1 } } }
                    else { try await phases.closeActual { writes.value.withLock { $0 += 1 } } }
                    XCTFail("A closed scope entered its executor")
                } catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
            }
            XCTAssertEqual(writes.value.withLock { $0 }, 0); XCTAssertEqual(try attempts.countOwned(), 0)
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
        }
    }
    func testScopeCloseKeepsAdmissionAndActivityUntilActualPhaseReturn() throws {
        try withScope { h in
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope), gate = RecoveryScopeGate()
            let work = Task {
                try await phases.run {
                    gate.entered.withLock { $0 = true }
                    guard gate.resume.wait(timeout: .now() + 10) == .success else { throw RecoveryScopeTestFailure.timeout }
                }
            }
            defer { gate.resume.signal(); scope.close(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            try await Self.eventually { gate.entered.withLock { $0 } }
            scope.close()
            XCTAssertThrowsError(try h.owner.verifyCurrent()); XCTAssertThrowsError(try h.owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try h.activity.open().acquireExclusive())
            gate.resume.signal(); try await work.value
            try h.owner.verifyCurrent(); let reply = try h.owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
        }
    }
    func testClaimRefusesHeldScopeThenWaitsForReleasedScopesRunningPhase() throws {
        try withScope { h in
            let account = h.account, identity = h.identity
            let peer = XPCPeerCredentials(processID: getpid(), userID: identity.uid, auditSessionID: 1), checks = RecoveryScopeCounter()
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope), gate = RecoveryScopeGate()
            defer { gate.resume.signal(); scope.close(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let rights = try SetupRetainedRecoveryAuthorization.openOwned(peer: peer, currentOwner: identity, incarnation: UUID(),
                verifyRights: { checks.value.withLock { $0 += 1 } })
            let baseline = checks.value.withLock { $0 }, start = ContinuousClock.now
            do {
                _ = try await SetupRestartRecovery.Claim.openOwned(owner: h.owner, authorization: rights,
                    processLease: h.processLease, accountID: account.accountID, until: .now.advanced(by: .seconds(5)))
                XCTFail("A durable scope allowed another claim")
            } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            XCTAssertLessThan(start.duration(to: .now), .milliseconds(100)); XCTAssertEqual(checks.value.withLock { $0 }, baseline)
            let work = Task {
                try await phases.run {
                    gate.entered.withLock { $0 = true }
                    guard gate.resume.wait(timeout: .now() + 10) == .success else { throw RecoveryScopeTestFailure.timeout }
                }
            }
            try await Self.eventually { gate.entered.withLock { $0 } }; scope.close()
            let freshRights = try SetupRetainedRecoveryAuthorization.openOwned(peer: peer, currentOwner: identity, incarnation: UUID(),
                verifyRights: { checks.value.withLock { $0 += 1 } })
            let before = checks.value.withLock { $0 }, returned = RecoveryScopeBoolean()
            let claim = Task {
                let value = try await SetupRestartRecovery.Claim.openOwned(owner: h.owner, authorization: freshRights,
                    processLease: h.processLease, accountID: account.accountID, until: .now.advanced(by: .seconds(5)))
                returned.value.withLock { $0 = true }; return value
            }
            try await ContinuousClock().sleep(for: .milliseconds(100))
            XCTAssertFalse(returned.value.withLock { $0 }); XCTAssertEqual(checks.value.withLock { $0 }, before)
            gate.resume.signal(); try await work.value
            let actual = try await claim.value; actual.abandon(); try h.owner.verifyCurrent()
        }
    }
    func testFinalCustodyCloseStaysPendingUntilClosedScopesLastPhaseReturns() throws {
        try withScope { h in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let scope = try h.owner.acquireMaintenanceRecoveryScope(custody: h.shutdown)
            let phases = try h.owner.maintenanceRecoveryPhases(scope: scope), gate = RecoveryScopeGate()
            let work = Task {
                try await phases.run {
                    gate.entered.withLock { $0 = true }
                    guard gate.resume.wait(timeout: .now() + 10) == .success else { throw RecoveryScopeTestFailure.timeout }
                }
            }
            defer { gate.resume.signal(); scope.close(); custody.releaseAfterJoining(); h.placement.close(); h.processLease.close() }
            try await Self.eventually { gate.entered.withLock { $0 } }; scope.close()
            let pending = await custody.closeAfterJoiningResult(); XCTAssertEqual(pending, .pending)
            XCTAssertNoThrow(try h.processLease.validate()); XCTAssertNoThrow(try h.placement.validate())
            XCTAssertThrowsError(try h.activity.open().acquireExclusive())
            gate.resume.signal(); try await work.value
            let closed = await custody.closeAfterJoiningResult(); XCTAssertEqual(closed, .closed)
            XCTAssertThrowsError(try h.processLease.validate()); XCTAssertThrowsError(try h.placement.validate())
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
            custody.releaseAfterJoining()
        }
    }

    func testAdapterTerminalPathClosesItsRetainedScopeAfterActualBodyReturn() throws {
        try withScope { h in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let retained = Mutex<SetupAccountOwner.MaintenanceRecoveryScope?>(nil), calls = RecoveryScopeCounter()
            defer { retained.withLock { $0?.close() }; custody.releaseAfterJoining(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let control = try SetupMaintenanceRecoveryNativeAdapter.OwnedAcquisitionControl(beforeMint: { scope in
                retained.withLock { $0 = scope }
            }, observe: { _ in
                XCTAssertEqual(h.owner.statusLaneCheck(), .pinned)
                XCTAssertThrowsError(try h.activity.open().acquireExclusive())
                calls.value.withLock { $0 += 1 }; return .noWindow
            })
            let driver = try SetupMaintenanceRecoveryNativeAdapter.driverOwned(owner: h.owner, custody: custody, control: control)
            let result = try await driver.acquire(Self.retryRequest(), .now.advanced(by: .seconds(5)))
            guard case .terminal(.noWindow) = result else { return XCTFail("Expected terminal fixture observation") }
            XCTAssertEqual(calls.value.withLock { $0 }, 1); XCTAssertNotNil(retained.withLock { $0 })
            try h.owner.verifyCurrent(); let reply = try h.owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
        }
    }
    func testAdapterBodyErrorExplicitlyClosesItsRetainedScope() throws {
        try withScope { h in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let retained = Mutex<SetupAccountOwner.MaintenanceRecoveryScope?>(nil), calls = RecoveryScopeCounter()
            defer { retained.withLock { $0?.close() }; custody.releaseAfterJoining(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let control = try SetupMaintenanceRecoveryNativeAdapter.OwnedAcquisitionControl(beforeMint: { scope in
                retained.withLock { $0 = scope }
            }, observe: { _ in
                XCTAssertEqual(h.owner.statusLaneCheck(), .pinned)
                calls.value.withLock { $0 += 1 }; throw RecoveryScopeTestFailure.timeout
            })
            let driver = try SetupMaintenanceRecoveryNativeAdapter.driverOwned(owner: h.owner, custody: custody, control: control)
            do { _ = try await driver.acquire(Self.retryRequest(), .now.advanced(by: .seconds(5))); XCTFail("Expected fixture body error") }
            catch { XCTAssertTrue(error is RecoveryScopeTestFailure) }
            XCTAssertEqual(calls.value.withLock { $0 }, 1); XCTAssertNotNil(retained.withLock { $0 })
            try h.owner.verifyCurrent(); let reply = try h.owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
        }
    }
    func testAdapterMintErrorClosesScopeWithoutEnteringTheExecutor() throws {
        try withScope { h in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: h.owner, shutdown: h.shutdown)
            let retained = Mutex<SetupAccountOwner.MaintenanceRecoveryScope?>(nil), calls = RecoveryScopeCounter()
            let attempts = try h.owner.observeMaintenanceRecoveryExecutorOwned()
            defer { retained.withLock { $0?.close() }; custody.releaseAfterJoining(); try? h.owner.close(); h.placement.close(); h.processLease.close() }
            let control = try SetupMaintenanceRecoveryNativeAdapter.OwnedAcquisitionControl(beforeMint: { scope in
                retained.withLock { $0 = scope }; scope.close()
            }, observe: { _ in calls.value.withLock { $0 += 1 }; return .noWindow })
            let driver = try SetupMaintenanceRecoveryNativeAdapter.driverOwned(owner: h.owner, custody: custody, control: control)
            do { _ = try await driver.acquire(Self.retryRequest(), .now.advanced(by: .seconds(5))); XCTFail("A closed scope minted phases") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            XCTAssertEqual(calls.value.withLock { $0 }, 0); XCTAssertEqual(try attempts.countOwned(), 0)
            try h.owner.verifyCurrent(); let reply = try h.owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try h.activity.open().acquireExclusive(); exclusive.close()
        }
    }

}
