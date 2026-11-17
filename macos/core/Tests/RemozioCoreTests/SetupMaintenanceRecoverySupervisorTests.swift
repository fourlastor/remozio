import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

private actor RecoverySupervisorGate {
    private var opened = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if opened { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func open() {
        opened = true
        let pending = waiters; waiters = []
        for waiter in pending { waiter.resume() }
    }
}

private final class RecoverySupervisorCustody: SetupMaintenanceRecoveryProcessCustody, @unchecked Sendable {
    let retired = Mutex(false), closeStarted = Mutex(0), closeFinished = Mutex(0)
    let closeWasCancelled = Mutex(false)
    let closeAttempts = Mutex(0), disposalJoined = Mutex(0), admissionsClosed = Mutex(0)
    let validationTaskContexts = Mutex<[Bool]>([])
    private let closeOutcomes: Mutex<[AdministrativeSetupShutdown.RecoveryCloseResult]>
    private let validationPhases: SetupRetainedInvocationReservation.RestorationPhases?
    let fixture: ReleaseActivityFixture?
    let token: ReleaseActivityToken?
    let releaseGate: RecoverySupervisorGate?
    init(shared: Bool = false, releaseGate: RecoverySupervisorGate? = nil,
        closeOutcomes: [AdministrativeSetupShutdown.RecoveryCloseResult] = [],
        validationPhases: SetupRetainedInvocationReservation.RestorationPhases? = nil) throws {
        self.closeOutcomes = .init(closeOutcomes); self.validationPhases = validationPhases
        fixture = shared ? try ReleaseActivityFixture() : nil
        token = try fixture?.open().acquireShared()
        self.releaseGate = releaseGate
    }
    func validate() throws {
        validationTaskContexts.withLock { $0.append(withUnsafeCurrentTask { $0 != nil }) }
        if retired.withLock({ $0 }) { throw JournalLeaseError.invalidated }
        try token?.validate()
    }
    func validateForRecovery() async -> Bool {
        do {
            if let validationPhases { try await validationPhases.cleanup { try self.validate() } }
            else { try validate() }
            return true
        } catch { return false }
    }
    func closeAdmission() { admissionsClosed.withLock { $0 += 1 } }
    func releaseAfterJoining() { disposalJoined.withLock { $0 += 1 } }
    func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
        closeAttempts.withLock { $0 += 1 }
        let planned: AdministrativeSetupShutdown.RecoveryCloseResult? = closeOutcomes.withLock { $0.isEmpty ? nil : $0.removeFirst() }
        if let planned, planned != .closed { return planned }
        await closeAfterJoining(); return .closed
    }
    func closeAfterJoining() async {
        closeStarted.withLock { $0 += 1 }
        closeWasCancelled.withLock { $0 = Task.isCancelled }
        await releaseGate?.wait()
        token?.close(); closeFinished.withLock { $0 += 1 }
    }
}

private final class RecoverySupervisorClock: @unchecked Sendable {
    struct State {
        var now: ContinuousClock.Instant
        var sleeps: [Duration] = []
        var rearms = 0
    }
    let epoch = ContinuousClock.now
    private let state: Mutex<State>
    private let passFirstRearm: Bool
    init(passFirstRearm: Bool = false) {
        self.passFirstRearm = passFirstRearm
        state = .init(.init(now: epoch))
    }
    var now: ContinuousClock.Instant { state.withLock { $0.now } }
    var sleeps: [Duration] { state.withLock { $0.sleeps } }
    var rearms: Int { state.withLock { $0.rearms } }
    func advance(_ duration: Duration) { state.withLock { $0.now = $0.now.advanced(by: duration) } }
    var timing: SetupMaintenanceRecoverySupervisor.Timing {
        .init(now: { self.now }, sleep: { deadline in
            try Task.checkCancellation()
            let parked = self.state.withLock { state in
                let delay = state.now.duration(to: deadline)
                guard delay > .zero else { return false }
                state.sleeps.append(delay); state.now = deadline
                if delay == .seconds(60) {
                    state.rearms += 1
                    return !(self.passFirstRearm && state.rearms == 1)
                }
                return false
            }
            if parked { try await ContinuousClock().sleep(until: .now.advanced(by: .seconds(60))) }
            await Task.yield()
        })
    }
}

private enum RecoverySupervisorTestFailure: Error { case timeout, join }
private struct RecoverySupervisorPrivateFailure: Error, CustomStringConvertible {
    var description: String { "private-caller-secret-and-path" }
}
private final class RecoverySupervisorWeakReference: @unchecked Sendable {
    weak var value: SetupMaintenanceRecoverySupervisor?
    init(_ value: SetupMaintenanceRecoverySupervisor?) { self.value = value }
}

@MainActor
final class SetupMaintenanceRecoverySupervisorTests: XCTestCase {
    private typealias Supervisor = SetupMaintenanceRecoverySupervisor
    private static func request(_ byte: UInt8 = 1, revision: UInt8 = 3) throws -> Supervisor.Request {
        try .init(accountID: Data(repeating: byte, count: 16), windowID: Data(repeating: byte + 1, count: 16),
            revision: Data(repeating: revision, count: 16))
    }
    private static func eventually(_ check: @escaping @Sendable () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await check()) {
            guard ContinuousClock.now < deadline else { throw RecoverySupervisorTestFailure.timeout }
            try await ContinuousClock().sleep(until: .now.advanced(by: .milliseconds(1)))
        }
    }
    func testOneWindowRefusesDuplicateRevisionAndGlobalOverlapThenKeepsTheCompletedKey() async throws {
        let custody = try RecoverySupervisorCustody(), gate = RecoverySupervisorGate(), calls = Mutex(0)
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }
            return .owner(.init(run: { _ in await gate.wait(); return .phase(.needsOwnerRecovery) }, join: {}))
        }))
        let request = try Self.request(), changed = try Self.request(revision: 9), other = try Self.request(5)
        let admitted = await supervisor.schedule(request); XCTAssertTrue(admitted)
        try await Self.eventually { calls.withLock { $0 } == 1 }
        let duplicate = await supervisor.schedule(request), revision = await supervisor.schedule(changed)
        let overlap = await supervisor.schedule(other)
        XCTAssertFalse(duplicate); XCTAssertFalse(revision); XCTAssertFalse(overlap)
        await gate.open()
        try await Self.eventually { await supervisor.observation(for: request.key) == .phase(.needsOwnerRecovery) }
        let replay = await supervisor.schedule(changed); XCTAssertFalse(replay)
        let next = await supervisor.schedule(other); XCTAssertTrue(next)
        try await Self.eventually { calls.withLock { $0 } == 2 }
        await supervisor.close(); XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testTypedBusyUsesFreshAcquisitionAndBoundedBackoffWithinOneDeadline() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock()
        let deadlines = Mutex<[ContinuousClock.Instant]>([]), identities = Mutex<[UUID]>([]), runs = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, deadline in
            deadlines.withLock { $0.append(deadline) }
            let count = identities.withLock { $0.append(UUID()); return $0.count }
            if count <= 5 { return .busyBeforeOwner }
            return .owner(.init(run: { actual in
                XCTAssertEqual(actual, deadline); runs.withLock { $0 += 1 }; return .phase(.needsOwnerRecovery)
            }, join: {}))
        }), timing: clock.timing)
        let request = try Self.request(); let admitted = await supervisor.schedule(request); XCTAssertTrue(admitted)
        try await Self.eventually { await supervisor.observation(for: request.key) == .phase(.needsOwnerRecovery) }
        XCTAssertEqual(runs.withLock { $0 }, 1)
        XCTAssertEqual(Set(identities.withLock { $0 }).count, 6)
        XCTAssertTrue(deadlines.withLock { $0.allSatisfy { $0 == clock.epoch.advanced(by: .seconds(120)) } })
        XCTAssertEqual(clock.sleeps, [.milliseconds(250), .milliseconds(500), .seconds(1), .seconds(2), .seconds(2)])
        await supervisor.close()
    }
    func testBusyDeadlineWritesNothingAndArmsOneSixtySecondWait() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock()
        let starts = Mutex<[ContinuousClock.Instant]>([]), deadlines = Mutex<[ContinuousClock.Instant]>([]), writes = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, deadline in
            starts.withLock { $0.append(clock.now) }; deadlines.withLock { $0.append(deadline) }
            if clock.now >= deadline { writes.withLock { $0 += 1 }; return .terminal(.noWindow) }
            return .busyBeforeOwner
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .busy && clock.rearms == 1 }
        let expected = clock.epoch.advanced(by: .seconds(120))
        XCTAssertTrue(starts.withLock { $0.allSatisfy { $0 < expected } })
        XCTAssertTrue(deadlines.withLock { !$0.isEmpty && $0.allSatisfy { $0 == expected } })
        XCTAssertEqual(writes.withLock { $0 }, 0)
        XCTAssertEqual(clock.sleeps.last, .seconds(60))
        XCTAssertTrue(clock.sleeps.dropLast().allSatisfy { $0 > .zero && $0 <= .seconds(2) })
        XCTAssertEqual(clock.sleeps.dropLast().reduce(.zero, +), .seconds(120))
        await supervisor.close(); let state = await supervisor.observation(for: request.key)
        XCTAssertEqual(state, .cancelled)
    }
    func testSixtySecondRearmStartsFreshCustodyWithANewAbsoluteDeadline() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(passFirstRearm: true)
        let deadlines = Mutex<[ContinuousClock.Instant]>([])
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, deadline in
            deadlines.withLock { $0.append(deadline) }
            return clock.rearms == 0 ? .busyBeforeOwner : .terminal(.phase(.needsOwnerRecovery))
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .phase(.needsOwnerRecovery) }
        XCTAssertEqual(clock.rearms, 1)
        XCTAssertEqual(Set(deadlines.withLock { $0 }), Set([clock.epoch.advanced(by: .seconds(120)), clock.epoch.advanced(by: .seconds(300))]))
        await supervisor.close()
    }
    func testGenericConstructorBusyErrorIsNotPreOwnerRetryPermission() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(), calls = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }; throw JournalLeaseError.busy
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertTrue(clock.sleeps.isEmpty)
        await supervisor.close()
    }
    func testOwnerBusyErrorRunsOnceAndJoinsWithoutRearmingOrReplaying() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock()
        let calls = Mutex(0), runs = Mutex(0), joins = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }
            return .owner(.init(run: { _ in runs.withLock { $0 += 1 }; throw JournalLeaseError.busy },
                join: { joins.withLock { $0 += 1 } }))
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
        let again = await supervisor.schedule(try Self.request(revision: 8)); XCTAssertFalse(again)
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(runs.withLock { $0 }, 1); XCTAssertEqual(joins.withLock { $0 }, 1)
        XCTAssertTrue(clock.sleeps.isEmpty); await supervisor.close()
    }
    func testTerminalRowStopsBeforeOwnerCreationAndRefusesAnotherRevision() async throws {
        let custody = try RecoverySupervisorCustody(), calls = Mutex(0), clock = RecoverySupervisorClock()
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }; return .terminal(.phase(.needsOwnerRecovery))
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .phase(.needsOwnerRecovery) }
        let again = await supervisor.schedule(try Self.request(revision: 7)); XCTAssertFalse(again)
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertTrue(clock.sleeps.isEmpty); await supervisor.close()
    }
    func testShutdownJoinsRealWorkerAndCleanupEvenWhenTheCloseCallerIsCancelled() async throws {
        let runGate = RecoverySupervisorGate(), cleanupGate = RecoverySupervisorGate()
        let custody = try RecoverySupervisorCustody(shared: true), entered = Mutex(false), cancelled = Mutex(0)
        let joining = Mutex(false), joinCancelled = Mutex(false), writes = Mutex(0), closed = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await runGate.open(); await cleanupGate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in
                entered.withLock { $0 = true }; await runGate.wait(); try Task.checkCancellation()
                writes.withLock { $0 += 1 }; return .phase(.restored)
            }, cancel: { cancelled.withLock { $0 += 1 } }, join: {
                joining.withLock { $0 = true }; joinCancelled.withLock { $0 = Task.isCancelled }; await cleanupGate.wait()
            }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { entered.withLock { $0 } }
        let close = Task { await supervisor.close(); closed.withLock { $0 = true } }
        close.cancel()
        try await Self.eventually { cancelled.withLock { $0 > 0 } }
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertThrowsError(try installer.acquireExclusive())
        await runGate.open(); try await Self.eventually { joining.withLock { $0 } }
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertThrowsError(try installer.acquireExclusive())
        XCTAssertFalse(joinCancelled.withLock { $0 }); await cleanupGate.open(); await close.value
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertEqual(writes.withLock { $0 }, 0)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testFailedJoinObservationCannotReleaseCustodyBeforeTheActualWorkerEnds() async throws {
        let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody(shared: true)
        let running = Mutex(false), joinFailures = Mutex(0), joining = Mutex(false), cancelled = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        let worker = Task { running.withLock { $0 = true }; await gate.wait(); running.withLock { $0 = false } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in throw RecoverySupervisorPrivateFailure() }, cancel: { worker.cancel(); cancelled.withLock { $0 = true } }, join: {
                joining.withLock { $0 = true }
                let failed = Task<Void, any Error> { throw RecoverySupervisorTestFailure.join }
                do { try await failed.value } catch { joinFailures.withLock { $0 += 1 } }
                await worker.value
            }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { joining.withLock { $0 } && joinFailures.withLock { $0 } == 1 && running.withLock { $0 } }
        let close = Task { await supervisor.close() }
        try await Self.eventually { cancelled.withLock { $0 } }
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0); XCTAssertThrowsError(try installer.acquireExclusive())
        await gate.open(); await close.value
        XCTAssertFalse(running.withLock { $0 }); XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testCancellationDuringJoinStillCancelsTheActualOwner() async throws {
        let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody(shared: true)
        let joining = Mutex(false), installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        let worker = Task { await gate.wait() }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in return .noWindow }, cancel: { worker.cancel() }, join: {
                joining.withLock { $0 = true }; await worker.value
            }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { joining.withLock { $0 } }
        let close = Task { await supervisor.close() }
        try await Self.eventually { worker.isCancelled }
        XCTAssertThrowsError(try installer.acquireExclusive())
        await gate.open(); await close.value
        let result = await supervisor.observation(for: request.key); XCTAssertEqual(result, .noWindow)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testRetirementKeepsCustodyAndAdmissionClosedUntilAllLifecycleJoinsFinish() async throws {
        let runGate = RecoverySupervisorGate(), releaseGate = RecoverySupervisorGate()
        let custody = try RecoverySupervisorCustody(shared: true, releaseGate: releaseGate), entered = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await runGate.open(); await releaseGate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in entered.withLock { $0 = true }; await runGate.wait(); try Task.checkCancellation(); return .noWindow }, join: {}))
        }))
        _ = await supervisor.schedule(try Self.request()); try await Self.eventually { entered.withLock { $0 } }
        let retirement = Task { await supervisor.retire() }
        let exitBeforeJoin = await supervisor.shouldExit; XCTAssertFalse(exitBeforeJoin)
        let newWork = await supervisor.schedule(try Self.request(6)); XCTAssertFalse(newWork)
        XCTAssertThrowsError(try installer.acquireExclusive()); await runGate.open()
        try await Self.eventually { custody.closeStarted.withLock { $0 } == 1 }
        let exitDuringLifecycleJoin = await supervisor.shouldExit; XCTAssertFalse(exitDuringLifecycleJoin)
        XCTAssertThrowsError(try installer.acquireExclusive()); await releaseGate.open(); await retirement.value
        let exitReady = await supervisor.shouldExit; XCTAssertTrue(exitReady)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1); let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testValidationRetirementStartsCloseWithoutConstructingAnOwner() async throws {
        let custody = try RecoverySupervisorCustody(), calls = Mutex(0); custody.retired.withLock { $0 = true }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }; return .terminal(.noWindow)
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.isClosed }
        let status = await supervisor.observation(for: request.key), exit = await supervisor.shouldExit
        XCTAssertEqual(status, .retired); XCTAssertTrue(exit); XCTAssertEqual(calls.withLock { $0 }, 0)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testDroppingTheSupervisorStillCancelsAndJoinsItsActualWorker() async throws {
        let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody(shared: true)
        let entered = Mutex(false), cancelled = Mutex(false), writes = Mutex(0)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        var supervisor: Supervisor? = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in
                entered.withLock { $0 = true }; await gate.wait(); try Task.checkCancellation(); writes.withLock { $0 += 1 }; return .noWindow
            }, cancel: { cancelled.withLock { $0 = true } }, join: {}))
        }))
        let weak = RecoverySupervisorWeakReference(supervisor); _ = await supervisor?.schedule(try Self.request())
        try await Self.eventually { entered.withLock { $0 } }; supervisor = nil
        try await Self.eventually { weak.value == nil && cancelled.withLock { $0 } }
        XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0)
        await gate.open(); try await Self.eventually { custody.disposalJoined.withLock { $0 } == 1 }
        XCTAssertEqual(writes.withLock { $0 }, 0)
        XCTAssertEqual(custody.closeAttempts.withLock { $0 }, 0)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0)
        XCTAssertThrowsError(try installer.acquireExclusive())
        await custody.closeAfterJoining()
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testExpiredUnusedOwnerJoinsThenRearmsWithFreshOwnerAndDeadline() async throws {
        let custody = try RecoverySupervisorCustody(shared: true), clock = RecoverySupervisorClock(passFirstRearm: true)
        let gate = RecoverySupervisorGate(), joining = Mutex(false), joins = Mutex(0), runs = Mutex(0), cancellations = Mutex(0)
        let deadlines = Mutex<[ContinuousClock.Instant]>([]), installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, deadline in
            let call = deadlines.withLock { $0.append(deadline); return $0.count }
            if call == 1 {
                clock.advance(.seconds(121))
                return .owner(.init(run: { _ in XCTFail("Expired owner ran"); return .noWindow },
                    cancel: { cancellations.withLock { $0 += 1 } }, join: {
                        joining.withLock { $0 = true }; await gate.wait(); joins.withLock { $0 += 1 }
                    }))
            }
            XCTAssertEqual(joins.withLock { $0 }, 1)
            return .owner(.init(run: { actual in
                XCTAssertEqual(actual, deadline); runs.withLock { $0 += 1 }; return .phase(.needsOwnerRecovery)
            }, join: { joins.withLock { $0 += 1 } }))
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { joining.withLock { $0 } }
        XCTAssertEqual(deadlines.withLock { $0.count }, 1); XCTAssertEqual(clock.rearms, 0)
        XCTAssertThrowsError(try installer.acquireExclusive()); await gate.open()
        try await Self.eventually { await supervisor.observation(for: request.key) == .phase(.needsOwnerRecovery) }
        XCTAssertEqual(deadlines.withLock { $0 }, [clock.epoch.advanced(by: .seconds(120)), clock.epoch.advanced(by: .seconds(301))])
        XCTAssertEqual(cancellations.withLock { $0 }, 1); XCTAssertEqual(joins.withLock { $0 }, 2)
        XCTAssertEqual(runs.withLock { $0 }, 1); XCTAssertEqual(clock.rearms, 1); await supervisor.close()
    }
    func testConcurrentCloseCallersShareOneUncancelledCustodianJoin() async throws {
        let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody(releaseGate: gate)
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in .terminal(.noWindow) }))
        let first = Task { await supervisor.close() }, second = Task { await supervisor.close() }
        first.cancel(); try await Self.eventually { custody.closeStarted.withLock { $0 } == 1 }
        XCTAssertFalse(custody.closeWasCancelled.withLock { $0 }); await gate.open(); await first.value; await second.value
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testWorkerErrorsBecomeRedactedObservationsWithoutAnEscapingFailure() async throws {
        let custody = try RecoverySupervisorCustody()
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in throw RecoverySupervisorPrivateFailure() }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
        let status = await supervisor.observation(for: request.key)
        XCTAssertEqual(status?.description, "SetupMaintenanceRecoveryObservation(redacted)")
        XCTAssertFalse(String(describing: status).contains("private-caller-secret-and-path")); await supervisor.close()
    }
    func testCloseAndRetireRefuseNewWorkWithoutAnActiveWindow() async throws {
        for retirement in [false, true] {
            let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody(releaseGate: gate)
            defer { Task { await gate.open() } }
            let calls = Mutex(0)
            let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                calls.withLock { $0 += 1 }; return .terminal(.noWindow)
            }))
            let close = Task {
                if retirement { await supervisor.retire() } else { await supervisor.close() }
            }
            try await Self.eventually { custody.closeStarted.withLock { $0 } == 1 }
            let admitted = await supervisor.schedule(try Self.request()); XCTAssertFalse(admitted)
            let beforeJoin = await supervisor.shouldExit; XCTAssertFalse(beforeJoin)
            XCTAssertEqual(calls.withLock { $0 }, 0)
            await gate.open(); await close.value
            let exit = await supervisor.shouldExit; XCTAssertEqual(exit, retirement)
        }
    }
    func testOwnerAndDriverCannotPublishSupervisorOnlyResults() async throws {
        let invalid: [Supervisor.Observation] = [.recovering, .joining, .busy, .cancelled, .retired]
        for owned in [false, true] {
            for result in invalid {
                let custody = try RecoverySupervisorCustody(), joins = Mutex(0)
                let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                    if owned {
                        return .owner(.init(run: { _ in result }, join: { joins.withLock { $0 += 1 } }))
                    }
                    return .terminal(result)
                }))
                let request = try Self.request(); _ = await supervisor.schedule(request)
                try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
                let closed = await supervisor.isClosed, exit = await supervisor.shouldExit
                XCTAssertFalse(closed); XCTAssertFalse(exit)
                XCTAssertEqual(joins.withLock { $0 }, owned ? 1 : 0)
                XCTAssertEqual(custody.closeStarted.withLock { $0 }, 0)
                await supervisor.close()
            }
        }
    }
    func testCompletedOwnerResultSurvivesCancelAndRetirementDuringJoin() async throws {
        let results: [Supervisor.Observation] = [.phase(.restored), .failed(.serviceUnavailable), .noWindow]
        for retirement in [false, true] {
            for result in results {
                let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody()
                let joining = Mutex(false), cancelled = Mutex(false)
                defer { Task { await gate.open() } }
                let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                    .owner(.init(run: { _ in result }, cancel: { cancelled.withLock { $0 = true } }, join: {
                        joining.withLock { $0 = true }; await gate.wait()
                    }))
                }))
                let request = try Self.request(); _ = await supervisor.schedule(request)
                try await Self.eventually { joining.withLock { $0 } }
                let close = Task {
                    if retirement { await supervisor.retire() } else { await supervisor.close() }
                }
                try await Self.eventually { cancelled.withLock { $0 } }
                custody.retired.withLock { $0 = true }
                XCTAssertEqual(custody.closeStarted.withLock { $0 }, 0)
                await gate.open(); await close.value
                let observation = await supervisor.observation(for: request.key); XCTAssertEqual(observation, result)
            }
        }
    }
    func testCancelledAcquisitionStillCancelsAndJoinsItsUnusedOwner() async throws {
        let gate = RecoverySupervisorGate(), custody = try RecoverySupervisorCustody()
        let acquiring = Mutex(false), cancelled = Mutex(false), runs = Mutex(0), joins = Mutex(0), cancels = Mutex(0)
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            acquiring.withLock { $0 = true }
            await withTaskCancellationHandler { await gate.wait() } onCancel: { cancelled.withLock { $0 = true } }
            return .owner(.init(run: { _ in runs.withLock { $0 += 1 }; return .noWindow },
                cancel: { cancels.withLock { $0 += 1 } }, join: { joins.withLock { $0 += 1 } }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { acquiring.withLock { $0 } }
        let close = Task { await supervisor.close() }
        try await Self.eventually { cancelled.withLock { $0 } }
        XCTAssertEqual(custody.closeStarted.withLock { $0 }, 0)
        await gate.open(); await close.value
        let result = await supervisor.observation(for: request.key); XCTAssertEqual(result, .cancelled)
        XCTAssertEqual(runs.withLock { $0 }, 0); XCTAssertEqual(joins.withLock { $0 }, 1)
        XCTAssertGreaterThanOrEqual(cancels.withLock { $0 }, 1)
    }
    func testInvalidCustodyStillCancelsAndJoinsItsUnusedOwner() async throws {
        let custody = try RecoverySupervisorCustody(), runs = Mutex(0), joins = Mutex(0), cancels = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            custody.retired.withLock { $0 = true }
            return .owner(.init(run: { _ in runs.withLock { $0 += 1 }; return .noWindow },
                cancel: { cancels.withLock { $0 += 1 } }, join: { joins.withLock { $0 += 1 } }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.isClosed }
        let result = await supervisor.observation(for: request.key), exit = await supervisor.shouldExit
        XCTAssertEqual(result, .retired); XCTAssertTrue(exit)
        XCTAssertEqual(runs.withLock { $0 }, 0); XCTAssertEqual(joins.withLock { $0 }, 1)
        XCTAssertEqual(cancels.withLock { $0 }, 1)
    }
    func testKeyAndRequestRedactDescriptionsDumpsAndMirrors() throws {
        let request = try Self.request(0xab, revision: 0xcd)
        XCTAssertEqual(String(describing: request.key), "SetupMaintenanceRecoveryKey(redacted)")
        XCTAssertEqual(String(reflecting: request.key), "SetupMaintenanceRecoveryKey(redacted)")
        XCTAssertEqual(String(describing: request), "SetupMaintenanceRecoveryRequest(redacted)")
        XCTAssertEqual(String(reflecting: request), "SetupMaintenanceRecoveryRequest(redacted)")
        XCTAssertTrue(Mirror(reflecting: request.key).children.isEmpty)
        XCTAssertTrue(Mirror(reflecting: request).children.isEmpty)
        var keyDump = "", requestDump = ""
        dump(request.key, to: &keyDump); dump(request, to: &requestDump)
        XCTAssertFalse(keyDump.contains("accountID")); XCTAssertFalse(keyDump.contains("windowID"))
        XCTAssertFalse(requestDump.contains("revision")); XCTAssertFalse(requestDump.contains("171"))
    }
    func testBusyWindowYieldsItsSlotAndWaitsForTheOtherWindowToJoin() async throws {
        let clock = RecoverySupervisorClock(), custody = try RecoverySupervisorCustody()
        let rearm = RecoverySupervisorGate(), otherRun = RecoverySupervisorGate(), otherJoin = RecoverySupervisorGate()
        let sleeping = Mutex(false), woke = Mutex(false), otherRunning = Mutex(false), otherJoining = Mutex(false)
        let firstRuns = Mutex(0), otherJoined = Mutex(false), firstCalls = Mutex(0)
        defer { Task { await rearm.open(); await otherRun.open(); await otherJoin.open() } }
        let first = try Self.request(), other = try Self.request(5)
        let timing = Supervisor.Timing(now: { clock.now }, sleep: { deadline in
            let delay = clock.now.duration(to: deadline)
            if delay == .seconds(60) {
                sleeping.withLock { $0 = true }; await rearm.wait()
                clock.advance(delay); woke.withLock { $0 = true }; try Task.checkCancellation()
            } else { clock.advance(delay); await Task.yield(); try Task.checkCancellation() }
        })
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { request, _ in
            if request.key == first.key {
                firstCalls.withLock { $0 += 1 }
                if !woke.withLock({ $0 }) { return .busyBeforeOwner }
                XCTAssertTrue(otherJoined.withLock { $0 })
                return .owner(.init(run: { _ in firstRuns.withLock { $0 += 1 }; return .noWindow }, join: {}))
            }
            return .owner(.init(run: { _ in
                otherRunning.withLock { $0 = true }; await otherRun.wait(); return .noWindow
            }, join: {
                otherJoining.withLock { $0 = true }; await otherJoin.wait(); otherJoined.withLock { $0 = true }
            }))
        }), timing: timing)
        _ = await supervisor.schedule(first)
        try await Self.eventually { sleeping.withLock { $0 } }
        let admitted = await supervisor.schedule(other); XCTAssertTrue(admitted)
        try await Self.eventually { otherRunning.withLock { $0 } }
        let calls = firstCalls.withLock { $0 }; await rearm.open()
        try await Self.eventually { woke.withLock { $0 } }
        XCTAssertEqual(firstRuns.withLock { $0 }, 0); XCTAssertEqual(firstCalls.withLock { $0 }, calls)
        await otherRun.open(); try await Self.eventually { otherJoining.withLock { $0 } }
        XCTAssertEqual(firstRuns.withLock { $0 }, 0)
        await otherJoin.open()
        try await Self.eventually { await supervisor.observation(for: first.key) == .noWindow }
        XCTAssertEqual(firstRuns.withLock { $0 }, 1); XCTAssertTrue(otherJoined.withLock { $0 })
        await supervisor.close()
    }

    func testSpuriousAcquireCancellationIsAFailureWithoutRetry() async throws {
        let custody = try RecoverySupervisorCustody(), calls = Mutex(0), clock = RecoverySupervisorClock()
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }; throw CancellationError()
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertTrue(clock.sleeps.isEmpty)
        let exit = await supervisor.shouldExit; XCTAssertFalse(exit)
        await supervisor.close()
    }
    func testSpuriousOwnerCancellationJoinsAndReportsFailure() async throws {
        let custody = try RecoverySupervisorCustody(), joins = Mutex(0), runs = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in runs.withLock { $0 += 1 }; throw CancellationError() },
                join: { joins.withLock { $0 += 1 } }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .failed(.serviceUnavailable) }
        XCTAssertEqual(runs.withLock { $0 }, 1); XCTAssertEqual(joins.withLock { $0 }, 1)
        XCTAssertEqual(custody.closeAttempts.withLock { $0 }, 0)
        await supervisor.close()
    }
    func testCustodyLossInAcquireErrorRetiresInsteadOfStrandingAdmission() async throws {
        let custody = try RecoverySupervisorCustody(), calls = Mutex(0)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }; custody.retired.withLock { $0 = true }
            throw RecoverySupervisorPrivateFailure()
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.shouldExit }
        let observation = await supervisor.observation(for: request.key)
        XCTAssertEqual(observation, .retired); XCTAssertEqual(calls.withLock { $0 }, 1)
        XCTAssertEqual(custody.admissionsClosed.withLock { $0 }, 1)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testCustodyLossInOwnerErrorKeepsTheLeaseThroughTheActualJoin() async throws {
        let custody = try RecoverySupervisorCustody(shared: true), gate = RecoverySupervisorGate(), joining = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in
                custody.retired.withLock { $0 = true }; throw RecoverySupervisorPrivateFailure()
            }, join: { joining.withLock { $0 = true }; await gate.wait() }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { joining.withLock { $0 } }
        let before = await supervisor.shouldExit; XCTAssertFalse(before)
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0)
        XCTAssertThrowsError(try installer.acquireExclusive())
        await gate.open(); try await Self.eventually { await supervisor.shouldExit }
        let observation = await supervisor.observation(for: request.key); XCTAssertEqual(observation, .retired)
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testPendingAndFailedCloseRetainRealCustodyUntilOneExplicitRetry() async throws {
        let outcomes: [AdministrativeSetupShutdown.RecoveryCloseResult] = [.pending, .failed]
        for outcome in outcomes {
            let custody = try RecoverySupervisorCustody(shared: true, closeOutcomes: [outcome, .closed])
            let installer = try XCTUnwrap(custody.fixture).open()
            let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                XCTFail("Closing an idle supervisor must not acquire work"); return .terminal(.noWindow)
            }))
            await supervisor.retire()
            let result = await supervisor.closureResult, exit = await supervisor.shouldExit
            XCTAssertEqual(result, outcome); XCTAssertFalse(exit)
            XCTAssertEqual(custody.closeAttempts.withLock { $0 }, 1)
            XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0)
            XCTAssertThrowsError(try installer.acquireExclusive())
            await Task.yield(); XCTAssertEqual(custody.closeAttempts.withLock { $0 }, 1)
            await supervisor.retire()
            let completed = await supervisor.closureResult, canExit = await supervisor.shouldExit
            XCTAssertEqual(completed, .closed); XCTAssertTrue(canExit)
            XCTAssertEqual(custody.closeAttempts.withLock { $0 }, 2)
            XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
            let exclusive = try installer.acquireExclusive(); exclusive.close()
        }
    }
    func testCustodyValidationUsesTheSuppliedBlockingPhaseRunner() async throws {
        let phases = try SetupRetainedInvocationReservation.RestorationPhases.owned(executor: SetupAuditUpgradeWorkExecutor())
        let custody = try RecoverySupervisorCustody(validationPhases: phases)
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in .terminal(.noWindow) }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .noWindow }
        let contexts = custody.validationTaskContexts.withLock { $0 }
        XCTAssertFalse(contexts.isEmpty); XCTAssertTrue(contexts.allSatisfy { !$0 })
        await supervisor.close()
    }
    func testScheduleWaitUsesTheInjectedClockAndCapsTheDeadlineWithoutAcquiring() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(), gate = RecoverySupervisorGate()
        let entered = Mutex(false), calls = Mutex(0)
        defer { Task { await gate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }
            return .owner(.init(run: { _ in entered.withLock { $0 = true }; await gate.wait(); return .noWindow }, join: {}))
        }), timing: clock.timing)
        _ = await supervisor.schedule(try Self.request()); try await Self.eventually { entered.withLock { $0 } }
        let next = try Self.request(5)
        let result = await supervisor.scheduleWhenAvailable(next, until: clock.epoch.advanced(by: .seconds(600)))
        XCTAssertEqual(result, .deadlineReached); XCTAssertEqual(clock.now, clock.epoch.advanced(by: .seconds(120)))
        XCTAssertEqual(clock.sleeps, [.seconds(120)]); XCTAssertEqual(calls.withLock { $0 }, 1)
        let observation = await supervisor.observation(for: next.key); XCTAssertNil(observation)
        await gate.open(); await supervisor.close()
    }
    func testCancelledScheduleWaitAcquiresNothingAndDoesNotChangeTheActiveWorker() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(), gate = RecoverySupervisorGate()
        let entered = Mutex(false), sleeping = Mutex(false), calls = Mutex(0)
        defer { Task { await gate.open() } }
        let timing = Supervisor.Timing(now: { clock.now }, sleep: { _ in
            sleeping.withLock { $0 = true }; try await ContinuousClock().sleep(for: .seconds(60))
        })
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            calls.withLock { $0 += 1 }
            return .owner(.init(run: { _ in entered.withLock { $0 = true }; await gate.wait(); return .noWindow }, join: {}))
        }), timing: timing)
        _ = await supervisor.schedule(try Self.request()); try await Self.eventually { entered.withLock { $0 } }
        let next = try Self.request(5), deadline = clock.epoch.advanced(by: .seconds(120))
        let waiting = Task { @Sendable [supervisor, next, deadline] in await supervisor.scheduleWhenAvailable(next, until: deadline) }
        try await Self.eventually { sleeping.withLock { $0 } }; waiting.cancel()
        let result = await waiting.value; XCTAssertEqual(result, .cancelled)
        XCTAssertEqual(calls.withLock { $0 }, 1); let observation = await supervisor.observation(for: next.key); XCTAssertNil(observation)
        await gate.open(); await supervisor.close()
    }
    func testCloseAndRetireWakeTheScheduleWaitWithoutAnotherAcquisition() async throws {
        for retirement in [false, true] {
            let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(), gate = RecoverySupervisorGate()
            let entered = Mutex(false), sleeping = Mutex(false), calls = Mutex(0)
            defer { Task { await gate.open() } }
            let timing = Supervisor.Timing(now: { clock.now }, sleep: { _ in
                sleeping.withLock { $0 = true }; try await ContinuousClock().sleep(for: .seconds(60))
            })
            let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
                calls.withLock { $0 += 1 }
                return .owner(.init(run: { _ in entered.withLock { $0 = true }; await gate.wait(); return .noWindow }, join: {}))
            }), timing: timing)
            _ = await supervisor.schedule(try Self.request()); try await Self.eventually { entered.withLock { $0 } }
            let next = try Self.request(5), deadline = clock.epoch.advanced(by: .seconds(120))
            let waiting = Task { @Sendable [supervisor, next, deadline] in await supervisor.scheduleWhenAvailable(next, until: deadline) }
            try await Self.eventually { sleeping.withLock { $0 } }
            let closing = Task { @Sendable [supervisor, retirement] in
                if retirement { await supervisor.retire() } else { await supervisor.close() }
            }
            let result = await waiting.value; XCTAssertEqual(result, retirement ? .retired : .closed)
            XCTAssertEqual(calls.withLock { $0 }, 1)
            await gate.open(); await closing.value
        }
    }
    func testConcurrentScheduleWaitersRefuseTheSameKeyAfterTheActiveJoin() async throws {
        let custody = try RecoverySupervisorCustody(), clock = RecoverySupervisorClock(), gate = RecoverySupervisorGate()
        let entered = Mutex(false), sleeps = Mutex(0), calls = Mutex(0)
        defer { Task { await gate.open() } }
        let timing = Supervisor.Timing(now: { clock.now }, sleep: { _ in
            sleeps.withLock { $0 += 1 }; try await ContinuousClock().sleep(for: .seconds(60))
        })
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            let count = calls.withLock { $0 += 1; return $0 }
            if count == 1 {
                return .owner(.init(run: { _ in entered.withLock { $0 = true }; await gate.wait(); return .noWindow }, join: {}))
            }
            return .terminal(.noWindow)
        }), timing: timing)
        _ = await supervisor.schedule(try Self.request()); try await Self.eventually { entered.withLock { $0 } }
        let next = try Self.request(5), deadline = clock.epoch.advanced(by: .seconds(120))
        let first = Task { @Sendable [supervisor, next, deadline] in await supervisor.scheduleWhenAvailable(next, until: deadline) }
        let second = Task { @Sendable [supervisor, next, deadline] in await supervisor.scheduleWhenAvailable(next, until: deadline) }
        try await Self.eventually { sleeps.withLock { $0 } == 2 }; await gate.open()
        let firstResult = await first.value, secondResult = await second.value
        let results = [firstResult, secondResult]
        XCTAssertEqual(results.filter { $0 == .scheduled }.count, 1)
        XCTAssertEqual(results.filter { $0 == .duplicate }.count, 1)
        try await Self.eventually { calls.withLock { $0 } == 2 }
        await supervisor.close()
    }

}
