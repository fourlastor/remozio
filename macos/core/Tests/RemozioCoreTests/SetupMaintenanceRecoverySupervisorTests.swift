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
    let fixture: ReleaseActivityFixture?
    let token: ReleaseActivityToken?
    let releaseGate: RecoverySupervisorGate?
    init(shared: Bool = false, releaseGate: RecoverySupervisorGate? = nil) throws {
        fixture = shared ? try ReleaseActivityFixture() : nil
        token = try fixture?.open().acquireShared()
        self.releaseGate = releaseGate
    }
    func validate() throws {
        if retired.withLock({ $0 }) { throw JournalLeaseError.invalidated }
        try token?.validate()
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
            return .owner(.init(run: { _ in await gate.wait(); return .phase(.needsOwnerRecovery) }))
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
            }))
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
        let starts = Mutex<[ContinuousClock.Instant]>([]), deadlines = Mutex<[ContinuousClock.Instant]>([])
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, deadline in
            starts.withLock { $0.append(clock.now) }; deadlines.withLock { $0.append(deadline) }
            return .busyBeforeOwner
        }), timing: clock.timing)
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { await supervisor.observation(for: request.key) == .busy && clock.rearms == 1 }
        let expected = clock.epoch.advanced(by: .seconds(120))
        XCTAssertTrue(starts.withLock { $0.allSatisfy { $0 < expected } })
        XCTAssertTrue(deadlines.withLock { !$0.isEmpty && $0.allSatisfy { $0 == expected } })
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
        let running = Mutex(false), joinFailures = Mutex(0), joining = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await gate.open() } }
        let worker = Task { running.withLock { $0 = true }; await gate.wait(); running.withLock { $0 = false } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in throw RecoverySupervisorPrivateFailure() }, cancel: { worker.cancel() }, join: {
                joining.withLock { $0 = true }
                let failed = Task<Void, any Error> { throw RecoverySupervisorTestFailure.join }
                do { try await failed.value } catch { joinFailures.withLock { $0 += 1 } }
                await worker.value
            }))
        }))
        let request = try Self.request(); _ = await supervisor.schedule(request)
        try await Self.eventually { joining.withLock { $0 } && joinFailures.withLock { $0 } == 1 && running.withLock { $0 } }
        let close = Task { await supervisor.close() }
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
        _ = await supervisor.schedule(try Self.request())
        try await Self.eventually { joining.withLock { $0 } }
        let close = Task { await supervisor.close() }
        try await Self.eventually { worker.isCancelled }
        XCTAssertThrowsError(try installer.acquireExclusive())
        await gate.open(); await close.value
        XCTAssertEqual(custody.closeFinished.withLock { $0 }, 1)
    }
    func testRetirementKeepsCustodyAndAdmissionClosedUntilAllLifecycleJoinsFinish() async throws {
        let runGate = RecoverySupervisorGate(), releaseGate = RecoverySupervisorGate()
        let custody = try RecoverySupervisorCustody(shared: true, releaseGate: releaseGate), entered = Mutex(false)
        let installer = try XCTUnwrap(custody.fixture).open()
        defer { Task { await runGate.open(); await releaseGate.open() } }
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: { _, _ in
            .owner(.init(run: { _ in entered.withLock { $0 = true }; await runGate.wait(); try Task.checkCancellation(); return .noWindow }))
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
            }, cancel: { cancelled.withLock { $0 = true } }))
        }))
        let weak = RecoverySupervisorWeakReference(supervisor); _ = await supervisor?.schedule(try Self.request())
        try await Self.eventually { entered.withLock { $0 } }; supervisor = nil
        try await Self.eventually { weak.value == nil && cancelled.withLock { $0 } }
        XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertEqual(custody.closeFinished.withLock { $0 }, 0)
        await gate.open(); try await Self.eventually { custody.closeFinished.withLock { $0 } == 1 }
        XCTAssertEqual(writes.withLock { $0 }, 0); let exclusive = try installer.acquireExclusive(); exclusive.close()
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
}
