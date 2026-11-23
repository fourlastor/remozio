import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

private actor SetupLifecycleGate {
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
private final class SetupLifecycleClock: @unchecked Sendable {
    private struct Waiter {
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, any Error>
    }
    private struct State {
        var now: ContinuousClock.Instant
        var waiters: [UUID: Waiter] = [:]
        var cancelled: Set<UUID> = []
        var timerDeadline: ContinuousClock.Instant?
        var timerCallback: (@Sendable () -> Void)?
        var timerArms = 0, timerCancels = 0
        var sleeps: [ContinuousClock.Instant] = []
    }
    let epoch = ContinuousClock.now
    private let state: Mutex<State>
    init() { state = .init(.init(now: epoch)) }
    var now: ContinuousClock.Instant { state.withLock { $0.now } }
    var deadlines: [ContinuousClock.Instant] {
        state.withLock { Array($0.waiters.values.map(\.deadline)) + ($0.timerDeadline.map { [$0] } ?? []) }
    }
    var timerArms: Int { state.withLock { $0.timerArms } }
    var timerCancels: Int { state.withLock { $0.timerCancels } }
    var cooperativeSleeps: [ContinuousClock.Instant] { state.withLock { $0.sleeps } }
    var watchdogDriver: AdministrativeSetupLifecycle.RetirementWatchdog.TimerDriver {
        get throws {
            try .owned(arm: { deadline, callback in
                self.state.withLock { $0.timerDeadline = deadline; $0.timerCallback = callback; $0.timerArms += 1 }
            }, cancel: {
                self.state.withLock { $0.timerDeadline = nil; $0.timerCallback = nil; $0.timerCancels += 1 }
            })
        }
    }
    func fireWatchdogEarly() {
        let callback = state.withLock { value in
            let callback = value.timerCallback; value.timerCallback = nil; value.timerDeadline = nil; return callback
        }
        callback?()
    }
    func advance(_ duration: Duration) {
        let (due, callback) = state.withLock { value -> ([CheckedContinuation<Void, any Error>], (@Sendable () -> Void)?) in
            value.now = value.now.advanced(by: duration)
            let ids = value.waiters.filter { $0.value.deadline <= value.now }.map(\.key)
            let pending = ids.compactMap { value.waiters.removeValue(forKey: $0)?.continuation }
            var callback: (@Sendable () -> Void)?
            if let deadline = value.timerDeadline, deadline <= value.now {
                callback = value.timerCallback; value.timerCallback = nil; value.timerDeadline = nil
            }
            return (pending, callback)
        }
        for waiter in due { waiter.resume() }
        callback?()
    }
    private func cancel(_ id: UUID) {
        let pending = state.withLock { value -> CheckedContinuation<Void, any Error>? in
            if let waiter = value.waiters.removeValue(forKey: id) { return waiter.continuation }
            value.cancelled.insert(id); return nil
        }
        pending?.resume(throwing: CancellationError())
    }
    private func sleep(_ deadline: ContinuousClock.Instant) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let immediate = state.withLock { value -> Result<Void, any Error>? in
                    value.sleeps.append(deadline)
                    if value.cancelled.remove(id) != nil { return .failure(CancellationError()) }
                    if value.now >= deadline { return .success(()) }
                    value.waiters[id] = .init(deadline: deadline, continuation: continuation)
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: { self.cancel(id) }
    }
    var timing: SetupMaintenanceRecoverySupervisor.Timing {
        .init(now: { self.now }, sleep: { try await self.sleep($0) })
    }
}
private final class SetupLifecycleCustody: SetupMaintenanceRecoveryProcessCustody, @unchecked Sendable {
    func joinRecoverySessions() async {}
    func observeRecoverySessionsForDisposal() async {}
    func retainSupervisorDisposal(_ actual: Task<Void, Never>) {}
    struct Counters {
        var validations = 0, admissionsClosed = 0, closeAttempts = 0, actualCloses = 0, finishedCloses = 0
        var invalid = false
        var outcomes: [AdministrativeSetupShutdown.RecoveryCloseResult] = []
        var task: Task<Void, Never>?
    }
    let counts = Mutex(Counters())
    let closeGate: SetupLifecycleGate?
    init(closeGate: SetupLifecycleGate? = nil) { self.closeGate = closeGate }
    func validate() throws {
        let invalid = counts.withLock { $0.validations += 1; return $0.invalid }
        if invalid { throw AdministrativeSetupError.changedInstallation }
    }
    func closeAdmission() { counts.withLock { $0.admissionsClosed += 1 } }
    func closeAfterJoining() async { _ = await closeAfterJoiningResult() }
    func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
        let (task, outcome) = counts.withLock { state in
            state.closeAttempts += 1
            if state.task == nil {
                state.actualCloses += 1
                let gate = closeGate
                state.task = Task {
                    await gate?.wait()
                    self.counts.withLock { $0.finishedCloses += 1 }
                }
            }
            return (state.task!, state.outcomes.isEmpty ? nil : state.outcomes.removeFirst())
        }
        if let outcome { return outcome }
        await task.value
        return .closed
    }
}
private final class SetupLifecycleProbe: @unchecked Sendable {
    struct State {
        var hostChecks = 0, opens = 0, discoveries = 0, activeDiscoveries = 0, maximumDiscoveries = 0
        var confirmations = 0, stopped = 0, invalidHost = false, invalidLease = false, failedDiscoveries = 0
        var prepareError: AdministrativeSetupServiceError?
        var admissionHeld = false
        var rows: [RuntimeMaintenanceWindowRecord] = []
        var exits: [(Int32, ContinuousClock.Instant)] = []
    }
    let state = Mutex(State())
}
private struct SetupLifecycleFixture: Sendable {
    typealias Lifecycle = AdministrativeSetupLifecycle
    typealias Supervisor = SetupMaintenanceRecoverySupervisor
    let clock: SetupLifecycleClock, custody: SetupLifecycleCustody, probe: SetupLifecycleProbe
    let routing: Lifecycle.Routing, supervisor: Supervisor, lifecycle: Lifecycle
    init(clock: SetupLifecycleClock = .init(), rows: [RuntimeMaintenanceWindowRecord] = [], prepareGate: SetupLifecycleGate? = nil,
        discoveryGate: SetupLifecycleGate? = nil, confirmationGate: SetupLifecycleGate? = nil,
        closeGate: SetupLifecycleGate? = nil,
        terminalSchedulingResult: Supervisor.SchedulingResult? = nil,
        terminalSchedulingOverride: (@Sendable () -> Supervisor.SchedulingResult?)? = nil,
        availability: @escaping @Sendable () -> AsyncStream<Void> = { AsyncStream { $0.finish() } },
        acquire: @escaping @Sendable (Supervisor.Request, ContinuousClock.Instant) async throws -> Supervisor.Acquisition = { _, _ in .terminal(.noWindow) }) throws {
        let custody = SetupLifecycleCustody(closeGate: closeGate), probe = SetupLifecycleProbe()
        probe.state.withLock { $0.rows = rows }
        let routing = Lifecycle.Routing(validateStartup: {
            if probe.state.withLock({ $0.invalidLease }) { throw AdministrativeSetupError.changedInstallation }
        })
        let supervisor = try Supervisor.openOwned(custody: custody, driver: .init(acquire: acquire), timing: clock.timing)
        let terminal: (@Sendable () -> Supervisor.SchedulingResult?)?
        if let terminalSchedulingOverride { terminal = terminalSchedulingOverride }
        else if let terminalSchedulingResult { terminal = { terminalSchedulingResult } }
        else { terminal = nil }
        let runtime = try Lifecycle.Runtime.owned(supervisor: supervisor, discover: { _ in
            probe.state.withLock { $0.discoveries += 1; $0.activeDiscoveries += 1; $0.maximumDiscoveries = max($0.maximumDiscoveries, $0.activeDiscoveries) }
            defer { probe.state.withLock { $0.activeDiscoveries -= 1 } }
            await discoveryGate?.wait()
            if probe.state.withLock({ $0.admissionHeld }) { throw SetupAccountOwner.MaintenanceRecoveryAdmissionError.busyBeforeOwner }
            let values = probe.state.withLock { value -> [RuntimeMaintenanceWindowRecord]? in
                if value.failedDiscoveries > 0 { value.failedDiscoveries -= 1; return nil }
                return value.rows
            }
            guard let values else { throw PreparationStoreError.corruptRecord }
            return values
        }, confirmServing: { _ in
            await confirmationGate?.wait()
            probe.state.withLock { $0.confirmations += 1 }
        }, availability: availability, terminalSchedulingResult: terminal)
        let lifecycle = try Lifecycle.openOwned(routing: routing, timing: clock.timing,
            validateStartup: {
                if probe.state.withLock({ $0.invalidLease }) { throw AdministrativeSetupError.changedInstallation }
            }, validateHost: {
                let invalid = probe.state.withLock { $0.hostChecks += 1; return $0.invalidHost }
                if invalid { throw AdministrativeSetupServiceError.changedConfiguration }
                return .init(verifyInventory: { _ in })
            }, watchdogTimer: try clock.watchdogDriver, prepare: { _ in
                probe.state.withLock { $0.opens += 1 }
                if let error = probe.state.withLock({ $0.prepareError }) { throw error }
                await prepareGate?.wait()
                return runtime
            }, stopListener: { probe.state.withLock { $0.stopped += 1 } },
            terminate: { code in probe.state.withLock { $0.exits.append((code, clock.now)) } })
        self.clock = clock; self.custody = custody; self.probe = probe
        self.routing = routing; self.supervisor = supervisor; self.lifecycle = lifecycle
    }
    static func row(_ seed: UInt8 = 1, revision: UInt8 = 9) throws -> RuntimeMaintenanceWindowRecord {
        func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
        let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: bytes(50), installationID: bytes(51),
            authority: .init(accountID: bytes(seed), ownerUID: getuid(), directoryID: bytes(seed + 1)),
            target: .init(accountID: bytes(seed + 2), ownerUID: getuid() + 1000, directoryID: bytes(seed + 3)),
            releaseDigest: bytes(52, 32), candidateDigest: bytes(53, 32), authorityPolicyDigest: bytes(54, 32),
            operationDigest: bytes(55, 32), restorationDigest: bytes(56, 32), mutationFootprintDigest: bytes(57, 32),
            authorityGrantDigest: bytes(58, 32), targetConsentDigest: bytes(59, 32), administratorIntentDigest: bytes(60, 32))
        return try .init(id: bytes(seed + 4), revision: bytes(revision), purpose: .retainedRuntime, scope: scope)
    }
}

private final class SetupLifecycleActivityFixture: @unchecked Sendable {
    let fixture: ReleaseActivityFixture
    let barrier: ReleaseActivityBarrier
    let independent: ReleaseActivityBarrier
    init() throws {
        fixture = try ReleaseActivityFixture(); barrier = try fixture.open(); independent = try fixture.open()
    }
}

final class AdministrativeSetupLifecycleTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case deadline }
    private func eventually(_ condition: @escaping @Sendable () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(120) / 4)
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw Failure.deadline }
            await Task.yield()
        }
    }
    func testHostCustodyIsCheckedBeforeOpeningRuntime() async throws {
        let f = try SetupLifecycleFixture(); await f.lifecycle.start()
        try await eventually { f.routing.state == .serving }
        XCTAssertEqual(f.probe.state.withLock { $0.opens }, 1)
        XCTAssertGreaterThan(f.probe.state.withLock { $0.hostChecks }, 0)
        await f.lifecycle.close()
    }
    func testPendingStartupNeverReportsVerified() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(prepareGate: gate)
        await f.lifecycle.start(); try await eventually { f.probe.state.withLock { $0.opens == 1 } }
        let checks = f.probe.state.withLock { $0.hostChecks }
        for _ in 0..<3 { XCTAssertEqual(f.routing.checkStatus(), .busy) }
        XCTAssertEqual(f.probe.state.withLock { $0.hostChecks }, checks)
        XCTAssertFalse(f.routing.allowsNormal)
        await gate.open(); await f.lifecycle.close()
    }
    func testMutationRoutingStaysClosedAtEveryStartupBoundary() async throws {
        for boundary in 0..<3 {
            let gate = SetupLifecycleGate()
            let f = try SetupLifecycleFixture(prepareGate: boundary == 0 ? gate : nil,
                discoveryGate: boundary == 1 ? gate : nil, confirmationGate: boundary == 2 ? gate : nil)
            await f.lifecycle.start()
            try await eventually { boundary == 0 ? f.probe.state.withLock { $0.opens == 1 } : f.probe.state.withLock { $0.discoveries == 1 } }
            XCTAssertFalse(f.routing.allowsNormal); XCTAssertThrowsError(try f.routing.normalOwner())
            await gate.open(); await f.lifecycle.close()
        }
    }
    func testUnreadableDiscoveryRetriesOnlyAfterFiveHundredMilliseconds() async throws {
        let f = try SetupLifecycleFixture(); f.probe.state.withLock { $0.failedDiscoveries = 1 }
        await f.lifecycle.start()
        let retry = f.clock.epoch.advanced(by: .milliseconds(500))
        try await eventually { f.clock.deadlines.contains(retry) }
        XCTAssertEqual(f.probe.state.withLock { $0.hostChecks }, 1)
        f.clock.advance(.milliseconds(499)); XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 1)
        f.clock.advance(.milliseconds(1)); try await eventually { f.routing.state == .serving }
        XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 2)
        // Two discovery attempts, then one separate fresh check before normal dispatch opens.
        XCTAssertEqual(f.probe.state.withLock { $0.hostChecks }, 3)
        await f.lifecycle.close()
    }
    func testDiscoverySignalsStaySingleFlight() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(discoveryGate: gate)
        await f.lifecycle.start(); try await eventually { f.probe.state.withLock { $0.activeDiscoveries == 1 } }
        await f.lifecycle.requestDiscovery(); await f.lifecycle.requestDiscovery()
        XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 1)
        await gate.open(); try await eventually { f.probe.state.withLock { $0.discoveries == 2 } }
        XCTAssertEqual(f.probe.state.withLock { $0.maximumDiscoveries }, 1)
        await f.lifecycle.close()
    }
    func testCustodyDriftBeforeRetryPreventsAnotherDiscovery() async throws {
        let f = try SetupLifecycleFixture(); f.probe.state.withLock { $0.failedDiscoveries = 1 }
        await f.lifecycle.start(); try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .milliseconds(500))) }
        f.probe.state.withLock { $0.invalidHost = true }; f.clock.advance(.milliseconds(500))
        try await eventually { f.routing.state == .closed }
        XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 1)
    }
    func testServingWaitsForTheActualDiscoveryReturn() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(discoveryGate: gate)
        await f.lifecycle.start(); try await eventually { f.probe.state.withLock { $0.activeDiscoveries == 1 } }
        XCTAssertEqual(f.routing.state, .discovering); XCTAssertEqual(f.probe.state.withLock { $0.confirmations }, 0)
        await gate.open(); try await eventually { f.routing.state == .serving }
        XCTAssertEqual(f.probe.state.withLock { $0.activeDiscoveries }, 0)
        await f.lifecycle.close()
    }
    func testStartupWaitsForTheActualWorkerJoin() async throws {
        let gate = SetupLifecycleGate(), joining = Mutex(false)
        let row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let f = try SetupLifecycleFixture(rows: [row], acquire: { _, _ in
            .owner(.init(run: { _ in .noWindow }, join: { joining.withLock { $0 = true }; await gate.wait() }))
        })
        await f.lifecycle.start(); try await eventually { joining.withLock { $0 } }
        XCTAssertEqual(f.routing.state, .discovering); XCTAssertEqual(f.probe.state.withLock { $0.confirmations }, 0)
        await gate.open(); try await eventually { f.routing.state == .serving }; await f.lifecycle.close()
    }
    func testTwoAccountsProgressOnlyAfterTheActiveOwnerJoins() async throws {
        let gate = SetupLifecycleGate(), calls = Mutex(0), joined = Mutex(false)
        let rows = try await SetupExecutorAdmissionTestFixture.make { try [SetupLifecycleFixture.row(), SetupLifecycleFixture.row(10)] }
        let f = try SetupLifecycleFixture(rows: rows, acquire: { _, _ in
            let count = calls.withLock { $0 += 1; return $0 }
            if count == 1 { return .owner(.init(run: { _ in await gate.wait(); return .noWindow }, join: { joined.withLock { $0 = true } })) }
            XCTAssertTrue(joined.withLock { $0 }); return .terminal(.noWindow)
        })
        await f.lifecycle.start(); try await eventually { calls.withLock { $0 } == 1 }
        XCTAssertEqual(f.routing.state, .discovering); await gate.open()
        try await eventually { f.routing.state == .serving }; XCTAssertEqual(calls.withLock { $0 }, 2)
        await f.lifecycle.close()
    }
    func testAChangedRevisionCannotReplayTheCompletedWindow() async throws {
        let calls = Mutex(0), row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let f = try SetupLifecycleFixture(rows: [row], acquire: { _, _ in calls.withLock { $0 += 1 }; return .terminal(.noWindow) })
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }
        let next = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row(revision: 10) }
        f.probe.state.withLock { $0.rows = [next] }; await f.lifecycle.requestDiscovery()
        try await eventually { f.probe.state.withLock { $0.discoveries } == 2 }
        XCTAssertEqual(calls.withLock { $0 }, 1); await f.lifecycle.close()
    }
    func testEachWindowGetsACompleteAttemptAfterThePreviousAttemptFinishes() async throws {
        let clock = SetupLifecycleClock(), deadlines = Mutex<[Data: ContinuousClock.Instant]>([:])
        let rows = try await SetupExecutorAdmissionTestFixture.make { try [SetupLifecycleFixture.row(), SetupLifecycleFixture.row(10)] }
        let f = try SetupLifecycleFixture(clock: clock, rows: rows, acquire: { request, _ in
            .owner(.init(run: { deadline in
                deadlines.withLock { $0[request.key.accountID] = deadline }
                try await clock.timing.sleep(deadline)
                return .noWindow
            }, join: {}))
        })
        await f.lifecycle.start()
        try await eventually { deadlines.withLock { $0[rows[0].scope.authority.accountID] } == clock.epoch.advanced(by: .seconds(120)) }
        try await eventually { clock.deadlines.contains(clock.epoch.advanced(by: .seconds(120))) }
        clock.advance(.seconds(120))
        try await eventually { deadlines.withLock { $0[rows[1].scope.authority.accountID] } == clock.epoch.advanced(by: .seconds(240)) }
        try await eventually { clock.deadlines.contains(clock.epoch.advanced(by: .seconds(240))) }
        XCTAssertEqual(f.routing.state, .discovering)
        clock.advance(.seconds(119)); XCTAssertEqual(f.routing.state, .discovering)
        clock.advance(.seconds(1)); try await eventually { f.routing.state == .serving }
        XCTAssertEqual(deadlines.withLock { $0.count }, 2); await f.lifecycle.close()
    }
    func testRepeatedRecoveryTriggersDoNotRepeatTheBody() async throws {
        let calls = Mutex(0), row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let f = try SetupLifecycleFixture(rows: [row], acquire: { _, _ in calls.withLock { $0 += 1 }; return .terminal(.noWindow) })
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }
        await f.lifecycle.requestDiscovery(); await f.lifecycle.requestDiscovery()
        try await eventually { f.probe.state.withLock { $0.discoveries } >= 2 }
        XCTAssertEqual(calls.withLock { $0 }, 1); await f.lifecycle.close()
    }
    private func terminalSchedulingRetires(_ result: SetupMaintenanceRecoverySupervisor.SchedulingResult) async throws {
        let discovery = SetupLifecycleGate(), close = SetupLifecycleGate()
        let row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let injected = result == .invalidProcess || result == .cancelled
        let f = try SetupLifecycleFixture(rows: [row], discoveryGate: discovery, closeGate: close,
            terminalSchedulingResult: injected ? result : nil)
        var supervisorClose: Task<Void, Never>?
        do {
            for refused in [SetupMaintenanceRecoverySupervisor.SchedulingResult.scheduled, .duplicate, .deadlineReached] {
                XCTAssertThrowsError(try AdministrativeSetupLifecycle.Runtime.owned(supervisor: f.supervisor,
                    discover: { _ in [] }, terminalSchedulingResult: { refused }))
            }
            await f.lifecycle.start()
            try await eventually {
                f.probe.state.withLock { $0.activeDiscoveries == 1 }
                    && f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(1)))
            }
            if !injected {
                supervisorClose = Task {
                    if result == .retired { await f.supervisor.retire() }
                    else { await f.supervisor.close() }
                }
                try await eventually { f.custody.counts.withLock { $0.admissionsClosed == 1 } }
            }
            await discovery.open()
            try await eventually {
                f.routing.state == .retiring && f.custody.counts.withLock { $0.actualCloses == 1 }
                    && f.clock.timerArms == 1
            }
            XCTAssertEqual(f.clock.now, f.clock.epoch)
            XCTAssertEqual(f.probe.state.withLock { $0.confirmations }, 0)
            XCTAssertFalse(f.routing.allowsNormal)
            XCTAssertThrowsError(try f.routing.normalOwner())
            XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
            XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 0)
            await close.open()
            await supervisorClose?.value
            await f.lifecycle.close()
            XCTAssertEqual(f.routing.state, .closed)
            XCTAssertEqual(f.custody.counts.withLock { $0.actualCloses }, 1)
            XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 1)
            XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 1)
            XCTAssertTrue(f.probe.state.withLock { $0.exits.isEmpty })
        } catch {
            await discovery.open(); await close.open(); await supervisorClose?.value
            await f.lifecycle.close()
            throw error
        }
    }
    func testRetiredSchedulingRetiresBeforeTheNextIdleCheck() async throws {
        try await terminalSchedulingRetires(.retired)
    }
    func testInvalidProcessSchedulingRetiresBeforeTheNextIdleCheck() async throws {
        try await terminalSchedulingRetires(.invalidProcess)
    }
    func testClosedSchedulingRetiresWhileIdleCustodyStillPasses() async throws {
        try await terminalSchedulingRetires(.closed)
    }
    func testCancelledSchedulingRetiresWithoutLeavingDiscoveryPending() async throws {
        try await terminalSchedulingRetires(.cancelled)
    }
    func testSchedulingCancellationDuringRetirementKeepsTheFirstDeadlineAndCloseTask() async throws {
        let work = SetupLifecycleGate(), close = SetupLifecycleGate(), acquired = Mutex(0)
        let rows = try await SetupExecutorAdmissionTestFixture.make { try [SetupLifecycleFixture.row(), SetupLifecycleFixture.row(10)] }
        let f = try SetupLifecycleFixture(rows: [rows[1]], closeGate: close, acquire: { _, _ in
            acquired.withLock { $0 += 1 }
            return .owner(.init(run: { _ in await work.wait(); return .noWindow }, join: {}))
        })
        do {
            let occupied = try SetupMaintenanceRecoverySupervisor.Request(accountID: rows[0].scope.authority.accountID,
                windowID: rows[0].id, revision: rows[0].revision)
            let scheduled = await f.supervisor.schedule(occupied); XCTAssertTrue(scheduled)
            try await eventually { acquired.withLock { $0 == 1 } }
            await f.lifecycle.start()
            try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(120))) }
            await f.lifecycle.requestRetirement()
            let deadline = f.clock.epoch.advanced(by: .seconds(300))
            try await eventually { f.clock.deadlines.contains(deadline) && f.custody.counts.withLock { $0.admissionsClosed == 1 } }
            f.clock.advance(.milliseconds(250)); await f.lifecycle.requestRetirement()
            await work.open()
            try await eventually { f.custody.counts.withLock { $0.actualCloses == 1 } }
            XCTAssertEqual(f.clock.timerArms, 1)
            XCTAssertTrue(f.clock.deadlines.contains(deadline))
            XCTAssertFalse(f.routing.allowsNormal)
            XCTAssertEqual(f.routing.state, .retiring)
            XCTAssertEqual(acquired.withLock { $0 }, 1)
            XCTAssertEqual(f.probe.state.withLock { $0.confirmations }, 0)
            XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
            await close.open(); await f.lifecycle.close()
            XCTAssertEqual(f.custody.counts.withLock { $0.actualCloses }, 1)
            XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 1)
            XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 1)
            XCTAssertTrue(f.probe.state.withLock { $0.exits.isEmpty })
        } catch {
            await work.open(); await close.open(); await f.lifecycle.close()
            throw error
        }
    }

    func testTerminalRearmAfterServingRetiresThroughTheOwnedSchedulingControl() async throws {
        for result in [SetupMaintenanceRecoverySupervisor.SchedulingResult.retired, .invalidProcess, .closed] {
            let work = SetupLifecycleGate(), close = SetupLifecycleGate(), acquired = Mutex(0)
            let terminal = Mutex<SetupMaintenanceRecoverySupervisor.SchedulingResult?>(nil)
            let rows = try await SetupExecutorAdmissionTestFixture.make { try [SetupLifecycleFixture.row(), SetupLifecycleFixture.row(10)] }
            let f = try SetupLifecycleFixture(closeGate: close, terminalSchedulingOverride: { terminal.withLock { $0 } }, acquire: { _, _ in
                acquired.withLock { $0 += 1 }
                return .owner(.init(run: { _ in await work.wait(); return .noWindow }, join: {}))
            })
            do {
                await f.lifecycle.start()
                try await eventually { f.routing.state == .serving }
                let occupied = try SetupMaintenanceRecoverySupervisor.Request(accountID: rows[0].scope.authority.accountID,
                    windowID: rows[0].id, revision: rows[0].revision)
                let scheduled = await f.supervisor.schedule(occupied); XCTAssertTrue(scheduled)
                try await eventually { acquired.withLock { $0 == 1 } }
                f.probe.state.withLock { $0.rows = [rows[1]] }; await f.lifecycle.requestDiscovery()
                try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(120))) }
                f.clock.advance(.seconds(120))
                try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(180))) }
                XCTAssertEqual(f.routing.state, .serving)
                XCTAssertEqual(f.clock.timerArms, 0)
                terminal.withLock { $0 = result }; f.clock.advance(.seconds(60))
                try await eventually { f.routing.state == .retiring && f.clock.timerArms == 1 }
                XCTAssertFalse(f.routing.allowsNormal)
                XCTAssertEqual(f.clock.timerArms, 1)
                XCTAssertTrue(f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(480))))
                XCTAssertEqual(acquired.withLock { $0 }, 1)
                XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
                await work.open()
                try await eventually { f.custody.counts.withLock { $0.actualCloses == 1 } }
                XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 0)
                await close.open(); await f.lifecycle.close()
                XCTAssertEqual(f.routing.state, .closed)
                XCTAssertEqual(f.custody.counts.withLock { $0.actualCloses }, 1)
                XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 1)
                XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 1)
                XCTAssertTrue(f.probe.state.withLock { $0.exits.isEmpty })
            } catch {
                await work.open(); await close.open(); await f.lifecycle.close()
                throw error
            }
        }
    }

    func testIdleCustodyUsesOneSecondCadenceWithoutAdmission() async throws {
        let f = try SetupLifecycleFixture(); await f.lifecycle.start()
        try await eventually { f.routing.state == .serving && f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(1))) }
        let count = f.custody.counts.withLock { $0.validations }
        f.clock.advance(.milliseconds(900)); XCTAssertEqual(f.custody.counts.withLock { $0.validations }, count)
        f.clock.advance(.milliseconds(100)); try await eventually { f.custody.counts.withLock { $0.validations > count } }
        XCTAssertEqual(f.custody.counts.withLock { $0.admissionsClosed }, 0); await f.lifecycle.close()
    }
    func testIdleDriftRetiresWithoutReplacingACompletedResult() async throws {
        let row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let f = try SetupLifecycleFixture(rows: [row]); await f.lifecycle.start()
        try await eventually { f.routing.state == .serving }
        f.custody.counts.withLock { $0.invalid = true }; f.clock.advance(.seconds(1))
        try await eventually { f.routing.state == .closed }
        let key = try SetupMaintenanceRecoverySupervisor.Key(accountID: row.scope.authority.accountID, windowID: row.id)
        let observation = await f.supervisor.observation(for: key); XCTAssertEqual(observation, .noWindow)
    }
    func testResumedIdleTimerDoesNotReplayMissedTicks() async throws {
        let f = try SetupLifecycleFixture(); await f.lifecycle.start()
        try await eventually { f.routing.state == .serving && f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(1))) }
        let count = f.custody.counts.withLock { $0.validations }; f.clock.advance(.seconds(50))
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(51))) }
        XCTAssertEqual(f.custody.counts.withLock { $0.validations }, count + 1); await f.lifecycle.close()
    }
    func testRetirementClosesRoutingBeforeTheCloseJoin() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }
        await f.lifecycle.requestRetirement(); try await eventually { f.custody.counts.withLock { $0.actualCloses == 1 } }
        XCTAssertEqual(f.routing.state, .retiring); XCTAssertFalse(f.routing.allowsNormal)
        XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
        await gate.open(); await f.lifecycle.close()
    }
    func testBlockedRetireCannotBlockTheIndependentDeadlineCallback() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }
        await f.lifecycle.requestRetirement()
        let deadline = f.clock.epoch.advanced(by: .seconds(300))
        try await eventually { f.clock.deadlines.contains(deadline) && f.custody.counts.withLock { $0.actualCloses == 1 } }
        f.clock.advance(.seconds(300)); try await eventually { f.probe.state.withLock { $0.exits.count == 1 } }
        XCTAssertEqual(f.probe.state.withLock { $0.exits.first?.0 }, 75); XCTAssertEqual(f.routing.state, .retiring)
        XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
        await gate.open(); await f.lifecycle.close()
    }
    func testRepeatedRetirementDoesNotResetItsFirstDeadline() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }; await f.lifecycle.requestRetirement()
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(300))) }
        f.clock.advance(.seconds(299)); await f.lifecycle.requestRetirement(); f.clock.advance(.seconds(1))
        try await eventually { f.probe.state.withLock { $0.exits.count == 1 } }
        XCTAssertEqual(f.probe.state.withLock { $0.exits.first?.1 }, f.clock.epoch.advanced(by: .seconds(300)))
        await gate.open(); await f.lifecycle.close()
    }
    func testWatchdogReportsTheCodeAndMomentWithoutExitingXCTest() async throws {
        let clock = SetupLifecycleClock(), calls = Mutex<[(Int32, ContinuousClock.Instant)]>([])
        let watchdog = AdministrativeSetupLifecycle.RetirementWatchdog(timing: clock.timing, timer: try clock.watchdogDriver,
            terminate: { code in calls.withLock { $0.append((code, clock.now)) } })
        let deadline = watchdog.start(); XCTAssertEqual(watchdog.start(), deadline)
        try await eventually { clock.deadlines.contains(deadline) }
        clock.advance(.seconds(299)); XCTAssertTrue(calls.withLock { $0.isEmpty })
        clock.advance(.seconds(1)); try await eventually { calls.withLock { $0.count == 1 } }
        XCTAssertEqual(calls.withLock { $0.first?.0 }, 75); XCTAssertEqual(calls.withLock { $0.first?.1 }, deadline)
        watchdog.didClose()
    }
    func testOrderlyExitRequiresTheActualFinalClose() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }; await f.lifecycle.requestRetirement()
        try await eventually { f.custody.counts.withLock { $0.actualCloses == 1 } }
        let before = await f.supervisor.shouldExit; XCTAssertFalse(before); XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 0)
        await gate.open(); await f.lifecycle.close()
        let after = await f.supervisor.shouldExit; XCTAssertTrue(after); XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 1)
        XCTAssertTrue(f.probe.state.withLock { $0.exits.isEmpty })
    }
    func testTimedOutCloseRetainsTheSameActualTaskUntilItsLateReturn() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        f.custody.counts.withLock { $0.outcomes = [.timedOut] }
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }; await f.lifecycle.requestRetirement()
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .milliseconds(250))) }
        f.clock.advance(.milliseconds(250)); try await eventually { f.custody.counts.withLock { $0.closeAttempts == 2 } }
        XCTAssertEqual(f.custody.counts.withLock { $0.actualCloses }, 1)
        await gate.open(); await f.lifecycle.close(); XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 1)
    }
    func testRetiringRoutingCannotReopenAfterAnExternalCloseFailure() async throws {
        let routing = AdministrativeSetupLifecycle.Routing(validateStartup: {})
        routing.move(to: .retiring); routing.move(to: .serving); routing.move(to: .starting)
        XCTAssertEqual(routing.state, .retiring); XCTAssertFalse(routing.allowsNormal)
        XCTAssertThrowsError(try routing.normalOwner()); routing.move(to: .closed)
        routing.move(to: .serving); XCTAssertEqual(routing.state, .closed)
    }
    func testDeadlineCallbackDoesNotReplayAWindowOrFabricateClosure() async throws {
        let gate = SetupLifecycleGate(), calls = Mutex(0)
        let row = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleFixture.row() }
        let f = try SetupLifecycleFixture(rows: [row], closeGate: gate, acquire: { _, _ in calls.withLock { $0 += 1 }; return .terminal(.noWindow) })
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }; await f.lifecycle.requestRetirement()
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(300))) }
        f.clock.advance(.seconds(300)); try await eventually { f.probe.state.withLock { $0.exits.count == 1 } }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(f.probe.state.withLock { $0.rows }, [row])
        XCTAssertEqual(f.custody.counts.withLock { $0.finishedCloses }, 0)
        await gate.open(); await f.lifecycle.close()
    }
    func testStatusRemainsNonverifiedDuringRetirement() async throws {
        let gate = SetupLifecycleGate(), f = try SetupLifecycleFixture(closeGate: gate)
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }; await f.lifecycle.requestRetirement()
        XCTAssertEqual(f.routing.checkStatus(), .busy)
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        XCTAssertEqual(f.routing.status(peer), .unavailable)
        await gate.open(); await f.lifecycle.close(); XCTAssertEqual(f.routing.checkStatus(), .refused)
    }
    func testStartupActivityIsReleasedBeforePendingDiscovery() async throws {
        let activity = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleActivityFixture() }
        let gate = SetupLifecycleGate(), sequence = Mutex<[String]>([])
        let f = try AdministrativeSetupService.openOwnedStartup(activity.barrier, verify: {
            sequence.withLock { $0.append("verify") }
            XCTAssertThrowsError(try activity.independent.acquireExclusive()) {
                XCTAssertEqual($0 as? ReleaseActivityError, .busy)
            }
            return 1
        }, makePending: { verified in
            XCTAssertEqual(verified, 1); sequence.withLock { $0.append("pending") }
            XCTAssertThrowsError(try activity.independent.acquireExclusive())
            return try SetupLifecycleFixture(prepareGate: gate)
        })
        XCTAssertEqual(sequence.withLock { $0 }, ["verify", "pending"])
        await f.lifecycle.start(); try await eventually { f.probe.state.withLock { $0.opens == 1 } }
        XCTAssertEqual(f.routing.state, .starting)
        let exclusive = try activity.independent.acquireExclusive(); exclusive.close()
        await gate.open(); await f.lifecycle.close()
    }
    func testServingKeepsNoStartupActivityAndOnlyTheActualScopeBlocksExclusive() async throws {
        let activity = try await SetupExecutorAdmissionTestFixture.make { try SetupLifecycleActivityFixture() }
        let f = try AdministrativeSetupService.openOwnedStartup(activity.barrier, verify: {
            XCTAssertThrowsError(try activity.independent.acquireExclusive())
        }, makePending: { _ in try SetupLifecycleFixture() })
        await f.lifecycle.start(); try await eventually { f.routing.state == .serving }
        let first = try activity.independent.acquireExclusive(); first.close()
        let scopeActivity = try activity.barrier.acquireShared()
        XCTAssertThrowsError(try activity.independent.acquireExclusive()) {
            XCTAssertEqual($0 as? ReleaseActivityError, .busy)
        }
        scopeActivity.close(); let after = try activity.independent.acquireExclusive(); after.close()
        await f.lifecycle.close()
    }
    func testHostFailuresRetireInsteadOfBecomingStoreRetries() async throws {
        for failure in [AdministrativeSetupServiceError.changedConfiguration, .wrongRelease, .wrongExecutable] {
            let f = try SetupLifecycleFixture(); f.probe.state.withLock { $0.prepareError = failure }
            await f.lifecycle.start(); try await eventually { f.routing.state == .closed }
            XCTAssertEqual(f.probe.state.withLock { $0.opens }, 1)
            XCTAssertFalse(f.clock.cooperativeSleeps.contains(f.clock.epoch.advanced(by: .milliseconds(500))))
            XCTAssertEqual(f.probe.state.withLock { $0.stopped }, 1)
            XCTAssertTrue(f.probe.state.withLock { $0.exits.isEmpty })
        }
        // The existing unreadable-store test proves the separate 500ms retry path.
    }
    func testAdmissionRefusalWaitsForReleaseInsteadOfPollingAtFiveHundredMilliseconds() async throws {
        let admission = try SetupOwnerAsyncWork.fixtureOwned(), token = try admission.admit()
        let f = try SetupLifecycleFixture(availability: { admission.availability() })
        f.probe.state.withLock { $0.admissionHeld = true }
        await f.lifecycle.start()
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(60))) }
        f.clock.advance(.milliseconds(500)); XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 1)
        XCTAssertFalse(f.clock.cooperativeSleeps.contains(f.clock.epoch.advanced(by: .milliseconds(500))))
        f.probe.state.withLock { $0.admissionHeld = false }; token.close()
        try await eventually { f.routing.state == .serving }
        XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 2); await f.lifecycle.close()
    }
    func testAdmissionWaitKeepsItsSixtySecondFallbackAndStopsAfterRelease() async throws {
        let admission = try SetupOwnerAsyncWork.fixtureOwned(), token = try admission.admit()
        let f = try SetupLifecycleFixture(availability: { admission.availability() })
        f.probe.state.withLock { $0.admissionHeld = true }; await f.lifecycle.start()
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(60))) }
        f.clock.advance(.seconds(59)); XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 1)
        f.clock.advance(.seconds(1)); try await eventually { f.probe.state.withLock { $0.discoveries == 2 } }
        try await eventually { f.clock.deadlines.contains(f.clock.epoch.advanced(by: .seconds(120))) }
        f.probe.state.withLock { $0.admissionHeld = false }; token.close()
        try await eventually { f.routing.state == .serving }; XCTAssertEqual(f.probe.state.withLock { $0.discoveries }, 3)
        await f.lifecycle.close()
    }
    func testEarlyIndependentWatchdogFireRearmsAndClosureCancelsTheTimer() throws {
        for finishBeforeDeadline in [false, true] {
            let clock = SetupLifecycleClock(), calls = Mutex<[Int32]>([])
            let watchdog = AdministrativeSetupLifecycle.RetirementWatchdog(timing: clock.timing,
                timer: try clock.watchdogDriver, terminate: { code in calls.withLock { $0.append(code) } })
            let deadline = watchdog.start(); XCTAssertEqual(clock.timerArms, 1)
            clock.fireWatchdogEarly(); XCTAssertEqual(clock.timerArms, 2)
            XCTAssertEqual(clock.deadlines, [deadline]); XCTAssertTrue(clock.cooperativeSleeps.isEmpty)
            XCTAssertTrue(calls.withLock { $0.isEmpty })
            if finishBeforeDeadline { watchdog.didClose() }
            clock.advance(.seconds(300))
            XCTAssertEqual(calls.withLock { $0 }, finishBeforeDeadline ? [] : [75])
            XCTAssertGreaterThan(clock.timerCancels, 0); watchdog.didClose()
        }
    }
    func testNativeDispatchWatchdogCallsTheInjectedClosureWithoutAnyCooperativeSleep() async throws {
        let now = Mutex(ContinuousClock.now.advanced(by: Duration.seconds(-300) + Duration.milliseconds(300)))
        let slept = Mutex(0), codes = Mutex<[Int32]>([]), fired = expectation(description: "independent Dispatch watchdog")
        let timing = SetupMaintenanceRecoverySupervisor.Timing(now: { now.withLock { $0 } }, sleep: { _ in
            slept.withLock { $0 += 1 }; throw CancellationError()
        })
        let watchdog = AdministrativeSetupLifecycle.RetirementWatchdog(timing: timing, terminate: { code in
            codes.withLock { $0.append(code) }; fired.fulfill()
        })
        let deadline = watchdog.start(); now.withLock { $0 = deadline }
        await fulfillment(of: [fired], timeout: Double(120) / 4)
        XCTAssertEqual(codes.withLock { $0 }, [75]); XCTAssertEqual(slept.withLock { $0 }, 0)
        watchdog.didClose()
    }

}

func setupLifecycleRecoveryRowOwned() throws -> RuntimeMaintenanceWindowRecord {
    try RuntimeMaintenanceOwnedControl.require()
    return try SetupLifecycleFixture.row()
}
