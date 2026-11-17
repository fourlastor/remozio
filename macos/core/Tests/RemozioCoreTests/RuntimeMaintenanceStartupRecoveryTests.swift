import Darwin
import Dispatch
import Synchronization
import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

private enum StartupTestError: Error, Equatable { case expected }
/// Real owned machine rows and account locks. Native code identity and launchd remain outside these tests.
private final class StartupHarness: @unchecked Sendable {
    typealias Row = RuntimeMaintenanceWindowRecord
    let f: RuntimeMaintenanceWriterFixture
    let barrier: UpdateAdmissionBarrier
    let initial: Row
    let witness = RestorationTestWitness(200)
    var inspected = RuntimeJobStopSession.Observation.absent
    var registrations = 0, observations = 0, classifications = 0, writes: [Row.Phase] = []
    var classification = RuntimeMaintenanceRuntimeObservation.State.new
    var failScopeAfterPhase: Row.Phase?, driftFloorAfterPhase: Row.Phase?
    var beforeRegistration: (@Sendable () -> Void)?, afterObservation: (@Sendable () -> Void)?
    var inspectOverride: (@Sendable () throws -> RuntimeJobStopSession.Observation)?
    var failPhase: Row.Phase?, commitBeforeFailure = false, rejectCode = false, postCommitScopeFailure = false
    var lastTransition: PreparationIntentStore.RuntimeMaintenanceTransition?
    var attemptedRows: [Row] = [], committedRows: [Row] = []
    var beforeWrite: (@Sendable (Row) throws -> Void)?, afterWrite: (@Sendable (Row) throws -> Void)?
    var verifyOverride: (@Sendable () throws -> Void)?
    init(_ fixture: RuntimeMaintenanceWriterFixture) throws {
        self.f = fixture
        let f = fixture
        let source = try f.machine().stableRuntimeSource(candidate: f.candidate)
        let a = try XCTUnwrap(source.preparations.first { $0.accountID == f.authority.accountID })
        let b = try XCTUnwrap(source.preparations.first { $0.accountID == f.target.accountID })
        let ownerA = LocalAccountIdentity(uid: a.ownerUID, primaryGroupID: getgid(), directoryID: a.directoryID)
        let ownerB = LocalAccountIdentity(uid: b.ownerUID, primaryGroupID: getgid(), directoryID: b.directoryID)
        let entry = try f.machine().retainedSetupInitialRuntimeEntry(owner: ownerB, candidate: f.candidate)
        let inputs = try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: nil,
            verifyCurrent: {}, readRelay: { _ in throw StartupTestError.expected })
        let commitments = try RuntimeMaintenanceCommitments.observing(entry: entry, inputs: inputs,
            authorityAccountID: a.accountID, authorityOwner: ownerA, targetOwner: ownerB,
            candidate: f.candidate, purpose: .retainedRuntime)
        initial = try Row(id: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
            purpose: .retainedRuntime, scope: commitments.scope)
        let gate = try XCTUnwrap(source.actual.admission.accounts.first { $0.accountID == a.accountID })
        let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
        barrier = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
            owner: getuid(), expected: gate.identity, scope: .account(a.accountID))
    }
    func frame() throws -> RuntimeMaintenanceStartupFrame {
        let frame = try f.machine().runtimeMaintenanceStartupFrame(accountID: initial.scope.authority.accountID, candidate: f.candidate)
        guard let phase = driftFloorAfterPhase, writes.contains(phase) else { return frame }
        let source = frame.source
        let target = try XCTUnwrap(source.preparations.first { $0.accountID == initial.scope.target.accountID })
        var revision = target.revision; revision[0] ^= 1
        let changed = try AccountPreparationIntent(setupID: target.setupID, revision: revision, macID: target.macID,
            installationID: target.installationID, releaseDigest: target.releaseDigest, accountID: target.accountID,
            ownerUID: target.ownerUID, directoryID: target.directoryID, policyBytes: target.policyBytes,
            initializationBytes: target.initializationBytes, authorityPublicKey: target.authorityPublicKey, storagePrepared: target.storagePrepared)
        let drifted = try MachineUpdateStableRuntimeSource(actual: source.actual,
            preparations: source.preparations.map { $0.accountID == target.accountID ? changed : $0 },
            initializations: source.initializations, candidate: f.candidate)
        return .init(source: drifted, window: frame.window)
    }
    func write(_ next: Row, previous: Row?, drain: UpdateDrainToken? = nil) throws -> Row {
        let receipt = try f.machine().writeRuntimeMaintenanceTransition(next, replacing: previous,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain)
        lastTransition = receipt
        return receipt.record
    }
    func seed(_ phase: Row.Phase) throws {
        var row = try write(initial, previous: nil)
        guard phase != .authorized else { return }
        let drain = try barrier.beginDrain(); defer { drain.close() }
        row = try write(RuntimeMaintenanceStartupPolicy.row(row, phase: .draining, service: .notStopped), previous: row, drain: drain)
        let binding = try AuthorityMaintenanceBinding(accountID: row.scope.authority.accountID, attemptID: row.id,
            revision: row.revision, incarnation: Data(repeating: 71, count: 16), connectionID: Data(repeating: 72, count: 16))
        row = try f.machine().persistRuntimeMaintenanceBindingTransition(binding, window: row,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain).record
        if phase == .draining { return }
        if phase == .needsOwnerRecovery {
            _ = try write(RuntimeMaintenanceStartupPolicy.row(row, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .cleanupPending), previous: row); return
        }
        for nextPhase in [Row.Phase.stopping, .stopped, .executing, .workSettled, .restoring, .reopenPending] {
            let operation: Row.OperationOutcome = nextPhase == .executing ? .unknown
                : [.stopping, .stopped].contains(nextPhase) ? .notStarted : .committed
            let service: Row.ServiceOutcome = nextPhase == .stopping ? .notStopped
                : nextPhase == .restoring ? .restartPending : nextPhase == .reopenPending ? .healthy : .stopped
            let next = try RuntimeMaintenanceStartupPolicy.row(row, phase: nextPhase, operation: operation, service: service)
            row = try write(next, previous: row)
            if nextPhase == phase { return }
        }
        XCTFail("Unsupported seed phase")
    }
    func persistForRecovery(_ next: Row, previous: Row) throws -> Row {
        writes.append(next.phase); attemptedRows.append(next)
        try beforeWrite?(next)
        if failPhase == next.phase && !commitBeforeFailure { throw StartupTestError.expected }
        let value = try write(next, previous: previous); committedRows.append(value)
        if failScopeAfterPhase == next.phase { postCommitScopeFailure = true }
        try afterWrite?(value)
        if failPhase == next.phase { throw StartupTestError.expected }
        return value
    }
    func verifyCurrent() throws {
        if postCommitScopeFailure { throw StartupTestError.expected }
        try verifyOverride?()
    }
    func open(afterProbePolicy: @escaping @Sendable (Row, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
        try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
    }, supervisorWork: RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork? = nil) throws -> RuntimeMaintenanceStartupRecovery {
        try .openOwned(frame: frame(), release: f.candidate, admission: f.admission, directory: f.directory,
            accountBarrier: barrier, read: { try self.frame() }, persist: { next, previous in
                try self.persistForRecovery(next, previous: previous)
            }, verify: {
                try self.verifyCurrent()
            }, inspect: { _ in try self.inspectOverride?() ?? self.inspected }, observe: { _, _, pid in
                self.observations += 1
                guard !self.rejectCode, pid == self.witness.processID else { throw StartupTestError.expected }
                self.afterObservation?(); return self.witness
            }, observeOperation: { _ in self.classifications += 1; return self.classification }, register: {
                self.beforeRegistration?(); self.registrations += 1; self.inspected = .matching(self.witness.processID)
            }, afterProbePolicy: afterProbePolicy, supervisorWork: supervisorWork)
    }

}

private final class StartupMetrics: Sendable {
    let actions = Mutex<[AuthorityMaintenanceChannelRequest.Action]>([]), hellos = Mutex(0), probes = Mutex(0), gates = Mutex(0)
}

/// A callback transport for owned tests. It supplies no native peer identity or Authority endpoint evidence.
private final class StartupDriver: AuthorityMaintenanceClientDriver, Sendable {
    typealias Request = AuthorityMaintenanceChannelRequest
    let epoch: Data, barrier: UpdateAdmissionBarrier
    let metrics: StartupMetrics
    let closed = Mutex(false), onProbe = Mutex<(@Sendable () -> Void)?>(nil)
    let invalidated = Mutex<(@Sendable () -> Void)?>(nil)
    let onExchange = Mutex<(@Sendable (Request.Action) -> Void)?>(nil)
    let refuseProbe: Bool, failGate: Bool, notReadyOpen: Bool
    init(epoch: Data, barrier: UpdateAdmissionBarrier, refuseProbe: Bool = false, failGate: Bool = false, notReadyOpen: Bool = false, metrics: StartupMetrics? = nil) {
        self.metrics = metrics ?? StartupMetrics(); self.epoch = epoch; self.barrier = barrier; self.refuseProbe = refuseProbe; self.failGate = failGate; self.notReadyOpen = notReadyOpen
    }
    func start(_ invalidated: @escaping @Sendable () -> Void) { self.invalidated.withLock { $0 = invalidated } }
    func invalidate() { invalidated.withLock { $0 }?() }
    func close() { closed.withLock { $0 = true } }
    func fresh() -> StartupDriver {
        .init(epoch: epoch, barrier: barrier, refuseProbe: refuseProbe, failGate: failGate, notReadyOpen: notReadyOpen, metrics: metrics)
    }
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        metrics.hellos.withLock { $0 += 1 }; reply(.hello(AuthorityMaintenanceChannelScope.protocolVersion))
    }
    func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        metrics.probes.withLock { $0 += 1 }; onProbe.withLock { $0 }?()
        do {
            guard !refuseProbe else { reply(.bytes(nil)); return }
            let q = try AuthorityMaintenanceIncarnationRequest.decode(bytes)
            reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: q, incarnation: epoch).encoded))
        } catch { reply(.bytes(nil)) }
    }
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do {
            let q = try Request.decode(bytes); metrics.actions.withLock { $0.append(q.action) }
            let binding = try q.binding ?? AuthorityMaintenanceBinding(accountID: q.accountID, attemptID: q.attemptID,
                revision: q.revision, incarnation: epoch, connectionID: Data(repeating: 93, count: 16))
            let refused = q.action == .open && notReadyOpen
            let work = try q.action == .open && !refused ? MaintenanceStopTestDriver.work() : nil
            reply(.bytes(try AuthorityMaintenanceChannelResponse(request: q, binding: binding, work: work,
                outcome: refused ? .refused : .applied).encoded))
            onExchange.withLock { $0 }?(q.action)
        } catch { reply(.bytes(nil)) }
    }
    func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        metrics.gates.withLock { $0 += 1 }
        do {
            let q = try AuthorityMaintenanceGateRequest.decode(bytes)
            // A real shared probe must succeed only after the fresh EX drain was closed.
            let token = try barrier.acquireAdmission(); try token.validate(); token.close()
            reply(.bytes(try AuthorityMaintenanceGateResponse(request: q, authorityIncarnation: epoch,
                hold: failGate ? .held : .released, admission: .available).encoded))
        } catch { reply(.bytes(nil)) }
    }
}

private enum AutomaticSupervisorTestError: Error {
    case phaseWaitExpired, phaseReleaseExpired, reentryWaitExpired
    case workerReturnedBeforePhase(String)
}
private final class AutomaticSupervisorPhaseGate: @unchecked Sendable {
    typealias Control = AuthorityMaintenanceXPCClient.OwnedSupervisorPhaseControl
    let event = Mutex<Control.Event?>(nil)
    let reentryDispatched = Mutex(false), reentryReturned = Mutex(false)
    let workerResult = Mutex<Result<RuntimeMaintenanceWindowRecord, any Error>?>(nil)
    private let deadline: ContinuousClock.Instant
    private let resume = DispatchSemaphore(value: 0)
    private let boundary: Control.Boundary
    private let rpc: Control.RPC?
    init(_ boundary: Control.Boundary, rpc: Control.RPC? = nil, until deadline: ContinuousClock.Instant) {
        self.boundary = boundary; self.rpc = rpc; self.deadline = deadline
    }
    func control() throws -> Control {
        try .init { event in
            if event.boundary == .beforeRPCDispatch, self.event.withLock({ $0 }) != nil {
                self.reentryDispatched.withLock { $0 = true }; return
            }
            guard event.boundary == self.boundary, event.rpc == self.rpc else { return }
            let first = self.event.withLock { current in
                guard current == nil else { return false }; current = event; return true
            }
            guard first else { return }
            while self.resume.wait(timeout: .now() + .milliseconds(10)) != .success {
                guard ContinuousClock.now < self.deadline else { throw AutomaticSupervisorTestError.phaseReleaseExpired }
            }
        }
    }
    func open() { resume.signal() }
}

final class RuntimeMaintenanceStartupRecoveryTests: XCTestCase {
    private func withAsyncStartup(_ phase: RuntimeMaintenanceWindowRecord.Phase, epoch: UInt8 = 81,
        refuseProbe: Bool = false, failGate: Bool = false,
        body: @escaping @Sendable (StartupHarness, StartupDriver) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let h = try StartupHarness(f); try h.seed(phase)
            let driver = StartupDriver(epoch: Data(repeating: epoch, count: 16), barrier: h.barrier,
                refuseProbe: refuseProbe, failGate: failGate)
            let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, Error>?>(nil)
            Task {
                do { try await body(h, driver); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + 50) == .success else { return XCTFail("Startup task did not settle") }
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    private static func complete(_ h: StartupHarness, _ driver: StartupDriver, timeoutSeconds: Int? = nil,
        startup: RuntimeMaintenanceStartupRecovery? = nil, until deadline: ContinuousClock.Instant? = nil,
        beforeOpen: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in }) async throws -> RuntimeMaintenanceWindowRecord {
        let startup = try startup ?? h.open(), attempts = Mutex(0)
        return try await startup.runOwned(makeDriver: {
            let first = attempts.withLock { $0 += 1; return $0 == 1 }
            return first ? driver : driver.fresh()
        }, capturePeer: { h.witness }, requirePeerLive: { peer in
            guard try !peer.hasExited() else { throw StartupTestError.expected }
        }, beforeHealthyOpen: beforeOpen,
            until: deadline ?? .now.advanced(by: timeoutSeconds.map { Duration.seconds($0) } ?? restorationTestForwardDeadline))
    }
    private static func failed(_ h: StartupHarness, _ driver: StartupDriver,
        startup: RuntimeMaintenanceStartupRecovery? = nil, timeoutSeconds: Int = 5) async -> Error? {
        do { _ = try await complete(h, driver, timeoutSeconds: timeoutSeconds, startup: startup); XCTFail("Expected refusal"); return nil }
        catch { return error }
    }
    func testDriverInvalidationAfterDecisionProofRetriesWithFreshClients() throws {
        try withAsyncStartup(.draining) { h, _ in
            let startup = try h.open(), drivers = Mutex<[StartupDriver]>([]), probes = Mutex(0)
            let row = try await startup.runOwned(makeDriver: {
                let d = StartupDriver(epoch: Data(repeating: 81, count: 16), barrier: h.barrier)
                drivers.withLock { $0.append(d) }; return d
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, afterProbe: {
                if probes.withLock({ $0 += 1; return $0 == 1 }) {
                    XCTAssertTrue(h.writes.isEmpty)
                    drivers.withLock { $0.last }?.invalidate()
                }
            }, until: .now.advanced(by: restorationTestForwardDeadline))
            let all = drivers.withLock { $0 }
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(all.count, 3)
            XCTAssertTrue(all.allSatisfy { $0.closed.withLock { $0 } })
            XCTAssertTrue(all.prefix(2).allSatisfy { $0.metrics.actions.withLock { $0 }.isEmpty })
            XCTAssertEqual(all.map { $0.metrics.probes.withLock { $0 } }, [1, 1, 1])
            XCTAssertEqual(h.writes, [.needsOwnerRecovery, .restoring, .reopenPending, .restored])
            XCTAssertEqual(h.registrations, 1)
        }
    }
    func testDriverInvalidationAfterHealthyProofRetriesBeforeActorFinish() throws {
        try withAsyncStartup(.stopped) { h, _ in
            let startup = try h.open(), drivers = Mutex<[StartupDriver]>([]), probes = Mutex(0)
            let row = try await startup.runOwned(makeDriver: {
                let d = StartupDriver(epoch: Data(repeating: 81, count: 16), barrier: h.barrier)
                drivers.withLock { $0.append(d) }; return d
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, afterProbe: {
                // This synchronous hook runs on the client actor before its greeted guard.
                // The callback invalidates the lifetime while finish remains queued on that actor.
                if probes.withLock({ $0 += 1; return $0 == 1 }) { drivers.withLock { $0.last }?.invalidate() }
            }, until: .now.advanced(by: restorationTestForwardDeadline))
            let all = drivers.withLock { $0 }
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(all.count, 2)
            XCTAssertTrue(all[0].closed.withLock { $0 }); XCTAssertTrue(all[0].metrics.actions.withLock { $0 }.isEmpty)
            XCTAssertEqual(all[1].metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(h.writes, [.restoring, .reopenPending, .restored]); XCTAssertEqual(h.registrations, 1)
        }
    }
    func testClosedSameEpochCancelRecordsHealthFailure() throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            let startup = try h.open()
            do {
                _ = try await startup.runOwned(makeDriver: { driver }, capturePeer: { h.witness }, requirePeerLive: { _ in },
                    beforeCancel: { await $0.close() }, until: .now.advanced(by: .seconds(20)))
                XCTFail("Expected a closed client refusal")
            } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
            XCTAssertEqual(h.writes, [.needsOwnerRecovery]); XCTAssertEqual(try h.frame().window?.failure, .healthFailed)
            XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty)
        }
    }
    func testCancelledBeforeRunDoesNotPrepareOrWrite() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let startup = try h.open()
            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                return await Self.failed(h, driver, startup: startup)
            }
            let error = await task.value
            XCTAssertTrue(error is CancellationError)
            XCTAssertTrue(h.writes.isEmpty); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(try h.frame().window?.phase, .stopped)
        }
    }
    func testCancellationAfterDecisionProofLeavesDrainingForNextStartup() throws {
        try withAsyncStartup(.draining) { h, driver in
            let startup = try h.open()
            let task = Task { () -> Error? in
                do {
                    _ = try await startup.runOwned(makeDriver: { driver }, capturePeer: { h.witness }, requirePeerLive: { _ in },
                        afterProbe: { withUnsafeCurrentTask { $0?.cancel() } }, until: .now.advanced(by: .seconds(20)))
                    XCTFail("Expected cancellation"); return nil
                } catch { return error }
            }
            let error = await task.value
            XCTAssertTrue(error is CancellationError)
            XCTAssertTrue(h.writes.isEmpty); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(try h.frame().window?.phase, .draining)
            XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty)
        }
    }
    func testCancellationInsideHealthyOpenLeavesRestoringWithoutFallback() throws {
        try withAsyncStartup(.stopped) { h, driver in
            driver.onExchange.withLock { $0 = { action in
                if action == .open { withUnsafeCurrentTask { $0?.cancel() } }
            } }
            let task = Task { await Self.failed(h, driver, timeoutSeconds: 30) }
            let error = await task.value
            XCTAssertTrue(error is CancellationError)
            XCTAssertEqual(h.writes, [.restoring]); XCTAssertEqual(try h.frame().window?.phase, .restoring)
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, [.open]); XCTAssertEqual(driver.metrics.gates.withLock { $0 }, 0)
        }
    }
    func testCancellationInsideSavedReopenLeavesPendingWithoutFallback() throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            driver.onExchange.withLock { $0 = { action in
                if action == .reopen { withUnsafeCurrentTask { $0?.cancel() } }
            } }
            let task = Task { await Self.failed(h, driver, timeoutSeconds: 30) }
            let error = await task.value
            XCTAssertTrue(error is CancellationError)
            XCTAssertEqual(h.writes, [.reopenPending]); XCTAssertEqual(try h.frame().window?.phase, .reopenPending)
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, [.reopen]); XCTAssertEqual(driver.metrics.gates.withLock { $0 }, 0)
        }
    }
    func testConflictingLaunchdJobRecordsOneServiceFailure() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .conflicting
            _ = await Self.failed(h, driver, timeoutSeconds: 20)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.observations, 0)
            XCTAssertEqual(h.writes, [.needsOwnerRecovery]); XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable)
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testUnsafeLaunchdPidsRecordOneServiceFailure() throws {
        for pid in [pid_t(0), pid_t(1)] {
            try withAsyncStartup(.restoring) { h, driver in
                h.inspected = .matching(pid)
                _ = await Self.failed(h, driver, timeoutSeconds: 20)
                XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.observations, 0)
                XCTAssertEqual(h.writes, [.needsOwnerRecovery]); XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable)
                XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
            }
        }
    }
    func testProcessExitAfterObservationRecordsOneServiceFailure() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .matching(h.witness.processID)
            h.afterObservation = { h.witness.exited.withLock { $0 = true } }
            _ = await Self.failed(h, driver, timeoutSeconds: 20)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.observations, 1)
            XCTAssertEqual(h.writes, [.needsOwnerRecovery]); XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable)
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testAbsentRegisteredJobWaitsUntilDeadlineAndRecordsOneServiceFailure() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let inspections = Mutex(0)
            h.inspectOverride = { inspections.withLock { $0 += 1 }; return .absent }
            _ = await Self.failed(h, driver, timeoutSeconds: 15)
            XCTAssertEqual(h.registrations, 1); XCTAssertEqual(h.observations, 0)
            XCTAssertGreaterThan(inspections.withLock { $0 }, 2)
            XCTAssertEqual(h.writes, [.restoring, .needsOwnerRecovery]); XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable)
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testOtherAccountPreparationAndInitializationDriftDoesNotChangeTheStartupFloor() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let h = try StartupHarness(f); try h.seed(.restoring)
            let frame = try h.frame(), row = try XCTUnwrap(frame.window), source = frame.source
            let template = try XCTUnwrap(source.preparations.first), initial = try template.initialAuthority
            let account = AccountPreparationIntent.randomID(), uid = try XCTUnwrap(source.preparations.map(\.ownerUID).max()) + 1
            let policy = try CommandElevationPolicy(macID: template.macID, accountID: account, callerUID: uid,
                allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(template.macID), 2: .bytes(account), 3: .bytes(AccountPreparationIntent.randomID()),
                4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let declaration = AuthorityJournalInitialization(descriptor: descriptor, codePolicy: initial.codePolicy,
                capabilities: initial.capabilities, allowedContracts: initial.allowedContracts)
            let bytes = try declaration.initializationBytes, digest = try declaration.initializationDigest
            let setup = AccountPreparationIntent.randomID(), directory = UUID()
            func changed(_ marker: UInt8) throws -> RuntimeMaintenanceStartupFrame {
                let preparation = try AccountPreparationIntent(setupID: setup, revision: Data(repeating: marker, count: 16),
                    macID: template.macID, installationID: template.installationID, releaseDigest: source.actual.inventory.releaseDigest,
                    accountID: account, ownerUID: uid, directoryID: directory, policyBytes: policy.canonicalBytes, initializationBytes: bytes)
                let initialization = try AuthorityInitializationIntent(setupID: setup, revision: Data(repeating: marker, count: 16),
                    installationID: template.installationID, macID: template.macID, accountID: account,
                    releaseDigest: source.actual.inventory.releaseDigest, initializationDigest: digest, initializationBytes: bytes,
                    journalPath: "/owned/other/journal/journal.sqlite", continuityPath: "/owned/other/continuity/continuity.sqlite")
                return .init(source: try MachineUpdateStableRuntimeSource(actual: source.actual,
                    preparations: source.preparations + [preparation], initializations: source.initializations + [initialization], candidate: f.candidate), window: row)
            }
            let before = try changed(41), after = try changed(42)
            XCTAssertNotEqual(before.source.preparations, after.source.preparations)
            XCTAssertNotEqual(before.source.initializations, after.source.initializations)
            let floor = try RuntimeMaintenanceStartupFloor(frame: before, release: f.candidate)
            XCTAssertNoThrow(try floor.requireCurrent(after, window: row, release: f.candidate))
        }
    }
    func testClosedAfterHealthyProbeRetriesOnAFreshClientWithoutRecovery() throws {
        try withAsyncStartup(.stopped) { h, _ in
            let startup = try h.open(), drivers = Mutex<[StartupDriver]>([]), attempts = Mutex(0), captures = Mutex(0)
            let row = try await startup.runOwned(makeDriver: {
                let d = StartupDriver(epoch: Data(repeating: 81, count: 16), barrier: h.barrier)
                drivers.withLock { $0.append(d) }; return d
            }, capturePeer: { captures.withLock { $0 += 1 }; return h.witness }, requirePeerLive: { _ in },
            beforeHealthyOpen: { client in
                if attempts.withLock({ $0 += 1; return $0 == 1 }) { await client.close() }
            }, until: .now.advanced(by: restorationTestForwardDeadline))
            let all = drivers.withLock { $0 }
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(all.count, 2)
            XCTAssertFalse(all[0] === all[1]); XCTAssertTrue(all[0].metrics.actions.withLock { $0 }.isEmpty)
            XCTAssertEqual(all[1].metrics.actions.withLock { $0 }, [.open, .reopen]); XCTAssertEqual(captures.withLock { $0 }, 1)
            XCTAssertEqual(h.writes, [.restoring, .reopenPending, .restored]); XCTAssertEqual(h.registrations, 1)
        }
    }
    func testConcurrentSecondRunRefusesWithoutWritingOrChangingTheFirstRun() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .matching(h.witness.processID)
            let startup = try h.open(), entered = AsyncStream<Void>.makeStream(), resume = AsyncStream<Void>.makeStream()
            let first = Task {
                try await Self.complete(h, driver, startup: startup, beforeOpen: { _ in
                    entered.continuation.yield(())
                    for await _ in resume.stream { break }
                })
            }
            var wait = entered.stream.makeAsyncIterator(); _ = await wait.next()
            let before = h.writes
            let error = await Self.failed(h, driver, startup: startup)
            XCTAssertEqual(error as? JournalLeaseError, .invalidated); XCTAssertEqual(h.writes, before)
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 1)
            resume.continuation.yield(()); resume.continuation.finish(); entered.continuation.finish()
            let restored = try await first.value
            XCTAssertEqual(restored.phase, .restored); XCTAssertEqual(h.writes, [.reopenPending, .restored])
        }
    }
    func testNotReadyThenReadyUsesTwoFreshClientsAndOnlyOnePending() throws {
        try withAsyncStartup(.stopped) { h, _ in
            let startup = try h.open(), drivers = Mutex<[StartupDriver]>([])
            let row = try await startup.runOwned(makeDriver: {
                let first = drivers.withLock { $0.isEmpty }
                let d = StartupDriver(epoch: Data(repeating: 81, count: 16), barrier: h.barrier, notReadyOpen: first)
                drivers.withLock { $0.append(d) }; return d
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, until: .now.advanced(by: restorationTestForwardDeadline))
            let all = drivers.withLock { $0 }
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(all.count, 2); XCTAssertFalse(all[0] === all[1])
            XCTAssertEqual(all.flatMap { $0.metrics.actions.withLock { $0 } }, [.open, .open, .reopen])
            XCTAssertEqual(h.writes, [.restoring, .reopenPending, .restored]); XCTAssertEqual(h.registrations, 1)
        }
    }
    func testSameEpochDrainingUsesOneProbeAndSavedReopenWithoutOpenOrArm() throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .notStopped); XCTAssertEqual(row.operation, .notStarted)
            XCTAssertEqual(h.writes, [.reopenPending, .restored]); XCTAssertEqual(driver.metrics.actions.withLock { $0 }, [.reopen])
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 1); XCTAssertEqual(driver.metrics.probes.withLock { $0 }, 1)
            XCTAssertEqual(driver.metrics.gates.withLock { $0 }, 1); XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.classifications, 0)
        }
    }
    func testSameEpochStoppingRecordsRecoveryWithoutReopen() throws {
        try withAsyncStartup(.stopping, epoch: 71) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.failure, .cleanupPending); XCTAssertEqual(h.writes, [.needsOwnerRecovery])
            XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty); XCTAssertEqual(h.registrations, 0)
        }
    }
    func testRestartClosesDecisionClientBeforeRegistrationAndUsesAFreshHealthyClient() throws {
        try withAsyncStartup(.draining) { h, driver in
            h.beforeRegistration = { XCTAssertTrue(driver.closed.withLock { $0 }); XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty) }
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, .notStarted)
            XCTAssertEqual(h.writes, [.needsOwnerRecovery, .restoring, .reopenPending, .restored])
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, [.open, .reopen]); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 2)
            XCTAssertEqual(driver.metrics.probes.withLock { $0 }, 2); XCTAssertEqual(h.registrations, 1); XCTAssertEqual(h.classifications, 0)
        }
    }
    func testExecutingObservesThenAdoptsBeforeTheHealthyClient() throws {
        try withAsyncStartup(.executing) { h, driver in
            h.inspected = .matching(h.witness.processID)
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, .committed)
            XCTAssertEqual(h.writes, [.workSettled, .restoring, .reopenPending, .restored])
            XCTAssertEqual(h.classifications, 1); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, [.open, .reopen]); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 1)
            XCTAssertEqual(driver.metrics.probes.withLock { $0 }, 1); XCTAssertEqual(row.gate?.authorityIncarnation, driver.epoch)
            XCTAssertEqual(try h.frame().window, row)
        }
    }
    func testStoppedWithTheOldEpochCannotOpenHealthyOrReleaseItsDrain() throws {
        try withAsyncStartup(.stopped, epoch: 71) { h, driver in
            let error = await Self.failed(h, driver)
            XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery)
            XCTAssertEqual(h.writes, [.restoring, .needsOwnerRecovery]); XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty)
            XCTAssertEqual(try h.frame().window?.failure, .healthFailed); XCTAssertEqual(driver.metrics.gates.withLock { $0 }, 0)
        }
    }
    func testLostDecisionProbeRetriesUntilDeadlineAndRecordsOneServiceFailure() throws {
        try withAsyncStartup(.draining, refuseProbe: true) { h, driver in
            _ = await Self.failed(h, driver)
            XCTAssertEqual(h.writes, [.needsOwnerRecovery]); XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty)
            XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable); XCTAssertEqual(h.registrations, 0)
            XCTAssertGreaterThan(driver.metrics.probes.withLock { $0 }, 1)
        }
    }
    func testPolicyRefusalPreservesItsErrorAndDoesNotRepeatTheDecision() throws {
        try withAsyncStartup(.draining) { h, driver in
            let decisions = Mutex(0)
            let startup = try h.open(afterProbePolicy: { _, _ in decisions.withLock { $0 += 1 }; throw StartupTestError.expected })
            let error = await Self.failed(h, driver, startup: startup, timeoutSeconds: 30)
            XCTAssertEqual(error as? StartupTestError, .expected); XCTAssertEqual(decisions.withLock { $0 }, 1)
            XCTAssertEqual(driver.metrics.probes.withLock { $0 }, 1); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 1)
            XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty); XCTAssertEqual(h.writes, [.needsOwnerRecovery])
        }
    }
    func testUncertainPendingCommitAfterProbeSendsNoReopenAndNoFallbackWrite() throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            h.failPhase = .reopenPending; h.commitBeforeFailure = true
            _ = await Self.failed(h, driver)
            XCTAssertEqual(h.writes, [.reopenPending]); XCTAssertTrue(driver.metrics.actions.withLock { $0 }.isEmpty)
            XCTAssertEqual(try h.frame().window?.phase, .reopenPending)
        }
    }
    func testHealthyFailureAfterRestartBridgeStillRecordsOneFinalFailure() throws {
        try withAsyncStartup(.draining, failGate: true) { h, driver in
            _ = await Self.failed(h, driver, timeoutSeconds: 25)
            XCTAssertEqual(h.writes, [.needsOwnerRecovery, .restoring, .reopenPending, .needsOwnerRecovery])
            XCTAssertEqual(try h.frame().window?.failure, .admissionUnconfirmed); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 2)
        }
    }
    func testReaderReturnsTheExactRealWindowWithItsProtectedSource() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let h = try StartupHarness(f); XCTAssertNil(try h.frame().window); try h.seed(.executing)
            let frame = try h.frame(), row = try XCTUnwrap(frame.window)
            XCTAssertEqual(row.phase, .executing)
            try f.machine().requireRuntimeMaintenanceObservationWindow(row, candidate: f.candidate)
            try frame.source.actual.requireSame(as: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate))
        }
    }
    func testStoppedRegistersOnceWithoutOperationObservation() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.operation, .notStarted); XCTAssertEqual(h.registrations, 1); XCTAssertEqual(h.classifications, 0)
        }
    }
    func testExecutingClassifiesAndRecordsTheObservedOperationBeforeRestoration() throws {
        try withAsyncStartup(.executing) { h, driver in
            h.classification = .partial
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.operation, .unknown); XCTAssertEqual(h.classifications, 1); XCTAssertEqual(h.registrations, 1)
            XCTAssertEqual(h.writes, [.workSettled, .restoring, .reopenPending, .restored])
        }
    }
    func testAnOwnedMatchingJobIsAdoptedWithoutRegistration() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .matching(h.witness.processID)
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(h.observations, 2); XCTAssertEqual(h.writes, [.reopenPending, .restored])
        }
    }
    func testAJobWithoutALivePidDoesNotRegisterAReplacement() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .matching(nil); _ = await Self.failed(h, driver)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.writes, [.needsOwnerRecovery])
            XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testWrongCodeDuringAdoptionStopsBeforeRegistration() throws {
        try withAsyncStartup(.restoring) { h, driver in
            h.inspected = .matching(h.witness.processID); h.rejectCode = true
            _ = await Self.failed(h, driver)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.writes, [.needsOwnerRecovery])
            XCTAssertEqual(try h.frame().window?.failure, .serviceUnavailable); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testASecondLiveDrainHolderIsBusyAndWritesNothing() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let h = try StartupHarness(f); try h.seed(.stopped)
            let held = try h.barrier.beginDrain(); defer { held.close() }
            let before = try h.frame().window
            XCTAssertThrowsError(try h.open()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            XCTAssertEqual(try h.frame().window, before); XCTAssertTrue(h.writes.isEmpty)
        }
    }
    func testUncertainWorkSettledCommitStopsWithoutRegistrationOrFallbackWrite() throws {
        try withAsyncStartup(.executing) { h, driver in
            h.failPhase = .workSettled; h.commitBeforeFailure = true
            _ = await Self.failed(h, driver)
            XCTAssertEqual(h.writes, [.workSettled]); XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.classifications, 1)
            XCTAssertEqual(try h.frame().window?.phase, .workSettled); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testUncertainRestoringCommitStopsWithoutAnyJobAction() throws {
        try withAsyncStartup(.stopped) { h, driver in
            h.failPhase = .restoring; h.commitBeforeFailure = true
            _ = await Self.failed(h, driver)
            XCTAssertEqual(h.writes, [.restoring]); XCTAssertEqual(h.observations, 0); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testStartupPendingRecordsRecoveryOnceWithoutAnyJobAction() throws {
        try withAsyncStartup(.reopenPending) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.failure, .admissionUnconfirmed); XCTAssertEqual(h.writes, [.needsOwnerRecovery])
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.observations, 0); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testExistingOwnerRecoveryIsNotAutomaticallyAdopted() throws {
        try withAsyncStartup(.needsOwnerRecovery) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertTrue(h.writes.isEmpty)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testAuthorizedRecordsManualCleanupWithoutABinding() throws {
        try withAsyncStartup(.authorized) { h, driver in
            let row = try await Self.complete(h, driver)
            XCTAssertNil(row.shutdownBinding); XCTAssertEqual(row.failure, .cleanupPending)
            XCTAssertEqual(row.operation, .notStarted); XCTAssertEqual(h.registrations, 0); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testDrainingDoesNoWriteOrJobActionBeforeTheAuthenticatedProbe() throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            driver.onProbe.withLock { $0 = {
                XCTAssertTrue(h.writes.isEmpty); XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.classifications, 0)
            } }
            _ = try await Self.complete(h, driver)
            XCTAssertEqual(driver.metrics.probes.withLock { $0 }, 1)
        }
    }
    func testConfirmedRestoringCommitWithConfigurationDriftRecordsRecoveryOnce() throws {
        try withAsyncStartup(.stopped) { h, driver in
            h.failScopeAfterPhase = .restoring
            let error = await Self.failed(h, driver)
            XCTAssertEqual(error as? RuntimePreparationError, .changedScope)
            XCTAssertEqual(h.writes, [.restoring, .needsOwnerRecovery]); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(try h.frame().window?.failure, .changedScope); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testConfirmedWorkSettledCommitWithScopeDriftDoesNotLookUncertain() throws {
        try withAsyncStartup(.executing) { h, driver in
            h.failScopeAfterPhase = .workSettled; _ = await Self.failed(h, driver)
            XCTAssertEqual(h.writes, [.workSettled, .needsOwnerRecovery]); XCTAssertEqual(h.registrations, 0)
            XCTAssertEqual(try h.frame().window?.phase, .needsOwnerRecovery)
        }
    }
    func testConfirmedCommitWithRealFloorComparisonDriftRecordsRecoveryExactlyOnce() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let before = try h.frame(), original = try XCTUnwrap(before.window)
            let floor = try RuntimeMaintenanceStartupFloor(frame: before, release: h.f.candidate)
            h.driftFloorAfterPhase = .restoring
            let error = await Self.failed(h, driver)
            XCTAssertEqual(error as? RuntimePreparationError, .changedScope)
            let drifted = try h.frame()
            XCTAssertThrowsError(try floor.requireCurrent(.init(source: drifted.source, window: original), window: original, release: h.f.candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            XCTAssertEqual(h.writes, [.restoring, .needsOwnerRecovery]); XCTAssertEqual(drifted.window?.failure, .changedScope)
            XCTAssertEqual(h.registrations, 0); XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
        }
    }
    func testDecisionProbeRetriesWithNewClientsAndNoIntermediateWrites() throws {
        try withAsyncStartup(.draining) { h, _ in
            let startup = try h.open(), drivers = Mutex<[StartupDriver]>([])
            let row = try await startup.runOwned(makeDriver: {
                let number = drivers.withLock { $0.count }
                let driver = StartupDriver(epoch: Data(repeating: 81, count: 16), barrier: h.barrier, refuseProbe: number < 2)
                if number < 3 {
                    driver.onProbe.withLock { $0 = {
                        XCTAssertTrue(h.writes.isEmpty); XCTAssertEqual(h.registrations, 0)
                    } }
                }
                drivers.withLock { $0.append(driver) }; return driver
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, until: .now.advanced(by: restorationTestForwardDeadline))
            let all = drivers.withLock { $0 }
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(all.count, 4)
            XCTAssertTrue(all.prefix(3).allSatisfy { $0.closed.withLock { $0 } && $0.metrics.actions.withLock { $0 }.isEmpty })
            XCTAssertEqual(all.map { $0.metrics.probes.withLock { $0 } }, [1, 1, 1, 1])
            XCTAssertEqual(h.writes, [.needsOwnerRecovery, .restoring, .reopenPending, .restored])
            XCTAssertEqual(h.registrations, 1)
        }
    }
    func testRegisteredProcessAppearsAfterSeveralInspectionsWithoutASecondRegistration() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let waiting = Mutex(0)
            h.inspectOverride = {
                guard h.registrations > 0 else { return .absent }
                let n = waiting.withLock { $0 += 1; return $0 }
                if n < 3 {
                    XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 0)
                    return n == 1 ? .absent : .matching(nil)
                }
                return .matching(h.witness.processID)
            }
            let row = try await Self.complete(h, driver)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(h.registrations, 1)
            XCTAssertGreaterThanOrEqual(waiting.withLock { $0 }, 3)
            XCTAssertEqual(h.writes, [.restoring, .reopenPending, .restored])
            XCTAssertEqual(driver.metrics.hellos.withLock { $0 }, 1)
        }
    }
    func testAutomaticCallbacksWithoutPhasesStayOnTheClientActor() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let clientCell = Mutex<AuthorityMaintenanceXPCClient?>(nil), seen = Mutex<Set<String>>([])
            let isolated: @Sendable (String) -> Void = { label in
                guard let client = clientCell.withLock({ $0 }) else { return XCTFail("Missing actual client") }
                client.assertIsolated()
                _ = seen.withLock { $0.insert(label) }
            }
            h.beforeWrite = { row in
                if row.phase == .reopenPending { isolated("pending") }
                if row.phase == .restored { isolated("restored") }
            }
            defer { h.beforeWrite = nil }
            let control = try AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl { event in
                if event.boundary == .drainRelease { isolated("releaseDrain") }
            }
            let row = try await h.open().runOwned(makeDriver: { driver }, capturePeer: {
                isolated("capturePeer"); return h.witness
            }, requirePeerLive: { _ in isolated("requirePeerLive") }, beforeHealthyOpen: { client in
                clientCell.withLock { $0 = client }
            }, afterProbe: { isolated("afterProbe") }, ownedPhaseControl: control,
                until: .now.advanced(by: restorationTestForwardDeadline))
            XCTAssertEqual(row.phase, .restored)
            XCTAssertEqual(seen.withLock { $0 }, Set(["afterProbe", "capturePeer", "requirePeerLive", "pending", "restored", "releaseDrain"]))
        }
    }

    func testAutomaticPhaseKeepsActorIsolationAndReopenPrecedesQueuedReentry() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let events = Mutex<[String]>([]), armed = Mutex(true)
            let closing = Mutex<Task<Void, Never>?>(nil)
            driver.onExchange.withLock { hook in
                hook = { action in if action == .reopen { events.withLock { $0.append("reopen") } } }
            }
            defer { h.verifyOverride = nil; driver.onExchange.withLock { $0 = nil } }
            _ = try? await Self.complete(h, driver, beforeOpen: { client in
                h.verifyOverride = {
                    let first = armed.withLock { value in let first = value; value = false; return first }
                    guard first else { return }
                    client.preconditionIsolated()
                    events.withLock { $0.append("phase") }
                    let task = Task { @Sendable [client] in
                        await client.close()
                        events.withLock { $0.append("closed") }
                    }
                    closing.withLock { $0 = task }
                }
            })
            let task = try XCTUnwrap(closing.withLock { $0 })
            await task.value
            XCTAssertEqual(events.withLock { $0 }, ["phase", "reopen", "closed"])
            XCTAssertEqual(driver.metrics.actions.withLock { $0.filter { $0 == .reopen }.count }, 1)
            XCTAssertEqual(h.writes.filter { $0 == .reopenPending }.count, 1)
        }
    }

    func testNativeConstructorRefusesTheOrdinaryCallerBeforeProtectedAccess() throws {
        guard getuid() > 0, geteuid() == getuid() else { return XCTFail("This test requires the ordinary owner") }
        XCTAssertThrowsError(try RuntimeMaintenanceStartupRecovery.open(accountID: Data(repeating: 61, count: 16))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    private static func automaticPhaseEvent(_ gate: AutomaticSupervisorPhaseGate,
        until deadline: ContinuousClock.Instant) async throws -> AutomaticSupervisorPhaseGate.Control.Event {
        while gate.event.withLock({ $0 }) == nil {
            if let result = gate.workerResult.withLock({ $0 }) {
                let outcome: String
                switch result {
                case .success: outcome = "returned without reaching the selected phase"
                case .failure(let error): outcome = "failed before the selected phase: \(error)"
                }
                throw AutomaticSupervisorTestError.workerReturnedBeforePhase(outcome)
            }
            guard ContinuousClock.now < deadline else { throw AutomaticSupervisorTestError.phaseWaitExpired }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
        return try XCTUnwrap(gate.event.withLock { $0 })
    }
    private func supervisorReentry(_ boundary: AutomaticSupervisorPhaseGate.Control.Boundary,
        rpc: AutomaticSupervisorPhaseGate.Control.RPC? = nil, close: Bool, secondRestore: Bool = false) throws {
        try withAsyncStartup(.stopped) { h, driver in
            let deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
            let gate = AutomaticSupervisorPhaseGate(boundary, rpc: rpc, until: deadline), cancellation = SetupAuditUpgradeCancellation()
            defer { gate.open() }
            defer { XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired") }
            let phases = try SetupRetainedInvocationReservation.RestorationPhases.owned(executor: SetupAuditUpgradeWorkExecutor(),
                deadline: deadline, cancellation: cancellation)
            let work = try RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork(phases: phases,
                cancellation: cancellation, control: gate.control())
            let startup = try h.open(supervisorWork: work)
            let worker = Task { @Sendable [h, driver, startup, gate] in
                do {
                    let row = try await Self.complete(h, driver, startup: startup, until: deadline)
                    gate.workerResult.withLock { $0 = .success(row) }; return row
                } catch {
                    gate.workerResult.withLock { $0 = .failure(error) }; throw error
                }
            }
            let event = try await Self.automaticPhaseEvent(gate, until: deadline)
            let before = driver.metrics.actions.withLock { $0 }
            var reentry: Task<Void, Never>?
            if close { await event.client.close() }
            else {
                let operation: @Sendable () async -> Void = {
                    defer { gate.reentryReturned.withLock { $0 = true } }
                    do {
                        if secondRestore {
                            let context = try XCTUnwrap(event.restoration)
                            _ = try await event.client.restoreStartupHealthyOwned(context.proof, owner: context.owner,
                                capturePeer: { h.witness }, requirePeerLive: { _ in }, until: deadline,
                                persist: { try h.persistForRecovery($0, previous: $1) })
                        } else {
                            _ = try await event.client.observeIncarnationOwned(until: deadline)
                        }
                    } catch { }
                }
                let canReachRPC = boundary == .afterProbe || boundary == .openRequest || boundary == .gateAfter && !secondRestore
                    || ((boundary == .beforeRPCVerify || boundary == .afterRPCVerify) && (rpc == .reopen || rpc == .gate)) && !secondRestore
                if canReachRPC {
                    reentry = Task { @Sendable [operation] in await operation() }
                    while !gate.reentryDispatched.withLock({ $0 }) && !gate.reentryReturned.withLock({ $0 }) {
                        guard ContinuousClock.now < deadline else { throw AutomaticSupervisorTestError.reentryWaitExpired }
                        try await ContinuousClock().sleep(for: .milliseconds(1))
                    }
                } else { await operation() }
            }
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, before)
            gate.open(); await reentry?.value
            let outcome = await worker.result
            let row = try XCTUnwrap(h.frame().window)
            switch outcome {
            case .success(let confirmed): XCTAssertEqual(confirmed.phase, .restored); XCTAssertEqual(row, confirmed)
            case .failure: XCTAssertEqual(row.phase, .needsOwnerRecovery)
            }
            XCTAssertLessThanOrEqual(h.writes.filter { $0 == .reopenPending }.count, 1)
            XCTAssertLessThanOrEqual(h.writes.filter { $0 == .restored }.count, 1)
            XCTAssertEqual(h.writes.filter { $0 == .needsOwnerRecovery }.count, row.phase == .needsOwnerRecovery ? 1 : 0)
            XCTAssertFalse(driver.metrics.actions.withLock { $0 }.contains { $0 == .arm || $0 == .cancel })
            XCTAssertNoThrow(try cancellation.check())
        }
    }
    private enum SupervisorReconnectReentry: Sendable { case close, observe, reconnect }
    private func supervisorReconnectReentry(_ boundary: AutomaticSupervisorPhaseGate.Control.Boundary,
        rpc: AutomaticSupervisorPhaseGate.Control.RPC? = nil, action: SupervisorReconnectReentry) throws {
        try withAsyncStartup(.draining, epoch: 71) { h, driver in
            let deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
            let gate = AutomaticSupervisorPhaseGate(boundary, rpc: rpc, until: deadline), cancellation = SetupAuditUpgradeCancellation()
            defer { gate.open() }
            defer { XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired") }
            let phases = try SetupRetainedInvocationReservation.RestorationPhases.owned(executor: SetupAuditUpgradeWorkExecutor(),
                deadline: deadline, cancellation: cancellation)
            let work = try RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork(phases: phases,
                cancellation: cancellation, control: gate.control())
            let startup = try h.open(supervisorWork: work)
            let worker = Task { @Sendable [h, driver, startup, gate] in
                do {
                    let row = try await Self.complete(h, driver, startup: startup, until: deadline)
                    gate.workerResult.withLock { $0 = .success(row) }; return row
                } catch {
                    gate.workerResult.withLock { $0 = .failure(error) }; throw error
                }
            }
            let event = try await Self.automaticPhaseEvent(gate, until: deadline)
            let before = driver.metrics.actions.withLock { $0 }
            switch action {
            case .close: await event.client.close()
            case .observe: _ = try? await event.client.observeIncarnationOwned(until: deadline)
            case .reconnect:
                let context = try XCTUnwrap(event.reconnect)
                _ = try? await event.client.cancelAndReopenStartupOwned(context.proof, custody: context.custody,
                    until: deadline)
            }
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, before)
            gate.open(); let outcome = await worker.result
            let row = try XCTUnwrap(h.frame().window)
            switch outcome {
            case .success(let confirmed): XCTAssertEqual(confirmed, row); XCTAssertEqual(row.phase, .restored)
            case .failure: XCTAssertEqual(row.phase, .needsOwnerRecovery)
            }
            XCTAssertEqual(row.operation, .notStarted)
            XCTAssertLessThanOrEqual(h.writes.filter { $0 == .reopenPending }.count, 1)
            XCTAssertLessThanOrEqual(h.writes.filter { $0 == .restored }.count, 1)
            XCTAssertLessThanOrEqual(driver.metrics.actions.withLock { $0.filter { $0 == .reopen }.count }, 1)
            XCTAssertFalse(driver.metrics.actions.withLock { $0 }.contains { $0 == .arm || $0 == .cancel })
            XCTAssertNoThrow(try cancellation.check())
        }
    }
    private func nativeDeadlineAfterWrite(_ phase: RuntimeMaintenanceWindowRecord.Phase) throws {
        try withAsyncStartup(.stopped) { h, driver in
            let expired = Mutex(false), cancellation = SetupAuditUpgradeCancellation(), deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
            defer { XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired") }
            let base = try SetupRetainedInvocationReservation.RestorationPhases.owned(executor: SetupAuditUpgradeWorkExecutor(),
                deadline: deadline, cancellation: cancellation)
            let trigger = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: phase == .restoring ? .beforePending : phase == .reopenPending ? .beforeRestored : .afterRestored,
                expired: { expired.withLock { $0 } })
            let phases = try base.forOwnedAttempt(until: deadline, expiration: trigger)
            let work = try RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork(phases: phases, cancellation: cancellation)
            let startup = try h.open(supervisorWork: work)
            h.afterWrite = { row in if row.phase == phase { expired.withLock { $0 = true } } }
            let result: Result<RuntimeMaintenanceWindowRecord, any Error>
            do { result = .success(try await Self.complete(h, driver, startup: startup, until: deadline)) }
            catch { result = .failure(error) }
            let row = try XCTUnwrap(h.frame().window)
            XCTAssertTrue(expired.withLock { $0 }); XCTAssertNoThrow(try cancellation.check())
            if phase == .restored {
                guard case .success(let confirmed) = result else { return XCTFail("Confirmed restoration was lost") }
                XCTAssertEqual(confirmed, row); XCTAssertEqual(row.phase, .restored)
                XCTAssertFalse(h.writes.contains(.needsOwnerRecovery))
            } else {
                guard case .failure = result else { return XCTFail("Expired native work reported success") }
                XCTAssertEqual(row.phase, .needsOwnerRecovery)
                XCTAssertEqual(row.failure, phase == .restoring ? .healthFailed : .admissionUnconfirmed)
                XCTAssertEqual(h.writes.filter { $0 == .needsOwnerRecovery }.count, 1)
            }
        }
    }
    func testSupervisorSameEpochReconnectReconnectValidationClose() throws {
        try supervisorReconnectReentry(.reconnectValidation, action: .close)
    }
    func testSupervisorSameEpochReconnectReconnectValidationObserve() throws {
        try supervisorReconnectReentry(.reconnectValidation, action: .observe)
    }
    func testSupervisorSameEpochReconnectReconnectValidationReconnect() throws {
        try supervisorReconnectReentry(.reconnectValidation, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectReconnectPendingClose() throws {
        try supervisorReconnectReentry(.reconnectPending, action: .close)
    }
    func testSupervisorSameEpochReconnectReconnectPendingObserve() throws {
        try supervisorReconnectReentry(.reconnectPending, action: .observe)
    }
    func testSupervisorSameEpochReconnectReconnectPendingReconnect() throws {
        try supervisorReconnectReentry(.reconnectPending, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectReconnectReleaseClose() throws {
        try supervisorReconnectReentry(.reconnectRelease, action: .close)
    }
    func testSupervisorSameEpochReconnectReconnectReleaseObserve() throws {
        try supervisorReconnectReentry(.reconnectRelease, action: .observe)
    }
    func testSupervisorSameEpochReconnectReconnectReleaseReconnect() throws {
        try supervisorReconnectReentry(.reconnectRelease, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectPersistRestoredClose() throws {
        try supervisorReconnectReentry(.persistRestored, action: .close)
    }
    func testSupervisorSameEpochReconnectPersistRestoredObserve() throws {
        try supervisorReconnectReentry(.persistRestored, action: .observe)
    }
    func testSupervisorSameEpochReconnectPersistRestoredReconnect() throws {
        try supervisorReconnectReentry(.persistRestored, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyReopenClose() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .reopen, action: .close)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyReopenObserve() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .reopen, action: .observe)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyReopenReconnect() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .reopen, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyReopenClose() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .reopen, action: .close)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyReopenObserve() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .reopen, action: .observe)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyReopenReconnect() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .reopen, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyGateClose() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .gate, action: .close)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyGateObserve() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .gate, action: .observe)
    }
    func testSupervisorSameEpochReconnectBeforeRPCVerifyGateReconnect() throws {
        try supervisorReconnectReentry(.beforeRPCVerify, rpc: .gate, action: .reconnect)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyGateClose() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .gate, action: .close)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyGateObserve() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .gate, action: .observe)
    }
    func testSupervisorSameEpochReconnectAfterRPCVerifyGateReconnect() throws {
        try supervisorReconnectReentry(.afterRPCVerify, rpc: .gate, action: .reconnect)
    }
    func testSupervisorDeadlineAfterRestoringWritesTheNormalHealthFallback() throws {
        try nativeDeadlineAfterWrite(.restoring)
    }
    func testSupervisorDeadlineAfterPendingWritesTheAdmissionFallback() throws {
        try nativeDeadlineAfterWrite(.reopenPending)
    }
    func testSupervisorDeadlineAfterConfirmedRestoredKeepsTheConfirmedResult() throws {
        try nativeDeadlineAfterWrite(.restored)
    }
    func testSupervisorTerminalCaptureAcceptsRestoredMetadataFromAnOlderRelease() throws {
        try withAsyncStartup(.stopped) { h, driver in
            let current = try await Self.complete(h, driver), scope = current.scope
            let oldScope = try RuntimeMaintenanceWindowRecord.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: scope.authority, target: scope.target, releaseDigest: Data(repeating: 0xa1, count: 32),
                candidateDigest: Data(repeating: 0xa2, count: 32), authorityPolicyDigest: scope.authorityPolicyDigest,
                operationDigest: scope.operationDigest, restorationDigest: scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            let old = try RuntimeMaintenanceWindowRecord(id: current.id, revision: current.revision, purpose: current.purpose,
                scope: oldScope, phase: .restored, operation: current.operation, service: current.service,
                gate: current.gate, shutdownBinding: current.shutdownBinding)
            let frame = RuntimeMaintenanceStartupFrame(source: try h.frame().source, window: old)
            XCTAssertThrowsError(try RuntimeMaintenanceStartupFloor(frame: frame, release: h.f.candidate))
            let writes = h.writes, actions = driver.metrics.actions.withLock { $0 }
            let reported = try RuntimeMaintenanceStartupRecovery.terminalForSupervisorOwned(frame: frame, accountID: scope.authority.accountID)
            let request = try SetupMaintenanceRecoverySupervisor.Request(accountID: scope.authority.accountID,
                windowID: old.id, revision: Data(repeating: 0x29, count: 16))
            XCTAssertNotEqual(request.revision, old.revision)
            XCTAssertEqual(SetupMaintenanceRecoveryNativeAdapter.terminalObservation(reported, request: request), .phase(.restored))
            XCTAssertEqual(reported, old); XCTAssertEqual(h.writes, writes)
            XCTAssertEqual(driver.metrics.actions.withLock { $0 }, actions)
        }
    }
    func testSupervisorTerminalCaptureRejectsAForeignAccount() throws {
        try withAsyncStartup(.stopped) { h, driver in
            _ = try await Self.complete(h, driver)
            let frame = try h.frame()
            XCTAssertThrowsError(try RuntimeMaintenanceStartupRecovery.terminalForSupervisorOwned(frame: frame,
                accountID: Data(repeating: 0xef, count: 16))) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        }
    }
    func testSupervisorCloseDuringAfterProbeFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.afterProbe, close: true)
    }
    func testSupervisorSecondOperationDuringAfterProbeFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.afterProbe, close: false)
    }
    func testSupervisorCloseDuringOpenRequestFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.openRequest, close: true)
    }
    func testSupervisorSecondOperationDuringOpenRequestFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.openRequest, close: false)
    }
    func testSupervisorCloseDuringVerifyBeforeOpenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.verifyBeforeOpen, close: true)
    }
    func testSupervisorSecondOperationDuringVerifyBeforeOpenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.verifyBeforeOpen, close: false)
    }
    func testSupervisorCloseDuringHealthyBindingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.healthyBinding, close: true)
    }
    func testSupervisorSecondOperationDuringHealthyBindingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.healthyBinding, close: false)
    }
    func testSupervisorCloseDuringValidateBeforePendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.validateBeforePending, close: true)
    }
    func testSupervisorSecondOperationDuringValidateBeforePendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.validateBeforePending, close: false)
    }
    func testSupervisorCloseDuringCapturePeerFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.capturePeer, close: true)
    }
    func testSupervisorSecondOperationDuringCapturePeerFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.capturePeer, close: false)
    }
    func testSupervisorCloseDuringPreparePendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.preparePending, close: true)
    }
    func testSupervisorSecondOperationDuringPreparePendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.preparePending, close: false)
    }
    func testSupervisorCloseDuringPersistPendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.persistPending, close: true)
    }
    func testSupervisorSecondOperationDuringPersistPendingFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.persistPending, close: false)
    }
    func testSupervisorCloseDuringReleaseDrainFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.releaseDrain, close: true)
    }
    func testSupervisorSecondOperationDuringReleaseDrainFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.releaseDrain, close: false)
    }
    func testSupervisorCloseDuringBeforeReopenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.beforeReopen, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeReopenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.beforeReopen, close: false)
    }
    func testSupervisorCloseDuringAfterReopenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.afterReopen, close: true)
    }
    func testSupervisorSecondOperationDuringAfterReopenFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.afterReopen, close: false)
    }
    func testSupervisorCloseDuringGateBeforeFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.gateBefore, close: true)
    }
    func testSupervisorSecondOperationDuringGateBeforeFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.gateBefore, close: false)
    }
    func testSupervisorCloseDuringGateAfterFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.gateAfter, close: true)
    }
    func testSupervisorSecondOperationDuringGateAfterFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.gateAfter, close: false)
    }
    func testSupervisorCloseDuringPeerBeforeRestoredFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.peerBeforeRestored, close: true)
    }
    func testSupervisorSecondOperationDuringPeerBeforeRestoredFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.peerBeforeRestored, close: false)
    }
    func testSupervisorCloseDuringPersistRestoredFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.persistRestored, close: true)
    }
    func testSupervisorSecondOperationDuringPersistRestoredFailsClosedWithoutDuplicateWrites() throws {
        try supervisorReentry(.persistRestored, close: false)
    }
    func testSupervisorCloseDuringBeforeRPCVerifyHelloFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .hello, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeRPCVerifyHelloFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .hello, close: false)
    }
    func testSupervisorCloseDuringBeforeRPCVerifyIncarnationFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .incarnation, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeRPCVerifyIncarnationFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .incarnation, close: false)
    }
    func testSupervisorCloseDuringBeforeRPCVerifyOpenFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .open, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeRPCVerifyOpenFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .open, close: false)
    }
    func testSupervisorCloseDuringBeforeRPCVerifyReopenFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .reopen, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeRPCVerifyReopenFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .reopen, close: false)
    }
    func testSupervisorCloseDuringBeforeRPCVerifyGateFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .gate, close: true)
    }
    func testSupervisorSecondOperationDuringBeforeRPCVerifyGateFailsClosed() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .gate, close: false)
    }
    func testSupervisorCloseDuringAfterRPCVerifyHelloFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .hello, close: true)
    }
    func testSupervisorSecondOperationDuringAfterRPCVerifyHelloFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .hello, close: false)
    }
    func testSupervisorCloseDuringAfterRPCVerifyIncarnationFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .incarnation, close: true)
    }
    func testSupervisorSecondOperationDuringAfterRPCVerifyIncarnationFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .incarnation, close: false)
    }
    func testSupervisorCloseDuringAfterRPCVerifyOpenFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .open, close: true)
    }
    func testSupervisorSecondOperationDuringAfterRPCVerifyOpenFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .open, close: false)
    }
    func testSupervisorCloseDuringAfterRPCVerifyReopenFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .reopen, close: true)
    }
    func testSupervisorSecondOperationDuringAfterRPCVerifyReopenFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .reopen, close: false)
    }
    func testSupervisorCloseDuringAfterRPCVerifyGateFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .gate, close: true)
    }
    func testSupervisorSecondOperationDuringAfterRPCVerifyGateFailsClosed() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .gate, close: false)
    }
    func testSupervisorSecondRestoreDuringAfterProbeCannotDuplicateWrites() throws {
        try supervisorReentry(.afterProbe, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringOpenRequestCannotDuplicateWrites() throws {
        try supervisorReentry(.openRequest, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringVerifyBeforeOpenCannotDuplicateWrites() throws {
        try supervisorReentry(.verifyBeforeOpen, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringHealthyBindingCannotDuplicateWrites() throws {
        try supervisorReentry(.healthyBinding, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringValidateBeforePendingCannotDuplicateWrites() throws {
        try supervisorReentry(.validateBeforePending, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringCapturePeerCannotDuplicateWrites() throws {
        try supervisorReentry(.capturePeer, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringPreparePendingCannotDuplicateWrites() throws {
        try supervisorReentry(.preparePending, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringPersistPendingCannotDuplicateWrites() throws {
        try supervisorReentry(.persistPending, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringReleaseDrainCannotDuplicateWrites() throws {
        try supervisorReentry(.releaseDrain, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringBeforeReopenCannotDuplicateWrites() throws {
        try supervisorReentry(.beforeReopen, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringAfterReopenCannotDuplicateWrites() throws {
        try supervisorReentry(.afterReopen, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringGateBeforeCannotDuplicateWrites() throws {
        try supervisorReentry(.gateBefore, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringGateAfterCannotDuplicateWrites() throws {
        try supervisorReentry(.gateAfter, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringPeerBeforeRestoredCannotDuplicateWrites() throws {
        try supervisorReentry(.peerBeforeRestored, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringPersistRestoredCannotDuplicateWrites() throws {
        try supervisorReentry(.persistRestored, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringBeforeRPCVerifyOpenCannotDuplicateWrites() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .open, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringBeforeRPCVerifyReopenCannotDuplicateWrites() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .reopen, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringBeforeRPCVerifyGateCannotDuplicateWrites() throws {
        try supervisorReentry(.beforeRPCVerify, rpc: .gate, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringAfterRPCVerifyOpenCannotDuplicateWrites() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .open, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringAfterRPCVerifyReopenCannotDuplicateWrites() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .reopen, close: false, secondRestore: true)
    }
    func testSupervisorSecondRestoreDuringAfterRPCVerifyGateCannotDuplicateWrites() throws {
        try supervisorReentry(.afterRPCVerify, rpc: .gate, close: false, secondRestore: true)
    }

}

/// Owned transports and real writer receipts exercise the in-process origin.
/// These tests do not qualify installed Root identity or launchd behaviour.
private final class ExplicitStartupRights: Sendable {
    let value = Mutex(true)
}
private final class ExplicitDeadlineTrigger: Sendable {
    private let value = Mutex(false)
    func expire() { value.withLock { $0 = true } }
    var expired: Bool { value.withLock { $0 } }
}
private final class ExplicitStartupFixture: @unchecked Sendable {
    typealias Row = RuntimeMaintenanceWindowRecord
    typealias Joined = SetupRetainedOrphanClaim.Joined
    let h: StartupHarness
    let activity: ReleaseActivityFixture
    let retained: SetupRetainedOrphanClaimTests.Frame
    let processLease: SetupProcessLease
    let driver: StartupDriver
    let rightsLive = ExplicitStartupRights()
    var invocation: SetupRetainedInvocation?
    var claim: SetupRetainedOrphanClaim?
    init(_ f: RuntimeMaintenanceWriterFixture, epoch: UInt8 = 81, reserveInProcess: Bool = true) throws {
        h = try StartupHarness(f); activity = try ReleaseActivityFixture()
        let source = try f.machine().stableRuntimeSource(candidate: f.candidate)
        let target = try XCTUnwrap(source.preparations.first { $0.accountID == f.target.accountID })
        retained = try .init(machine: f.machine(), candidate: f.candidate,
            targetOwner: .init(uid: target.ownerUID, primaryGroupID: getgid(), directoryID: target.directoryID), activity: activity)
        processLease = try .openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
        driver = .init(epoch: Data(repeating: epoch, count: 16), barrier: h.barrier)
        if reserveInProcess {
            invocation = try retained.invocation()
            try retained.window(XCTUnwrap(invocation), id: h.initial.id, revision: h.initial.revision)
        }
    }
    func seed(_ origin: Row.Phase, failure: Row.Failure = .cleanupPending,
        retainReceipt: Bool = false) throws {
        try h.seed(origin)
        if origin != .needsOwnerRecovery {
            let previous = try XCTUnwrap(h.frame().window)
            _ = try h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                service: previous.service, failure: failure), previous: previous)
        }
        if retainReceipt { try XCTUnwrap(invocation).retainMaintenanceRecoveryTransition(XCTUnwrap(h.lastTransition)) }
    }
    func join() async throws -> Joined {
        if invocation != nil { try retained.lose(&invocation) }
        let live = rightsLive
        let authorization = try retained.authorize(verify: {
            guard live.value.withLock({ $0 }) else { throw StartupTestError.expected }
        })
        let claim = try retained.claim(authorization); self.claim = claim
        return try await claim.join()
    }
    func freshJoined() async throws -> Joined {
        claim?.abandon(); rightsLive.value.withLock { $0 = true }
        return try await join()
    }
    func resources() throws -> (ReleaseDestinationLease, UpdateOrdinaryAdmissionLease) {
        let f = h.f
        let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
        let machine = try f.machine().stableRuntimeSource(candidate: f.candidate).actual.admission.machine
        let directory = try ReleaseDestinationLease(anchor: anchor, relativeDirectory: "machine", owner: getuid())
        let activity = try ReleaseActivityBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()), owner: getuid())
        let gate = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()), owner: getuid(), expected: machine)
        let admission = try UpdateOrdinaryAdmissionLease(activity: activity, admission: gate,
            directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()), expected: machine)
        return (directory, admission)
    }
    func restore(_ joined: Joined, until deadline: ContinuousClock.Instant = .now.advanced(by: restorationTestForwardDeadline),
        frame: RuntimeMaintenanceStartupFrame? = nil,
        ownedDeadline: SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl? = nil,
        phaseControl: AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl? = nil,
        retryDriverFactory: (@Sendable () -> StartupDriver)? = nil,
        onClientAttempt: (@Sendable (Int, ContinuousClock.Instant) -> Void)? = nil) async throws -> Row {
        let (directory, admission) = try resources()
        defer { admission.close(); directory.close() }
        let attempts = Mutex(0), h = self.h, driver = self.driver
        // A slow runner must never turn an expired forward deadline into the refusal or row that a test expects.
        // A test that passes an already expired deadline tests that refusal on purpose, so the check skips it.
        let deadlineWasLive = ContinuousClock.now < deadline
        defer { if deadlineWasLive { XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired") } }
        return try await RuntimeMaintenanceStartupRecovery.restoreExplicitOwned(joined: joined, processLease: processLease,
            frame: frame ?? h.frame(), release: h.f.candidate, admission: admission, directory: directory,
            accountBarrier: h.barrier, read: { try h.frame() }, persist: { try h.persistForRecovery($0, previous: $1) },
            verify: { try h.verifyCurrent() }, inspect: { _ in try h.inspectOverride?() ?? h.inspected },
            observe: { _, _, pid in
                h.observations += 1
                guard !h.rejectCode, pid == h.witness.processID else { throw StartupTestError.expected }
                h.afterObservation?(); return h.witness
            }, register: {
                h.beforeRegistration?(); h.registrations += 1; h.inspected = .matching(h.witness.processID)
            }, makeDriver: {
                let attempt = attempts.withLock { $0 += 1; return $0 }
                onClientAttempt?(attempt, .now)
                return attempt == 1 ? driver : retryDriverFactory?() ?? driver.fresh()
            }, capturePeer: { h.witness }, requirePeerLive: {
                guard try !$0.hasExited() else { throw StartupTestError.expected }
            }, ownedDeadline: ownedDeadline, ownedPhaseControl: phaseControl, until: deadline)
    }
    deinit { claim?.abandon(); processLease.close() }
}

/// Forward deadline for restoration tests that must reach `restored`. A restore takes about 14 s on the review Mac
/// and up to about 30 s on a busy CI runner, and a test with client retries runs it more than once. The production deadline is 120 s. Tests that end the deadline on purpose use
/// `OwnedDeadlineControl`, which only shortens this bound.
let restorationTestForwardDeadline: Duration = .seconds(90)

private final class ExplicitActorPhaseGate: @unchecked Sendable {
    typealias Control = AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl
    let stream: AsyncStream<Control.Event>
    private let continuation: AsyncStream<Control.Event>.Continuation
    private let released = DispatchSemaphore(value: 0)
    private let used = Mutex(false)
    private let deadline: ContinuousClock.Instant
    let visited = Mutex<[Control.Boundary]>([])
    init(until deadline: ContinuousClock.Instant) {
        self.deadline = deadline
        let pair = AsyncStream<Control.Event>.makeStream()
        stream = pair.stream; continuation = pair.continuation
    }
    func stop(_ event: Control.Event) throws {
        let first = used.withLock { used in guard !used else { return false }; used = true; return true }
        guard first else { return }
        visited.withLock { $0.append(event.boundary) }
        continuation.yield(event)
        let remaining = ContinuousClock.now.duration(to: deadline).components
        let seconds = max(0, Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18)
        guard released.wait(timeout: .now() + seconds) == .success else { throw StartupTestError.expected }
    }
    func open() { released.signal(); continuation.finish() }
    deinit { open() }
}

final class RuntimeMaintenanceExplicitRestorationTests: XCTestCase {
    typealias Row = RuntimeMaintenanceWindowRecord
    private func withFixture(epoch: UInt8 = 81,
        _ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let fixture = try ExplicitStartupFixture(f, epoch: epoch)
            defer {
                fixture.h.beforeWrite = nil; fixture.h.afterWrite = nil; fixture.h.verifyOverride = nil
                fixture.h.afterObservation = nil; fixture.h.inspectOverride = nil
                fixture.driver.onExchange.withLock { $0 = nil }
            }
            let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, Error>?>(nil)
            Task {
                do { try await body(fixture); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + 50) == .success else { return XCTFail("Explicit restoration did not return") }
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    private static func refuses(_ body: () async throws -> Row) async {
        do { _ = try await body(); XCTFail("Expected explicit refusal") } catch {}
    }
    private static func automatic(_ f: ExplicitStartupFixture, epoch: UInt8 = 81) async throws -> Row {
        let h = f.h, driver = StartupDriver(epoch: Data(repeating: epoch, count: 16), barrier: h.barrier)
        let recovery = try h.open()
        let deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
        do {
            return try await recovery.runOwned(makeDriver: { driver.fresh() }, capturePeer: { h.witness }, requirePeerLive: { _ in },
                until: deadline)
        } catch {
            XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired")
            throw error
        }
    }
    private enum PhaseReentry: Int, Sendable { case close, observe, secondRestore, secondReconnect }
    private enum PhaseWaitError: Error { case boundaryDeadline }
    private struct PhaseWaitFailure: Error { let wait: any Error, worker: any Error }
    private static func phaseEvent(_ gate: ExplicitActorPhaseGate, until deadline: ContinuousClock.Instant)
        async throws -> ExplicitActorPhaseGate.Control.Event {
        try await withThrowingTaskGroup(of: ExplicitActorPhaseGate.Control.Event.self) { group in
            group.addTask { for await event in gate.stream { return event }; throw StartupTestError.expected }
            group.addTask { try await ContinuousClock().sleep(until: deadline); throw PhaseWaitError.boundaryDeadline }
            defer { group.cancelAll() }
            let event = try await group.next()
            return try XCTUnwrap(event)
        }
    }
    private func phaseReentry(_ boundary: ExplicitActorPhaseGate.Control.Boundary, _ action: PhaseReentry) throws {
        let reconnect = action == .secondReconnect
        try withFixture(epoch: reconnect ? 71 : 81) { f in
            try f.seed(reconnect ? .needsOwnerRecovery : .stopped, retainReceipt: reconnect)
            let joined = try await f.join(), deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
            let gate = ExplicitActorPhaseGate(until: deadline)
            let control = try ExplicitActorPhaseGate.Control { event in
                if event.boundary == boundary { try gate.stop(event) }
            }
            let fresh = Mutex<[StartupDriver]>([]), attempts = Mutex<[(Int, ContinuousClock.Instant)]>([])
            let worker = Task {
                try await f.restore(joined, until: deadline, phaseControl: control, retryDriverFactory: {
                    let driver = StartupDriver(epoch: Data(repeating: 82, count: 16), barrier: f.h.barrier)
                    fresh.withLock { $0.append(driver) }; return driver
                }, onClientAttempt: { number, started in attempts.withLock { $0.append((number, started)) } })
            }
            let event: ExplicitActorPhaseGate.Control.Event
            do { event = try await Self.phaseEvent(gate, until: deadline) }
            catch {
                gate.open()
                if case .failure(let workerError) = await worker.result { throw PhaseWaitFailure(wait: error, worker: workerError) }
                throw error
            }
            XCTAssertEqual(event.boundary, boundary)
            XCTAssertEqual(gate.visited.withLock { $0 }, [boundary])
            XCTAssertLessThan(ContinuousClock.now, deadline)
            switch event.scope {
            case .healthy: XCTAssertFalse(reconnect)
            case .reconnect: XCTAssertTrue(reconnect)
            }
            let before = f.driver.metrics.actions.withLock { $0 }
            var refused = action == .close
            do {
                switch action {
                case .close: await event.client.close()
                case .observe: _ = try await event.client.observeIncarnationOwned(until: .now.advanced(by: .seconds(1)))
                case .secondRestore:
                    guard case .healthy(let owner) = event.scope else { throw StartupTestError.expected }
                    _ = try await event.client.restoreStartupHealthyOwned(event.proof, owner: owner,
                        capturePeer: { f.h.witness }, requirePeerLive: { _ in }, until: .now.advanced(by: .seconds(1)),
                        persist: { try f.h.persistForRecovery($0, previous: $1) })
                case .secondReconnect:
                    guard case .reconnect(let prepared) = event.scope else { throw StartupTestError.expected }
                    _ = try await event.client.cancelAndReopenExplicitOwned(event.proof, prepared: prepared,
                        until: .now.advanced(by: .seconds(1)))
                }
            } catch {
                refused = true
                XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery)
            }
            XCTAssertTrue(refused)
            XCTAssertTrue(f.driver.closed.withLock { $0 })
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, before)
            gate.open()
            let result = await worker.result
            // This driver belongs only to the refused connection. A later attempt has a distinct driver and metrics.
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, before)
            XCTAssertTrue(f.driver.closed.withLock { $0 })
            let starts = attempts.withLock { $0 }, later = fresh.withLock { $0 }
            XCTAssertFalse(starts.isEmpty)
            XCTAssertTrue(starts.allSatisfy { $0.1 < deadline })
            XCTAssertLessThanOrEqual(starts.count, 2)
            XCTAssertEqual(starts.map { $0.0 }, (0..<starts.count).map { $0 + 1 })
            let row = try XCTUnwrap(f.h.frame().window)
            switch result {
            case .success(let restored):
                XCTAssertEqual(boundary, .beforePending)
                XCTAssertFalse(reconnect)
                XCTAssertEqual(starts.count, 2); XCTAssertEqual(later.count, 1)
                let retry = try XCTUnwrap(later.first)
                XCTAssertFalse(retry === f.driver); XCTAssertNotEqual(retry.epoch, f.driver.epoch)
                XCTAssertEqual(retry.metrics.hellos.withLock { $0 }, 1)
                XCTAssertEqual(retry.metrics.probes.withLock { $0 }, 1)
                XCTAssertEqual(retry.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(retry.metrics.gates.withLock { $0 }, 1)
                XCTAssertEqual(f.driver.metrics.gates.withLock { $0 }, 0)
                XCTAssertLessThan(ContinuousClock.now, deadline)
                XCTAssertEqual(restored, row); XCTAssertEqual(row.phase, .restored)
                let gate = try XCTUnwrap(row.gate)
                XCTAssertEqual(gate.authorityIncarnation, retry.epoch)
                XCTAssertNotEqual(gate.authorityIncarnation, f.driver.epoch)
                XCTAssertEqual(gate.hold, .released); XCTAssertEqual(gate.admission, .available)
                XCTAssertEqual(gate.challenge.count, 16); XCTAssertEqual(gate.responseDigest.count, 32)
                let pending = try XCTUnwrap(f.h.committedRows.first { $0.phase == .reopenPending })
                XCTAssertEqual(gate.requestRevision, pending.revision)
                try f.retained.assertReleased()
            case .failure:
                XCTAssertEqual(row.phase, .needsOwnerRecovery)
                XCTAssertTrue(later.isEmpty)
                if boundary != .beforePending { XCTAssertEqual(row.failure, .admissionUnconfirmed) }
                else { XCTAssertFalse(f.h.committedRows.contains { $0.phase == .reopenPending }) }
                f.retained.assertHeld()
            }
        }
    }
    func testActorReentryBeforePendingClose() throws { try phaseReentry(.beforePending, .close) }
    func testActorReentryBeforePendingObserve() throws { try phaseReentry(.beforePending, .observe) }
    func testActorReentryBeforePendingSecondRestore() throws { try phaseReentry(.beforePending, .secondRestore) }
    func testActorReentryBeforePendingSecondReconnect() throws { try phaseReentry(.beforePending, .secondReconnect) }
    func testActorReentryPendingWriteClose() throws { try phaseReentry(.pendingWrite, .close) }
    func testActorReentryPendingWriteObserve() throws { try phaseReentry(.pendingWrite, .observe) }
    func testActorReentryPendingWriteSecondRestore() throws { try phaseReentry(.pendingWrite, .secondRestore) }
    func testActorReentryPendingWriteSecondReconnect() throws { try phaseReentry(.pendingWrite, .secondReconnect) }
    func testActorReentryDrainReleaseClose() throws { try phaseReentry(.drainRelease, .close) }
    func testActorReentryDrainReleaseObserve() throws { try phaseReentry(.drainRelease, .observe) }
    func testActorReentryDrainReleaseSecondRestore() throws { try phaseReentry(.drainRelease, .secondRestore) }
    func testActorReentryDrainReleaseSecondReconnect() throws { try phaseReentry(.drainRelease, .secondReconnect) }

    func testExplicitSavedTargetReconnectUsesThePendingRevisionAndReleasesOnlyAfterReadback() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery, retainReceipt: true)
            let joined = try await f.join(), original = try XCTUnwrap(f.h.frame().window)
            f.retained.assertHeld()
            let row = try await f.restore(joined)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.h.committedRows.first?.service, .restartPending)
            XCTAssertEqual(row.service, .notStopped); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.requestRevision, f.h.committedRows[1].revision)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.reopen])
            XCTAssertEqual(f.driver.metrics.gates.withLock { $0 }, 1)
            XCTAssertEqual(f.h.classifications, 0); XCTAssertEqual(f.h.registrations, 0)
            try f.retained.assertReleased()
        }
    }
    func testSameIncarnationWithoutAProductionReceiptRefusesWithoutWritingOrReopening() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery)
            let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
            await Self.refuses { try await f.restore(joined) }
            XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.probes.withLock { $0 }, 1)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty)
            f.retained.assertHeld()
        }
    }
    func testARecoveryFailureCodeCannotReplaceTheMissingDrainingReceiptCase0() throws {
        do {
                let failure: Row.Failure = .cleanupPending
            try withFixture(epoch: 71) { f in
                try f.h.seed(.draining)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: .notStopped, failure: failure), previous: previous)
                let joined = try await f.join(), original = try XCTUnwrap(f.h.frame().window)
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                f.retained.assertHeld()
            }
        }
    }
    func testARecoveryFailureCodeCannotReplaceTheMissingDrainingReceiptCase1() throws {
        do {
                let failure: Row.Failure = .serviceUnavailable
            try withFixture(epoch: 71) { f in
                try f.h.seed(.draining)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: .notStopped, failure: failure), previous: previous)
                let joined = try await f.join(), original = try XCTUnwrap(f.h.frame().window)
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                f.retained.assertHeld()
            }
        }
    }
    func testARecoveryFailureCodeCannotReplaceTheMissingDrainingReceiptCase2() throws {
        do {
                let failure: Row.Failure = .admissionUnconfirmed
            try withFixture(epoch: 71) { f in
                try f.h.seed(.draining)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: .notStopped, failure: failure), previous: previous)
                let joined = try await f.join(), original = try XCTUnwrap(f.h.frame().window)
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                f.retained.assertHeld()
            }
        }
    }
    func testARecoveryFailureCodeCannotReplaceTheMissingDrainingReceiptCase3() throws {
        do {
                let failure: Row.Failure = .healthFailed
            try withFixture(epoch: 71) { f in
                try f.h.seed(.draining)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: .notStopped, failure: failure), previous: previous)
                let joined = try await f.join(), original = try XCTUnwrap(f.h.frame().window)
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                f.retained.assertHeld()
            }
        }
    }
    func testReceiptsFromStoppingRestoringAndPendingCannotAuthorizeSavedTargetReconnectCase0() throws {
        do {
                let origin: Row.Phase = .stopping
            try withFixture(epoch: 71) { f in
                try f.h.seed(origin)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: previous.service, failure: .cleanupPending), previous: previous)
                let before = try XCTUnwrap(f.h.frame().window)
                XCTAssertThrowsError(try XCTUnwrap(f.invocation).retainMaintenanceRecoveryTransition(XCTUnwrap(f.h.lastTransition)))
                XCTAssertEqual(try f.h.frame().window, before); XCTAssertTrue(f.h.writes.isEmpty)
            }
        }
    }
    func testReceiptsFromStoppingRestoringAndPendingCannotAuthorizeSavedTargetReconnectCase1() throws {
        do {
                let origin: Row.Phase = .restoring
            try withFixture(epoch: 71) { f in
                try f.h.seed(origin)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: previous.service, failure: .cleanupPending), previous: previous)
                let before = try XCTUnwrap(f.h.frame().window)
                XCTAssertThrowsError(try XCTUnwrap(f.invocation).retainMaintenanceRecoveryTransition(XCTUnwrap(f.h.lastTransition)))
                XCTAssertEqual(try f.h.frame().window, before); XCTAssertTrue(f.h.writes.isEmpty)
            }
        }
    }
    func testReceiptsFromStoppingRestoringAndPendingCannotAuthorizeSavedTargetReconnectCase2() throws {
        do {
                let origin: Row.Phase = .reopenPending
            try withFixture(epoch: 71) { f in
                try f.h.seed(origin)
                let previous = try XCTUnwrap(f.h.frame().window)
                _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                    service: previous.service, failure: .cleanupPending), previous: previous)
                let before = try XCTUnwrap(f.h.frame().window)
                XCTAssertThrowsError(try XCTUnwrap(f.invocation).retainMaintenanceRecoveryTransition(XCTUnwrap(f.h.lastTransition)))
                XCTAssertEqual(try f.h.frame().window, before); XCTAssertTrue(f.h.writes.isEmpty)
            }
        }
    }
    func testAStaleDrainingReceiptRefusesWithoutWritingOrReopening() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery, retainReceipt: true)
            let previous = try XCTUnwrap(f.h.frame().window)
            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                service: previous.service, failure: .cleanupPending), previous: previous)
            let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
            await Self.refuses { try await f.restore(joined) }
            XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty); f.retained.assertHeld()
        }
    }
    func testHealthyExplicitRestorationPreservesEachOperationAndNeverClassifiesOrReplaysTheBodyCase0() throws {
        do {
                let origin: Row.Phase = .stopped
            try withFixture { f in
                try f.seed(origin)
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                let row = try await f.restore(joined)
                XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
                XCTAssertEqual(row.operation, original.operation)
                XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
                XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(f.h.classifications, 0); try f.retained.assertReleased()
            }
        }
    }
    func testHealthyExplicitRestorationPreservesEachOperationAndNeverClassifiesOrReplaysTheBodyCase1() throws {
        do {
                let origin: Row.Phase = .workSettled
            try withFixture { f in
                try f.seed(origin)
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                let row = try await f.restore(joined)
                XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
                XCTAssertEqual(row.operation, original.operation)
                XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
                XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(f.h.classifications, 0); try f.retained.assertReleased()
            }
        }
    }
    func testHealthyExplicitRestorationPreservesEachOperationAndNeverClassifiesOrReplaysTheBodyCase2() throws {
        do {
                let origin: Row.Phase = .executing
            try withFixture { f in
                try f.seed(origin)
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                let row = try await f.restore(joined)
                XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
                XCTAssertEqual(row.operation, original.operation)
                XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
                XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(f.h.classifications, 0); try f.retained.assertReleased()
            }
        }
    }
    func testHealthyExplicitRestorationPreservesEachOperationAndNeverClassifiesOrReplaysTheBodyCase3() throws {
        do {
                let origin: Row.Phase = .reopenPending
            try withFixture { f in
                try f.seed(origin)
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                let row = try await f.restore(joined)
                XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
                XCTAssertEqual(row.operation, original.operation)
                XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
                XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(f.h.classifications, 0); try f.retained.assertReleased()
            }
        }
    }
    func testHealthyExplicitRestorationPreservesEachOperationAndNeverClassifiesOrReplaysTheBodyCase4() throws {
        try withFixture { f in
            try f.seed(.needsOwnerRecovery)
            let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
            let deadline = ContinuousClock.now.advanced(by: restorationTestForwardDeadline)
            do {
                let row = try await f.restore(joined, until: deadline)
                XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
                XCTAssertEqual(row.operation, original.operation)
                XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
                XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
                XCTAssertEqual(f.h.classifications, 0); try f.retained.assertReleased()
            } catch {
                XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired")
                throw error
            }
        }
    }
    func testUnboundAndRepairRequiredRowsRefuseBeforeAnyWriteOrRpcCase0() throws {
        do {
                let bound: Bool = false
            try withFixture { f in
                if bound { try f.seed(.stopped, failure: .repairRequired) }
                else {
                    try f.h.seed(.authorized)
                    let previous = try XCTUnwrap(f.h.frame().window)
                    _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                        service: previous.service, failure: .cleanupPending), previous: previous)
                }
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0); f.retained.assertHeld()
            }
        }
    }
    func testUnboundAndRepairRequiredRowsRefuseBeforeAnyWriteOrRpcCase1() throws {
        do {
                let bound: Bool = true
            try withFixture { f in
                if bound { try f.seed(.stopped, failure: .repairRequired) }
                else {
                    try f.h.seed(.authorized)
                    let previous = try XCTUnwrap(f.h.frame().window)
                    _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                        service: previous.service, failure: .cleanupPending), previous: previous)
                }
                let original = try XCTUnwrap(f.h.frame().window), joined = try await f.join()
                await Self.refuses { try await f.restore(joined) }
                XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
                XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0); f.retained.assertHeld()
            }
        }
    }
    func testStaleClaimCannotOpenRestorationOrTouchTheRow() throws {
        try withFixture { f in
            try f.seed(.stopped); let old = try await f.join()
            _ = try await f.freshJoined()
            await Self.refuses { try await f.restore(old) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            f.retained.assertHeld()
        }
    }
    func testCheckedSettlementRejectsForeignAndStaleJoinedThenTheCurrentClaimAdopts() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { first in
            try MachineUpdateReplacementTests.withMaintenanceWriterFixture { second in
                let f = try ExplicitStartupFixture(first), activity = try ReleaseActivityFixture()
                let source = try second.machine().stableRuntimeSource(candidate: second.candidate)
                let target = try XCTUnwrap(source.preparations.first { $0.accountID == second.target.accountID })
                let other = try SetupRetainedOrphanClaimTests.Frame(machine: second.machine(), candidate: second.candidate,
                    targetOwner: .init(uid: target.ownerUID, primaryGroupID: getgid(), directoryID: target.directoryID), activity: activity)
                let done = DispatchSemaphore(value: 0), outcome = Mutex<Result<Void, Error>?>(nil)
                Task {
                    do {
                        try f.seed(.stopped); let stale = try await f.join()
                        f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
                        await Self.refuses { try await f.restore(stale) }
                        f.h.afterWrite = nil; f.claim?.abandon(); f.rightsLive.value.withLock { $0 = true }
                        let rights = try f.retained.authorize(), target = try SetupRetainedOrphanClaim.Target.capture(owner: f.retained.owner, authorization: rights)
                        let token = try f.retained.owner.claimRetainedOrphan(target: target, authorization: rights)
                        try await token.joinTask().value
                        let work = try token.currentRestoration(), completed = try await work.value()
                        var invocation: SetupRetainedInvocation? = try other.invocation(); try other.lose(&invocation)
                        let claim = try other.claim(), foreign = try await claim.join()
                        let reads = Mutex(0)
                        f.h.verifyOverride = { reads.withLock { $0 += 1 } }
                        for joined in [foreign, stale] {
                            XCTAssertThrowsError(try token.finishRestorationOwned(completed, work: work,
                                processLease: f.processLease, joined: joined)) {
                                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                            }
                            XCTAssertEqual(reads.withLock { $0 }, 0)
                            f.retained.assertHeld(); other.assertHeld()
                        }
                        f.h.verifyOverride = nil; token.ownerDropped(); rights.close()
                        XCTAssertTrue(try foreign.releaseIfWindowFree()); try other.assertReleased()
                        let current = try await f.freshJoined(), before = f.driver.metrics.actions.withLock { $0 }
                        let confirmed = try f.h.frame().window
                        f.h.verifyOverride = { throw StartupTestError.expected }
                        await Self.refuses { try await current.finishRecordedRestorationOwned(processLease: f.processLease) }
                        f.h.verifyOverride = nil
                        XCTAssertEqual(try f.h.frame().window, confirmed); f.retained.assertHeld()
                        f.processLease.close()
                        await Self.refuses { try await current.finishRecordedRestorationOwned(processLease: f.processLease) }
                        XCTAssertEqual(try f.h.frame().window, confirmed); f.retained.assertHeld()
                        let freshLease = try SetupProcessLease.openOwned(directory: .init(anchor: f.activity.root.path,
                            relativeDirectory: "Machine", owner: getuid()))
                        defer { freshLease.close() }
                        let row = try await current.finishRecordedRestorationOwned(processLease: freshLease)
                        XCTAssertEqual(row.phase, .restored); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, before)
                        try f.retained.assertReleased()
                        outcome.withLock { $0 = .success(()) }
                    } catch { outcome.withLock { $0 = .failure(error) } }
                    done.signal()
                }
                guard done.wait(timeout: .now() + 50) == .success else { return XCTFail("Checked settlement did not return") }
                try XCTUnwrap(outcome.withLock { $0 }).get()
            }
        }
    }

    func testCallerLossAfterTheConfirmedRestoredWriteKeepsACompletionForFreshClaimAdoption() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
            await Self.refuses { try await f.restore(joined) }
            XCTAssertEqual(try f.h.frame().window?.phase, .restored); f.retained.assertHeld()
            f.h.afterWrite = nil
            let adopter = try await f.freshJoined(), calls = f.driver.metrics.actions.withLock { $0 }
            await Self.refuses { try await f.restore(adopter) }
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            let row = try await adopter.finishRecordedRestorationOwned(processLease: f.processLease)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            try f.retained.assertReleased()
        }
    }
    func testSameClaimCanAdoptAConfirmedCompletionAfterItsRightsBecomeCurrentAgain() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
            await Self.refuses { try await f.restore(joined) }; f.retained.assertHeld()
            f.rightsLive.value.withLock { $0 = true }; f.h.afterWrite = nil
            let calls = f.driver.metrics.actions.withLock { $0 }
            let row = try await joined.finishRecordedRestorationOwned(processLease: f.processLease)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            try f.retained.assertReleased()
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase0() throws {
        do {
                let phase: Row.Phase = .restoring
            do {
                let committed: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase1() throws {
        do {
                let phase: Row.Phase = .restoring
            do {
                let committed: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase2() throws {
        do {
                let phase: Row.Phase = .reopenPending
            do {
                let committed: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase3() throws {
        do {
                let phase: Row.Phase = .reopenPending
            do {
                let committed: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase4() throws {
        do {
                let phase: Row.Phase = .restored
            do {
                let committed: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testEachUncertainWriteKeepsBothAdmissionsAndCannotSupplyACompletionCase5() throws {
        do {
                let phase: Row.Phase = .restored
            do {
                let committed: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    f.h.failPhase = phase; f.h.commitBeforeFailure = committed
                    await Self.refuses { try await f.restore(joined) }
                    XCTAssertEqual(f.h.writes.last, phase)
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                    XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery))
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase0() throws {
        do {
                let phase: Row.Phase = .restoring
            do {
                let directoryDrift: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase1() throws {
        do {
                let phase: Row.Phase = .restoring
            do {
                let directoryDrift: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase2() throws {
        do {
                let phase: Row.Phase = .reopenPending
            do {
                let directoryDrift: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase3() throws {
        do {
                let phase: Row.Phase = .reopenPending
            do {
                let directoryDrift: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase4() throws {
        do {
                let phase: Row.Phase = .restored
            do {
                let directoryDrift: Bool = false
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testPostWriteHostAndDirectoryDriftCannotCreateACompletionOrReleaseAdmissionsCase5() throws {
        do {
                let phase: Row.Phase = .restored
            do {
                let directoryDrift: Bool = true
                try withFixture { f in
                    try f.seed(.stopped); let joined = try await f.join()
                    if directoryDrift { f.h.driftFloorAfterPhase = phase }
                    else { f.h.failScopeAfterPhase = phase }
                    await Self.refuses { try await f.restore(joined) }
                    await Self.refuses { try await joined.finishRecordedRestorationOwned(processLease: f.processLease) }
                    f.retained.assertHeld()
                }
            }
        }
    }
    func testCallerLossBeforePendingRecordsTheFailureWithoutOldCallerRights() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            f.driver.onExchange.withLock { $0 = { action in
                if action == .open { f.rightsLive.value.withLock { $0 = false } }
            } }
            // Every fresh connection must see the same loss hook.
            f.h.afterObservation = { f.rightsLive.value.withLock { $0 = false } }
            await Self.refuses { try await f.restore(joined) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery)
            XCTAssertEqual(f.h.writes, [.restoring, .needsOwnerRecovery])
            XCTAssertFalse(f.driver.metrics.actions.withLock { $0 }.contains(.reopen)); f.retained.assertHeld()
        }
    }
    func testAutomaticRecoveryUsesTheHealthyPathForAnExplicitRestoringCrashRow() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let previous = try XCTUnwrap(f.h.frame().window)
            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                service: .restartPending), previous: previous)
            let row = try await Self.automatic(f)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .healthy)
            XCTAssertEqual(row.operation, previous.operation); XCTAssertEqual(f.h.classifications, 0)
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase0() throws {
        do {
                let origin: Row.Phase = .needsOwnerRecovery
            do {
                let reconnect: Bool = false
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase1() throws {
        do {
                let origin: Row.Phase = .needsOwnerRecovery
            do {
                let reconnect: Bool = true
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase2() throws {
        do {
                let origin: Row.Phase = .restoring
            do {
                let reconnect: Bool = false
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase3() throws {
        do {
                let origin: Row.Phase = .restoring
            do {
                let reconnect: Bool = true
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase4() throws {
        do {
                let origin: Row.Phase = .reopenPending
            do {
                let reconnect: Bool = false
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticRecoveryKeepsEachExistingCrashRowDecisionCase5() throws {
        do {
                let origin: Row.Phase = .reopenPending
            do {
                let reconnect: Bool = true
                try withFixture { f in
                    try f.seed(reconnect ? .needsOwnerRecovery : .executing)
                    if origin != .needsOwnerRecovery {
                        let previous = try XCTUnwrap(f.h.frame().window)
                        let restoring = try f.h.write(RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring,
                            service: .restartPending), previous: previous)
                        if origin == .reopenPending {
                            _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(restoring, phase: .reopenPending,
                                service: reconnect ? .notStopped : .healthy), previous: restoring)
                        }
                    }
                    let original = try XCTUnwrap(f.h.frame().window), row = try await Self.automatic(f)
                    if origin == .needsOwnerRecovery { XCTAssertEqual(row, original); XCTAssertTrue(f.h.writes.isEmpty) }
                    else if origin == .reopenPending {
                        XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .admissionUnconfirmed)
                    } else { XCTAssertEqual(row.phase, .restored) }
                    XCTAssertEqual(f.h.classifications, 0)
                }
            }
        }
    }
    func testAutomaticUntypedRestoringCheckStillRecordsHealthFailed() throws {
        try withFixture { f in
            try f.h.seed(.stopped)
            f.h.inspectOverride = {
                if f.h.registrations > 0 { f.h.postCommitScopeFailure = true }
                return .absent
            }
            do { _ = try await Self.automatic(f); XCTFail("Expected the untyped restoring check to fail") } catch {}
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .healthFailed)
        }
    }
    func testBlockedRestorationKeepsTheOriginalAdmissionsAndReportsARegisteredWorker() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal() }
            f.h.beforeWrite = { row in
                if row.phase == .restoring { entered.signal(); _ = release.wait(timeout: .now() + 10) }
            }
            let work = Task { try await f.restore(joined) }
            XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
            f.retained.assertHeld()
            XCTAssertEqual(f.retained.status.worker, .observed(.registered))
            XCTAssertEqual(f.retained.status.cleanup, .observed(.joining))
            release.signal(); _ = try await work.value
            try f.retained.assertReleased()
        }
    }
    func testWrongAccountPurposeWindowAndScopeRefuseWithoutWritingOrRpcCase0() throws {
        do {
                let mismatch: Int = 0
            try withFixture { f in
                try f.seed(.stopped); let joined = try await f.join()
                let frame = try f.h.frame(), row = try XCTUnwrap(frame.window), scope = row.scope
                let wrongScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                    authority: mismatch == 0 ? scope.target : scope.authority,
                    target: mismatch == 0 ? scope.authority : scope.target,
                    releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                    authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                    restorationDigest: mismatch == 3 ? Data(repeating: 0x54, count: 32) : scope.restorationDigest,
                    mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                    targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
                let changed = try Row(id: mismatch == 2 ? Data(repeating: 0x53, count: 16) : row.id,
                    revision: row.revision, purpose: mismatch == 1 ? .retainedPolicy : row.purpose, scope: wrongScope,
                    phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                    shutdownBinding: mismatch == 0 || mismatch == 2 ? nil : row.shutdownBinding)
                await Self.refuses { try await f.restore(joined, frame: .init(source: frame.source, window: changed)) }
                XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
                XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
            }
        }
    }
    func testWrongAccountPurposeWindowAndScopeRefuseWithoutWritingOrRpcCase1() throws {
        do {
                let mismatch: Int = 1
            try withFixture { f in
                try f.seed(.stopped); let joined = try await f.join()
                let frame = try f.h.frame(), row = try XCTUnwrap(frame.window), scope = row.scope
                let wrongScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                    authority: mismatch == 0 ? scope.target : scope.authority,
                    target: mismatch == 0 ? scope.authority : scope.target,
                    releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                    authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                    restorationDigest: mismatch == 3 ? Data(repeating: 0x54, count: 32) : scope.restorationDigest,
                    mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                    targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
                let changed = try Row(id: mismatch == 2 ? Data(repeating: 0x53, count: 16) : row.id,
                    revision: row.revision, purpose: mismatch == 1 ? .retainedPolicy : row.purpose, scope: wrongScope,
                    phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                    shutdownBinding: mismatch == 0 || mismatch == 2 ? nil : row.shutdownBinding)
                await Self.refuses { try await f.restore(joined, frame: .init(source: frame.source, window: changed)) }
                XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
                XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
            }
        }
    }
    func testWrongAccountPurposeWindowAndScopeRefuseWithoutWritingOrRpcCase2() throws {
        do {
                let mismatch: Int = 2
            try withFixture { f in
                try f.seed(.stopped); let joined = try await f.join()
                let frame = try f.h.frame(), row = try XCTUnwrap(frame.window), scope = row.scope
                let wrongScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                    authority: mismatch == 0 ? scope.target : scope.authority,
                    target: mismatch == 0 ? scope.authority : scope.target,
                    releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                    authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                    restorationDigest: mismatch == 3 ? Data(repeating: 0x54, count: 32) : scope.restorationDigest,
                    mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                    targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
                let changed = try Row(id: mismatch == 2 ? Data(repeating: 0x53, count: 16) : row.id,
                    revision: row.revision, purpose: mismatch == 1 ? .retainedPolicy : row.purpose, scope: wrongScope,
                    phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                    shutdownBinding: mismatch == 0 || mismatch == 2 ? nil : row.shutdownBinding)
                await Self.refuses { try await f.restore(joined, frame: .init(source: frame.source, window: changed)) }
                XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
                XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
            }
        }
    }
    func testWrongAccountPurposeWindowAndScopeRefuseWithoutWritingOrRpcCase3() throws {
        do {
                let mismatch: Int = 3
            try withFixture { f in
                try f.seed(.stopped); let joined = try await f.join()
                let frame = try f.h.frame(), row = try XCTUnwrap(frame.window), scope = row.scope
                let wrongScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                    authority: mismatch == 0 ? scope.target : scope.authority,
                    target: mismatch == 0 ? scope.authority : scope.target,
                    releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                    authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                    restorationDigest: mismatch == 3 ? Data(repeating: 0x54, count: 32) : scope.restorationDigest,
                    mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                    targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
                let changed = try Row(id: mismatch == 2 ? Data(repeating: 0x53, count: 16) : row.id,
                    revision: row.revision, purpose: mismatch == 1 ? .retainedPolicy : row.purpose, scope: wrongScope,
                    phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                    shutdownBinding: mismatch == 0 || mismatch == 2 ? nil : row.shutdownBinding)
                await Self.refuses { try await f.restore(joined, frame: .init(source: frame.source, window: changed)) }
                XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
                XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
            }
        }
    }
    func testDeadlineBeforeCustodyDoesNotWriteOrSendRpc() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            await Self.refuses { try await f.restore(joined, until: .now.advanced(by: .seconds(-1))) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            f.retained.assertHeld()
        }
    }
    func testDeadlineAfterEachHealthyWriteUsesTheActualConfirmedPhaseCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            let trigger = ExplicitDeadlineTrigger(), reached = Mutex<Row.Phase?>(nil)
            let control = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .beforePending, expired: { trigger.expired })
            f.h.afterWrite = { row in
                if row.phase == .restoring { reached.withLock { $0 = row.phase }; trigger.expire() }
            }
            await Self.refuses { try await f.restore(joined, until: .now.advanced(by: restorationTestForwardDeadline), ownedDeadline: control) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery)
            XCTAssertEqual(row.failure, .healthFailed); f.retained.assertHeld()
            XCTAssertEqual(reached.withLock { $0 }, .restoring)
            XCTAssertTrue(f.h.committedRows.contains { $0.phase == .restoring })
        }
    }
    func testDeadlineAfterEachHealthyWriteUsesTheActualConfirmedPhaseCase1() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            let trigger = ExplicitDeadlineTrigger(), reached = Mutex<Row.Phase?>(nil)
            let control = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .beforeRestored, expired: { trigger.expired })
            f.h.afterWrite = { row in
                if row.phase == .reopenPending { reached.withLock { $0 = row.phase }; trigger.expire() }
            }
            await Self.refuses { try await f.restore(joined, until: .now.advanced(by: restorationTestForwardDeadline), ownedDeadline: control) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery)
            XCTAssertEqual(row.failure, .admissionUnconfirmed); f.retained.assertHeld()
            XCTAssertEqual(reached.withLock { $0 }, .reopenPending)
            XCTAssertTrue(f.h.committedRows.contains { $0.phase == .reopenPending })
        }
    }
    func testDeadlineAfterEachHealthyWriteUsesTheActualConfirmedPhaseCase2() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            let trigger = ExplicitDeadlineTrigger(), reached = Mutex<Row.Phase?>(nil)
            let control = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .afterRestored, expired: { trigger.expired })
            f.h.afterWrite = { row in
                if row.phase == .restored { reached.withLock { $0 = row.phase }; trigger.expire() }
            }
            let row = try await f.restore(joined, until: .now.advanced(by: restorationTestForwardDeadline), ownedDeadline: control)
            XCTAssertEqual(row.phase, .restored); try f.retained.assertReleased()
            XCTAssertEqual(reached.withLock { $0 }, .restored)
            XCTAssertTrue(f.h.committedRows.contains { $0.phase == .restored })
        }
    }
    func testReconnectDeadlineBeforePendingPreservesTheOriginFailureAndNotStoppedService() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery, retainReceipt: true); let joined = try await f.join()
            let trigger = ExplicitDeadlineTrigger(), reached = Mutex<Row.Phase?>(nil)
            let control = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .beforePending, expired: { trigger.expired })
            f.h.afterWrite = { row in
                if row.phase == .restoring { reached.withLock { $0 = row.phase }; trigger.expire() }
            }
            await Self.refuses { try await f.restore(joined, until: .now.advanced(by: restorationTestForwardDeadline), ownedDeadline: control) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(reached.withLock { $0 }, .restoring)
            XCTAssertTrue(f.h.committedRows.contains { $0.phase == .restoring })
            XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.service, .notStopped)
            XCTAssertEqual(row.failure, .cleanupPending); XCTAssertEqual(f.h.writes, [.restoring, .needsOwnerRecovery])
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty); f.retained.assertHeld()
        }
    }
    func testNativeExplicitOriginRefusesTheOrdinaryOwnerBeforeOpeningFixedPaths() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires an ordinary owner") }
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join()
            do {
                _ = try await RuntimeMaintenanceStartupRecovery.restoreExplicitNative(joined: joined, processLease: f.processLease,
                    accountID: f.h.initial.scope.authority.accountID, until: .now.advanced(by: .seconds(1)))
                XCTFail("An owned claim cannot open installed Root custody")
            } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            f.retained.assertHeld()
        }
    }
    func testForeignInProcessWindowKeepsTheOriginalChangedScopeErrorBeforePhaseChecks() throws {
        try withFixture { f in
            try f.seed(.stopped); let joined = try await f.join(), frame = try f.h.frame()
            let row = try XCTUnwrap(frame.window)
            let foreign = try Row(id: Data(repeating: 0xd9, count: 16), revision: row.revision, purpose: row.purpose, scope: row.scope)
            do {
                _ = try await f.restore(joined, frame: .init(source: frame.source, window: foreign))
                XCTFail("Expected changedScope for the foreign window")
            } catch RuntimePreparationError.changedScope {} catch { XCTFail("Wrong error: \(error)") }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            f.retained.assertHeld()
        }
    }

}


private final class RestartShutdownProbe: Sendable {
    private let closed = Mutex(false)
    func didClose() { closed.withLock { $0 = true } }
    var isClosed: Bool { closed.withLock { $0 } }
}

/// Restart uses real owned SQLite writers and account locks. Native peer identity and launchd remain unqualified.
final class RuntimeMaintenanceRestartRestorationTests: XCTestCase {
    typealias Row = RuntimeMaintenanceWindowRecord
    typealias Claim = SetupRestartRecovery.Claim
    private func withFixture(epoch: UInt8 = 81,
        _ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { material in
            let fixture = try ExplicitStartupFixture(material, epoch: epoch, reserveInProcess: false)
            defer {
                fixture.h.beforeWrite = nil; fixture.h.afterWrite = nil; fixture.h.verifyOverride = nil
                fixture.h.afterObservation = nil; fixture.h.inspectOverride = nil
                fixture.driver.onExchange.withLock { $0 = nil }; fixture.driver.onProbe.withLock { $0 = nil }
            }
            let result = Mutex<Result<Void, any Error>?>(nil), done = DispatchSemaphore(value: 0)
            Task {
                do { try await body(fixture); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + 50) == .success else { return XCTFail("Restart restoration did not return") }
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    private static func claim(_ f: ExplicitStartupFixture,
        authorization: SetupRetainedRecoveryAuthorization? = nil, accountID: Data? = nil,
        processLease: SetupProcessLease? = nil) async throws -> Claim {
        let live = f.rightsLive
        let rights = try authorization ?? f.retained.authorize(verify: {
            guard live.value.withLock({ $0 }) else { throw StartupTestError.expected }
        })
        return try await .openOwned(owner: f.retained.owner, authorization: rights, processLease: processLease ?? f.processLease,
            accountID: accountID ?? f.h.initial.scope.authority.accountID, until: .now.advanced(by: .seconds(5)))
    }
    private static func restore(_ f: ExplicitStartupFixture, _ claim: Claim,
        frame: RuntimeMaintenanceStartupFrame? = nil,
        deadline: ContinuousClock.Instant = .now.advanced(by: restorationTestForwardDeadline),
        expiry: SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl? = nil,
        beforeCustody: @escaping @Sendable () async throws -> Void = {}) async throws -> Row {
        let (directory, admission) = try f.resources()
        defer { admission.close(); directory.close() }
        let attempts = Mutex(0), h = f.h, driver = f.driver
        // A test that passes an already expired deadline tests that refusal on purpose; every other restore must end
        // before its forward deadline, so a slow runner cannot turn an expired deadline into the expected result.
        let deadlineWasLive = ContinuousClock.now < deadline
        defer { if deadlineWasLive { XCTAssertLessThan(ContinuousClock.now, deadline, "forward deadline expired") } }
        return try await RuntimeMaintenanceStartupRecovery.restoreRestartOwned(claim: claim,
            frame: frame ?? h.frame(), release: h.f.candidate, admission: admission, directory: directory,
            accountBarrier: h.barrier, read: { try h.frame() }, persist: { try h.persistForRecovery($0, previous: $1) },
            verify: { try h.verifyCurrent() }, inspect: { _ in try h.inspectOverride?() ?? h.inspected },
            observe: { _, _, pid in
                h.observations += 1
                guard !h.rejectCode, pid == h.witness.processID else { throw StartupTestError.expected }
                h.afterObservation?(); return h.witness
            }, register: {
                h.beforeRegistration?(); h.registrations += 1; h.inspected = .matching(h.witness.processID)
            }, makeDriver: { attempts.withLock { $0 += 1; return $0 == 1 } ? driver : driver.fresh() },
            capturePeer: { h.witness }, requirePeerLive: {
                guard try !$0.hasExited() else { throw StartupTestError.expected }
            }, ownedDeadline: expiry, beforeCustody: beforeCustody, until: deadline)
    }
    private static func refuses<T>(_ body: () async throws -> T) async {
        do { _ = try await body(); XCTFail("Expected restart refusal") } catch {}
    }
    private static func available(_ f: ExplicitStartupFixture) throws {
        try f.retained.owner.verifyCurrent()
        let reply = try f.retained.owner.acquireSetupReplyAdmission(); reply.close()
        let activity = try f.retained.installer.acquireExclusive(); activity.close()
    }
    private static func releasedAndClosed(_ f: ExplicitStartupFixture) async throws {
        try available(f); try await f.retained.owner.closeWhenIdle()
    }

    func testAbandonBeforeStartingReleasesBothAdmissionsAndActivityAndAllowsShutdown() throws {
        try withFixture { f in
            let claim = try await Self.claim(f); f.retained.assertHeld(); claim.abandon()
            try await Self.releasedAndClosed(f)
        }
    }
    func testRightsCheckedExitBeforeStartingReleasesTheIdleSlot() throws {
        try withFixture { f in
            let claim = try await Self.claim(f)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released)
            try await Self.releasedAndClosed(f)
        }
    }
    func testFreshRightsAndAccountReadsUseTheOriginalLargeStackExecutor() throws {
        try withFixture { f in
            let stack = Mutex<Int>(0), checks = Mutex(0)
            let rights = try f.retained.authorize(verify: {
                checks.withLock { $0 += 1 }; stack.withLock { $0 = pthread_get_stacksize_np(pthread_self()) }
            })
            let claim = try await Self.claim(f, authorization: rights)
            XCTAssertGreaterThan(checks.withLock { $0 }, 1)
            XCTAssertGreaterThanOrEqual(stack.withLock { $0 }, SetupAuditUpgradeWorkExecutor.stackBytes)
            claim.abandon(); try await Self.releasedAndClosed(f)
        }
    }
    func testWrongAccountRefusesBeforeCreatingASlot() throws {
        try withFixture { f in
            await Self.refuses { try await Self.claim(f, accountID: Data(repeating: 0x33, count: 16)) }
            try await Self.releasedAndClosed(f)
        }
    }
    func testRecycledDirectoryIdentityRefusesBeforeCreatingASlot() throws {
        try withFixture { f in
            let a = f.retained.binding.authorityOwner
            let recycled = LocalAccountIdentity(uid: a.uid, primaryGroupID: a.primaryGroupID, directoryID: UUID())
            let rights = try f.retained.authorize(identity: recycled)
            await Self.refuses { try await Self.claim(f, authorization: rights) }
            try await Self.releasedAndClosed(f)
        }
    }
    func testAnotherAuthenticatedUserCannotTakeAsAccountOrExistingSlot() throws {
        try withFixture { f in
            let claim = try await Self.claim(f), b = f.retained.binding.targetOwner
            let peer = XPCPeerCredentials(processID: getpid(), userID: b.uid, auditSessionID: 1)
            let wrong = try f.retained.authorize(peer: peer, identity: b)
            await Self.refuses { try await Self.claim(f, authorization: wrong) }
            f.retained.assertHeld(); claim.abandon(); try await Self.releasedAndClosed(f)
        }
    }
    func testLiveInProcessRecordRefusesTheRestartOrigin() throws {
        try withFixture { f in
            f.invocation = try f.retained.invocation()
            await Self.refuses { try await Self.claim(f) }
            f.retained.assertHeld(); try XCTUnwrap(f.invocation).close(); f.invocation = nil
            try await Self.releasedAndClosed(f)
        }
    }
    func testSettledInProcessRecordCanRestoreItsNeedsOwnerRecoveryWindow() throws {
        try withFixture { f in
            f.invocation = try f.retained.invocation()
            try f.retained.window(XCTUnwrap(f.invocation), id: f.h.initial.id, revision: f.h.initial.revision)
            try f.seed(.stopped); try XCTUnwrap(f.invocation).close(); f.invocation = nil
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .settled)
            let claim = try await Self.claim(f), restored = try await Self.restore(f, claim)
            XCTAssertEqual(restored.phase, .restored); try await Self.releasedAndClosed(f)
        }
    }
    func testASecondRestartClaimAndANormalReservationCannotEnterTheHeldSlot() throws {
        try withFixture { f in
            let claim = try await Self.claim(f)
            await Self.refuses { try await Self.claim(f) }
            XCTAssertThrowsError(try f.retained.invocation())
            f.retained.assertHeld(); claim.abandon(); try await Self.releasedAndClosed(f)
        }
    }
    func testClosedProcessLeaseRefusesBeforeCreatingASlot() throws {
        try withFixture { f in
            f.processLease.close(); await Self.refuses { try await Self.claim(f) }
            try await Self.releasedAndClosed(f)
        }
    }
    func testNativeFactoryRefusesOwnedRightsAndNeverOpensCustody() throws {
        try withFixture { f in
            let rights = try f.retained.authorize()
            await Self.refuses {
                try await Claim.openNative(owner: f.retained.owner, authorization: rights, processLease: f.processLease,
                    accountID: f.h.initial.scope.authority.accountID, until: .now.advanced(by: .seconds(3)))
            }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testAnUnregisteredOwnedPermitCannotForgeTheOwnerSlotOrReleaseProof() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let rights = try f.retained.authorize()
            let claim = try await f.retained.owner.unregisteredRestartOwned(authorization: rights, processLease: f.processLease,
                accountID: f.h.initial.scope.authority.accountID)
            XCTAssertThrowsError(try claim.requireCurrentAuthorization())
            await Self.refuses { try await Self.restore(f, claim) }
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            claim.abandon(); try await Self.releasedAndClosed(f)
        }
    }
    func testUnboundWindowRefusalAutomaticallyReleasesTheSlotAndAllowsShutdown() throws {
        try withFixture { f in
            try f.h.seed(.authorized); let claim = try await Self.claim(f)
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testRepairRequiredWindowRefusalAutomaticallyReleasesTheSlotAndAllowsShutdown() throws {
        try withFixture { f in
            try f.seed(.stopped, failure: .repairRequired); let claim = try await Self.claim(f)
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testMissingWindowRefusalAutomaticallyReleasesBeforeCreatingATask() throws {
        try withFixture { f in
            let claim = try await Self.claim(f), frame = try f.h.frame()
            await Self.refuses { try await Self.restore(f, claim, frame: frame) }
            try await Self.releasedAndClosed(f)
        }
    }
    func testExpiredDeadlineBeforeCustodyAutomaticallyReleasesAndAllowsShutdown() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            await Self.refuses { try await Self.restore(f, claim, deadline: .now.advanced(by: .seconds(-1))) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testSameIncarnationRefusalHasARightsCheckedExitWithoutWritingTheWindow() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(try f.h.frame().window, original); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.probes.withLock { $0 }, 1)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty); f.retained.assertHeld()
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released); try await Self.releasedAndClosed(f)
        }
    }
    func testExpiredRightsCannotReleaseAfterTheSameIncarnationProbe() throws {
        try withFixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery); let claim = try await Self.claim(f)
            await Self.refuses { try await Self.restore(f, claim) }
            f.rightsLive.value.withLock { $0 = false }
            await Self.refuses { try await claim.releaseWithoutRestoration() }; f.retained.assertHeld()
            claim.abandon(); f.rightsLive.value.withLock { $0 = true }
            let fresh = try await Self.claim(f)
            let released = try await fresh.releaseWithoutRestoration(); XCTAssertTrue(released); try await Self.releasedAndClosed(f)
        }
    }
    func testConfirmedCompletionCanBeAdoptedByAFreshClaimWhileTheOwnerCloses() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
            await Self.refuses { try await Self.restore(f, claim) }; f.retained.assertHeld()
            let calls = f.driver.metrics.actions.withLock { $0 }
            let done = Mutex(false)
            let closing = Task { try await f.retained.owner.closeWhenIdle(); done.withLock { $0 = true } }
            // close() synchronously closes admission, even when its retained work prevents an immediate close.
            XCTAssertThrowsError(try f.retained.owner.close()); XCTAssertFalse(done.withLock { $0 })
            claim.abandon(); f.h.afterWrite = nil; f.rightsLive.value.withLock { $0 = true }
            let adopter = try await Self.claim(f)
            let row = try await adopter.finishRecordedRestoration()
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            try await closing.value; XCTAssertTrue(done.withLock { $0 })
            let exclusive = try f.retained.installer.acquireExclusive(); exclusive.close()
        }
    }
    func testClosingOwnerRefusesANewStoppedAttemptWithoutAnyWriteOrRpc() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            // Closing starts before restoration can install a task. The stopped origin would otherwise restore.
            XCTAssertThrowsError(try f.retained.owner.close())
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            XCTAssertEqual(f.driver.metrics.probes.withLock { $0 }, 0)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty)
            try await f.retained.owner.closeWhenIdle()
            await Self.refuses { try await Self.claim(f) }
        }
    }
    func testUnsettledCompletionRefusesANewAttemptAndRequiresFreshReadbackBeforeRelease() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
            await Self.refuses { try await Self.restore(f, claim) }; claim.abandon()
            f.h.afterWrite = nil; f.rightsLive.value.withLock { $0 = true }
            let adopter = try await Self.claim(f), calls = f.driver.metrics.actions.withLock { $0 }
            await Self.refuses { try await Self.restore(f, adopter) }
            let released = try await adopter.releaseWithoutRestoration(); XCTAssertFalse(released); f.retained.assertHeld()
            f.h.postCommitScopeFailure = true
            await Self.refuses { try await adopter.finishRecordedRestoration() }; f.retained.assertHeld()
            f.h.postCommitScopeFailure = false
            _ = try await adopter.finishRecordedRestoration()
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls); try await Self.releasedAndClosed(f)
        }
    }
    func testLiveWriterAndCancelledWaiterKeepBothAdmissionsUntilActualReturn() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            defer { resume.signal() }
            f.h.beforeWrite = { row in if row.phase == .restoring { entered.signal(); _ = resume.wait(timeout: .now() + 10) } }
            let restoring = Task { try await Self.restore(f, claim) }
            XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
            restoring.cancel(); claim.abandon(); f.retained.assertHeld()
            resume.signal(); await Self.refuses { try await restoring.value }
            f.h.beforeWrite = nil
            let fresh = try await Self.claim(f)
            let released = try await fresh.releaseWithoutRestoration(); XCTAssertTrue(released); try await Self.releasedAndClosed(f)
        }
    }
    func testBusyAccountDrainClosesTheRefusedAttemptWithoutRpcOrAWriter() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), drain = try f.h.barrier.beginDrain()
            defer { drain.close() }
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            drain.close(); try await Self.releasedAndClosed(f)
        }
    }
    func testRestartCapabilityDescriptionsAndMirrorsRedactAllIdentity() throws {
        try withFixture { f in
            let claim = try await Self.claim(f)
            XCTAssertEqual(String(describing: claim), "SetupRestartRecoveryClaim(redacted)")
            XCTAssertEqual(String(reflecting: claim), "SetupRestartRecoveryClaim(redacted)")
            XCTAssertTrue(Mirror(reflecting: claim).children.isEmpty)
            var dumped = ""; dump(claim, to: &dumped)
            XCTAssertFalse(dumped.contains(f.h.initial.id.base64EncodedString()))
            claim.abandon(); try await Self.releasedAndClosed(f)
        }
    }
    func testHealthyRestartPreservesTheOperationAndWriterOrderCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            let row = try await Self.restore(f, claim)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(f.h.classifications, 0); try await Self.releasedAndClosed(f)
        }
    }
    func testHealthyRestartPreservesTheOperationAndWriterOrderCase1() throws {
        try withFixture { f in
            try f.seed(.executing); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            let row = try await Self.restore(f, claim)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(f.h.classifications, 0); try await Self.releasedAndClosed(f)
        }
    }
    func testHealthyRestartPreservesTheOperationAndWriterOrderCase2() throws {
        try withFixture { f in
            try f.seed(.workSettled); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            let row = try await Self.restore(f, claim)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(f.h.classifications, 0); try await Self.releasedAndClosed(f)
        }
    }
    func testHealthyRestartPreservesTheOperationAndWriterOrderCase3() throws {
        try withFixture { f in
            try f.seed(.reopenPending); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            let row = try await Self.restore(f, claim)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(f.h.classifications, 0); try await Self.releasedAndClosed(f)
        }
    }
    func testHealthyRestartPreservesTheOperationAndWriterOrderCase4() throws {
        try withFixture { f in
            try f.seed(.needsOwnerRecovery); let original = try XCTUnwrap(f.h.frame().window), claim = try await Self.claim(f)
            let row = try await Self.restore(f, claim)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertEqual(row.gate?.admission, .available)
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            XCTAssertEqual(f.h.classifications, 0); try await Self.releasedAndClosed(f)
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .restoring; f.h.commitBeforeFailure = false
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .restoring)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase1() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .restoring; f.h.commitBeforeFailure = true
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .restoring)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase2() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .reopenPending; f.h.commitBeforeFailure = false
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .reopenPending)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase3() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .reopenPending; f.h.commitBeforeFailure = true
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .reopenPending)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase4() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .restored; f.h.commitBeforeFailure = false
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .restored)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testUncertainWriterNeverAllowsReleaseOrCompletionCase5() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .restored; f.h.commitBeforeFailure = true
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes.last, .restored)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await claim.finishRecordedRestoration() }
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
        }
    }
    func testControlledDeadlineAfterTheConfirmedWriterUsesItsActualPhaseCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), trigger = ExplicitDeadlineTrigger()
            let expiry = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .beforePending, expired: { trigger.expired })
            f.h.afterWrite = { row in if row.phase == .restoring { trigger.expire() } }
            await Self.refuses { try await Self.restore(f, claim, expiry: expiry) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released)
            try await Self.releasedAndClosed(f)
        }
    }
    func testControlledDeadlineAfterTheConfirmedWriterUsesItsActualPhaseCase1() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), trigger = ExplicitDeadlineTrigger()
            let expiry = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .beforeRestored, expired: { trigger.expired })
            f.h.afterWrite = { row in if row.phase == .reopenPending { trigger.expire() } }
            await Self.refuses { try await Self.restore(f, claim, expiry: expiry) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery)
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released)
            try await Self.releasedAndClosed(f)
        }
    }
    func testControlledDeadlineAfterTheConfirmedWriterUsesItsActualPhaseCase2() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), trigger = ExplicitDeadlineTrigger()
            let expiry = try SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl(
                phase: .afterRestored, expired: { trigger.expired })
            f.h.afterWrite = { row in if row.phase == .restored { trigger.expire() } }
            let restored = try await Self.restore(f, claim, expiry: expiry)
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(restored, row)
            try await Self.releasedAndClosed(f)
        }
    }
    func testForeignProtectedFrameRefusesWithoutWriterOrRpcCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), frame = try f.h.frame()
            let row = try XCTUnwrap(frame.window), scope = row.scope
            let changedScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: 0 == 0 ? scope.target : scope.authority, target: 0 == 0 ? scope.authority : scope.target,
                releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                restorationDigest: 0 == 3 ? Data(repeating: 0x77, count: 32) : scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            // Pin the actual first window so a replacement cannot silently select another scope.
            try await claim.restorationPhases().run { try claim.capture(row) }
            let changed = try Row(id: 0 == 2 ? Data(repeating: 0x78, count: 16) : row.id,
                revision: row.revision, purpose: 0 == 1 ? .retainedPolicy : row.purpose, scope: changedScope,
                phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                shutdownBinding: 0 == 0 || 0 == 2 ? nil : row.shutdownBinding)
            await Self.refuses { try await Self.restore(f, claim, frame: .init(source: frame.source, window: changed)) }
            XCTAssertEqual(try f.h.frame().window, row); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testForeignProtectedFrameRefusesWithoutWriterOrRpcCase1() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), frame = try f.h.frame()
            let row = try XCTUnwrap(frame.window), scope = row.scope
            let changedScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: 1 == 0 ? scope.target : scope.authority, target: 1 == 0 ? scope.authority : scope.target,
                releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                restorationDigest: 1 == 3 ? Data(repeating: 0x77, count: 32) : scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            // Pin the actual first window so a replacement cannot silently select another scope.
            try await claim.restorationPhases().run { try claim.capture(row) }
            let changed = try Row(id: 1 == 2 ? Data(repeating: 0x78, count: 16) : row.id,
                revision: row.revision, purpose: 1 == 1 ? .retainedPolicy : row.purpose, scope: changedScope,
                phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                shutdownBinding: 1 == 0 || 1 == 2 ? nil : row.shutdownBinding)
            await Self.refuses { try await Self.restore(f, claim, frame: .init(source: frame.source, window: changed)) }
            XCTAssertEqual(try f.h.frame().window, row); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testForeignProtectedFrameRefusesWithoutWriterOrRpcCase2() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), frame = try f.h.frame()
            let row = try XCTUnwrap(frame.window), scope = row.scope
            let changedScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: 2 == 0 ? scope.target : scope.authority, target: 2 == 0 ? scope.authority : scope.target,
                releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                restorationDigest: 2 == 3 ? Data(repeating: 0x77, count: 32) : scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            // Pin the actual first window so a replacement cannot silently select another scope.
            try await claim.restorationPhases().run { try claim.capture(row) }
            let changed = try Row(id: 2 == 2 ? Data(repeating: 0x78, count: 16) : row.id,
                revision: row.revision, purpose: 2 == 1 ? .retainedPolicy : row.purpose, scope: changedScope,
                phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                shutdownBinding: 2 == 0 || 2 == 2 ? nil : row.shutdownBinding)
            await Self.refuses { try await Self.restore(f, claim, frame: .init(source: frame.source, window: changed)) }
            XCTAssertEqual(try f.h.frame().window, row); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }
    func testForeignProtectedFrameRefusesWithoutWriterOrRpcCase3() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), frame = try f.h.frame()
            let row = try XCTUnwrap(frame.window), scope = row.scope
            let changedScope = try Row.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: 3 == 0 ? scope.target : scope.authority, target: 3 == 0 ? scope.authority : scope.target,
                releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                restorationDigest: 3 == 3 ? Data(repeating: 0x77, count: 32) : scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            // Pin the actual first window so a replacement cannot silently select another scope.
            try await claim.restorationPhases().run { try claim.capture(row) }
            let changed = try Row(id: 3 == 2 ? Data(repeating: 0x78, count: 16) : row.id,
                revision: row.revision, purpose: 3 == 1 ? .retainedPolicy : row.purpose, scope: changedScope,
                phase: row.phase, operation: row.operation, service: row.service, failure: row.failure,
                shutdownBinding: 3 == 0 || 3 == 2 ? nil : row.shutdownBinding)
            await Self.refuses { try await Self.restore(f, claim, frame: .init(source: frame.source, window: changed)) }
            XCTAssertEqual(try f.h.frame().window, row); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }

    func testACapturedTargetAccountAlsoExcludesTheLiveInProcessRecord() throws {
        try withFixture { f in
            f.invocation = try f.retained.invocation()
            let b = f.retained.binding.targetOwner
            let peer = XPCPeerCredentials(processID: getpid(), userID: b.uid, auditSessionID: 1)
            let rights = try f.retained.authorize(peer: peer, identity: b)
            await Self.refuses { try await Self.claim(f, authorization: rights, accountID: f.h.initial.scope.target.accountID) }
            f.retained.assertHeld(); try XCTUnwrap(f.invocation).close(); f.invocation = nil
            try await Self.releasedAndClosed(f)
        }
    }
    func testConfirmedHostDriftCanReleaseOnlyAfterActualFailureCleanupClosesCustody() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failScopeAfterPhase = .restoring
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(f.h.writes, [.restoring, .needsOwnerRecovery]); f.retained.assertHeld()
            f.h.postCommitScopeFailure = false
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released)
            try await Self.releasedAndClosed(f)
        }
    }
    func testAFreshClaimCanRetryAKnownFailedRestorationWithoutReplayingAnOperation() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.rejectCode = true; await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(try f.h.frame().window?.phase, .needsOwnerRecovery); f.retained.assertHeld()
            claim.abandon(); f.h.rejectCode = false
            let fresh = try await Self.claim(f), row = try await Self.restore(f, fresh)
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(f.h.classifications, 0)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.open, .reopen])
            try await Self.releasedAndClosed(f)
        }
    }
    func testAnUncertainWriterStillRefusesAFreshClaimsSafeExit() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.failPhase = .restoring; f.h.commitBeforeFailure = true
            await Self.refuses { try await Self.restore(f, claim) }; claim.abandon()
            let fresh = try await Self.claim(f)
            let released = try await fresh.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await Self.restore(f, fresh) }
            XCTAssertEqual(f.h.writes, [.restoring]); f.retained.assertHeld()
        }
    }

    func testARealRecoveryRowChangedAfterPinReleasesTheRefusedSlotAndAllowsShutdown() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f), original = try XCTUnwrap(f.h.frame().window)
            try await claim.restorationPhases().run { try claim.capture(original) }
            let changed = try RuntimeMaintenanceStartupPolicy.row(original, phase: .needsOwnerRecovery,
                service: original.service, failure: .repairRequired)
            _ = try f.h.write(changed, previous: original)
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(try f.h.frame().window, changed); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            try await Self.releasedAndClosed(f)
        }
    }

    func testAnOldAbandonedAttemptCannotReleaseANewerClaimantsIdleSlot() throws {
        try withFixture { f in
            try f.seed(.stopped); let old = try await Self.claim(f)
            let (latch, release) = AsyncStream<Void>.makeStream()
            let entered = DispatchSemaphore(value: 0)
            defer { release.finish() }
            let failing = Task {
                try await Self.restore(f, old, beforeCustody: {
                    entered.signal()
                    for await _ in latch { break }
                    throw StartupTestError.expected
                })
            }
            XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
            old.abandon(); f.retained.assertHeld()
            let current = try await Self.claim(f)
            release.yield(()); release.finish()
            await Self.refuses { try await failing.value }
            old.abandon(); await old.releaseRefusedAttemptIfSafe()
            f.retained.assertHeld(); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            let released = try await current.releaseWithoutRestoration(); XCTAssertTrue(released)
            try await Self.releasedAndClosed(f)
        }
    }
    func testAnAbandonedSuccessorLetsTheRefusedActualAttemptReleaseAndFinishShutdown() throws {
        try withFixture { f in
            try f.seed(.stopped); let old = try await Self.claim(f)
            let (latch, release) = AsyncStream<Void>.makeStream()
            let entered = DispatchSemaphore(value: 0), closed = RestartShutdownProbe()
            defer { release.finish() }
            let failing = Task { @Sendable [f, latch, entered, old] in
                try await Self.restore(f, old, beforeCustody: { @Sendable [latch, entered] in
                    entered.signal()
                    for await _ in latch { break }
                    throw StartupTestError.expected
                })
            }
            XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
            old.abandon()
            let successor = try await Self.claim(f)
            successor.abandon(); f.retained.assertHeld()
            let closing = Task { @Sendable [f, closed] in try await f.retained.owner.closeWhenIdle(); closed.didClose() }
            XCTAssertThrowsError(try f.retained.owner.close())
            XCTAssertFalse(closed.isClosed)
            release.yield(()); release.finish()
            await Self.refuses { try await failing.value }
            let deadline = ContinuousClock.now.advanced(by: .seconds(5))
            while !closed.isClosed {
                guard ContinuousClock.now < deadline else {
                    closing.cancel(); return XCTFail("The abandoned restart slot stranded shutdown")
                }
                try await ContinuousClock().sleep(for: .milliseconds(1))
            }
            try await closing.value
            XCTAssertTrue(f.h.writes.isEmpty); XCTAssertEqual(f.driver.metrics.hellos.withLock { $0 }, 0)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0 }.isEmpty)
            let exclusive = try f.retained.installer.acquireExclusive(); exclusive.close()
        }
    }
    func testConfirmedActiveRowCannotReleaseWhenTheFailureWriterNeverStartsCase0() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.afterWrite = { row in if row.phase == .restoring { f.processLease.close() } }
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(try f.h.frame().window?.phase, .restoring)
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
            claim.abandon(); f.h.afterWrite = nil
            // The new owned lease makes the exit's own identity check valid again.
            // The last confirmed active row must still prevent admission release.
            let replacement = try SetupProcessLease.openOwned(directory: .init(anchor: f.activity.root.path,
                relativeDirectory: "Machine", owner: getuid()))
            defer { replacement.close() }
            let current = try await Self.claim(f, processLease: replacement)
            let writes = f.h.writes, calls = f.driver.metrics.actions.withLock { $0 }
            let released = try await current.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await Self.restore(f, current) }
            XCTAssertEqual(f.h.writes, writes); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            f.retained.assertHeld()
        }
    }
    func testConfirmedActiveRowCannotReleaseWhenTheFailureWriterNeverStartsCase1() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f)
            f.h.afterWrite = { row in if row.phase == .reopenPending { f.processLease.close() } }
            await Self.refuses { try await Self.restore(f, claim) }
            XCTAssertEqual(try f.h.frame().window?.phase, .reopenPending)
            XCTAssertFalse(f.h.writes.contains(.needsOwnerRecovery)); f.retained.assertHeld()
            claim.abandon(); f.h.afterWrite = nil
            // The new owned lease makes the exit's own identity check valid again.
            // The last confirmed active row must still prevent admission release.
            let replacement = try SetupProcessLease.openOwned(directory: .init(anchor: f.activity.root.path,
                relativeDirectory: "Machine", owner: getuid()))
            defer { replacement.close() }
            let current = try await Self.claim(f, processLease: replacement)
            let writes = f.h.writes, calls = f.driver.metrics.actions.withLock { $0 }
            let released = try await current.releaseWithoutRestoration(); XCTAssertFalse(released)
            await Self.refuses { try await Self.restore(f, current) }
            XCTAssertEqual(f.h.writes, writes); XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, calls)
            f.retained.assertHeld()
        }
    }

}
