import Darwin
import Dispatch
import Synchronization
import Foundation
import XCTest
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
    var beforeRegistration: (@Sendable () -> Void)?
    var inspectOverride: (@Sendable () throws -> RuntimeJobStopSession.Observation)?
    var failPhase: Row.Phase?, commitBeforeFailure = false, rejectCode = false, postCommitScopeFailure = false
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
        try f.machine().writeRuntimeMaintenanceTransition(next, replacing: previous,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain).record
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
    func open(afterProbePolicy: @escaping @Sendable (Row, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
        try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
    }) throws -> RuntimeMaintenanceStartupRecovery {
        try .openOwned(frame: frame(), release: f.candidate, admission: f.admission, directory: f.directory,
            accountBarrier: barrier, read: { try self.frame() }, persist: { next, previous in
                self.writes.append(next.phase)
                if self.failPhase == next.phase && !self.commitBeforeFailure { throw StartupTestError.expected }
                let value = try self.write(next, previous: previous)
                if self.failScopeAfterPhase == next.phase { self.postCommitScopeFailure = true }
                if self.failPhase == next.phase { throw StartupTestError.expected }
                return value
            }, verify: {
                if self.postCommitScopeFailure { throw StartupTestError.expected }
            }, inspect: { _ in try self.inspectOverride?() ?? self.inspected }, observe: { _, _, pid in
                self.observations += 1
                guard !self.rejectCode, pid == self.witness.processID else { throw StartupTestError.expected }
                return self.witness
            }, observeOperation: { _ in self.classifications += 1; return self.classification }, register: {
                self.beforeRegistration?(); self.registrations += 1; self.inspected = .matching(self.witness.processID)
            }, afterProbePolicy: afterProbePolicy)
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
    let refuseProbe: Bool, failGate: Bool, notReadyOpen: Bool
    init(epoch: Data, barrier: UpdateAdmissionBarrier, refuseProbe: Bool = false, failGate: Bool = false, notReadyOpen: Bool = false, metrics: StartupMetrics? = nil) {
        self.metrics = metrics ?? StartupMetrics(); self.epoch = epoch; self.barrier = barrier; self.refuseProbe = refuseProbe; self.failGate = failGate; self.notReadyOpen = notReadyOpen
    }
    func start(_ invalidated: @escaping @Sendable () -> Void) {}
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
    private static func complete(_ h: StartupHarness, _ driver: StartupDriver, timeoutSeconds: Int = 25,
        startup: RuntimeMaintenanceStartupRecovery? = nil,
        beforeOpen: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in }) async throws -> RuntimeMaintenanceWindowRecord {
        let startup = try startup ?? h.open(), attempts = Mutex(0)
        return try await startup.runOwned(makeDriver: {
            let first = attempts.withLock { $0 += 1; return $0 == 1 }
            return first ? driver : driver.fresh()
        }, capturePeer: { h.witness }, requirePeerLive: { peer in
            guard try !peer.hasExited() else { throw StartupTestError.expected }
        }, beforeHealthyOpen: beforeOpen, until: .now.advanced(by: .seconds(timeoutSeconds)))
    }
    private static func failed(_ h: StartupHarness, _ driver: StartupDriver,
        startup: RuntimeMaintenanceStartupRecovery? = nil, timeoutSeconds: Int = 5) async -> Error? {
        do { _ = try await complete(h, driver, timeoutSeconds: timeoutSeconds, startup: startup); XCTFail("Expected refusal"); return nil }
        catch { return error }
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
            }, until: .now.advanced(by: .seconds(30)))
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
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, until: .now.advanced(by: .seconds(30)))
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
    func testLostDecisionProbeRetriesUntilDeadlineWithoutMutation() throws {
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
            }, capturePeer: { h.witness }, requirePeerLive: { _ in }, until: .now.advanced(by: .seconds(30)))
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
    func testNativeConstructorRefusesTheOrdinaryCallerBeforeProtectedAccess() throws {
        guard getuid() > 0, geteuid() == getuid() else { return XCTFail("This test requires the ordinary owner") }
        XCTAssertThrowsError(try RuntimeMaintenanceStartupRecovery.open(accountID: Data(repeating: 61, count: 16))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
