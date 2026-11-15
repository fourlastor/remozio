import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class RestorationTestWitness: RuntimeJobExitWitness, Sendable {
    let processID: pid_t
    let exited = Mutex(false)
    init(_ processID: pid_t) { self.processID = processID }
    func hasExited() throws -> Bool { exited.withLock { $0 } }
}

/// Owned stop, body and restoration with real owned admission files and real Authority store locks.
/// Rows are record-only here; the real writer and floor reader are covered in RuntimeMaintenanceRestorationFloorTests.
private final class RestorationHarness: @unchecked Sendable {
    typealias Record = RuntimeMaintenanceWindowRecord
    let f: MaintenanceStopTestFixture, client: AuthorityMaintenanceXPCClient
    let capture: RuntimeMaintenanceStopCapture, file: MaintenanceCloseFileFixture, stores: MaintenanceBodyStores
    let process = RestorationTestWitness(200)
    var observation: RuntimeJobStopSession.Observation = .matching(100)
    var bodyCalls = 0, bootstraps = 0, inspections = 0, floorReads = 0, windowReads = 0, observed: [pid_t] = []
    var failClose = false, failFloors = false, faultPhase: Record.Phase?
    var onBootstrap: () throws -> Void = {}
    var onRestorationCallback: () throws -> Void = {}
    var row: Record?, writes: [Record] = []
    init(purpose: Record.Purpose = .retainedRuntime) async throws {
        let f = try MaintenanceStopTestFixture(purpose: purpose), client = try f.client()
        self.f = f; self.client = client; capture = try await f.capture(client)
        file = try .init(); try file.publish(capture.marker)
        stores = try .init(mac: f.window.scope.macID, account: f.cohort.accountID, policy: f.runtime.plan.host.codePolicy)
    }
    deinit { try? file.close() }
    var probe: UpdateAdmissionBarrier { get throws {
        try .init(directory: .init(anchor: f.files.activity.root.path, relativeDirectory: "Machine", owner: getuid()),
            owner: getuid(), expected: f.cohort.accountIdentity, scope: .account(f.cohort.accountID))
    } }
    var phases: [Record.Phase] { writes.map(\.phase) }
    func pair(_ policy: AuthorityCodePolicy) throws -> AuthorityJournalCutoverInspection {
        let storage = try AuthorityStorage(openJournal: { try self.stores.openJournal(readOnly: true) },
            openContinuity: { try self.stores.openContinuity(excluding: $0, readOnly: true) })
        guard failClose else { return try .init(storage: storage, expectedPolicy: policy, verifyCurrent: {}) }
        return try .openOwned(storage: storage, expectedPolicy: policy, verifyCurrent: {}, closeStorage: {
            try $0.close(); throw MaintenanceStopTestFault.expected
        })
    }
    /// Stops the owned job and runs one body inside the machine loan. The stop owner stays open for restoration.
    func stopAndRunBody(throwing: Bool = false) throws -> RuntimeMaintenanceAuthorityStop {
        let permit = try RuntimeMaintenanceStopPermit.openOwned(capture: capture, until: .now.advanced(by: .seconds(5)),
            readMarker: { try self.file.readback(self.capture.marker) })
        return try f.ordinary.withMachineAdmission { scope in
            let stop = try RuntimeMaintenanceAuthorityStop.openOwnedBound(permit: permit, purpose: f.window.purpose, cohort: f.cohort,
                scope: scope, drain: f.drain, directory: f.directory, inspect: { self.observation }, remove: {
                    self.observation = .absent; self.f.witness.exited.withLock { $0 = true }
                }, openPair: { _, policy in try self.pair(policy) })
            XCTAssertEqual(try stop.poll(), .registrationRemoved); try stop.requireRemoved()
            do {
                _ = try stop.withNativeBody(purpose: f.window.purpose, initialization: f.initialization,
                    policy: f.runtime.plan.host.codePolicy) { _ -> Int in
                    self.bodyCalls += 1; if throwing { throw MaintenanceStopTestFault.expected }; return 7
                }
                XCTAssertFalse(throwing || failClose)
            } catch { XCTAssertTrue(throwing || failClose) }
            return stop
        }
    }
    func executing() throws -> Record {
        let w = capture.window
        let value = try Record(id: w.id, revision: maintenanceCloseBytes(120), purpose: w.purpose, scope: w.scope, phase: .executing,
            operation: .unknown, service: .stopped, shutdownBinding: w.shutdownBinding)
        row = value; return value
    }
    func persist(_ next: Record, _ previous: Record) throws -> Record {
        XCTAssertEqual(row, previous); try next.requireReplacing(previous); writes.append(next)
        if faultPhase == next.phase { throw MaintenanceStopTestFault.expected }
        row = next; return next
    }
    func restore(_ stop: RuntimeMaintenanceAuthorityStop, operation: Record.OperationOutcome = .committed) throws -> RuntimeMaintenanceRestoration {
        try RuntimeMaintenanceRestoration.openOwned(stop: stop, executing: executing(), operation: operation, admission: f.ordinary,
            persist: { next, previous in try self.persist(next, previous) }, requireWindow: { window in
                try self.onRestorationCallback(); XCTAssertEqual(window, self.row); self.windowReads += 1
            }, inspect: {
                try self.onRestorationCallback(); self.inspections += 1; return self.observation
            }, bootstrap: {
                try self.onRestorationCallback(); self.bootstraps += 1; try self.onBootstrap(); self.observation = .matching(self.process.processID)
            }, observe: { pid in
                try self.onRestorationCallback(); self.observed.append(pid); return self.process
            }, floors: { _ in
                try self.onRestorationCallback(); self.floorReads += 1; if self.failFloors { throw MaintenanceStopTestFault.expected }
            })
    }
    func healthyBinding(_ restoration: RuntimeMaintenanceRestoration, incarnation: Data = maintenanceCloseBytes(130)) throws -> AuthorityMaintenanceBinding {
        try .init(accountID: f.cohort.accountID, attemptID: restoration.window.id, revision: restoration.window.revision,
            incarnation: incarnation, connectionID: maintenanceCloseBytes(131))
    }
    func rows(_ stop: RuntimeMaintenanceAuthorityStop) throws -> (settled: Record, restoring: Record) {
        let e = try executing(), binding = capture.window.shutdownBinding
        let settled = try Record(id: e.id, revision: maintenanceCloseBytes(121), purpose: e.purpose, scope: e.scope, phase: .workSettled,
            operation: .committed, service: .stopped, shutdownBinding: binding)
        let restoring = try Record(id: e.id, revision: maintenanceCloseBytes(122), purpose: e.purpose, scope: e.scope, phase: .restoring,
            operation: .committed, service: .restartPending, shutdownBinding: binding)
        return (settled, restoring)
    }
}

final class RuntimeMaintenanceRestorationTests: XCTestCase, @unchecked Sendable {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private func expectRecovery(_ body: () throws -> Void) {
        XCTAssertThrowsError(try body()) { XCTAssertEqual($0 as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
    }

    func testFullChainReachesTheHealthyPendingRowUnderTheHeldDrainAfterTheBodyPairCloses() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        XCTAssertEqual(stop.bodyPairClose, .closed); XCTAssertTrue(stop.restorationReady)
        // Every restoration callback runs while Setup holds the account EX drain and nobody holds A's writer locks.
        h.onRestorationCallback = {
            try h.f.drain.validate(); try h.stores.requireReleased()
        }
        h.onBootstrap = {
            XCTAssertThrowsError(try h.probe.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        }
        let r = try h.restore(stop)
        XCTAssertEqual(h.phases, [.workSettled, .restoring]); XCTAssertEqual(h.bootstraps, 1); XCTAssertEqual(h.floorReads, 1)
        XCTAssertGreaterThan(h.windowReads, 0); XCTAssertEqual(r.window, h.row); XCTAssertEqual(r.window.phase, .restoring)
        XCTAssertEqual(r.stoppedBinding, h.capture.window.shutdownBinding); XCTAssertEqual(r.window.operation, .committed)
        // The post-construction methods run off the original thread after the stop owner and its boundary are retired.
        stop.close(); XCTAssertThrowsError(try stop.poll())
        let pending = try await Task.detached { () throws -> Record in
            XCTAssertThrowsError(try r.requireWitnessLive())
            let q = try r.openRequest(challenge: maintenanceCloseBytes(132, 32))
            XCTAssertEqual(q.action, .open); XCTAssertNil(q.binding); XCTAssertEqual(q.revision, r.window.revision)
            XCTAssertEqual(q.attemptID, r.window.id); XCTAssertEqual(q.gate, h.f.cohort.accountIdentity)
            try r.acceptWitness(h.process); try r.requireWitnessLive(); XCTAssertEqual(h.observed, [200])
            try r.validateBeforePending(); try r.validateBeforePending(); XCTAssertEqual(h.floorReads, 3)
            XCTAssertThrowsError(try r.requireHealthyBinding(h.healthyBinding(r, incarnation: r.stoppedBinding.incarnation)))
            return try r.pendingRecord(binding: h.healthyBinding(r))
        }.value
        XCTAssertEqual(pending.phase, .reopenPending); XCTAssertEqual(pending.service, .healthy)
        XCTAssertEqual(pending.shutdownBinding, r.stoppedBinding); XCTAssertEqual(pending.operation, .committed)
        try pending.requireReplacing(r.window)
        XCTAssertThrowsError(try r.pendingRecord(binding: h.healthyBinding(r)))
        XCTAssertThrowsError(try r.commitOwnerRecovery(.healthFailed)); XCTAssertEqual(h.phases, [.workSettled, .restoring])
        XCTAssertThrowsError(try r.releaseOwnedDrain(after: r.window)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try h.f.drain.validate(); XCTAssertThrowsError(try h.probe.acquireAdmission())
        try r.releaseOwnedDrain(after: pending)
        XCTAssertThrowsError(try h.f.drain.validate()); let admitted = try h.probe.acquireAdmission(); admitted.close()
        XCTAssertThrowsError(try r.releaseOwnedDrain(after: pending)); XCTAssertThrowsError(try r.validateBeforePending())
        XCTAssertEqual(h.bodyCalls, 1); XCTAssertEqual(h.bootstraps, 1)
        try r.requireWitnessLive(); h.process.exited.withLock { $0 = true }; XCTAssertThrowsError(try r.requireWitnessLive())
        await h.client.close()
    }

    func testUnsupportedPurposeCannotSettleOrRegisterRestoration() async throws {
        let h = try await RestorationHarness(purpose: .retainedPolicy), stop = try h.stopAndRunBody()
        defer { stop.close() }
        XCTAssertThrowsError(try h.restore(stop)) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        XCTAssertTrue(h.writes.isEmpty); XCTAssertEqual(h.bootstraps, 0); XCTAssertEqual(h.bodyCalls, 1)
        try h.f.drain.validate(); await h.client.close()
    }
    func testFailedDrainValidationDoesNotConsumeTheRelease() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        let owner = try h.restore(stop); try owner.acceptWitness(h.process)
        let pending = try owner.pendingRecord(binding: h.healthyBinding(owner))
        h.f.witness.failNextPoll.withLock { $0 = true }
        XCTAssertThrowsError(try owner.releaseOwnedDrain(after: pending)) {
            XCTAssertEqual($0 as? MaintenanceStopTestFault, .expected)
        }
        try h.f.drain.validate()
        try owner.releaseOwnedDrain(after: pending)
        XCTAssertThrowsError(try h.f.drain.validate())
        XCTAssertThrowsError(try owner.releaseOwnedDrain(after: pending))
        await h.client.close()
    }
    func testExactOwnerContextMismatchWritesRecoveryBeforeAnyDriverIsCreated() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        let owner = try h.restore(stop)
        let context = try owner.openRequest(challenge: maintenanceCloseBytes(133, 32))
        let wrong = try AuthorityMaintenanceChannelRequest(action: .open, accountID: context.accountID,
            attemptID: context.attemptID, revision: context.revision, installationID: context.installationID,
            gate: .init(device: context.gate.device, inode: context.gate.inode + 1), binding: nil, challenge: context.challenge)
        let client = try AuthorityMaintenanceXPCClient.openOwned(context: wrong, driver: MaintenanceStopTestDriver())
        do {
            _ = try await client.restoreHealthyOwned(owner: owner, until: .now.advanced(by: .seconds(1)),
                makeDriver: { XCTFail("No replacement driver before a context match"); throw MaintenanceStopTestFault.expected },
                capturePeer: { _ in XCTFail("No peer before a context match"); return h.process },
                persist: { next, previous in try h.persist(next, previous) })
            XCTFail("Expected owner recovery")
        } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
        XCTAssertEqual(h.phases, [.workSettled, .restoring, .needsOwnerRecovery])
        XCTAssertEqual(h.writes.last?.failure, .changedScope)
        XCTAssertThrowsError(try owner.commitOwnerRecovery(.healthFailed))
        try h.f.drain.validate(); await h.client.close(); await client.close()
    }
    func testNativeUsageRefusalDoesNotWriteAnOwnerRecoveryRow() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        let owner = try h.restore(stop), before = h.phases
        do {
            _ = try await h.client.restoreHealthyNative(owner: owner, until: .now.advanced(by: .seconds(1)),
                persist: { _, _ in XCTFail("No native writer for an ordinary owner"); throw MaintenanceStopTestFault.expected })
            XCTFail("Expected Root refusal")
        } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(h.phases, before); try h.f.drain.validate(); await h.client.close()
    }
    func testOffThreadOwnerCloseInvalidatesThePermitAndKeepsTheDrain() async throws {
        final class Box: @unchecked Sendable {
            let stop: RuntimeMaintenanceAuthorityStop
            init(_ stop: RuntimeMaintenanceAuthorityStop) { self.stop = stop }
        }
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(), box = Box(stop)
        let rows = try h.rows(stop)
        XCTAssertTrue(try stop.beginRestoration())
        let permit = try stop.issueOwnedRestorationPermit(restoring: rows.restoring, replacing: rows.settled, admission: h.f.ordinary)
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { box.stop.close(); finished.signal() }
        XCTAssertEqual(finished.wait(timeout: .now() + 3), .success)
        XCTAssertThrowsError(try permit.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try h.f.drain.validate(); await h.client.close()
    }
    func testRecoveryBeforePendingRunsFromAnotherThreadAndExpiredDrainRefusesValidation() async throws {
        final class Box: @unchecked Sendable {
            let r: RuntimeMaintenanceRestoration, done = DispatchSemaphore(value: 0), result = Mutex<Error?>(nil)
            init(_ r: RuntimeMaintenanceRestoration) { self.r = r }
        }
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(), box = Box(try h.restore(stop))
        stop.close()
        DispatchQueue.global().async {
            do { try box.r.validateBeforePending(); try box.r.commitOwnerRecovery(.healthFailed) }
            catch { box.result.withLock { $0 = error } }
            box.done.signal()
        }
        XCTAssertEqual(box.done.wait(timeout: .now() + 3), .success); XCTAssertNil(box.result.withLock { $0 })
        XCTAssertEqual(h.phases, [.workSettled, .restoring, .needsOwnerRecovery]); XCTAssertEqual(h.writes.last?.failure, .healthFailed)
        XCTAssertThrowsError(try box.r.commitOwnerRecovery(.healthFailed)); XCTAssertEqual(h.writes.count, 3)
        h.f.drain.close(); XCTAssertThrowsError(try box.r.validateBeforePending()); await h.client.close()
    }

    func testForcedCloseFailureAfterASuccessfulOrThrowingBodyBlocksRegistrationAndRecordsRecoveryOnce() async throws {
        for throwing in [false, true] {
            let h = try await RestorationHarness(); h.failClose = true
            let stop = try h.stopAndRunBody(throwing: throwing); defer { stop.close() }
            XCTAssertEqual(stop.bodyPairClose, .failed); XCTAssertFalse(stop.restorationReady)
            try h.stores.requireReleased()
            expectRecovery { _ = try h.restore(stop) }
            XCTAssertEqual(h.phases, [.needsOwnerRecovery]); XCTAssertEqual(h.writes.first?.failure, .cleanupPending)
            XCTAssertEqual(h.writes.first?.service, .stopped); XCTAssertEqual(h.bootstraps, 0); XCTAssertEqual(h.inspections, 0)
            let (settled, restoring) = try h.rows(stop)
            XCTAssertThrowsError(try stop.issueOwnedRestorationPermit(restoring: restoring, replacing: settled, admission: h.f.ordinary))
            XCTAssertThrowsError(try stop.withNativeBody(purpose: h.f.window.purpose, initialization: h.f.initialization,
                policy: h.f.runtime.plan.host.codePolicy) { _ in XCTFail() })
            XCTAssertThrowsError(try h.restore(stop)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(h.writes.count, 1)
            XCTAssertEqual(h.bodyCalls, 1); await h.client.close()
        }
    }

    func testPermitRefusesWrongAttemptAccountAndRowWithoutASecondIssue() async throws {
        for kind in 0..<3 {
            let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
            var (settled, restoring) = try h.rows(stop)
            let s = restoring.scope
            switch kind {
            case 0:
                restoring = try Record(id: maintenanceCloseBytes(141), revision: restoring.revision, purpose: restoring.purpose, scope: s,
                    phase: .restoring, operation: .committed, service: .restartPending)
            case 1:
                let other = try Record.Account(accountID: maintenanceCloseBytes(142), ownerUID: s.authority.ownerUID + 7, directoryID: maintenanceCloseBytes(143))
                let scope = try Record.Scope(macID: s.macID, installationID: s.installationID, authority: other, target: s.target,
                    releaseDigest: s.releaseDigest, candidateDigest: s.candidateDigest, authorityPolicyDigest: s.authorityPolicyDigest,
                    operationDigest: s.operationDigest, restorationDigest: s.restorationDigest, mutationFootprintDigest: s.mutationFootprintDigest,
                    authorityGrantDigest: s.authorityGrantDigest, targetConsentDigest: s.targetConsentDigest, administratorIntentDigest: s.administratorIntentDigest)
                restoring = try Record(id: restoring.id, revision: restoring.revision, purpose: restoring.purpose, scope: scope,
                    phase: .restoring, operation: .committed, service: .restartPending)
            default:
                settled = try Record(id: settled.id, revision: settled.revision, purpose: settled.purpose, scope: settled.scope,
                    phase: .stopped, service: .stopped, shutdownBinding: settled.shutdownBinding)
            }
            XCTAssertThrowsError(try stop.issueOwnedRestorationPermit(restoring: restoring, replacing: settled, admission: h.f.ordinary))
            let valid = try h.rows(stop)
            XCTAssertThrowsError(try stop.issueOwnedRestorationPermit(restoring: valid.restoring, replacing: valid.settled, admission: h.f.ordinary)) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            XCTAssertEqual(h.bootstraps, 0); await h.client.close()
        }
    }

    func testPermitIsSingleUseAndRefusesAnotherThreadAForkAndAClosedOwner() async throws {
        final class Transfer: @unchecked Sendable {
            let permit: RuntimeMaintenanceRestorationPermit, done = DispatchSemaphore(value: 0), rejected = Mutex(false)
            init(_ permit: RuntimeMaintenanceRestorationPermit) { self.permit = permit }
        }
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody()
        let (settled, restoring) = try h.rows(stop)
        let permit = try stop.issueOwnedRestorationPermit(restoring: restoring, replacing: settled, admission: h.f.ordinary)
        try permit.validate(); XCTAssertFalse(stop.restorationReady)
        let transfer = Transfer(permit)
        DispatchQueue.global().async {
            do { try transfer.permit.validate() } catch { transfer.rejected.withLock { $0 = true } }
            transfer.done.signal()
        }
        XCTAssertEqual(transfer.done.wait(timeout: .now() + 3), .success); XCTAssertTrue(transfer.rejected.withLock { $0 })
        let child = Self.forkProcess(); XCTAssertGreaterThanOrEqual(child, 0)
        if child == 0 { do { try permit.validate(); _exit(11) } catch { _exit(0) } }
        guard child > 0 else { throw MaintenanceStopTestFault.expected }
        var status: Int32 = 0
        while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        XCTAssertEqual(status, 0)
        var registrations = 0
        try RuntimeJobRegistration.reconcileOwnedRestoration(permit, requireWindow: { XCTAssertEqual($0, restoring) },
            inspect: { registrations == 0 ? .absent : .matching }, bootstrap: { registrations += 1 })
        XCTAssertEqual(registrations, 1)
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcileOwnedRestoration(permit, requireWindow: { _ in XCTFail() },
            inspect: { XCTFail(); return .absent }, bootstrap: { XCTFail() })) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try permit.validate(); stop.close()
        XCTAssertThrowsError(try permit.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try h.f.drain.validate(); await h.client.close()
    }
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is unavailable") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()

    func testAlreadyRegisteredJobIsNotAdoptedAndRecordsRecoveryOnce() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        h.observation = .matching(nil)
        expectRecovery { _ = try h.restore(stop) }
        XCTAssertEqual(h.phases, [.workSettled, .restoring, .needsOwnerRecovery]); XCTAssertEqual(h.bootstraps, 0)
        XCTAssertEqual(h.writes.last?.failure, .serviceUnavailable); XCTAssertEqual(h.writes.last?.service, .unknown)
        XCTAssertEqual(h.bodyCalls, 1); await h.client.close()
    }

    func testFailedOrUncertainRestoringCommitSendsNothingFurther() async throws {
        for phase in [Record.Phase.workSettled, .restoring] {
            let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
            h.faultPhase = phase
            expectRecovery { _ = try h.restore(stop) }
            XCTAssertEqual(h.phases.last, phase); XCTAssertFalse(h.phases.contains(.needsOwnerRecovery))
            XCTAssertEqual(h.bootstraps, 0); XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.floorReads, 0)
            try h.f.drain.validate(); await h.client.close()
        }
    }

    func testChangedFloorsAfterRegistrationRecordRecoveryOnceAndIssueNoPendingRow() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        h.failFloors = true
        expectRecovery { _ = try h.restore(stop) }
        XCTAssertEqual(h.phases, [.workSettled, .restoring, .needsOwnerRecovery]); XCTAssertEqual(h.bootstraps, 1)
        XCTAssertEqual(h.writes.last?.failure, .changedScope); XCTAssertEqual(h.writes.last?.service, .registered)
        XCTAssertEqual(h.bodyCalls, 1); await h.client.close()
    }

    func testOldPIDStalePeerAndForeignPIDWitnessesAreRefused() async throws {
        for kind in 0..<4 {
            let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
            let r = try h.restore(stop), peer: RestorationTestWitness
            switch kind {
            case 0: peer = RestorationTestWitness(100)
            case 1: peer = RestorationTestWitness(200); peer.exited.withLock { $0 = true }
            case 2: peer = RestorationTestWitness(201)
            default: peer = h.process; h.observation = .matching(nil)
            }
            XCTAssertThrowsError(try r.acceptWitness(peer)); XCTAssertThrowsError(try r.requireWitnessLive())
            XCTAssertThrowsError(try r.pendingRecord(binding: h.healthyBinding(r)))
            try r.commitOwnerRecovery(.healthFailed)
            XCTAssertThrowsError(try r.acceptWitness(h.process)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(h.phases, [.workSettled, .restoring, .needsOwnerRecovery]); XCTAssertEqual(h.writes.last?.service, .registered)
            XCTAssertThrowsError(try r.commitOwnerRecovery(.healthFailed)); XCTAssertEqual(h.writes.count, 3)
            XCTAssertEqual(h.bootstraps, 1); await h.client.close()
        }
    }

    func testExpiredCaptureOwnerIsNotReusedForRestorationIssuanceOrRegistration() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        h.f.ownerValid.withLock { $0 = false }
        XCTAssertThrowsError(try h.capture.validate())
        let owner = try h.restore(stop)
        try owner.validateBeforePending(); XCTAssertEqual(h.bootstraps, 1); XCTAssertEqual(h.bodyCalls, 1)
        await h.client.close()
    }
    func testRejectedOldWitnessCanBeReplacedByOneNewWitnessBeforePending() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        let owner = try h.restore(stop)
        XCTAssertThrowsError(try owner.acceptWitness(RestorationTestWitness(100)))
        try owner.acceptWitness(h.process); try owner.requireWitnessLive()
        XCTAssertThrowsError(try owner.acceptWitness(h.process))
        XCTAssertEqual(try owner.pendingRecord(binding: h.healthyBinding(owner)).phase, .reopenPending)
        XCTAssertEqual(h.bootstraps, 1); await h.client.close()
    }
    func testOwnedRestorationCannotSelectNativeEntries() async throws {
        let h = try await RestorationHarness(), stop = try h.stopAndRunBody(); defer { stop.close() }
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { fixture in
            let expected = try fixture.machine().stableMachineUpdateSnapshot(candidate: fixture.candidate)
            XCTAssertThrowsError(try RuntimeMaintenanceRestoration.openNative(stop: stop, executing: h.executing(), operation: .committed,
                admission: h.f.ordinary, release: fixture.candidate, expected: expected,
                persist: { _, _ in XCTFail("Root persistence must remain unreachable"); throw MaintenanceStopTestFault.expected })) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
        }
        XCTAssertTrue(h.writes.isEmpty); XCTAssertTrue(stop.restorationReady); await h.client.close()
    }
}

/// Real SQLite rows through the real writer. The receipt binds restoring to the exact workSettled row; floors read the actual frame.
final class RuntimeMaintenanceRestorationFloorTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private typealias Receipt = PreparationIntentStore.RuntimeMaintenanceTransition
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func write(_ row: Row, previous: Row?, f: RuntimeMaintenanceWriterFixture, drain: UpdateDrainToken? = nil) throws -> Receipt {
        try f.machine().writeRuntimeMaintenanceTransition(row, replacing: previous,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain)
    }
    func testRealRestoringReceiptAndFloorsReadTheActualStore() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let authorized = try Row(id: bytes(51), revision: bytes(52), purpose: .retainedRuntime,
                scope: .init(macID: before.inventory.macID, installationID: before.inventory.installationID,
                    authority: f.authority, target: f.target, releaseDigest: before.inventory.releaseDigest,
                    candidateDigest: bytes(1, 32), authorityPolicyDigest: bytes(2, 32), operationDigest: bytes(3, 32),
                    restorationDigest: bytes(4, 32), mutationFootprintDigest: bytes(5, 32), authorityGrantDigest: bytes(6, 32),
                    targetConsentDigest: bytes(7, 32), administratorIntentDigest: bytes(8, 32)))
            _ = try write(authorized, previous: nil, f: f)
            let gate = try XCTUnwrap(before.admission.accounts.first { $0.accountID == f.authority.accountID })
            let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
            let barrier = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                owner: getuid(), expected: gate.identity, scope: .account(gate.accountID))
            let drain = try barrier.beginDrain(); defer { drain.close() }
            let draining = try Row(id: authorized.id, revision: bytes(53), purpose: authorized.purpose, scope: authorized.scope, phase: .draining)
            _ = try write(draining, previous: authorized, f: f, drain: drain)
            let binding = try AuthorityMaintenanceBinding(accountID: f.authority.accountID, attemptID: authorized.id,
                revision: draining.revision, incarnation: bytes(54), connectionID: bytes(55))
            var previous = try f.machine().persistRuntimeMaintenanceBindingTransition(binding, window: draining,
                expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
                directory: f.directory, admission: f.admission, accountDrain: drain).record
            var receipts: [Row.Phase: Receipt] = [:]
            for phase in [Row.Phase.stopping, .stopped, .executing, .workSettled, .restoring] {
                let operation: Row.OperationOutcome = phase == .executing ? .unknown : [.stopping, .stopped].contains(phase) ? .notStarted : .committed
                let service: Row.ServiceOutcome = phase == .stopping ? .notStopped : phase == .restoring ? .restartPending : .stopped
                let row = try Row(id: previous.id, revision: AccountPreparationIntent.randomID(), purpose: previous.purpose,
                    scope: previous.scope, phase: phase, operation: operation, service: service, shutdownBinding: binding)
                receipts[phase] = try write(row, previous: previous, f: f); previous = row
            }
            let settled = try XCTUnwrap(receipts[.workSettled]).record, restoring = try XCTUnwrap(receipts[.restoring])
            try restoring.requireReplacement(restoring.record, replacing: settled)
            XCTAssertThrowsError(try restoring.requireReplacement(restoring.record, replacing: XCTUnwrap(receipts[.executing]).record))
            XCTAssertThrowsError(try XCTUnwrap(receipts[.workSettled]).requireReplacement(restoring.record, replacing: settled))
            func floors(_ window: Row, machine: PreparationFileIdentity? = nil, account: PreparationFileIdentity? = nil) throws {
                try RuntimeMaintenanceRestoration.requireFloors(machine: f.machine(), release: f.candidate, window: window,
                    expected: before, machineIdentity: machine ?? before.admission.machine, accountID: f.authority.accountID,
                    accountIdentity: account ?? gate.identity)
            }
            try floors(restoring.record); try floors(restoring.record)
            XCTAssertThrowsError(try floors(restoring.record, machine: gate.identity))
            XCTAssertThrowsError(try floors(restoring.record, account: before.admission.machine))
            XCTAssertThrowsError(try floors(settled))
            let failed = try Row(id: restoring.record.id, revision: AccountPreparationIntent.randomID(), purpose: restoring.record.purpose,
                scope: restoring.record.scope, phase: .needsOwnerRecovery, operation: .committed, service: .registered,
                failure: .changedScope, shutdownBinding: binding)
            _ = try write(failed, previous: restoring.record, f: f)
            XCTAssertThrowsError(try floors(restoring.record)); try floors(failed)
        }
    }
}
