import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned transport controls exercise client ordering. They do not prove installed Root or native peer identity.
final class AuthorityMaintenanceClientRecoveryTests: XCTestCase, @unchecked Sendable {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private enum Fault: Error { case injected }
    private final class Trace: Sendable { let values = Mutex<[String]>([]) }
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        enum Mode: Sendable, Equatable { case normal, heldArm, lostCancel, badHello, lostReopen, lostGate, foreignEpoch, busyGate, busyThenAvailable, heldGate, unknownGate, wrongChallenge }
        struct State {
            var mode = Mode.normal, calls: [Request] = [], gates: [AuthorityMaintenanceGateRequest] = []
            var invalidated: (@Sendable () -> Void)?, held: (@Sendable (AuthorityMaintenanceClientReply) -> Void)?
        }
        let state = Mutex(State()), trace: Trace, label: String
        init(_ label: String, trace: Trace) { self.label = label; self.trace = trace }
        func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            trace.values.withLock { $0.append(label + ".hello") }
            reply(.hello(state.withLock { $0.mode == .badHello ? 1 : AuthorityMaintenanceChannelScope.protocolVersion }))
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try Request.decode(bytes), mode = state.withLock { $0.calls.append(q); return $0.mode }
                trace.values.withLock { $0.append(label + "." + String(describing: q.action)) }
                if mode == .heldArm && q.action == .arm { state.withLock { $0.held = reply }; return }
                if mode == .lostCancel && q.action == .cancel || mode == .lostReopen && q.action == .reopen { reply(.bytes(nil)); return }
                let binding = try q.binding ?? AuthorityMaintenanceBinding(accountID: q.accountID, attemptID: q.attemptID,
                    revision: q.revision, incarnation: Data(repeating: 61, count: 16), connectionID: Data(repeating: 62, count: 16))
                reply(.bytes(try AuthorityMaintenanceChannelResponse(request: q, binding: binding,
                    work: q.action == .open ? MaintenanceStopTestDriver.work() : nil, outcome: .applied).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                var q = try AuthorityMaintenanceGateRequest.decode(bytes)
                let mode = state.withLock { $0.gates.append(q); return $0.mode }; trace.values.withLock { $0.append(label + ".gate") }
                if mode == .lostGate { reply(.bytes(nil)); return }
                if mode == .wrongChallenge {
                    q = try .init(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                        installationID: q.installationID, gate: q.gate, target: q.target, challenge: Data(repeating: 99, count: 16))
                }
                reply(.bytes(try AuthorityMaintenanceGateResponse(request: q,
                    authorityIncarnation: mode == .foreignEpoch ? Data(repeating: 99, count: 16) : q.target.incarnation,
                    hold: mode == .heldGate ? .held : mode == .unknownGate ? .unknown : .released, admission: mode == .busyGate || mode == .busyThenAvailable && state.withLock({ $0.gates.count }) <= 2 ? .busy : .available).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func close() { state.withLock { $0.invalidated }?() }
        func lateReply() { state.withLock { let f=$0.held; $0.held=nil; return f }?(.bytes(nil)) }
    }
    private final class Fixture: @unchecked Sendable {
        let native: MaintenanceStopTestFixture, client: AuthorityMaintenanceXPCClient
        let trace = Trace(), row = Mutex<Record?>(nil), writes = Mutex<[Record]>([])
        let old: Driver, fresh: Driver
        let faultPhase = Mutex<Record.Phase?>(nil), commitThenFail = Mutex(false), wrongPending = Mutex(false)
        init() throws {
            native = try .init(); old = Driver("old", trace: trace); fresh = Driver("new", trace: trace)
            let q = try Request(action: .open, accountID: native.cohort.accountID, attemptID: native.window.id,
                revision: native.window.revision, installationID: native.window.scope.installationID,
                gate: native.cohort.accountIdentity, binding: nil, challenge: Data(repeating: 1, count: 32))
            client = try .openOwned(context: q, driver: old, timeoutMilliseconds: 30, intervalMilliseconds: 1)
        }
        func start() async throws -> Record {
            let opened = try await client.start(until: .now.advanced(by: .seconds(3)))
            let draining = try Record(id: native.window.id, revision: native.window.revision, purpose: .retainedRuntime,
                scope: native.window.scope, phase: .draining)
            let value = try draining.retainingShutdownBinding(opened.binding); row.withLock { $0=value }; return value
        }
        func recover(_ window: Record, deadline: ContinuousClock.Instant = .now.advanced(by: .seconds(3))) async throws -> Record {
            try await client.cancelAndReopenOwned(window: window, drain: native.drain, directory: native.directory,
                until: deadline, makeDriver: {
                    self.trace.values.withLock { $0.append("make") }; XCTAssertThrowsError(try self.native.drain.validate())
                    return self.fresh
                }, persist: { next, previous in
                    self.trace.values.withLock { $0.append("write." + String(describing: next.phase)) }
                    self.writes.withLock { $0.append(next) }; XCTAssertEqual(self.row.withLock { $0 }, previous)
                    try next.requireReplacing(previous)
                    if self.faultPhase.withLock({ $0 }) == next.phase {
                        if self.commitThenFail.withLock({ $0 }) { self.row.withLock { $0=next } }
                        throw Fault.injected
                    }
                    if next.phase == .reopenPending && self.wrongPending.withLock({ $0 }) { return previous }
                    self.row.withLock { $0=next }; return next
                })
        }
        var phases: [Record.Phase] { writes.withLock { $0.map(\.phase) } }
        var newActions: [Request.Action] { fresh.state.withLock { $0.calls.map(\.action) } }
    }
    private func expectRecovery(_ body: () async throws -> Void) async {
        do { try await body(); XCTFail("Expected owner recovery") }
        catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
    }
    func testCancelCommitsPendingBeforeOneFreshHelloReopenAndExactReadback() async throws {
        let f=try Fixture(), window=try await f.start(), restored=try await f.recover(window)
        XCTAssertEqual(f.trace.values.withLock { $0 }, ["old.hello","old.open","old.cancel","write.reopenPending","make","new.hello","new.reopen","new.gate","write.restored"])
        XCTAssertEqual(f.phases,[.reopenPending,.restored]); XCTAssertEqual(f.newActions,[.reopen])
        XCTAssertEqual(restored.phase,.restored); XCTAssertNil(restored.shutdownBinding)
        let pending=try XCTUnwrap(f.writes.withLock { $0.first }), q=try XCTUnwrap(f.fresh.state.withLock { $0.gates.first })
        XCTAssertEqual(q.revision,pending.revision); XCTAssertEqual(q.target,window.shutdownBinding)
        XCTAssertEqual(restored.gate?.requestRevision,pending.revision); XCTAssertEqual(restored.gate?.challenge.count,16)
        XCTAssertEqual(restored.gate?.responseDigest.count,32); XCTAssertEqual(restored.service,.notStopped)
        XCTAssertEqual(restored.operation,.notStarted); XCTAssertEqual(restored.scope,window.scope)
    }
    func testTimedOutArmRecoversTheSavedTargetOnceAndIgnoresTheLateReply() async throws {
        let f=try Fixture(), window=try await f.start(); f.old.state.withLock { $0.mode = .heldArm }
        await expectRecovery { _=try await f.client.arm(until:.now.advanced(by:.seconds(1))) }
        _=try await f.recover(window); f.old.lateReply()
        XCTAssertEqual(f.old.state.withLock { $0.calls.map(\.action) },[.open,.arm]); XCTAssertEqual(f.newActions,[.reopen])
        XCTAssertEqual(f.phases,[.reopenPending,.restored])
    }
    func testCancelledCallerStillJoinsBoundedCleanupWithoutReplayingArm() async throws {
        let f=try Fixture(), window=try await f.start(); f.old.state.withLock { $0.mode = .heldArm }
        let task=Task {
            do { _=try await f.client.arm(until:.now.advanced(by:.seconds(2))) } catch { }
            return try await f.recover(window)
        }
        let end=ContinuousClock.now.advanced(by:.seconds(1))
        while !f.old.state.withLock({ $0.calls.contains { $0.action == .arm } }) {
            guard .now<end else { throw Fault.injected }; try await Task.sleep(for:.milliseconds(1))
        }
        task.cancel(); let result=try await task.value; XCTAssertEqual(result.phase,.restored)
        XCTAssertEqual(f.old.state.withLock { $0.calls.map(\.action) },[.open,.arm]); XCTAssertEqual(f.newActions,[.reopen])
    }
    func testLostCancelReplyDoesNotRetryCancelOrCreateANewOpen() async throws {
        let f=try Fixture(), window=try await f.start(); f.old.state.withLock { $0.mode = .lostCancel }
        _=try await f.recover(window)
        XCTAssertEqual(f.old.state.withLock { $0.calls.map(\.action) },[.open,.cancel]); XCTAssertEqual(f.newActions,[.reopen])
    }
    func testFailedPendingCommitSendsNoRecoveryRPCAndKeepsTheDrain() async throws {
        let f=try Fixture(), window=try await f.start(); f.faultPhase.withLock { $0 = .reopenPending }
        await expectRecovery { _=try await f.recover(window) }; try f.native.drain.validate()
        XCTAssertEqual(f.phases,[.reopenPending]); XCTAssertTrue(f.newActions.isEmpty)
        XCTAssertFalse(f.trace.values.withLock { $0.contains("make") })
        await expectRecovery { _=try await f.recover(window) }; XCTAssertEqual(f.phases,[.reopenPending])
    }
    func testUncertainPendingCommitNeverRewritesOrSendsRecovery() async throws {
        let f=try Fixture(), window=try await f.start(); f.faultPhase.withLock { $0 = .reopenPending }; f.commitThenFail.withLock { $0=true }
        await expectRecovery { _=try await f.recover(window) }
        XCTAssertEqual(f.phases,[.reopenPending]); XCTAssertTrue(f.newActions.isEmpty); try f.native.drain.validate()
    }
    func testWrongPendingReadbackCannotReleaseTheDrainOrConstructATransport() async throws {
        let f=try Fixture(), window=try await f.start(); f.wrongPending.withLock { $0=true }
        await expectRecovery { _=try await f.recover(window) }; try f.native.drain.validate()
        XCTAssertFalse(f.trace.values.withLock { $0.contains("make") }); XCTAssertTrue(f.newActions.isEmpty)
    }
    func testWrongHelloVersionPersistsOwnerRecoveryWithoutReopen() async throws {
        let f=try Fixture(), window=try await f.start(); f.fresh.state.withLock { $0.mode = .badHello }
        await expectRecovery { _=try await f.recover(window) }
        XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery]); XCTAssertTrue(f.newActions.isEmpty)
    }
    func testLostReopenIsTerminalAndCannotReachReadbackOrAnotherReopen() async throws {
        let f=try Fixture(), window=try await f.start(); f.fresh.state.withLock { $0.mode = .lostReopen }
        await expectRecovery { _=try await f.recover(window) }
        XCTAssertEqual(f.newActions,[.reopen]); XCTAssertTrue(f.fresh.state.withLock { $0.gates.isEmpty })
        XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery])
    }
    func testMissingHeldUnknownForeignAndUncorrelatedGateResultsNeverRestore() async throws {
        for mode in [Driver.Mode.lostGate,.heldGate,.unknownGate,.foreignEpoch,.wrongChallenge] {
            let f=try Fixture(), window=try await f.start(); f.fresh.state.withLock { $0.mode=mode }
            await expectRecovery { _=try await f.recover(window) }
            XCTAssertEqual(f.newActions,[.reopen]); XCTAssertEqual(f.fresh.state.withLock { $0.gates.count },1)
            XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery])
            XCTAssertEqual(f.row.withLock { $0?.failure },.admissionUnconfirmed)
        }
    }
    func testUncertainRestoredCommitCannotWriteAnotherTransitionOrReplayRecovery() async throws {
        let f=try Fixture(), window=try await f.start(); f.faultPhase.withLock { $0 = .restored }; f.commitThenFail.withLock { $0=true }
        await expectRecovery { _=try await f.recover(window) }
        XCTAssertEqual(f.phases,[.reopenPending,.restored]); XCTAssertEqual(f.newActions,[.reopen])
        await expectRecovery { _=try await f.recover(window) }; XCTAssertEqual(f.phases,[.reopenPending,.restored])
    }
    func testExpiredCleanupDeadlinePersistsOwnerRecoveryWithoutSendingHello() async throws {
        let f=try Fixture(), window=try await f.start()
        await expectRecovery { _=try await f.recover(window,deadline:.now.advanced(by:.seconds(-1))) }
        XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery]); XCTAssertTrue(f.newActions.isEmpty)
        XCTAssertFalse(f.trace.values.withLock { $0.contains("new.hello") })
    }
    func testWrongPhaseCannotCancelOrWriteAndCannotBeRetried() async throws {
        let f=try Fixture(), window=try await f.start()
        let wrong=try Record(id:window.id,revision:window.revision,purpose:window.purpose,scope:window.scope,
            phase:.stopping,shutdownBinding:window.shutdownBinding)
        await expectRecovery { _=try await f.recover(wrong) }
        XCTAssertEqual(f.old.state.withLock { $0.calls.map(\.action) },[.open]); XCTAssertTrue(f.phases.isEmpty)
    }
    func testLostDrainCannotPersistOrStartTheRecoveryTransport() async throws {
        let f=try Fixture(), window=try await f.start(); f.native.drain.close()
        await expectRecovery { _=try await f.recover(window) }; XCTAssertTrue(f.phases.isEmpty)
        XCTAssertFalse(f.trace.values.withLock { $0.contains("make") })
    }
    func testOwnedTransportCannotSelectTheNativeCleanupFactory() async throws {
        let f=try Fixture(), window=try await f.start()
        do {
            _=try await f.client.cancelAndReopenNative(window:window,drain:f.native.drain,directory:f.native.directory,
                until:.now.advanced(by:.seconds(2)),persist:{ _,_ in XCTFail(); throw Fault.injected })
            XCTFail()
        } catch { XCTAssertEqual(error as? JournalLeaseError,.rootRequired) }
        XCTAssertEqual(f.old.state.withLock { $0.calls.map(\.action) },[.open]); try f.native.drain.validate()
        await f.client.close()
    }
    private final class EndpointDriver: AuthorityMaintenanceClientDriver, Sendable {
        let endpoint: AuthorityMaintenanceXPCEndpoint
        let invalidated = Mutex<(@Sendable () -> Void)?>(nil)
        init(_ endpoint: AuthorityMaintenanceXPCEndpoint) { self.endpoint=endpoint }
        func start(_ invalidated: @escaping @Sendable () -> Void) { self.invalidated.withLock { $0=invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { endpoint.hello { reply(.hello($0)) } }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { endpoint.exchange(bytes) { reply(.bytes($0)) } }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { endpoint.readGate(bytes) { reply(.bytes($0)) } }
        func close() { endpoint.close(); invalidated.withLock { $0 }?() }
    }
    private final class SQLFixture: @unchecked Sendable {
        let f: RuntimeMaintenanceWriterFixture
        let last = Mutex<Record?>(nil)
        init(_ f: RuntimeMaintenanceWriterFixture) { self.f=f }
        func write(_ next: Record, previous: Record?, drain: UpdateDrainToken? = nil) throws -> Record {
            let snapshot=try f.machine().stableMachineUpdateSnapshot(candidate:f.candidate)
            let receipt=try f.machine().writeRuntimeMaintenanceTransition(next,replacing:previous,expected:snapshot,
                candidate:f.candidate,directory:f.directory,admission:f.admission,accountDrain:drain)
            if let previous { try receipt.requireReplacement(next,replacing:previous) }
            last.withLock { $0=receipt.record }; return receipt.record
        }
        func run(readbackHold: Record.GateReadback.Hold? = nil) async throws {
            let snapshot=try f.machine().stableMachineUpdateSnapshot(candidate:f.candidate)
            let gate=try XCTUnwrap(snapshot.admission.accounts.first { $0.accountID==f.authority.accountID }).identity
            let anchor=URL(fileURLWithPath:f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease { try .init(anchor:anchor,relativeDirectory:"machine",owner:getuid()) }
            let account=try UpdateAdmissionBarrier(directory:directory(),owner:getuid(),expected:gate,scope:.account(f.authority.accountID))
            let machine=try UpdateAdmissionBarrier(directory:directory(),owner:getuid(),expected:snapshot.admission.machine)
            let unrelated=try runtimeMaintenanceFixtureRows(f.databasePath,omitMaintenance:true)
            let scope=try Record.Scope(macID:snapshot.inventory.macID,installationID:snapshot.inventory.installationID,
                authority:f.authority,target:f.target,releaseDigest:snapshot.inventory.releaseDigest,
                candidateDigest:Data(repeating:1,count:32),authorityPolicyDigest:Data(repeating:2,count:32),
                operationDigest:Data(repeating:3,count:32),restorationDigest:Data(repeating:4,count:32),
                mutationFootprintDigest:Data(repeating:5,count:32),authorityGrantDigest:Data(repeating:6,count:32),
                targetConsentDigest:Data(repeating:7,count:32),administratorIntentDigest:Data(repeating:8,count:32))
            let authorized=try Record(id:AccountPreparationIntent.randomID(),revision:AccountPreparationIntent.randomID(),purpose:.retainedRuntime,scope:scope)
            _=try write(authorized,previous:nil)
            let drain=try account.beginDrain(); defer { drain.close() }
            let draining=try Record(id:authorized.id,revision:AccountPreparationIntent.randomID(),purpose:authorized.purpose,scope:scope,phase:.draining)
            _=try write(draining,previous:authorized,drain:drain)
            let clock=try AuthorityClock(); var epoch=clock.epoch.uuid
            let incarnation=withUnsafeBytes(of:&epoch) { Data($0) }
            let pairing=try AuthorityMaintenancePairingAdmission(accountID:f.authority.accountID,incarnation:incarnation)
            let hold=AuthorityMaintenanceAdmissionHold(projection:try .init(record:draining,macID:scope.macID,
                installationID:scope.installationID,account:f.authority,registration:snapshot.admission))
            let boundary=try UpdateAdmissionBoundary(machine:machine,account:account,verifyAdmission:{ try hold.requireOpen() })
            let access=try AuthorityMaintenanceChannelAccess.openOwned(admission:pairing,check:{ q in
                let target=q.action == .reopen ? q.binding : nil
                if let target { _=try pairing.reopenTarget(matching:target) }
                let row=try self.f.machine().runtimeMaintenanceCommandRecord(q,account:self.f.authority,
                    incarnation:incarnation,armedBinding:target,candidate:self.f.candidate)
                if row.phase == .draining { try hold.retain(row) }
            },observe:{ _ in try MaintenanceStopTestDriver.work() },reopen:{ q,release in
                let target=try XCTUnwrap(q.binding)
                let row=try self.f.machine().runtimeMaintenanceCommandRecord(q,account:self.f.authority,
                    incarnation:incarnation,armedBinding:target,candidate:self.f.candidate)
                try hold.reopen(row,binding:target,incarnation:incarnation,releaseBinding:release)
            },readGate:{ q in
                let observed=try AuthorityMaintenanceGateObservation.capture(request:q,incarnation:incarnation,hold:hold,boundary:boundary,read:{
                    try self.f.machine().runtimeMaintenanceGateRecord(q,account:self.f.authority,candidate:self.f.candidate)
                })
                if let readbackHold { return try .init(request:q,authorityIncarnation:incarnation,hold:readbackHold,admission:observed.admission) }
                return observed
            })
            let first=try AuthorityMaintenanceXPCEndpoint.openOwned(access:access,budget:.init(maximum:1))
            let second=try AuthorityMaintenanceXPCEndpoint.openOwned(access:access,budget:.init(maximum:1))
            let request=try Request(action:.open,accountID:f.authority.accountID,attemptID:draining.id,revision:draining.revision,
                installationID:scope.installationID,gate:gate,binding:nil,challenge:Data(repeating:1,count:32))
            let client=try AuthorityMaintenanceXPCClient.openOwned(context:request,driver:EndpointDriver(first))
            let opened=try await client.start(until:.now.advanced(by:.seconds(5)))
            let bound=try draining.retainingShutdownBinding(opened.binding); _=try write(bound,previous:draining,drain:drain)
            let restored: Record
            do {
                restored=try await client.cancelAndReopenOwned(window:bound,drain:drain,directory:f.directory,
                    until:.now.advanced(by:.seconds(5)),makeDriver:{ EndpointDriver(second) },persist:{ next,previous in
                        try self.write(next,previous:previous)
                    })
            } catch {
                await first.closeAndWait(); await second.closeAndWait()
                guard readbackHold != nil else { throw error }
                XCTAssertEqual(error as? AuthorityMaintenanceClientError,.needsOwnerRecovery)
                let failed=try XCTUnwrap(last.withLock { $0 })
                XCTAssertEqual(failed.phase,.needsOwnerRecovery); XCTAssertEqual(failed.failure,.admissionUnconfirmed)
                try f.machine().requireRuntimeMaintenanceObservationWindow(failed,candidate:f.candidate)
                try f.reopen(nil)
                try f.machine().requireRuntimeMaintenanceObservationWindow(failed,candidate:f.candidate)
                let startup=f.machine().runtimeMaintenanceStartupProjection(account:f.authority,candidate:f.candidate)
                XCTAssertTrue(startup.requiresLocalHold); XCTAssertTrue(startup.needsOwnerRecovery)
                XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath,omitMaintenance:true),unrelated)
                hold.close(); return
            }
            XCTAssertNil(readbackHold)
            await first.closeAndWait(); await second.closeAndWait()
            XCTAssertEqual(restored.phase,.restored); XCTAssertEqual(restored.gate?.authorityIncarnation,incarnation)
            try f.machine().requireRuntimeMaintenanceObservationWindow(restored,candidate:f.candidate)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath,omitMaintenance:true),unrelated)
            XCTAssertEqual(try pairing.connectionReservations(),0)
            let admitted=try boundary.acquireAdmission(); try admitted.validate(); admitted.close(); hold.close()
        }
    }
    private func withSQLCleanup(readbackHold: Record.GateReadback.Hold? = nil) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { fixture in
            let box=SQLFixture(fixture), done=DispatchSemaphore(value:0), result=Mutex<Result<Void,Error>?>(nil)
            Task {
                do { try await box.run(readbackHold:readbackHold); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            XCTAssertEqual(done.wait(timeout:.now()+30),.success)
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    func testActualSQLiteCommitsAndKernelGatesCompleteTheOwnedClientCleanupWithoutANewReservation() throws {
        try withSQLCleanup()
    }
    func testHeldReadbackPersistsOwnerRecoveryAcrossAnActualStoreRestart() throws {
        try withSQLCleanup(readbackHold:.held)
    }
    func testUnknownReadbackPersistsOwnerRecoveryAcrossAnActualStoreRestart() throws {
        try withSQLCleanup(readbackHold:.unknown)
    }
    func testBusyThenAvailableRereadsOnOneConnectionAndSavesOnlyTheFinalReadback() async throws {
        let f=try Fixture(), window=try await f.start(); f.fresh.state.withLock { $0.mode = .busyThenAvailable }
        let restored=try await f.recover(window), gates=f.fresh.state.withLock { $0.gates }
        XCTAssertEqual(f.newActions,[.reopen]); XCTAssertEqual(f.trace.values.withLock { $0.filter { $0=="new.hello" }.count },1)
        XCTAssertEqual(gates.count,3); XCTAssertEqual(Set(gates.map(\.challenge)).count,3)
        XCTAssertEqual(Set(gates.map(\.revision)).count,1); XCTAssertTrue(gates.allSatisfy { $0.target==window.shutdownBinding })
        let last=try XCTUnwrap(gates.last)
        let expected=try AuthorityMaintenanceGateResponse(request:last,authorityIncarnation:last.target.incarnation,
            hold:.released,admission:.available).readback(expectedIncarnation:last.target.incarnation)
        XCTAssertEqual(restored.gate,expected); XCTAssertEqual(f.phases,[.reopenPending,.restored])
    }
    func testBusyUntilTheCleanupDeadlinePersistsOwnerRecoveryWithOnlyOneReopen() async throws {
        let f=try Fixture(), window=try await f.start(); f.fresh.state.withLock { $0.mode = .busyGate }
        let began=ContinuousClock.now
        await expectRecovery { _=try await f.recover(window,deadline:began.advanced(by:.milliseconds(150))) }
        XCTAssertLessThan(began.duration(to:.now),.seconds(1)); XCTAssertEqual(f.newActions,[.reopen])
        XCTAssertEqual(f.trace.values.withLock { $0.filter { $0=="new.hello" }.count },1)
        let gates=f.fresh.state.withLock { $0.gates }; XCTAssertGreaterThan(gates.count,1)
        XCTAssertEqual(Set(gates.map(\.challenge)).count,gates.count)
        XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery]); XCTAssertEqual(f.row.withLock { $0?.failure },.admissionUnconfirmed)
    }
}
