import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned locks and injected transport exercise ordering. Native code identity and floor checks remain separate gates.
final class AuthorityMaintenanceHealthyClientTests: XCTestCase, @unchecked Sendable {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private enum Fault: Error { case injected }
    private final class Trace: Sendable { let values = Mutex<[String]>([]) }
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        struct State { var calls: [Request] = [], gates: [AuthorityMaintenanceGateRequest] = [] }
        let state = Mutex(State()), trace: Trace, epoch: Data, refused: Bool
        let lostReopen: Bool, lostOpen: Bool, hold: Record.GateReadback.Hold, busyCount: Int
        init(trace: Trace, epoch: Data, refused: Bool, lostReopen: Bool, lostOpen: Bool = false, hold: Record.GateReadback.Hold, busyCount: Int) {
            self.trace=trace; self.epoch=epoch; self.refused=refused; self.lostReopen=lostReopen; self.lostOpen=lostOpen; self.hold=hold; self.busyCount=busyCount
        }
        func start(_ invalidated: @escaping @Sendable () -> Void) { }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            trace.values.withLock { $0.append("hello") }; reply(.hello(1))
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try Request.decode(bytes); state.withLock { $0.calls.append(q) }
                trace.values.withLock { $0.append(String(describing: q.action)) }
                if q.action == .open && lostOpen { reply(.bytes(nil)); return }
                if q.action == .reopen && lostReopen { reply(.bytes(nil)); return }
                let binding = try q.binding ?? .init(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                    incarnation: epoch, connectionID: AccountPreparationIntent.randomID())
                let reject = q.action == .open && refused
                reply(.bytes(try AuthorityMaintenanceChannelResponse(request: q, binding: binding,
                    work: q.action == .open && !reject ? MaintenanceStopTestDriver.work() : nil,
                    outcome: reject ? .refused : .applied).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try AuthorityMaintenanceGateRequest.decode(bytes)
                let count = state.withLock { $0.gates.append(q); return $0.gates.count }
                trace.values.withLock { $0.append("gate") }
                reply(.bytes(try AuthorityMaintenanceGateResponse(request: q, authorityIncarnation: epoch, hold: hold,
                    admission: count <= busyCount ? .busy : .available).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func close() { }
    }
    private final class Fixture: @unchecked Sendable {
        let native: MaintenanceStopTestFixture, restoring: Record, client: AuthorityMaintenanceXPCClient
        let trace = Trace(), row: Mutex<Record>, writes = Mutex<[Record]>([]), drivers = Mutex<[Driver]>([])
        let faultPhase = Mutex<Record.Phase?>(nil), commitThenFail = Mutex(false), peerFailure = Mutex(false)
        let refuseCount = Mutex(0), lostOpenCount = Mutex(0), sameEpoch = Mutex(false), lostReopen = Mutex(false), busyCount = Mutex(0)
        let hold = Mutex(Record.GateReadback.Hold.released)
        let invalidPending = Mutex(false), ownerRecoveryCalls = Mutex(0)
        init() throws {
            native = try .init()
            let w=native.window, binding=try AuthorityMaintenanceBinding(accountID: w.scope.authority.accountID,
                attemptID: w.id, revision: AccountPreparationIntent.randomID(), incarnation: Data(repeating: 71,count:16),
                connectionID: AccountPreparationIntent.randomID())
            restoring=try Record(id:w.id,revision:AccountPreparationIntent.randomID(),purpose:.retainedRuntime,scope:w.scope,
                phase:.restoring,operation:.committed,service:.restartPending,shutdownBinding:binding)
            row=Mutex(restoring)
            let q=try Request(action:.open,accountID:w.scope.authority.accountID,attemptID:w.id,revision:restoring.revision,
                installationID:w.scope.installationID,gate:native.cohort.accountIdentity,binding:nil,
                challenge:AccountPreparationIntent.randomID()+AccountPreparationIntent.randomID())
            let idle=Driver(trace:trace,epoch:Data(repeating:72,count:16),refused:false,lostReopen:false,hold:.released,busyCount:0)
            client=try .openOwned(context:q,driver:idle,timeoutMilliseconds:100,intervalMilliseconds:1)
        }
        func run(until deadline: ContinuousClock.Instant = .now.advanced(by:.seconds(3))) async throws -> Record {
            try await client.restoreHealthyOwned(window:restoring,drain:native.drain,directory:native.directory,until:deadline,
                makeDriver:{
                    let count=self.drivers.withLock { $0.count }
                    let d=Driver(trace:self.trace,epoch:self.sameEpoch.withLock({$0}) ? self.restoring.shutdownBinding!.incarnation : Data(repeating:72,count:16),
                        refused:count < self.refuseCount.withLock({$0}),lostReopen:self.lostReopen.withLock({$0}),lostOpen:count < self.lostOpenCount.withLock({$0}),
                        hold:self.hold.withLock({$0}),busyCount:self.busyCount.withLock({$0}))
                    self.drivers.withLock { $0.append(d) };return d
                },verifyScope:{
                    try self.native.drain.validate();XCTAssertEqual(self.row.withLock({$0}),self.restoring)
                },preparePeer:{ _ in
                    self.trace.values.withLock { $0.append("peer") }
                    if self.peerFailure.withLock({$0}) { throw Fault.injected }
                },requirePeerLive:{
                    if self.peerFailure.withLock({$0}) { throw Fault.injected }
                },makePending:{ window, _ in
                    try Record(id:window.id,revision:self.invalidPending.withLock({$0}) ? window.revision : AccountPreparationIntent.randomID(),
                        purpose:window.purpose,scope:window.scope,phase:.reopenPending,operation:window.operation,service:.healthy,
                        shutdownBinding:window.shutdownBinding)
                },recoverRestoring:{ failure in
                    self.ownerRecoveryCalls.withLock {$0+=1}
                    self.trace.values.withLock {$0.append("write.needsOwnerRecovery")}
                    let failed=try Record(id:self.restoring.id,revision:AccountPreparationIntent.randomID(),purpose:self.restoring.purpose,
                        scope:self.restoring.scope,phase:.needsOwnerRecovery,operation:self.restoring.operation,service:self.restoring.service,
                        failure:failure,shutdownBinding:self.restoring.shutdownBinding)
                    self.writes.withLock {$0.append(failed)};self.row.withLock {$0=failed}
                },persist:{ next, previous in
                    self.trace.values.withLock { $0.append("write."+String(describing:next.phase)) }
                    self.writes.withLock { $0.append(next) };XCTAssertEqual(self.row.withLock({$0}),previous)
                    try next.requireReplacing(previous)
                    if next.phase == self.faultPhase.withLock({$0}) {
                        if self.commitThenFail.withLock({$0}) { self.row.withLock {$0=next} }
                        throw Fault.injected
                    }
                    if next.phase == .reopenPending { try self.native.drain.validate() }
                    if next.phase == .restored { XCTAssertThrowsError(try self.native.drain.validate()) }
                    self.row.withLock {$0=next};return next
                })
        }
        var phases:[Record.Phase] {writes.withLock {$0.map(\.phase)}}
        var actions:[Request.Action] {drivers.withLock {$0}.flatMap {$0.state.withLock {$0.calls.map(\.action)}}}
    }
    private func expectRecovery(_ body: () async throws -> Void) async {
        do {try await body();XCTFail("Expected recovery")} catch {XCTAssertEqual(error as? AuthorityMaintenanceClientError,.needsOwnerRecovery)}
    }
    func testHealthyCommitReleaseReopenAndReadbackUseOneNewConnectionAndPreserveTheOperation() async throws {
        let f=try Fixture(), result=try await f.run()
        XCTAssertEqual(f.trace.values.withLock {$0},["hello","open","peer","write.reopenPending","reopen","gate","write.restored"])
        XCTAssertEqual(f.phases,[.reopenPending,.restored]);XCTAssertEqual(f.actions,[.open,.reopen])
        XCTAssertEqual(result.operation,.committed);XCTAssertEqual(result.service,.healthy);XCTAssertNil(result.shutdownBinding)
        let d=try XCTUnwrap(f.drivers.withLock {$0.first}),q=try XCTUnwrap(d.state.withLock {$0.gates.first})
        XCTAssertEqual(q.target,f.restoring.shutdownBinding);XCTAssertNotEqual(result.gate?.authorityIncarnation,q.target.incarnation)
        XCTAssertEqual(result.gate?.requestRevision,q.revision);XCTAssertEqual(f.drivers.withLock {$0.count},1)
    }
    func testReadinessRefusalsRetryOnlyOpenBeforeThePendingCommit() async throws {
        let f=try Fixture();f.refuseCount.withLock {$0=2};_ = try await f.run()
        XCTAssertEqual(f.actions,[.open,.open,.open,.reopen]);XCTAssertEqual(f.phases,[.reopenPending,.restored])
        XCTAssertEqual(f.drivers.withLock {$0.count},3)
    }
    func testMissingOpenRepliesRetryFreshConnectionsBeforeOnePendingCommit() async throws {
        let f=try Fixture();f.lostOpenCount.withLock {$0=2};_ = try await f.run()
        XCTAssertEqual(f.actions,[.open,.open,.open,.reopen]);XCTAssertEqual(f.phases,[.reopenPending,.restored])
        XCTAssertEqual(f.drivers.withLock {$0.count},3)
    }
    func testBusyReadbackUsesOneReopenAndDistinctChallengesOnTheSameConnection() async throws {
        let f=try Fixture();f.busyCount.withLock {$0=2};_ = try await f.run()
        let d=try XCTUnwrap(f.drivers.withLock {$0.first}),gates=d.state.withLock {$0.gates}
        XCTAssertEqual(f.actions,[.open,.reopen]);XCTAssertEqual(gates.count,3);XCTAssertEqual(Set(gates.map(\.challenge)).count,3)
    }
    func testSameEpochCannotWriteHealthyOrReleaseTheDrain() async throws {
        let f=try Fixture();f.sameEpoch.withLock {$0=true};await expectRecovery {_ = try await f.run()}
        XCTAssertEqual(f.actions,[.open]);XCTAssertEqual(f.phases,[.needsOwnerRecovery]);try f.native.drain.validate()
    }
    func testUncertainPendingCommitSendsNoReopenOrRecoveryRewrite() async throws {
        for committed in [false,true] {
            let f=try Fixture();f.faultPhase.withLock {$0 = .reopenPending};f.commitThenFail.withLock {$0=committed}
            await expectRecovery {_ = try await f.run()};XCTAssertEqual(f.actions,[.open]);XCTAssertEqual(f.phases,[.reopenPending])
            try f.native.drain.validate()
        }
    }
    func testLostReopenIsNeverRetriedAndWritesRecoveryOnce() async throws {
        let f=try Fixture();f.lostReopen.withLock {$0=true};await expectRecovery {_ = try await f.run()}
        XCTAssertEqual(f.actions,[.open,.reopen]);XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery])
    }
    func testHeldOrUnknownReadbackCannotRestoreTheWindow() async throws {
        for hold in [Record.GateReadback.Hold.held,.unknown] {
            let f=try Fixture();f.hold.withLock {$0=hold};await expectRecovery {_ = try await f.run()}
            XCTAssertEqual(f.actions,[.open,.reopen]);XCTAssertEqual(f.phases,[.reopenPending,.needsOwnerRecovery])
        }
    }
    func testUncertainRestoredCommitCannotWriteAnotherTerminal() async throws {
        for committed in [false,true] {
            let f=try Fixture();f.faultPhase.withLock {$0 = .restored};f.commitThenFail.withLock {$0=committed}
            await expectRecovery {_ = try await f.run()};XCTAssertEqual(f.phases,[.reopenPending,.restored])
        }
    }
    func testUnavailableReadinessAtTheDeadlineLeavesTheDrainAndWritesRecovery() async throws {
        let f=try Fixture();f.refuseCount.withLock {$0=Int.max}
        await expectRecovery {_ = try await f.run(until:.now.advanced(by:.milliseconds(25)))}
        XCTAssertTrue(f.actions.allSatisfy {$0 == .open});XCTAssertEqual(f.phases,[.needsOwnerRecovery]);try f.native.drain.validate()
    }
    func testFailedPeerProofCannotWritePendingOrReleaseTheDrain() async throws {
        let f=try Fixture();f.peerFailure.withLock {$0=true};await expectRecovery {_ = try await f.run()}
        XCTAssertEqual(f.actions,[.open]);XCTAssertEqual(f.phases,[.needsOwnerRecovery]);try f.native.drain.validate()
    }
    func testValidationAfterPendingHandoffUsesClientRecoveryWithoutCallingTheOwner() async throws {
        let f=try Fixture();f.invalidPending.withLock {$0=true}
        await expectRecovery {_ = try await f.run()}
        XCTAssertEqual(f.ownerRecoveryCalls.withLock {$0},0)
        XCTAssertEqual(f.phases,[.needsOwnerRecovery]);XCTAssertEqual(f.row.withLock {$0.failure},.healthFailed)
        XCTAssertEqual(f.actions,[.open]);try f.native.drain.validate()
    }
    func testACompletedOrFailedClientCannotStartRestorationTwice() async throws {
        let f=try Fixture();_ = try await f.run();let before=f.phases
        await expectRecovery {_ = try await f.run()};XCTAssertEqual(f.phases,before);XCTAssertEqual(f.actions,[.open,.reopen])
    }
}
