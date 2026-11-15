import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Real SQLite writes, protected reads, and kernel gates. The transport does not prove installed native identity.
final class AuthorityMaintenanceHealthyIntegrationTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        let endpoint: AuthorityMaintenanceXPCEndpoint, account: UpdateAdmissionBarrier, busy: Bool
        let gates = Mutex<[AuthorityMaintenanceGateRequest]>([]), foreign = Mutex<UpdateDrainToken?>(nil)
        init(_ endpoint: AuthorityMaintenanceXPCEndpoint, account: UpdateAdmissionBarrier, busy: Bool) {
            self.endpoint=endpoint;self.account=account;self.busy=busy
        }
        func start(_ invalidated: @escaping @Sendable () -> Void) { }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { endpoint.hello { reply(.hello($0)) } }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q=try Request.decode(bytes)
                if q.action == .reopen && busy { let token=try account.beginDrain();foreign.withLock {$0=token} }
                endpoint.exchange(bytes) { reply(.bytes($0)) }
            } catch {reply(.bytes(nil))}
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q=try AuthorityMaintenanceGateRequest.decode(bytes), count=gates.withLock {$0.append(q);return $0.count}
                if count == 3 {foreign.withLock {$0?.close();$0=nil}}
                endpoint.readGate(bytes) {reply(.bytes($0))}
            } catch {reply(.bytes(nil))}
        }
        func close() {foreign.withLock {$0?.close();$0=nil};endpoint.close()}
    }
    private final class SQLFixture: @unchecked Sendable {
        let f: RuntimeMaintenanceWriterFixture
        let last=Mutex<Record?>(nil), writes=Mutex<[Record]>([])
        init(_ f: RuntimeMaintenanceWriterFixture) {self.f=f}
        func write(_ next: Record, previous: Record?, drain: UpdateDrainToken? = nil) throws -> Record {
            let snapshot=try f.machine().stableMachineUpdateSnapshot(candidate:f.candidate)
            let receipt=try f.machine().writeRuntimeMaintenanceTransition(next,replacing:previous,expected:snapshot,
                candidate:f.candidate,directory:f.directory,admission:f.admission,accountDrain:drain)
            if let previous {try receipt.requireReplacement(next,replacing:previous)}
            last.withLock {$0=receipt.record};writes.withLock {$0.append(receipt.record)};return receipt.record
        }
        func run(busy: Bool, failReadinessOnce: Bool, readbackHold: Record.GateReadback.Hold?) async throws {
            let snapshot=try f.machine().stableMachineUpdateSnapshot(candidate:f.candidate)
            let gate=try XCTUnwrap(snapshot.admission.accounts.first {$0.accountID==f.authority.accountID}).identity
            let anchor=URL(fileURLWithPath:f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease {try .init(anchor:anchor,relativeDirectory:"machine",owner:getuid())}
            let account=try UpdateAdmissionBarrier(directory:directory(),owner:getuid(),expected:gate,scope:.account(f.authority.accountID))
            let machine=try UpdateAdmissionBarrier(directory:directory(),owner:getuid(),expected:snapshot.admission.machine)
            let before=try runtimeMaintenanceFixtureRows(f.databasePath,omitMaintenance:true)
            let b:(UInt8,Int)->Data={Data(repeating:$0,count:$1)}
            let scope=try Record.Scope(macID:snapshot.inventory.macID,installationID:snapshot.inventory.installationID,
                authority:f.authority,target:f.target,releaseDigest:snapshot.inventory.releaseDigest,
                candidateDigest:b(1,32),authorityPolicyDigest:b(2,32),operationDigest:b(3,32),restorationDigest:b(4,32),
                mutationFootprintDigest:b(5,32),authorityGrantDigest:b(6,32),targetConsentDigest:b(7,32),administratorIntentDigest:b(8,32))
            var row=try Record(id:AccountPreparationIntent.randomID(),revision:AccountPreparationIntent.randomID(),purpose:.retainedRuntime,scope:scope)
            _=try write(row,previous:nil)
            let drain=try account.beginDrain();defer {drain.close()}
            let draining=try Record(id:row.id,revision:AccountPreparationIntent.randomID(),purpose:row.purpose,scope:scope,phase:.draining)
            _=try write(draining,previous:row,drain:drain);row=draining
            let stopped=try AuthorityMaintenanceBinding(accountID:f.authority.accountID,attemptID:row.id,revision:row.revision,
                incarnation:b(71,16),connectionID:AccountPreparationIntent.randomID())
            let bound=try row.retainingShutdownBinding(stopped);_=try write(bound,previous:row,drain:drain);row=bound
            for phase in [Record.Phase.stopping,.stopped,.executing,.workSettled,.restoring] {
                let operation:Record.OperationOutcome = phase == .executing ? .unknown : [.workSettled,.restoring].contains(phase) ? .committed : .notStarted
                let service:Record.ServiceOutcome = phase == .stopping ? .notStopped : phase == .restoring ? .restartPending : .stopped
                let next=try Record(id:row.id,revision:AccountPreparationIntent.randomID(),purpose:row.purpose,scope:scope,
                    phase:phase,operation:operation,service:service,shutdownBinding:stopped)
                _=try write(next,previous:row);row=next
            }
            let restoring=row, incarnation=b(72,16)
            let hold=AuthorityMaintenanceAdmissionHold(projection:try .init(record:restoring,macID:scope.macID,
                installationID:scope.installationID,account:f.authority,registration:snapshot.admission))
            defer {hold.close()}
            let pairing=try AuthorityMaintenancePairingAdmission(accountID:f.authority.accountID,incarnation:incarnation)
            defer {pairing.close()}
            let boundary=try UpdateAdmissionBoundary(machine:machine,account:account,verifyAdmission:{try hold.requireOpen()})
            let readinessCalls=Mutex(0), endpoints=Mutex<[AuthorityMaintenanceXPCEndpoint]>([]), drivers=Mutex<[Driver]>([])
            let access=try AuthorityMaintenanceChannelAccess.openOwned(admission:pairing,
                check:{_ in throw RuntimePreparationError.changedScope},observe:{_ in try MaintenanceStopTestDriver.work()},
                readGate:{q in
                    let observed=try AuthorityMaintenanceGateObservation.capture(request:q,incarnation:incarnation,hold:hold,boundary:boundary,read:{
                        try self.f.machine().runtimeMaintenanceGateRecord(q,account:self.f.authority,candidate:self.f.candidate)
                    })
                    return try readbackHold.map {try .init(request:q,authorityIncarnation:incarnation,hold:$0,admission:observed.admission)} ?? observed
                },healthyOpen:{q in
                    let count=readinessCalls.withLock {$0+=1;return $0}
                    if failReadinessOnce && count == 1 {throw RuntimeActivationError.unavailable}
                    guard let actual=try self.f.machine().runtimeMaintenanceHealthyRecord(q,account:self.f.authority,
                        incarnation:incarnation,candidate:self.f.candidate) else {throw RuntimePreparationError.changedScope}
                    try hold.requireHealthyStartup(actual);return actual
                },healthyReopen:{q,previous,release in
                    guard let actual=try self.f.machine().runtimeMaintenanceHealthyRecord(q,account:self.f.authority,
                        incarnation:incarnation,restoring:previous,candidate:self.f.candidate),let binding=q.binding else {throw RuntimePreparationError.changedScope}
                    try hold.reopenHealthy(actual,restoring:previous,binding:binding,incarnation:incarnation) {
                        try release()
                        guard try self.f.machine().runtimeMaintenanceHealthyRecord(q,account:self.f.authority,incarnation:incarnation,
                            restoring:previous,candidate:self.f.candidate)==actual else {throw RuntimePreparationError.changedScope}
                    }
                })
            let make:@Sendable ()throws->any AuthorityMaintenanceClientDriver={
                let endpoint=try AuthorityMaintenanceXPCEndpoint.openOwned(access:access,budget:.init(maximum:1))
                let driver=Driver(endpoint,account:account,busy:busy);endpoints.withLock {$0.append(endpoint)};drivers.withLock {$0.append(driver)};return driver
            }
            let q=try Request(action:.open,accountID:f.authority.accountID,attemptID:restoring.id,revision:restoring.revision,
                installationID:scope.installationID,gate:gate,binding:nil,challenge:b(1,32))
            let idle=try make(), client=try AuthorityMaintenanceXPCClient.openOwned(context:q,driver:idle,intervalMilliseconds:1)
            do {
                let restored=try await client.restoreHealthyOwned(window:restoring,drain:drain,directory:f.directory,
                    until:.now.advanced(by:.seconds(5)),makeDriver:make,verifyScope:{
                        try self.f.machine().requireRuntimeMaintenanceObservationWindow(restoring,candidate:self.f.candidate)
                    },preparePeer:{_ in},requirePeerLive:{},persist:{next,previous in try self.write(next,previous:previous)})
                XCTAssertNil(readbackHold);XCTAssertEqual(restored.phase,.restored);XCTAssertEqual(restored.operation,.committed)
                XCTAssertEqual(restored.gate?.authorityIncarnation,incarnation);XCTAssertNil(restored.shutdownBinding)
                try f.machine().requireRuntimeMaintenanceObservationWindow(restored,candidate:f.candidate)
                let token=try boundary.acquireAdmission();try token.validate();token.close()
                let gates=drivers.withLock {$0}.flatMap {$0.gates.withLock {$0}}
                XCTAssertEqual(gates.count,busy ? 3 : 1);XCTAssertEqual(Set(gates.map(\.challenge)).count,gates.count)
                XCTAssertTrue(gates.allSatisfy {$0.target==stopped})
            } catch {
                guard readbackHold != nil else {throw error}
                XCTAssertEqual(error as? AuthorityMaintenanceClientError,.needsOwnerRecovery)
                let failed=try XCTUnwrap(last.withLock {$0});XCTAssertEqual(failed.phase,.needsOwnerRecovery)
                try f.reopen(nil);try f.machine().requireRuntimeMaintenanceObservationWindow(failed,candidate:f.candidate)
                XCTAssertTrue(f.machine().runtimeMaintenanceStartupProjection(account:f.authority,candidate:f.candidate).requiresLocalHold)
            }
            for endpoint in endpoints.withLock({$0}) {await endpoint.closeAndWait()}
            XCTAssertFalse(pairing.hasArmedShutdown);XCTAssertEqual(try pairing.connectionReservations(),0)
            XCTAssertEqual(writes.withLock {$0.filter {$0.phase == .reopenPending}.count},1)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath,omitMaintenance:true),before)
        }
    }
    private func withHealthyRestoration(busy: Bool = false, failReadinessOnce: Bool = false, readbackHold: Record.GateReadback.Hold? = nil) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture {f in
            let box=SQLFixture(f),done=DispatchSemaphore(value:0),result=Mutex<Result<Void,Error>?>(nil)
            Task {
                do {try await box.run(busy:busy,failReadinessOnce:failReadinessOnce,readbackHold:readbackHold);result.withLock {$0 = .success(())}}
                catch {result.withLock {$0 = .failure(error)}}
                done.signal()
            }
            XCTAssertEqual(done.wait(timeout:.now()+30),.success);try XCTUnwrap(result.withLock {$0}).get()
        }
    }
    func testRealWriterAndStartupHoldRestoreOnANewIncarnationWithoutAnotherArm() throws {try withHealthyRestoration()}
    func testRealBusyGateRereadsOnTheSameConnectionBeforeRestored() throws {try withHealthyRestoration(busy:true)}
    func testReadinessRefusalThenReadyWritesOnlyOnePending() throws {try withHealthyRestoration(failReadinessOnce:true)}
    func testHeldReadbackPersistsRecoveryAcrossAnActualStoreRestart() throws {try withHealthyRestoration(readbackHold:.held)}
}
