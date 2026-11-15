import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Actual same-owner kernel gates exercise observation only. These controls prove no installed Root or native peer identity.
final class AuthorityMaintenanceGateObservationTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceGateRequest
    private func data(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private final class Fixture: @unchecked Sendable {
        let files: UpdateAdmissionTestFixture, identity: PreparationFileIdentity
        let clock: AuthorityClock, incarnation: Data
        let row: Record, request: Request, hold: AuthorityMaintenanceAdmissionHold, boundary: UpdateAdmissionBoundary
        init(clock: AuthorityClock? = nil, binding: AuthorityMaintenanceBinding? = nil) throws {
            files = try .init(); self.clock = try clock ?? AuthorityClock(); var epoch = self.clock.epoch.uuid
            incarnation = withUnsafeBytes(of: &epoch) { Data($0) }
            let account = Data(repeating: 1, count: 16), attempt = Data(repeating: 2, count: 16)
            let gate = try files.provisionAccount(account); identity = gate.1
            let authority = try Record.Account(accountID: account, ownerUID: getuid(), directoryID: Data(repeating: 3, count: 16))
            let scope = try Record.Scope(macID: Data(repeating: 4, count: 16), installationID: Data(repeating: 5, count: 16),
                authority: authority, target: .init(accountID: Data(repeating: 6, count: 16), ownerUID: 65001, directoryID: Data(repeating: 7, count: 16)),
                releaseDigest: Data(repeating: 1, count: 32), candidateDigest: Data(repeating: 2, count: 32), authorityPolicyDigest: Data(repeating: 3, count: 32),
                operationDigest: Data(repeating: 4, count: 32), restorationDigest: Data(repeating: 5, count: 32), mutationFootprintDigest: Data(repeating: 6, count: 32),
                authorityGrantDigest: Data(repeating: 7, count: 32), targetConsentDigest: Data(repeating: 8, count: 32), administratorIntentDigest: Data(repeating: 9, count: 32))
            let binding = try binding ?? AuthorityMaintenanceBinding(accountID: account, attemptID: attempt, revision: Data(repeating: 8, count: 16),
                incarnation: incarnation, connectionID: Data(repeating: 9, count: 16))
            row = try .init(id: attempt, revision: Data(repeating: 10, count: 16), purpose: .retainedRuntime, scope: scope,
                phase: .reopenPending, service: .notStopped, shutdownBinding: binding)
            request = try .init(accountID: account, attemptID: attempt, revision: row.revision, installationID: scope.installationID,
                gate: gate.1, target: binding, challenge: Data(repeating: 11, count: 16))
            let registration = try UpdateAdmissionRegistrationRecord(macID: scope.macID, installationID: scope.installationID,
                machine: files.identity, accounts: [.init(accountID: account, identity: gate.1)], designatedOwner: nil)
            let held = AuthorityMaintenanceAdmissionHold(projection: try .init(record: row, macID: scope.macID,
                installationID: scope.installationID, account: authority, registration: registration))
            hold = held
            boundary = try .init(machine: files.open(), account: gate.0, verifyAdmission: { try held.requireOpen() })
        }
        func accountGate() throws -> UpdateAdmissionBarrier {
            try .init(directory: .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid()),
                owner: getuid(), expected: identity, scope: .account(request.accountID))
        }
        func releaseHold() throws {
            try hold.reopen(row, binding: request.target, incarnation: incarnation, releaseBinding: {})
        }
        func capture(_ request: Request? = nil, read: (() throws -> Record)? = nil) throws -> AuthorityMaintenanceGateResponse {
            try AuthorityMaintenanceGateObservation.capture(request: request ?? self.request, incarnation: incarnation,
                hold: hold, boundary: boundary, read: read ?? { self.row })
        }
    }
    func testReleasedHoldAndActualGatesProduceTheRealClockEpochAndAdmitFreshWork() throws {
        let f = try Fixture(); try f.releaseHold()
        let value = try f.capture(), readback = try value.readback(expectedIncarnation: f.incarnation)
        var epoch = f.clock.epoch.uuid
        XCTAssertEqual(readback.authorityIncarnation, withUnsafeBytes(of: &epoch) { Data($0) })
        XCTAssertEqual(readback.hold, .released); XCTAssertEqual(readback.admission, .available)
        let fresh = try f.boundary.acquireAdmission(); try fresh.validate(); fresh.close()
    }
    func testHeldStartupRemainsHeldAndCannotReportAvailableAdmission() throws {
        let f = try Fixture(), result = try f.capture()
        XCTAssertEqual(result.hold, .held); XCTAssertEqual(result.admission, .busy)
        XCTAssertThrowsError(try f.hold.requireOpen())
    }
    func testForeignAccountDrainRemainsBusyAndOwnedAfterObservation() throws {
        let f = try Fixture(); try f.releaseHold()
        let drain = try f.accountGate().beginDrain(); defer { drain.close() }
        let result = try f.capture(); XCTAssertEqual(result.hold, .released); XCTAssertEqual(result.admission, .busy)
        try drain.validate(); XCTAssertThrowsError(try f.boundary.acquireAdmission())
    }
    func testForeignMachineDrainRemainsBusyAndOwnedAfterObservation() throws {
        let f = try Fixture(); try f.releaseHold()
        let drain = try f.files.open().beginDrain(); defer { drain.close() }
        XCTAssertEqual(try f.capture().admission, .busy); try drain.validate()
        XCTAssertThrowsError(try f.boundary.acquireAdmission())
    }
    func testTheSharedKernelLeaseStaysHeldThroughTheExactSecondRead() throws {
        let f = try Fixture(); try f.releaseHold(); var reads = 0
        let result = try f.capture(read: {
            reads += 1
            if reads == 2 {
                XCTAssertThrowsError(try f.accountGate().beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            }
            return f.row
        })
        XCTAssertEqual(reads, 2); XCTAssertEqual(result.admission, .available)
        let after = try f.accountGate().beginDrain(); try after.validate(); after.close()
    }
    func testChangedProtectedRevisionFailsAndReleasesBothProbeTokens() throws {
        let f = try Fixture(); try f.releaseHold(); var reads = 0
        XCTAssertThrowsError(try f.capture(read: {
            reads += 1
            if reads == 1 { return f.row }
            return try .init(id: f.row.id, revision: self.data(99), purpose: f.row.purpose, scope: f.row.scope,
                phase: .reopenPending, service: .notStopped, shutdownBinding: f.row.shutdownBinding)
        }))
        let account = try f.accountGate().beginDrain(), machine = try f.files.open().beginDrain()
        try account.validate(); try machine.validate(); account.close(); machine.close()
    }
    func testForeignPendingRevisionAndClosedHoldRefuseBeforeAResult() throws {
        let f = try Fixture(), q = f.request
        let foreign = try Request(accountID: q.accountID, attemptID: q.attemptID, revision: data(98), installationID: q.installationID,
            gate: q.gate, target: q.target, challenge: q.challenge)
        XCTAssertThrowsError(try f.capture(foreign)); f.hold.close(); XCTAssertThrowsError(try f.capture())
    }
    func testHelloThenReadbackCreatesNoReservationAndClosesWithItsWorker() async throws {
        let f = try Fixture(); try f.releaseHold()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: f.request.accountID, incarnation: f.incarnation)
        let entered = DispatchSemaphore(value: 0), unblock = DispatchSemaphore(value: 0), ended = DispatchSemaphore(value: 0), joining = DispatchSemaphore(value: 0)
        let replies = Mutex(0)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, check: { _ in XCTFail("No open command") },
            observe: { _ in throw RuntimePreparationError.changedScope }, readGate: { q in
                var reads = 0
                return try f.capture(q, read: {
                    reads += 1
                    if reads == 1 { entered.signal(); guard unblock.wait(timeout: .now() + 3) == .success else { throw RuntimePreparationError.changedScope } }
                    return f.row
                })
            })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1))
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.readGate(try f.request.encoded) { _ in replies.withLock { $0 += 1 } }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try pairing.connectionReservations(), 0)
        endpoint.close()
        let joined = Task { joining.signal(); await endpoint.closeAndWait(); ended.signal() }
        XCTAssertEqual(joining.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(ended.wait(timeout: .now() + .milliseconds(20)), .timedOut)
        unblock.signal(); await joined.value
        XCTAssertEqual(endpoint.pendingOperations(), 0); XCTAssertEqual(replies.withLock { $0 }, 0)
        XCTAssertEqual(try pairing.connectionReservations(), 0)
        let fresh = try f.boundary.acquireAdmission(); fresh.close()
    }
    func testReadbackWithoutHelloClosesBeforeTheProtectedReader() throws {
        let f = try Fixture(), reads = Mutex(0), invalidated = DispatchSemaphore(value: 0)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: f.request.accountID, incarnation: f.incarnation)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, check: { _ in XCTFail("No open") },
            observe: { _ in throw RuntimePreparationError.changedScope }, readGate: { q in
                reads.withLock { $0 += 1 }; return try f.capture(q)
            })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1),
            invalidate: { invalidated.signal() })
        endpoint.readGate(try f.request.encoded) { XCTAssertNil($0) }
        XCTAssertEqual(invalidated.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(reads.withLock { $0 }, 0); XCTAssertEqual(endpoint.pendingOperations(), 0)
        endpoint.hello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(try pairing.connectionReservations(), 0)
    }
    func testHelloThenReadbackReturnsTheRealGateAndEpochWithoutAReservation() async throws {
        let f = try Fixture(); try f.releaseHold()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: f.request.accountID, incarnation: f.incarnation)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, check: { _ in XCTFail("No open") },
            observe: { _ in throw RuntimePreparationError.changedScope }, readGate: { try f.capture($0) })
        let done = DispatchSemaphore(value: 0), response = Mutex<Data?>(nil), verified = Mutex(0)
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1),
            verify: { verified.withLock { $0 += 1 } })
        endpoint.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
        endpoint.readGate(try f.request.encoded) { value in response.withLock { $0 = value }; done.signal() }
        XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
        let result = try AuthorityMaintenanceGateResponse.decode(XCTUnwrap(response.withLock { $0 }), expected: f.request)
        XCTAssertEqual(result.authorityIncarnation, f.incarnation); XCTAssertEqual(result.hold, .released)
        XCTAssertEqual(result.admission, .available); XCTAssertGreaterThanOrEqual(verified.withLock { $0 }, 2)
        XCTAssertEqual(try pairing.connectionReservations(), 0); await endpoint.closeAndWait()
    }
    private enum Fault: Error { case injected }
    func testReadbackFailureClosesOnlyThatConnectionAndANewHelloCanReopenTheSavedTarget() async throws {
        let clock = try AuthorityClock(); var epoch = clock.epoch.uuid
        let incarnation = withUnsafeBytes(of: &epoch) { Data($0) }
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: data(1), incarnation: incarnation)
        let original = try pairing.openConnection(attemptID: data(2), revision: data(8)), binding = original.binding
        original.close()
        let f = try Fixture(clock: clock, binding: binding)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, check: { q in
            guard q.action == .reopen, q.binding == binding, q.revision == f.row.revision,
                  q.accountID == f.request.accountID, q.installationID == f.request.installationID,
                  q.gate == f.request.gate else { throw RuntimePreparationError.changedScope }
        }, observe: { _ in throw RuntimePreparationError.changedScope }, reopen: { _, release in
            try f.hold.reopen(f.row, binding: binding, incarnation: incarnation, releaseBinding: release)
        }, readGate: { _ in throw Fault.injected })
        let failed = DispatchSemaphore(value: 0), invalidated = DispatchSemaphore(value: 0)
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1),
            invalidate: { invalidated.signal() })
        endpoint.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
        endpoint.readGate(try f.request.encoded) { XCTAssertNil($0); failed.signal() }
        XCTAssertEqual(failed.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(invalidated.wait(timeout: .now() + 3), .success)
        await endpoint.closeAndWait(); XCTAssertThrowsError(try f.boundary.acquireAdmission())
        let q = try AuthorityMaintenanceChannelRequest(action: .reopen, accountID: f.request.accountID,
            attemptID: f.request.attemptID, revision: f.row.revision, installationID: f.request.installationID,
            gate: f.request.gate, binding: binding, challenge: data(19, 32))
        endpoint.exchange(try q.encoded) { XCTAssertNil($0) }
        XCTAssertThrowsError(try f.hold.requireOpen())
        let recovered = DispatchSemaphore(value: 0), bytes = Mutex<Data?>(nil)
        let replacement = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1))
        replacement.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
        replacement.exchange(try q.encoded) { value in bytes.withLock { $0 = value }; recovered.signal() }
        XCTAssertEqual(recovered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try AuthorityMaintenanceChannelResponse.decode(XCTUnwrap(bytes.withLock { $0 }), expected: q).outcome, .applied)
        XCTAssertEqual(try pairing.connectionReservations(), 0)
        let fresh = try f.boundary.acquireAdmission(); try fresh.validate(); fresh.close(); await replacement.closeAndWait()
    }

}
