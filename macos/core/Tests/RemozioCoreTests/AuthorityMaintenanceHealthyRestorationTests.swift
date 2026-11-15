import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Real protected reads and local owners. These fixtures do not prove installed Root or launchd restoration.
final class AuthorityMaintenanceHealthyRestorationTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private final class Fixture: @unchecked Sendable {
        let files: RuntimeMaintenanceReaderFixture, restoring: Record, gate: PreparationFileIdentity
        let admission: AuthorityMaintenancePairingAdmission, hold: AuthorityMaintenanceAdmissionHold
        let epoch = Data(repeating: 44, count: 16)
        let ready = Mutex(true), reads = Mutex(0)
        init(_ files: RuntimeMaintenanceReaderFixture, startup: Bool = true, sameEpoch: Bool = false) throws {
            self.files = files
            let before = try files.machine().stableMachineUpdateSnapshot(candidate: files.candidate)
            gate = try XCTUnwrap(before.admission.accounts.first { $0.accountID == files.authority.accountID }).identity
            let b: (UInt8, Int) -> Data = { Data(repeating: $0, count: $1) }
            let scope = try Record.Scope(macID: before.inventory.macID, installationID: before.inventory.installationID,
                authority: files.authority, target: .init(accountID: b(92,16), ownerUID: 65001, directoryID: b(93,16)),
                releaseDigest: before.inventory.releaseDigest, candidateDigest: b(2,32), authorityPolicyDigest: b(3,32),
                operationDigest: b(4,32), restorationDigest: b(5,32), mutationFootprintDigest: b(6,32),
                authorityGrantDigest: b(7,32), targetConsentDigest: b(8,32), administratorIntentDigest: b(9,32))
            let stopped = try AuthorityMaintenanceBinding(accountID: files.authority.accountID, attemptID: b(90,16),
                revision: b(80,16), incarnation: sameEpoch ? epoch : b(4,16), connectionID: b(5,16))
            restoring = try Record(id: stopped.attemptID, revision: b(91,16), purpose: .retainedRuntime, scope: scope,
                phase: .restoring, operation: .committed, service: .restartPending, shutdownBinding: stopped)
            admission = try .init(accountID: files.authority.accountID, incarnation: epoch)
            try files.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(Self.hex(files.authority.accountID))',X'\(Self.hex(restoring.id))',X'\(Self.hex(restoring.revision))',7,X'\(try Self.hex(restoring.encoded))')"])
            hold = .init(projection: try .init(record: startup ? restoring : nil, macID: scope.macID,
                installationID: scope.installationID, account: scope.authority, registration: before.admission))
        }
        static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        func request(_ action: Request.Action = .open, binding: AuthorityMaintenanceBinding? = nil,
            revision: Data? = nil, gate: PreparationFileIdentity? = nil) throws -> Request {
            try .init(action: action, accountID: restoring.scope.authority.accountID, attemptID: restoring.id,
                revision: revision ?? restoring.revision, installationID: restoring.scope.installationID,
                gate: gate ?? self.gate, binding: binding, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
        }
        func read(_ q: Request, from: Record? = nil) throws -> Record? {
            reads.withLock { $0 += 1 }
            return try files.machine().runtimeMaintenanceHealthyRecord(q, account: files.authority,
                incarnation: epoch, restoring: from, candidate: files.candidate)
        }
        func pending(service: Record.ServiceOutcome = .healthy, operation: Record.OperationOutcome = .committed) throws -> Record {
            try .init(id: restoring.id, revision: AccountPreparationIntent.randomID(), purpose: restoring.purpose,
                scope: restoring.scope, phase: .reopenPending, operation: operation, service: service,
                shutdownBinding: restoring.shutdownBinding)
        }
        func persist(_ row: Record) throws {
            try files.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=X'\(Self.hex(row.revision))',phase=\(row.phase.rawValue),record=X'\(try Self.hex(row.encoded))'")
        }
        func endpoint() throws -> AuthorityMaintenanceXPCEndpoint {
            let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission,
                check: { _ in throw RuntimePreparationError.changedScope }, observe: { _ in try MaintenanceStopTestDriver.work() },
                healthyOpen: { [self] q in
                    guard let row = try read(q), ready.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
                    try hold.requireHealthyStartup(row); return row
                }, healthyReopen: { [self] q, previous, release in
                    guard let row = try read(q, from: previous) else { throw RuntimePreparationError.changedScope }
                    try hold.reopenHealthy(row, restoring: previous, binding: XCTUnwrap(q.binding), incarnation: epoch) {
                        try release(); XCTAssertEqual(try read(q, from: previous), row)
                    }
                })
            return try .openOwned(access: access, budget: .init(maximum: 1))
        }
        func hello(_ endpoint: AuthorityMaintenanceXPCEndpoint) {
            endpoint.hello { XCTAssertEqual($0, 1) }
        }
        func call(_ endpoint: AuthorityMaintenanceXPCEndpoint, _ q: Request) throws -> AuthorityMaintenanceChannelResponse? {
            let done = DispatchSemaphore(value: 0), result = Mutex<Data?>(nil)
            endpoint.exchange(try q.encoded) { b in result.withLock { $0 = b }; done.signal() }
            guard done.wait(timeout: .now() + 3) == .success else { throw RuntimeActivationError.unavailable }
            return try result.withLock { try $0.map { try .decode($0, expected: q) } }
        }
    }
    private func fixture(startup: Bool = true, sameEpoch: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture { files in
            let f = try Fixture(files, startup: startup, sameEpoch: sameEpoch)
            defer { f.admission.close(); f.hold.close() }
            try body(f)
        }
    }
    func testHealthyOpenAndExactNextRevisionReleaseOnlyTheStartupHoldWithoutArming() throws {
        try fixture { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let rows = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            let opened = try XCTUnwrap(f.call(endpoint, f.request()))
            XCTAssertEqual(opened.outcome, .applied); XCTAssertEqual(opened.binding.incarnation, f.epoch)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
            XCTAssertFalse(f.admission.hasArmedShutdown); XCTAssertEqual(try f.admission.connectionReservations(), 1)
            XCTAssertThrowsError(try f.admission.shutdownBinding(matching: opened.binding))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
            let pending = try f.pending(); try f.persist(pending)
            let beforeRelease = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            let reopened = try f.call(endpoint, f.request(.reopen, binding: opened.binding, revision: pending.revision))
            XCTAssertEqual(reopened?.outcome, .applied)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .released)
            XCTAssertEqual(try f.admission.connectionReservations(), 0); XCTAssertFalse(f.admission.hasArmedShutdown)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), beforeRelease)
        }
    }
    func testSameIncarnationCannotBecomeHealthy() throws {
        try fixture(sameEpoch: true) { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            XCTAssertEqual(try f.call(endpoint, f.request())?.outcome, .refused)
            XCTAssertEqual(try f.admission.connectionReservations(), 0)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
        }
    }
    func testMetadataCannotCreateAStartupRestrictionOrAHealthyCandidate() throws {
        try fixture(startup: false) { f in
            let draining = try Record(id: f.restoring.id, revision: AccountPreparationIntent.randomID(), purpose: .retainedRuntime,
                scope: f.restoring.scope, phase: .draining)
            try f.hold.retain(draining)
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            XCTAssertEqual(try f.call(endpoint, f.request())?.outcome, .refused)
            XCTAssertEqual(try f.admission.connectionReservations(), 0)
        }
    }
    func testNotReadyRefusesWithoutConnectionOrDurableChangeAndAllowsFreshAttempt() throws {
        try fixture { f in
            let rows = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            f.ready.withLock { $0 = false }
            let first = try f.endpoint(); defer { first.close() }; f.hello(first)
            XCTAssertEqual(try f.call(first, f.request())?.outcome, .refused)
            XCTAssertEqual(try f.admission.connectionReservations(), 0)
            f.ready.withLock { $0 = true }
            let second = try f.endpoint(); defer { second.close() }; f.hello(second)
            XCTAssertEqual(try f.call(second, f.request())?.outcome, .applied)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
        }
    }
    func testAnotherConnectionCannotAdoptTheCandidate() throws {
        try fixture { f in
            let first = try f.endpoint(), second = try f.endpoint(); defer { first.close(); second.close() }
            f.hello(first); f.hello(second)
            let opened = try XCTUnwrap(f.call(first, f.request()))
            let pending = try f.pending(); try f.persist(pending)
            XCTAssertEqual(try f.call(second, f.request(.reopen, binding: opened.binding, revision: pending.revision))?.outcome, .refused)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
            XCTAssertEqual(try f.call(first, f.request(.reopen, binding: opened.binding, revision: pending.revision))?.outcome, .applied)
        }
    }
    func testCandidateCannotArmAndClosingItDoesNotReleaseTheHold() throws {
        try fixture { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let opened = try XCTUnwrap(f.call(endpoint, f.request()))
            XCTAssertEqual(try f.call(endpoint, f.request(.arm, binding: opened.binding))?.outcome, .refused)
            XCTAssertFalse(f.admission.hasArmedShutdown); endpoint.close()
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
        }
    }
    func testHealthyReleaseRefusesStaleRevisionOrForeignGate() throws {
        for foreignGate in [false, true] {
            try fixture { f in
                let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
                let opened = try XCTUnwrap(f.call(endpoint, f.request())), pending = try f.pending(); try f.persist(pending)
                let bad = try f.request(.reopen, binding: opened.binding,
                    revision: foreignGate ? pending.revision : f.restoring.revision,
                    gate: foreignGate ? .init(device: f.gate.device, inode: f.gate.inode + 1) : nil)
                XCTAssertEqual(try f.call(endpoint, bad)?.outcome, .refused)
                XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
            }
        }
    }
    func testHealthyReleaseCannotChangeTheOperationOutcome() throws {
        try fixture { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let opened = try XCTUnwrap(f.call(endpoint, f.request())), pending = try f.pending(operation: .failed)
            try f.persist(pending)
            XCTAssertEqual(try f.call(endpoint, f.request(.reopen, binding: opened.binding, revision: pending.revision))?.outcome, .refused)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
        }
    }
    func testHealthyOpenNeedsHelloAndExactProtectedRevision() throws {
        try fixture { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }
            let response = try f.call(endpoint, f.request())
            XCTAssertTrue(response == nil || response?.outcome == .refused)
            XCTAssertEqual(try f.admission.connectionReservations(), 0)
            let fresh = try f.endpoint(); defer { fresh.close() }; f.hello(fresh)
            XCTAssertEqual(try f.call(fresh, f.request(revision: Data(repeating: 99, count: 16)))?.outcome, .refused)
        }
    }
}
