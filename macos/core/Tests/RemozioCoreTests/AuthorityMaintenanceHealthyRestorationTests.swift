import CryptoKit
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
        /// The ordinary command check refuses unless a test accepts it. Counts show which path a request reached.
        let ordinary = Mutex(false), checks = Mutex(0), healthyReopens = Mutex(0)
        /// When set, the real readiness check runs where the native closures run it: after a healthy open read, before a reopen.
        let readiness = Mutex<(@Sendable () async throws -> Void)?>(nil)
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
                check: { [self] _ in
                    checks.withLock { $0 += 1 }
                    guard ordinary.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
                }, observe: { _ in try MaintenanceStopTestDriver.work() },
                healthyOpen: { [self] q in
                    // Like the native reader, an ordinary draining open returns nil and continues on the ordinary path.
                    guard let row = try read(q) else { return nil }
                    try hold.requireHealthyStartup(row)
                    guard ready.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
                    try await readiness.withLock({ $0 })?()
                    return row
                }, healthyReopen: { [self] q, previous, release in
                    healthyReopens.withLock { $0 += 1 }
                    try await readiness.withLock({ $0 })?()
                    guard let row = try read(q, from: previous) else { throw RuntimePreparationError.changedScope }
                    try hold.reopenHealthy(row, restoring: previous, binding: XCTUnwrap(q.binding), incarnation: epoch) {
                        try release(); XCTAssertEqual(try read(q, from: previous), row)
                    }
                })
            return try .openOwned(access: access, budget: .init(maximum: 1))
        }
        func hello(_ endpoint: AuthorityMaintenanceXPCEndpoint) {
            endpoint.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
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
            // The ordinary check accepts here, so only the candidate of each connection can refuse the foreign reopen.
            f.ordinary.withLock { $0 = true }
            let first = try f.endpoint(), second = try f.endpoint(), third = try f.endpoint()
            defer { first.close(); second.close(); third.close() }
            f.hello(first); f.hello(second); f.hello(third)
            let opened = try XCTUnwrap(f.call(first, f.request()))
            let own = try XCTUnwrap(f.call(third, f.request()))
            XCTAssertEqual(own.outcome, .applied); XCTAssertNotEqual(own.binding, opened.binding)
            XCTAssertEqual(try f.admission.connectionReservations(), 2)
            let pending = try f.pending(); try f.persist(pending)
            let reopen = try f.request(.reopen, binding: opened.binding, revision: pending.revision)
            // No candidate on this connection: the ordinary reconnect path finds no released binding to reopen.
            let checks = f.checks.withLock { $0 }
            XCTAssertEqual(try f.call(second, reopen)?.outcome, .refused)
            XCTAssertGreaterThan(f.checks.withLock { $0 }, checks)
            // Its own candidate does not let this connection release the binding of another connection.
            XCTAssertEqual(try f.call(third, reopen)?.outcome, .refused)
            XCTAssertEqual(f.healthyReopens.withLock { $0 }, 0)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
            XCTAssertEqual(try f.call(first, reopen)?.outcome, .applied)
            XCTAssertEqual(f.healthyReopens.withLock { $0 }, 1)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .released)
        }
    }
    func testTheRealHealthyReaderLeavesAnOrdinaryDrainingOpenUnchanged() throws {
        try fixture(startup: false) { f in
            let draining = try Record(id: f.restoring.id, revision: AccountPreparationIntent.randomID(), purpose: .retainedRuntime,
                scope: f.restoring.scope, phase: .draining)
            try f.persist(draining); f.ordinary.withLock { $0 = true }
            let rows = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let q = try f.request(revision: draining.revision)
            XCTAssertNil(try f.read(q))
            let reads = f.reads.withLock { $0 }
            let opened = try XCTUnwrap(f.call(endpoint, q))
            XCTAssertGreaterThan(f.reads.withLock { $0 }, reads)
            XCTAssertEqual(opened.outcome, .applied); XCTAssertEqual(opened.work, try MaintenanceStopTestDriver.work())
            XCTAssertEqual(opened.binding.revision, draining.revision); XCTAssertEqual(opened.binding.incarnation, f.epoch)
            XCTAssertGreaterThanOrEqual(f.checks.withLock { $0 }, 2)
            XCTAssertEqual(try f.admission.connectionReservations(), 1); XCTAssertFalse(f.admission.hasArmedShutdown)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
            // The connection has no healthy candidate: its next request takes the ordinary path, not the healthy reopen.
            let checks = f.checks.withLock { $0 }
            XCTAssertEqual(try f.call(endpoint, f.request(.cancel, binding: opened.binding, revision: draining.revision))?.outcome, .applied)
            XCTAssertGreaterThan(f.checks.withLock { $0 }, checks); XCTAssertEqual(f.healthyReopens.withLock { $0 }, 0)
            XCTAssertEqual(try f.admission.connectionReservations(), 0)
        }
    }
    /// The real wake service readiness, called where the native closures call it. Installed Root identity is not proved here.
    func testHealthyReopenRechecksReadinessBeforeReleasingTheHold() throws {
        let root = try AuthorityWakeSettingsTests.Fixture(install: false)
        try root.capability.install(root.options, commitDigest: Data(SHA256.hash(data: root.options.canonicalBytes)), verifyCurrent: {})
        let service = try root.service([AuthorityWakeSettingsTests.Driver()],
            binding: .init(accountID: root.h.registration.accountID, rootEpoch: root.h.clock))
        let expected = try AuthorityHealthyMaintenanceReadiness(accountID: root.h.registration.accountID, phonePush: root.options)
        try Self.blocking { try await service.start() }
        defer { try? Self.blocking { try await service.close() } }
        try fixture { f in
            f.readiness.withLock { $0 = { try await service.requireHealthyReadiness(expected, boundary: {}) } }
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let opened = try XCTUnwrap(f.call(endpoint, f.request())); XCTAssertEqual(opened.outcome, .applied)
            let pending = try f.pending(); try f.persist(pending)
            let rows = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            // The provider stops after the open: the installed commit is gone while the retained commit stays.
            root.capability.suspend(); XCTAssertNil(root.capability.installedCommitDigest)
            let reopen = try f.request(.reopen, binding: opened.binding, revision: pending.revision)
            XCTAssertEqual(try f.call(endpoint, reopen)?.outcome, .refused)
            XCTAssertEqual(f.healthyReopens.withLock { $0 }, 1)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held); XCTAssertFalse(f.admission.hasArmedShutdown)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
            // Readiness returns, but the refusal closed the connection that owned the candidate. Nothing else can release the hold.
            try root.capability.install(root.options, commitDigest: Data(SHA256.hash(data: root.options.canonicalBytes)), verifyCurrent: {})
            try Self.blocking { try await service.requireHealthyReadiness(expected, boundary: {}) }
            let fresh = try f.endpoint(); defer { fresh.close() }; f.hello(fresh)
            XCTAssertEqual(try f.call(fresh, reopen)?.outcome, .refused)
            XCTAssertEqual(f.healthyReopens.withLock { $0 }, 1)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
        }
    }
    private static func blocking(_ body: @escaping @Sendable () async throws -> Void) throws {
        let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, Error>?>(nil)
        Task { do { try await body(); result.withLock { $0 = .success(()) } } catch { result.withLock { $0 = .failure(error) } }; done.signal() }
        guard done.wait(timeout: .now() + 5) == .success else { throw RuntimeActivationError.unavailable }
        try XCTUnwrap(result.withLock { $0 }).get()
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
    private func probe(_ endpoint: AuthorityMaintenanceXPCEndpoint, account: Data) throws -> Data? {
        let done = DispatchSemaphore(value: 0), result = Mutex<Data?>(nil)
        let q = try AuthorityMaintenanceIncarnationRequest(accountID: account, challenge: AccountPreparationIntent.randomID())
        endpoint.observeIncarnation(try q.encoded) { b in result.withLock { $0 = b }; done.signal() }
        guard done.wait(timeout: .now() + 3) == .success else { throw RuntimeActivationError.unavailable }
        return try result.withLock { try $0.map { try AuthorityMaintenanceIncarnationResponse.decode($0, expected: q).incarnation } }
    }
    func testIncarnationProbeLeavesTheHoldCandidateAndRowsUnchangedAroundAHealthyOpen() throws {
        try fixture { f in
            let endpoint = try f.endpoint(); defer { endpoint.close() }; f.hello(endpoint)
            let account = f.restoring.scope.authority.accountID, rows = try runtimeMaintenanceFixtureRows(f.files.databasePath)
            XCTAssertEqual(try probe(endpoint, account: account), f.epoch); XCTAssertEqual(f.reads.withLock { $0 }, 0)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held); XCTAssertEqual(try f.admission.connectionReservations(), 0)
            let opened = try XCTUnwrap(f.call(endpoint, f.request()))
            XCTAssertEqual(opened.outcome, .applied); XCTAssertEqual(opened.binding.incarnation, f.epoch)
            let reads = f.reads.withLock { $0 }
            XCTAssertEqual(try probe(endpoint, account: account), f.epoch); XCTAssertEqual(f.reads.withLock { $0 }, reads)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .held); XCTAssertFalse(f.admission.hasArmedShutdown)
            XCTAssertEqual(try f.admission.connectionReservations(), 1)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.files.databasePath), rows)
            // The candidate survives the probe: its exact reopen still releases the startup hold.
            let pending = try f.pending(); try f.persist(pending)
            XCTAssertEqual(try f.call(endpoint, f.request(.reopen, binding: opened.binding, revision: pending.revision))?.outcome, .applied)
            XCTAssertEqual(try f.hold.gateHold(attemptID: f.restoring.id), .released)
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
