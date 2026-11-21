import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRecoverySessionShutdownTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case timeout }
    private actor Gate {
        private var open = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func wait() async {
            if open { return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func release() {
            open = true; let pending = waiters; waiters = []
            for waiter in pending { waiter.resume() }
        }
    }
    private final class Fixture: @unchecked Sendable {
        let source: RuntimeAuditUpgradeOperationTests.Harness
        let owner: SetupAccountOwner, placement: ReleaseDestinationLease, lease: SetupProcessLease
        let shutdown: AdministrativeSetupShutdown
        init() throws {
            source = try .init(); owner = try source.owner()
            placement = try .init(anchor: source.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            lease = try .openOwned(directory: .init(anchor: source.activity.root.path, relativeDirectory: "Machine", owner: getuid()))
            shutdown = .init(owner: owner, placement: placement, processLease: lease)
        }
        func session() throws -> AdministrativeSetupShutdown.RecoverySessionWork { try shutdown.registerRecoverySession(owner: owner) }
        func assertHeld() {
            XCTAssertNoThrow(try lease.validate()); XCTAssertNoThrow(try placement.validate())
            XCTAssertThrowsError(try SetupProcessLease.openOwned(directory: .init(anchor: source.activity.root.path,
                relativeDirectory: "Machine", owner: getuid()))) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        }
        func supervisor() throws -> SetupMaintenanceRecoverySupervisor {
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: owner, shutdown: shutdown)
            return try .openOwned(custody: custody, driver: .init(acquire: { _, _ in
                XCTFail("Idle shutdown must not schedule an engine"); return .terminal(.noWindow)
            }))
        }
        deinit { try? owner.close(); placement.close(); lease.close() }
    }
    private static func eventually(_ check: @escaping @Sendable () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !check() {
            guard ContinuousClock.now < deadline else { throw Failure.timeout }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
    }
    private func fixture(_ body: @escaping @Sendable (Fixture) async throws -> Void) throws {
        let f = try Fixture(), done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, any Error>?>(nil)
        Task {
            do { try await body(f); result.withLock { $0 = .success(()) } }
            catch { result.withLock { $0 = .failure(error) } }
            done.signal()
        }
        guard done.wait(timeout: .now() + 30) == .success else { throw Failure.timeout }
        try XCTUnwrap(result.withLock { $0 }).get()
    }
    func testNeverCreatedPublicationResolvesWithoutAWatchdog() throws {
        try fixture { f in
            let session = try f.session(), closed = Mutex(false), joined = Mutex(false)
            XCTAssertTrue(session.reservePublication())
            session.bindEndpointClose { closed.withLock { $0 = true } }
            let finalizer = Task { await f.shutdown.joinRecoverySessions(); joined.withLock { $0 = true } }
            try await Self.eventually { closed.withLock { $0 } }
            XCTAssertFalse(joined.withLock { $0 }); f.assertHeld()
            session.resolveWithoutWork()
            try await Self.eventually { joined.withLock { $0 } }; await finalizer.value
            try await f.shutdown.close(); XCTAssertThrowsError(try f.lease.validate())
        }
    }
    func testShutdownWaitsForRacingPublicationAndTheActualWrapperReturn() throws {
        try fixture { f in
            let session = try f.session(), gate = Gate(), closeRequested = Mutex(false)
            let joined = Mutex(false), returned = Mutex(false), cancelled = Mutex(false)
            XCTAssertTrue(session.reservePublication())
            session.bindEndpointClose { closeRequested.withLock { $0 = true } }
            let finalizer = Task { await f.shutdown.joinRecoverySessions(); joined.withLock { $0 = true } }
            try await Self.eventually { closeRequested.withLock { $0 } }
            let actual = Task {
                await gate.wait(); cancelled.withLock { $0 = Task.isCancelled }; returned.withLock { $0 = true }
            }
            session.publish(actual)
            XCTAssertFalse(joined.withLock { $0 }); XCTAssertFalse(returned.withLock { $0 }); f.assertHeld()
            await gate.release(); await actual.value; await finalizer.value
            XCTAssertTrue(cancelled.withLock { $0 }); XCTAssertTrue(returned.withLock { $0 })
            try await f.shutdown.close()
        }
    }
    func testConnectionCloseJoinsWithoutCancellingTheActualWork() throws {
        try fixture { f in
            let session = try f.session(), gate = Gate(), entered = Mutex(false), cancelled = Mutex(true), returned = Mutex(false)
            XCTAssertTrue(session.reservePublication())
            let actual = Task {
                entered.withLock { $0 = true }; await gate.wait()
                cancelled.withLock { $0 = Task.isCancelled }; returned.withLock { $0 = true }
            }
            session.publish(actual); try await Self.eventually { entered.withLock { $0 } }
            session.connectionDidClose(); session.connectionDidClose()
            XCTAssertFalse(returned.withLock { $0 }); f.assertHeld()
            await gate.release(); await actual.value
            XCTAssertFalse(cancelled.withLock { $0 }); XCTAssertTrue(returned.withLock { $0 })
            try await f.shutdown.close()
        }
    }
    func testTwoDirectCloseCallersAwaitTheBoundSupervisorWithoutHoldingTheOwnerLock() throws {
        try fixture { f in
            let supervisor = try f.supervisor(), session = try f.session(), gate = Gate()
            let closing = Mutex(false), firstReturned = Mutex(false), secondReturned = Mutex(false)
            XCTAssertTrue(session.reservePublication()); session.bindEndpointClose { closing.withLock { $0 = true } }
            session.publish(Task { await gate.wait() })
            let first = Task { try await f.shutdown.close(); firstReturned.withLock { $0 = true } }
            try await Self.eventually { closing.withLock { $0 } }
            let second = Task { try await f.shutdown.close(); secondReturned.withLock { $0 = true } }
            XCTAssertTrue(f.shutdown.belongs(to: f.owner)); XCTAssertFalse(f.shutdown.acceptsRecoverySessions)
            XCTAssertThrowsError(try f.session()); f.assertHeld()
            XCTAssertFalse(firstReturned.withLock { $0 }); XCTAssertFalse(secondReturned.withLock { $0 })
            await gate.release(); try await first.value; try await second.value
            XCTAssertTrue(firstReturned.withLock { $0 }); XCTAssertTrue(secondReturned.withLock { $0 })
            let closed = await supervisor.isClosed; XCTAssertTrue(closed)
            XCTAssertThrowsError(try f.lease.validate())
        }
    }
    func testOrdinarySupervisorDisposalJoinsTheSessionBeforeReleasingItsBinding() throws {
        try fixture { f in
            var supervisor: SetupMaintenanceRecoverySupervisor? = try f.supervisor()
            let session = try f.session(), gate = Gate(), closing = Mutex(false), returned = Mutex(false), cancelled = Mutex(true)
            XCTAssertTrue(session.reservePublication()); session.bindEndpointClose { closing.withLock { $0 = true } }
            session.publish(Task {
                await gate.wait(); cancelled.withLock { $0 = Task.isCancelled }; returned.withLock { $0 = true }
            })
            weak let old = supervisor; supervisor = nil; XCTAssertNil(old)
            XCTAssertTrue(f.shutdown.acceptsRecoverySessions)
            XCTAssertFalse(closing.withLock { $0 }); XCTAssertFalse(returned.withLock { $0 }); f.assertHeld()
            XCTAssertThrowsError(try f.supervisor())
            await gate.release(); try await Self.eventually { returned.withLock { $0 } }
            let replacement = Mutex<SetupMaintenanceRecoverySupervisor?>(nil)
            try await Self.eventually {
                guard let next = try? f.supervisor() else { return false }
                replacement.withLock { $0 = next }; return true
            }
            XCTAssertFalse(cancelled.withLock { $0 }); XCTAssertFalse(closing.withLock { $0 })
            XCTAssertTrue(f.shutdown.acceptsRecoverySessions)
            let nextSession = try f.session(); nextSession.resolveWithoutWork()
            try await f.shutdown.close(); XCTAssertThrowsError(try f.lease.validate())
            withExtendedLifetime(replacement) {}
        }
    }
    func testDirectCloseAfterDisposalWithPendingOwnerReturnsUnavailableAndRetainsLeases() throws {
        try fixture { f in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: f.owner, shutdown: f.shutdown)
            let id = UUID(); custody.retain(id, id: id)
            var supervisor: SetupMaintenanceRecoverySupervisor? = try .openOwned(custody: custody,
                driver: .init(acquire: { _, _ in .terminal(.noWindow) }))
            weak let old = supervisor; supervisor = nil; XCTAssertNil(old)
            let returned = Mutex(false)
            let close = Task {
                do { try await f.shutdown.close(); XCTFail("Pending owner reported closed") }
                catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
                returned.withLock { $0 = true }
            }
            try await Self.eventually { returned.withLock { $0 } }; await close.value; f.assertHeld()
            custody.joined(id); custody.releaseAfterJoining()
            try await f.shutdown.close(); XCTAssertThrowsError(try f.lease.validate())
        }
    }
    func testOwnedCustodyWithoutSupervisorPublicationRefusesDirectClose() throws {
        try fixture { f in
            let custody = try SetupMaintenanceRecoveryNativeAdapter.Custody(owner: f.owner, shutdown: f.shutdown)
            do { try await f.shutdown.close(); XCTFail("Unbound Owned custody reported closed") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            f.assertHeld(); custody.releaseAfterJoining(); try await f.shutdown.close()
        }
    }
    func testRetirementJoinsTheActualSessionBeforeReleasingEitherLease() throws {
        try fixture { f in
            let supervisor = try f.supervisor(), session = try f.session(), gate = Gate()
            let closing = Mutex(false), returned = Mutex(false), cancelled = Mutex(false)
            XCTAssertTrue(session.reservePublication()); session.bindEndpointClose { closing.withLock { $0 = true } }
            session.publish(Task { await gate.wait(); cancelled.withLock { $0 = Task.isCancelled } })
            let retire = Task { await supervisor.retire(); returned.withLock { $0 = true } }
            try await Self.eventually { closing.withLock { $0 } }
            XCTAssertFalse(returned.withLock { $0 }); XCTAssertFalse(f.shutdown.acceptsRecoverySessions); f.assertHeld()
            await gate.release(); await retire.value
            XCTAssertTrue(cancelled.withLock { $0 }); XCTAssertTrue(returned.withLock { $0 })
            XCTAssertThrowsError(try f.lease.validate()); XCTAssertThrowsError(try f.placement.validate())
        }
    }
    func testRegistrationRaceCannotEscapeTheShutdownSnapshot() throws {
        try fixture { f in
            let registered = Mutex(0), closed = Mutex(0)
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<20 {
                    group.addTask {
                        guard let session = try? f.session() else { return }
                        registered.withLock { $0 += 1 }
                        session.bindEndpointClose { closed.withLock { $0 += 1 } }
                    }
                }
                group.addTask { await f.shutdown.joinRecoverySessions() }
            }
            XCTAssertEqual(closed.withLock { $0 }, registered.withLock { $0 })
            XCTAssertFalse(f.shutdown.acceptsRecoverySessions); XCTAssertThrowsError(try f.session())
            try await f.shutdown.close()
        }
    }
}
