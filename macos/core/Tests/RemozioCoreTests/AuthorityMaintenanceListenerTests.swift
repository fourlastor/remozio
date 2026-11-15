import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Actual anonymous XPC with owned peer controls. Installed Root code admission remains a separate gate.
final class AuthorityMaintenanceListenerTests: XCTestCase, @unchecked Sendable {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private enum Fault: Error { case rejected, timedOut }
    private final class Pause: Sendable {
        private struct State { var continuation: CheckedContinuation<Void, Never>?; var resumed = false }
        private let state = Mutex(State())
        func wait() async {
            await withCheckedContinuation { c in
                let resumed = state.withLock { if $0.resumed { return true }; $0.continuation = c; return false }
                if resumed { c.resume() }
            }
        }
        func resume() { let c = state.withLock { $0.resumed = true; let c = $0.continuation; $0.continuation = nil; return c }; c?.resume() }
        var entered: Bool { state.withLock { $0.continuation != nil } }
    }
    private final class Fixture: Sendable {
        let admission: AuthorityMaintenancePairingAdmission
        let pause = Pause(), paused = Mutex(false), listenerValid = Mutex(true)
        let captures = Mutex(0)
        let activity: ReleaseActivityBarrier?
        init(activity: ReleaseActivityBarrier? = nil) throws {
            admission = try .init(accountID: Data(repeating: 1, count: 16), incarnation: Data(repeating: 4, count: 16)); self.activity = activity
        }
        func access() throws -> AuthorityMaintenanceChannelAccess {
            try .openOwned(admission: admission, acquireActivity: { [self] in try activity?.acquireShared() }, check: { _ in }, observe: { [self] q in
                captures.withLock { $0 += 1 }
                if q.action == .observe && paused.withLock({ $0 }) { await pause.wait() }
                return try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
                    exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
                    execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
                    pairing: .init(ready: true, stagedAttempts: admission.stagedReservations(), activityOwners: 0, operationActive: false))
            })
        }
    }
    private final class Builder: AuthorityMaintenanceEndpointBuilding, @unchecked Sendable {
        let access: AuthorityMaintenanceChannelAccess
        let created = Mutex(0), closed = Mutex(0), fail = Mutex(false), earlyClose = Mutex(false), suppressHandshake = Mutex(false)
        init(_ access: AuthorityMaintenanceChannelAccess) { self.access = access }
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
                  onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws -> AuthorityMaintenanceXPCEndpoint {
            if fail.withLock({ $0 }) { throw Fault.rejected }
            let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: budget,
                invalidate: { [weak connection, weak self] in connection?.invalidate(); onClose(); self?.closed.withLock { $0 += 1 } },
                onHandshake: { [self] in if !suppressHandshake.withLock({ $0 }) { onHandshake() } })
            connection.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); connection.exportedObject = endpoint
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }; connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            created.withLock { $0 += 1 }; if earlyClose.withLock({ $0 }) { endpoint.close() }; return endpoint
        }
    }
    private final class JoinCounts: Sendable {
        let started = Mutex(0), joined = Mutex(0)
    }
    private final class Peer: @unchecked Sendable {
        let connection: NSXPCConnection
        init(_ listener: NSXPCListener) {
            connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); connection.activate()
        }
        func close() { connection.invalidate() }
        deinit { close() }
        func call(_ q: Request) async throws -> Response {
            let state = Mutex<(Bool, Data?, Bool)>((false, nil, false))
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                state.withLock { if !$0.0 { $0 = (true, nil, true) } }
            }) as? any AuthorityMaintenanceXPCProtocol else { throw Fault.rejected }
            proxy.exchange(try q.encoded) { data in state.withLock { if !$0.0 { $0 = (true, data, false) } } }
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while !state.withLock({ $0.0 }) {
                guard ContinuousClock.now < deadline else { throw Fault.timedOut }; try await Task.sleep(for: .milliseconds(2))
            }
            let result = state.withLock { $0 }; guard !result.2, let data = result.1 else { throw Fault.rejected }
            return try Response.decode(data, expected: q)
        }
    }
    private func request(_ action: Request.Action, binding: AuthorityMaintenanceBinding? = nil) throws -> Request {
        try .init(action: action, accountID: Data(repeating: 1, count: 16), attemptID: Data(repeating: 2, count: 16),
            revision: Data(repeating: 3, count: 16), installationID: Data(repeating: 7, count: 16), gate: .init(device: 8, inode: 9),
            binding: binding, challenge: Data(repeating: 6, count: 32))
    }
    private func waitUntil(_ body: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !body() { guard ContinuousClock.now < deadline else { throw Fault.timedOut }; try await Task.sleep(for: .milliseconds(2)) }
    }
    private func makeOwner(_ f: Fixture, _ native: NSXPCListener, _ builder: Builder, maximum: Int = 2,
                       timeout: UInt64 = 5000) throws -> AuthorityMaintenanceXPCListener {
        try .openOwned(listener: native, builder: builder, maximumConnections: maximum, maximumOperations: 1,
            handshakeTimeoutMilliseconds: timeout, verifyCurrent: {
                guard f.listenerValid.withLock({ $0 }) else { throw Fault.rejected }
                try f.admission.requireAccount(Data(repeating: 1, count: 16))
            })
    }
    func testAnonymousOpenObserveAndJoinedCloseCannotRestartTheListener() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder)
        try owner.start(); XCTAssertThrowsError(try owner.start())
        let peer = Peer(native); defer { peer.close(); owner.close() }
        let opened = try await peer.call(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        let observed = try await peer.call(request(.observe, binding: opened.binding)); XCTAssertEqual(observed.outcome, .applied)
        await owner.closeAndWait(); await owner.closeAndWait()
        XCTAssertEqual(builder.created.withLock { $0 }, 1); XCTAssertEqual(builder.closed.withLock { $0 }, 1)
        XCTAssertEqual(owner.retainedEndpoints(), 0); XCTAssertEqual(try f.admission.connectionReservations(), 0)
        XCTAssertThrowsError(try owner.start())
    }
    func testListenerTeardownPreservesArmedBindingUntilExactExplicitReopen() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder)
        try owner.start(); let peer = Peer(native); defer { peer.close(); owner.close() }
        let opened = try await peer.call(request(.open)), armed = try await peer.call(request(.arm, binding: opened.binding))
        XCTAssertEqual(armed.outcome, .applied); await owner.closeAndWait()
        XCTAssertEqual(owner.retainedEndpoints(), 0); XCTAssertThrowsError(try f.admission.reserveStage())
        let target = try f.admission.shutdownBinding(matching: opened.binding)
        let other = try f.admission.refusalBinding(accountID: opened.binding.accountID, attemptID: opened.binding.attemptID, revision: opened.binding.revision)
        XCTAssertThrowsError(try target.reopen(matching: other)); XCTAssertThrowsError(try f.admission.reserveStage())
        try target.reopen(matching: opened.binding); let stage = try f.admission.reserveStage(); stage.close()
    }
    private func drain(disconnectFirst: Bool) async throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open()), installer = try activity.open()
        let native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder)
        try owner.start(); let peer = Peer(native), opened = try await peer.call(request(.open))
        f.paused.withLock { $0 = true }
        let q = try request(.observe, binding: opened.binding), exchange = Task { try await peer.call(q) }
        defer { f.pause.resume(); peer.close(); owner.close() }
        try await waitUntil { f.pause.entered }
        if disconnectFirst {
            peer.close(); try await waitUntil { builder.closed.withLock { $0 == 1 } }
            let other = Peer(native); defer { other.close() }
            do { _ = try await other.call(request(.open)); XCTFail("Retired work must retain the shared budget") } catch {}
            XCTAssertEqual(f.captures.withLock { $0 }, 2)
        }
        owner.close()
        let counts = JoinCounts()
        let join: @Sendable () async -> Void = { [owner, counts] in
            counts.started.withLock { $0 += 1 }; await owner.closeAndWait(); counts.joined.withLock { $0 += 1 }
        }
        let first = Task(operation: join), second = Task(operation: join)
        try await waitUntil { counts.started.withLock { $0 == 2 } }
        XCTAssertEqual(counts.joined.withLock { $0 }, 0); XCTAssertGreaterThan(owner.retainedEndpoints(), 0)
        XCTAssertThrowsError(try installer.acquireExclusive())
        f.pause.resume(); await first.value; await second.value
        let outcome = await exchange.result; if case .success = outcome { XCTFail("Disconnected exchange cannot report applied") }
        XCTAssertEqual(counts.joined.withLock { $0 }, 2); XCTAssertEqual(owner.retainedEndpoints(), 0)
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testListenerShutdownJoinsWorkBeforeReleasingActualActivity() async throws { try await drain(disconnectFirst: false) }
    func testListenerShutdownJoinsAlreadyDisconnectedWorkAndRetainsItsSharedBudget() async throws { try await drain(disconnectFirst: true) }
    func testChangedScopeRejectsStartAndAcceptBeforeConstructingAnEndpoint() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder)
        f.listenerValid.withLock { $0 = false }; XCTAssertThrowsError(try owner.start())
        XCTAssertEqual(builder.created.withLock { $0 }, 0)
        f.listenerValid.withLock { $0 = true }; try owner.start(); f.listenerValid.withLock { $0 = false }
        let peer = Peer(native); defer { peer.close(); owner.close() }
        do { _ = try await peer.call(request(.open)); XCTFail() } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 0); await owner.closeAndWait()
    }
    func testWrongListenerAndPrestartAcceptNeverReachTheBuilder() throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), wrong = NSXPCListener.anonymous(), builder = try Builder(f.access())
        let owner = try makeOwner(f, native, builder), first = NSXPCConnection(listenerEndpoint: native.endpoint)
        defer { owner.close(); first.invalidate(); wrong.invalidate() }
        XCTAssertFalse(owner.listener(native, shouldAcceptNewConnection: first))
        try owner.start(); let second = NSXPCConnection(listenerEndpoint: wrong.endpoint); defer { second.invalidate() }
        XCTAssertFalse(owner.listener(wrong, shouldAcceptNewConnection: second)); XCTAssertEqual(builder.created.withLock { $0 }, 0)
    }
    func testUnreportedHandshakeDeadlineRetiresTheEndpointAndReturnsCapacity() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access())
        builder.suppressHandshake.withLock { $0 = true }
        let owner = try makeOwner(f, native, builder, maximum: 1, timeout: 300); try owner.start()
        let peer = Peer(native); defer { peer.close(); owner.close() }
        let opened = try await peer.call(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        try await waitUntil { builder.closed.withLock { $0 == 1 } && owner.retainedEndpoints() == 0 }
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
        builder.suppressHandshake.withLock { $0 = false }; let fresh = Peer(native); defer { fresh.close() }
        let next = try await fresh.call(request(.open)); XCTAssertEqual(next.outcome, .applied)
        await owner.closeAndWait(); XCTAssertEqual(owner.retainedEndpoints(), 0)
    }
    func testConnectionLimitIsHeldUntilTheExactConnectionCloses() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder, maximum: 1)
        try owner.start(); let peer = Peer(native), opened = try await peer.call(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        defer { peer.close(); owner.close() }
        let other = Peer(native); defer { other.close() }
        do { _ = try await other.call(request(.open)); XCTFail() } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 1)
        peer.close(); try await waitUntil { builder.closed.withLock { $0 == 1 } && owner.retainedEndpoints() == 0 }
        let fresh = Peer(native); defer { fresh.close() }; _ = try await fresh.call(request(.open))
        XCTAssertEqual(builder.created.withLock { $0 }, 2); await owner.closeAndWait()
    }
    func testBuilderFailureReturnsItsReservationBeforeTheNextConnection() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder, maximum: 1)
        builder.fail.withLock { $0 = true }; try owner.start(); let peer = Peer(native)
        defer { peer.close(); owner.close() }
        do { _ = try await peer.call(request(.open)); XCTFail() } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 0); XCTAssertEqual(owner.retainedEndpoints(), 0)
        builder.fail.withLock { $0 = false }; let fresh = Peer(native); defer { fresh.close() }
        let opened = try await fresh.call(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        await owner.closeAndWait(); XCTAssertEqual(owner.retainedEndpoints(), 0)
    }
    func testCloseDuringConstructionCannotLeaveAnUntrackedEndpointOrReservation() async throws {
        let f = try Fixture(), native = NSXPCListener.anonymous(), builder = try Builder(f.access()), owner = try makeOwner(f, native, builder, maximum: 1)
        builder.earlyClose.withLock { $0 = true }; try owner.start(); let peer = Peer(native)
        defer { peer.close(); owner.close() }
        do { _ = try await peer.call(request(.open)); XCTFail() } catch {}
        try await waitUntil { builder.closed.withLock { $0 == 1 } && owner.retainedEndpoints() == 0 }
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
        builder.earlyClose.withLock { $0 = false }; let fresh = Peer(native); defer { fresh.close() }
        let opened = try await fresh.call(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        await owner.closeAndWait(); XCTAssertEqual(owner.retainedEndpoints(), 0)
    }
}
