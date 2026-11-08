import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Anonymous exchanges test transport and shutdown. They do not authenticate native Root or a dedicated service account.
final class MachineUpdateConsumerHealthListenerTests: XCTestCase, @unchecked Sendable {
    private final class ReplyBox<Value: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Value, Error>?
        private var timeout: Task<Void, Never>?
        func begin(_ continuation: CheckedContinuation<Value, Error>) {
            lock.withLock {
                self.continuation = continuation
                timeout = Task {
                    do { try await Task.sleep(for: .seconds(4)) }
                    catch { return }
                    resolve(.failure(MachineUpdateOwnedHealthFailure.timeout))
                }
            }
        }
        func resolve(_ result: Result<Value, Error>) {
            let saved = lock.withLock { () -> CheckedContinuation<Value, Error>? in
                let saved = continuation; continuation = nil; timeout?.cancel(); timeout = nil; return saved
            }
            saved?.resume(with: result)
        }
    }
    private final class Client: @unchecked Sendable {
        let connection: NSXPCConnection
        init(_ listener: NSXPCListener) {
            connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: MachineUpdateConsumerHealthXPCProtocol.self)
            connection.activate()
        }
        func hello() async throws -> (UInt64, Data?) {
            let box = ReplyBox<(UInt64, Data?)>()
            return try await withCheckedThrowingContinuation { continuation in
                box.begin(continuation)
                guard let proxy = connection.remoteObjectProxyWithErrorHandler({ box.resolve(.failure($0)) }) as? MachineUpdateConsumerHealthXPCProtocol else {
                    box.resolve(.failure(MachineUpdateOwnedHealthFailure.denied)); return
                }
                proxy.healthHello { version, bytes in box.resolve(.success((version, bytes))) }
            }
        }
        func check(_ bytes: Data) async throws -> Data? {
            let box = ReplyBox<Data?>()
            return try await withCheckedThrowingContinuation { continuation in
                box.begin(continuation)
                guard let proxy = connection.remoteObjectProxyWithErrorHandler({ box.resolve(.failure($0)) }) as? MachineUpdateConsumerHealthXPCProtocol else {
                    box.resolve(.failure(MachineUpdateOwnedHealthFailure.denied)); return
                }
                proxy.checkUpdateHealth(bytes) { box.resolve(.success($0)) }
            }
        }
        func close() { connection.invalidate() }
        deinit { close() }
    }
    private final class Builder: MachineUpdateConsumerHealthEndpointBuilding, @unchecked Sendable {
        let fixture: MachineUpdateOwnedHealthEndpointFixture
        let acquireActivity: @Sendable () throws -> any OwnedReleaseActivity
        let makeOwner: @Sendable () async throws -> any MachineUpdateConsumerHealthAnswering
        let created = Mutex(0), closed = Mutex(0), opened = Mutex(0)
        init(fixture: MachineUpdateOwnedHealthEndpointFixture, acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity,
            makeOwner: @escaping @Sendable () async throws -> any MachineUpdateConsumerHealthAnswering) {
            self.fixture = fixture; self.acquireActivity = acquireActivity; self.makeOwner = makeOwner
        }
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
            onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws -> any MachineUpdateHealthEndpoint {
            let invalidator = MachineUpdateHealthConnectionInvalidator(connection)
            let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
                acquireActivity: acquireActivity, budget: budget, onHandshake: onHandshake,
                invalidate: { [weak self] in invalidator.invalidate(); onClose(); self?.closed.withLock { $0 += 1 } },
                makeOwner: { [self] request in try request.claim(); opened.withLock { $0 += 1 }; return try await makeOwner() })
            connection.exportedInterface = NSXPCInterface(with: MachineUpdateConsumerHealthXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            created.withLock { $0 += 1 }; return endpoint
        }
    }
    private func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !condition() {
            guard ContinuousClock.now < deadline else { throw MachineUpdateOwnedHealthFailure.timeout }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    private func hello(_ client: Client, fixture: MachineUpdateOwnedHealthEndpointFixture) async throws {
        let result = try await client.hello(); XCTAssertEqual(result.0, 1); XCTAssertEqual(result.1, fixture.hello)
    }
    func testAnonymousExchangeChecksTheNonceAndClosesTheOwner() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let answerer = fixture.owner(), native = NSXPCListener.anonymous()
        let builder = Builder(fixture: fixture, acquireActivity: { try activity.acquireShared() }, makeOwner: { answerer })
        let listener = try MachineUpdateConsumerHealthXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try listener.start(); XCTAssertThrowsError(try listener.start())
        let client = Client(native), session = try fixture.session()
        try await hello(client, fixture: fixture)
        let response = try await client.check(session.request)
        XCTAssertEqual(try session.accept(XCTUnwrap(response), authenticatePeer: { _ in }).requirement, fixture.requirement)
        XCTAssertTrue(answerer.isClosed); client.close()
        try await listener.closeAndWait(); try await listener.closeAndWait(); XCTAssertThrowsError(try listener.start())
        XCTAssertEqual(builder.opened.withLock { $0 }, 1)
    }
    private func drain(disconnect: Bool) async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), gate = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let answerer = fixture.owner(), native = NSXPCListener.anonymous(), joined = Mutex(false)
        let builder = Builder(fixture: fixture, acquireActivity: { try activity.acquireShared() }, makeOwner: {
            await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }; return answerer
        })
        let listener = try MachineUpdateConsumerHealthXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try listener.start(); let client = Client(native), bytes = try fixture.session().request
        try await hello(client, fixture: fixture)
        let exchange = Task { try await client.check(bytes) }
        defer { gate.withLock { let old = $0; $0 = nil; old?.resume() }; client.close(); listener.close() }
        try await waitUntil { gate.withLock { $0 != nil } }
        if disconnect {
            client.close(); try await waitUntil { builder.closed.withLock { $0 == 1 } }
            let other = Client(native); defer { other.close() }; try await hello(other, fixture: fixture)
            do { let result = try await other.check(bytes); XCTAssertNil(result) } catch {}
            XCTAssertEqual(builder.opened.withLock { $0 }, 1)
        }
        let joining = Task { try await listener.closeAndWait(); joined.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(25))
        XCTAssertFalse(joined.withLock { $0 }); XCTAssertThrowsError(try installer.acquireExclusive())
        gate.withLock { let old = $0; $0 = nil; old?.resume() }; try await joining.value
        do { let result = try await exchange.value; XCTAssertNil(result) } catch {}
        XCTAssertTrue(answerer.isClosed); XCTAssertEqual(answerer.answers.withLock { $0 }, 0)
        let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testShutdownJoinsTheActiveFactoryBeforeReturning() async throws { try await drain(disconnect: false) }
    func testDisconnectedFactoryKeepsTheListenerBudgetUntilItSettles() async throws { try await drain(disconnect: true) }
    func testFailedCloseRemainsRetainedAfterTheConnectionDisappears() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), allowed = Mutex(false), native = NSXPCListener.anonymous()
        let answerer = fixture.owner(close: { guard allowed.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.closeFailed } })
        let builder = Builder(fixture: fixture, acquireActivity: { try activity.acquireShared() }, makeOwner: { answerer })
        let listener = try MachineUpdateConsumerHealthXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try listener.start(); let client = Client(native); try await hello(client, fixture: fixture)
        do { _ = try await client.check(fixture.session().request); XCTFail("The failed close must invalidate the response") } catch {}
        try await waitUntil { answerer.closeAttempts.withLock { $0 > 0 } }
        do { try await listener.closeAndWait(); XCTFail("A failed close cannot settle the listener") } catch {}
        XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertFalse(answerer.isClosed)
        allowed.withLock { $0 = true }; try await listener.closeAndWait(); client.close()
        XCTAssertTrue(answerer.isClosed); let exclusive = try installer.acquireExclusive(); exclusive.close()
    }
    func testDroppingTheListenerKeepsFailedSettlementUntilTheOwnerCloses() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), allowed = Mutex(false), native = NSXPCListener.anonymous()
        let answerer = fixture.owner(close: { guard allowed.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.closeFailed } })
        let builder = Builder(fixture: fixture, acquireActivity: { try activity.acquireShared() }, makeOwner: { answerer })
        var listener: MachineUpdateConsumerHealthXPCListener? = try .init(listener: native, builder: builder, verifyCurrent: {})
        weak var dropped = listener
        defer { allowed.withLock { $0 = true } }
        try listener?.start()
        let client = Client(native); defer { client.close() }
        try await hello(client, fixture: fixture)
        do { _ = try await client.check(fixture.session().request); XCTFail("The failed close must invalidate the response") } catch {}
        try await waitUntil { answerer.closeAttempts.withLock { $0 > 0 } }
        listener = nil
        try await waitUntil { dropped == nil }
        let attempts = answerer.closeAttempts.withLock { $0 }
        try await waitUntil { answerer.closeAttempts.withLock { $0 > attempts } }
        XCTAssertThrowsError(try installer.acquireExclusive())
        allowed.withLock { $0 = true }
        try await waitUntil { answerer.isClosed }
    }

    func testChangedScopeCannotStartOrConstructAnEndpoint() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let valid = Mutex(false), native = NSXPCListener.anonymous()
        let builder = Builder(fixture: fixture, acquireActivity: { try activity.acquireShared() }, makeOwner: { fixture.owner() })
        let listener = try MachineUpdateConsumerHealthXPCListener(listener: native, builder: builder, verifyCurrent: {
            guard valid.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
        })
        XCTAssertThrowsError(try listener.start()); valid.withLock { $0 = true }; try listener.start(); valid.withLock { $0 = false }
        let client = Client(native); defer { client.close() }
        do { _ = try await client.hello(); XCTFail("Changed scope must reject the connection") } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 0); try await listener.closeAndWait()
    }
}
