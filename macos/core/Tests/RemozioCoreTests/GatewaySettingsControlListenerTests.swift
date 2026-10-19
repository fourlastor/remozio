import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Anonymous NSXPC exercises lifecycle and shared work limits. Native Root and code admission remain separate checks.
final class GatewaySettingsControlListenerTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Builder: GatewaySettingsControlEndpointBuilding, @unchecked Sendable {
        let binding: GatewaySettingsControlBinding
        let execute: @Sendable (GatewaySettingsControlRequest) async throws -> GatewaySettingsControlObservation
        let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
        let created = Mutex(0)
        let closed = Mutex(0)
        init(binding: GatewaySettingsControlBinding,
             acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken? = { nil },
             execute: @escaping @Sendable (GatewaySettingsControlRequest) async throws -> GatewaySettingsControlObservation) {
            self.binding = binding; self.execute = execute; self.acquireActivity = acquireActivity
        }
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
                  onHandshake: @escaping @Sendable () -> Void,
                  onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsControlXPCEndpoint {
            let endpoint = GatewaySettingsControlXPCEndpoint(binding: binding, verify: {}, verifyCurrent: {},
                acquireActivity: acquireActivity, budget: budget, onHandshake: onHandshake,
                invalidate: { [weak connection, weak self] in
                    connection?.invalidate(); onClose(); self?.closed.withLock { $0 += 1 }
                }, execute: execute)
            connection.exportedInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            created.withLock { $0 += 1 }
            return endpoint
        }
    }
    private func binding() throws -> GatewaySettingsControlBinding {
        try .init(accountID: Data(repeating: 1, count: 16), rootEpoch: UUID())
    }
    private func change() throws -> AuthorityPhonePushSettingsChange {
        try .init(revisionDigest: Data(repeating: 2, count: 32), previousCommitDigest: Data(repeating: 3, count: 32),
            selectedCommitDigest: Data(repeating: 4, count: 32))
    }
    private func channel(_ listener: NSXPCListener, binding: GatewaySettingsControlBinding) throws -> (GatewaySettingsControlChannel, NSXPCConnection) {
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let driver = NativeGatewaySettingsControlDriver(connection: connection, verifyPeer: {})
        return (try .init(driver: driver, accountID: binding.accountID, expectedRootEpoch: binding.rootEpoch,
            timeoutMilliseconds: 2500, challenge: { Data(repeating: 5, count: 32) }), connection)
    }
    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testActualAnonymousExchangeClosesAndCannotReopenTheListener() async throws {
        let binding = try binding(), executions = Mutex(0)
        let builder = Builder(binding: binding) { _ in executions.withLock { $0 += 1 }; return .suspended }
        let native = NSXPCListener.anonymous()
        let owner = try GatewaySettingsControlXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try owner.start(); XCTAssertThrowsError(try owner.start())
        let (client, connection) = try channel(native, binding: binding)
        let response = try await client.execute(change(), action: .quiesce)
        XCTAssertEqual(response.observation, .suspended); connection.invalidate()
        await owner.closeAndWait(); await owner.closeAndWait()
        XCTAssertEqual(builder.created.withLock { $0 }, 1); XCTAssertEqual(executions.withLock { $0 }, 1)
        XCTAssertThrowsError(try owner.start())
    }
    private func drain(disconnectFirst: Bool) async throws {
        let binding = try binding(), gate = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let activityFixture = try ReleaseActivityFixture(), activity = try activityFixture.open(), installer = try activityFixture.open()
        let executions = Mutex(0), drained = Mutex(false)
        let builder = Builder(binding: binding, acquireActivity: { try activity.acquireShared() }) { _ in
            executions.withLock { $0 += 1 }
            await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
            return .suspended
        }
        let native = NSXPCListener.anonymous()
        let owner = try GatewaySettingsControlXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try owner.start()
        let (client, connection) = try channel(native, binding: binding), change = try change()
        let exchange = Task { try await client.execute(change, action: .quiesce) }
        defer { gate.withLock { let previous = $0; $0 = nil; previous?.resume() }; connection.invalidate(); owner.close() }
        try await waitUntil { gate.withLock { $0 != nil } }
        if disconnectFirst {
            connection.invalidate(); await client.close()
            try await waitUntil { builder.closed.withLock { $0 == 1 } }
            // A retired connection cannot return its still-running operation's global work slot.
            let (other, secondConnection) = try channel(native, binding: binding)
            defer { secondConnection.invalidate() }
            do { _ = try await other.execute(change, action: .quiesce); XCTFail("Disconnected work must retain its slot") }
            catch {}
            XCTAssertEqual(executions.withLock { $0 }, 1)
        }
        let joining = Task { await owner.closeAndWait(); drained.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertFalse(drained.withLock { $0 }); XCTAssertThrowsError(try installer.acquireExclusive())
        gate.withLock { let previous = $0; $0 = nil; previous?.resume() }
        await joining.value
        XCTAssertTrue(drained.withLock { $0 }); let exclusive = try installer.acquireExclusive(); exclusive.close()
        do { _ = try await exchange.value; XCTFail("Closed work cannot report a successful action") } catch {}
        XCTAssertEqual(executions.withLock { $0 }, 1)
    }
    func testShutdownJoinsAnActiveConnectionBeforeReleasingItsJournalScope() async throws {
        try await drain(disconnectFirst: false)
    }
    func testShutdownAlsoJoinsDisconnectedWorkAndRetainsTheSharedOperationLimit() async throws {
        try await drain(disconnectFirst: true)
    }
    func testChangedStartupScopeCannotOpenTheListenerOrConstructAnEndpoint() async throws {
        let binding = try binding(), builder = Builder(binding: binding) { _ in XCTFail(); return .unknown }
        let native = NSXPCListener.anonymous(), valid = Mutex(false)
        let owner = try GatewaySettingsControlXPCListener(listener: native, builder: builder, verifyCurrent: {
            guard valid.withLock({ $0 }) else { throw Failed() }
        })
        XCTAssertThrowsError(try owner.start()); XCTAssertEqual(builder.created.withLock { $0 }, 0)
        valid.withLock { $0 = true }; try owner.start(); valid.withLock { $0 = false }
        let (client, connection) = try channel(native, binding: binding)
        defer { connection.invalidate() }
        do { _ = try await client.execute(change(), action: .observe); XCTFail("A changed scope cannot admit an endpoint") } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 0); await owner.closeAndWait()
    }
}
