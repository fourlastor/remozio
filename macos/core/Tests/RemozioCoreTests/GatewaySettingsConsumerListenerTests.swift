import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Anonymous NSXPC exercises lifecycle and shared work limits. Native dedicated-account and code admission remain separate checks.
final class GatewaySettingsConsumerListenerTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private let fixture = try! GatewaySettingsConsumerControlFixture()
    private final class Builder: GatewaySettingsConsumerEndpointBuilding, @unchecked Sendable {
        let binding: GatewaySettingsConsumerBinding
        let execute: @Sendable (GatewaySettingsConsumerRequest) async throws -> GatewaySettingsConsumerObservation
        let acquireActivity: @Sendable () throws -> (any OwnedReleaseActivity)?
        let created = Mutex(0)
        let closed = Mutex(0)
        init(binding: GatewaySettingsConsumerBinding,
             acquireActivity: @escaping @Sendable () throws -> (any OwnedReleaseActivity)? = { nil },
             execute: @escaping @Sendable (GatewaySettingsConsumerRequest) async throws -> GatewaySettingsConsumerObservation) {
            self.binding = binding; self.execute = execute; self.acquireActivity = acquireActivity
        }
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
                  onHandshake: @escaping @Sendable () -> Void,
                  onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsConsumerXPCEndpoint {
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: binding, verify: {}, verifyCurrent: {},
                acquireActivity: acquireActivity, budget: budget, onHandshake: onHandshake,
                invalidate: { [weak connection, weak self] in
                    connection?.invalidate(); onClose(); self?.closed.withLock { $0 += 1 }
                }, execute: execute)
            connection.exportedInterface = NSXPCInterface(with: GatewaySettingsConsumerXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            created.withLock { $0 += 1 }
            return endpoint
        }
    }
    private func binding() throws -> GatewaySettingsConsumerBinding { try fixture.binding() }
    private func change() throws -> GatewayRuntimeSettingsFence { fixture.fence }
    private func channel(_ listener: NSXPCListener, binding: GatewaySettingsConsumerBinding) throws -> (GatewaySettingsConsumerChannel, NSXPCConnection) {
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let driver = NativeGatewaySettingsConsumerDriver(connection: connection, verifyPeer: {})
        return (try .init(driver: driver, role: binding.role, macID: binding.macID, accountID: binding.accountID, expectedGeneration: binding.generation,
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
        let builder = Builder(binding: binding) { _ in executions.withLock { $0 += 1 }; return .paused }
        let native = NSXPCListener.anonymous()
        let owner = try GatewaySettingsConsumerXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try owner.start(); XCTAssertThrowsError(try owner.start())
        let (client, connection) = try channel(native, binding: binding)
        let response = try await client.execute(change(), action: .quiesce)
        XCTAssertEqual(response.observation, .paused); connection.invalidate()
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
            return .paused
        }
        let native = NSXPCListener.anonymous()
        let owner = try GatewaySettingsConsumerXPCListener(listener: native, builder: builder, verifyCurrent: {})
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
        let owner = try GatewaySettingsConsumerXPCListener(listener: native, builder: builder, verifyCurrent: {
            guard valid.withLock({ $0 }) else { throw Failed() }
        })
        XCTAssertThrowsError(try owner.start()); XCTAssertEqual(builder.created.withLock { $0 }, 0)
        valid.withLock { $0 = true }; try owner.start(); valid.withLock { $0 = false }
        let (client, connection) = try channel(native, binding: binding)
        defer { connection.invalidate() }
        do { _ = try await client.execute(change(), action: .observe); XCTFail("A changed scope cannot admit an endpoint") } catch {}
        XCTAssertEqual(builder.created.withLock { $0 }, 0); await owner.closeAndWait()
    }
    func testActualAnonymousClientCanPauseAndAcceptEachCurrentConsumerOwner() async throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let consumer = try fixture.owner(role: role)
            let access = try GatewaySettingsConsumerAccess(owner: consumer, services: fixture.plan.pair.authority.material.runtime.services, verifyCurrent: {})
            let builder = Builder(binding: consumer.binding) { try await access.execute($0) }
            let native = NSXPCListener.anonymous()
            let listener = try GatewaySettingsConsumerXPCListener(listener: native, builder: builder, verifyCurrent: {})
            try listener.start()
            let (quiesce, firstConnection) = try channel(native, binding: consumer.binding)
            let paused = try await quiesce.execute(fixture.fence, action: .quiesce)
            XCTAssertEqual(paused.observation, .paused); XCTAssertEqual(paused.request.binding, consumer.binding)
            let (accept, secondConnection) = try channel(native, binding: paused.request.binding)
            let accepted = try await accept.execute(fixture.fence, action: .accept)
            XCTAssertEqual(accepted.observation, .accepted)
            XCTAssertEqual(builder.created.withLock { $0 }, 2)
            firstConnection.invalidate(); secondConnection.invalidate()
            await listener.closeAndWait(); try await consumer.close()
        }
    }

    func testDisconnectedWorkRetainsTheReadOnlyServiceScopeUntilActualSettlement() async throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        let binding = try binding(), gate = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let builder = Builder(binding: binding, acquireActivity: { try service.acquireShared() }) { _ in
            await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
            return .paused
        }
        let native = NSXPCListener.anonymous()
        let listener = try GatewaySettingsConsumerXPCListener(listener: native, builder: builder, verifyCurrent: {})
        try listener.start()
        let (client, connection) = try channel(native, binding: binding), fence = fixture.fence
        let exchange = Task { try await client.execute(fence, action: .quiesce) }
        defer { gate.withLock { let old = $0; $0 = nil; old?.resume() }; connection.invalidate(); listener.close() }
        try await waitUntil { gate.withLock { $0 != nil } }
        connection.invalidate(); await client.close()
        try await waitUntil { builder.closed.withLock { $0 == 1 } }
        XCTAssertThrowsError(try updater.acquireExclusive())
        let closed = Mutex(false), joining = Task { await listener.closeAndWait(); closed.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(25)); XCTAssertFalse(closed.withLock { $0 })
        gate.withLock { let old = $0; $0 = nil; old?.resume() }; await joining.value
        do { _ = try await exchange.value; XCTFail() } catch {}
        let update = try updater.acquireExclusive(); update.close()
    }

}
