import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerHostTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private struct Failed: Error {}
    private final class WeakHost {
        weak var value: GatewaySettingsConsumerHost?
        init(_ value: GatewaySettingsConsumerHost?) { self.value = value }
    }
    private final class Listener: OwnedGatewaySettingsConsumerListener, Sendable {
        struct State { var starts = 0, retired = false; var gate: CheckedContinuation<Void, Never>? }
        let state = Mutex(State())
        let hold: Bool
        init(hold: Bool = false) { self.hold = hold }
        func start() throws { state.withLock { $0.starts += 1 } }
        func close() { state.withLock { $0.retired = true } }
        func closeAndWait() async {
            close()
            if hold { await withCheckedContinuation { gate in state.withLock { $0.gate = gate } } }
        }
        func finish() { state.withLock { value in let gate = value.gate; value.gate = nil; return gate }?.resume() }
    }
    private final class Backend: OwnedGatewaySettingsConsumerRuntime, Sendable {
        struct State {
            var starts = 0, closes = 0, retired = false, startFailures = 0, closeFailures = 0
            var startGate: CheckedContinuation<Void, Never>?, closeGate: CheckedContinuation<Void, Never>?
        }
        let state = Mutex(State())
        let holdStart: Bool, holdClose: Bool
        init(holdStart: Bool = false, holdClose: Bool = false, startFailures: Int = 0, closeFailures: Int = 0) {
            self.holdStart = holdStart; self.holdClose = holdClose
            state.withLock { $0.startFailures = startFailures; $0.closeFailures = closeFailures }
        }
        func retire() { state.withLock { $0.retired = true } }
        func start() async throws {
            state.withLock { $0.starts += 1 }
            if holdStart { await withCheckedContinuation { gate in state.withLock { $0.startGate = gate } } }
            if state.withLock({ value in if value.startFailures > 0 { value.startFailures -= 1; return true }; return false }) { throw Failed() }
        }
        func closeAndWait() async throws {
            state.withLock { $0.closes += 1 }
            if state.withLock({ value in if value.closeFailures > 0 { value.closeFailures -= 1; return true }; return false }) { throw Failed() }
            if holdClose { await withCheckedContinuation { gate in state.withLock { $0.closeGate = gate } } }
        }
        func finishStart() { state.withLock { value in let gate = value.startGate; value.startGate = nil; return gate }?.resume() }
        func finishClose() { state.withLock { value in let gate = value.closeGate; value.closeGate = nil; return gate }?.resume() }
    }
    private func owner(_ fixture: GatewaySettingsConsumerControlFixture, backend: Backend,
                       initial: Bool = false) throws -> GatewaySettingsConsumerOwner {
        let fence = fixture.fence, plan = fixture.plan
        return try .init(role: .gateway, macID: fence.macID, accountID: fence.accountID, operations: .init(
            verifyScope: {}, readFence: { fence }, loadSelected: { binding, current in
                try .gateway(binding: binding, fence: current, configuration: .decode(XCTUnwrap(plan.artifacts.first {
                    if case .gatewayConfiguration = $0.file { true } else { false }
                }).selected), commit: plan.commit)
            }, makeRuntime: { _, _ in backend }), initialRuntime: initial ? backend : nil)
    }
    private func act(_ owner: GatewaySettingsConsumerOwner, _ fixture: GatewaySettingsConsumerControlFixture,
                     _ action: GatewaySettingsControlAction) async throws -> GatewaySettingsConsumerObservation {
        try await owner.performAuthenticated(.init(binding: owner.binding, fence: fixture.fence, action: action,
            challenge: Data(repeating: 2, count: 32)), verifyCaller: {}).observation
    }
    private func accept(_ owner: GatewaySettingsConsumerOwner, _ fixture: GatewaySettingsConsumerControlFixture) async throws {
        _ = try await act(owner, fixture, .quiesce); _ = try await act(owner, fixture, .accept)
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testControlStartsWithReleaseActivityButWithoutAnyProviderAccess() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(), owner = try owner(f, backend: backend)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(), host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared())
        do { try await host.poll(); XCTFail() } catch {}
        try await host.start(); try await host.poll()
        XCTAssertEqual(listener.state.withLock { $0.starts }, 1); XCTAssertEqual(backend.state.withLock { $0.starts }, 0)
        XCTAssertThrowsError(try updater.acquireExclusive())
        do { try await host.start(); XCTFail() } catch {}
        try await host.close(); let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testProviderFailureLeavesControlAvailableAndRetriesOnlyAcceptedWork() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(startFailures: 1), owner = try owner(f, backend: backend)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared(), retryMilliseconds: 100)
        try await host.start(); try await accept(owner, f); try await host.poll()
        XCTAssertFalse(listener.state.withLock { $0.retired })
        let observation = try await act(owner, f, .observe); XCTAssertEqual(observation, .accepted)
        try await host.poll(); XCTAssertEqual(backend.state.withLock { $0.starts }, 1)
        try await Task.sleep(for: .milliseconds(120)); try await host.poll()
        XCTAssertEqual(backend.state.withLock { $0.starts }, 2)
        try await host.close()
    }
    func testProviderStartAndCleanupFailuresRecoverThroughHostPolling() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(startFailures: 1, closeFailures: 1)
        let owner = try owner(f, backend: backend)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared(), retryMilliseconds: 100)
        try await host.start(); try await accept(owner, f); try await host.poll()
        let failed = try await act(owner, f, .observe); XCTAssertEqual(failed, .quiescing)
        XCTAssertFalse(listener.state.withLock { $0.retired })
        try await host.poll()
        XCTAssertEqual(backend.state.withLock { $0.starts }, 1); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
        try await Task.sleep(for: .milliseconds(120)); try await host.poll()
        let recovered = try await act(owner, f, .observe); XCTAssertEqual(recovered, .runtimeStarted)
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2); XCTAssertEqual(backend.state.withLock { $0.starts }, 2)
        try await host.close()
    }
    func testCloseRetainsActivityThroughListenerAndBackendDrainDespiteCancelledWaiter() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdClose: true), owner = try owner(f, backend: backend, initial: true)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(hold: true), host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared())
        try await host.start()
        let finished = Counter(), first = Task { try await host.close(); finished.value.withLock { $0 += 1 } }
        let second = Task { try await host.close(); finished.value.withLock { $0 += 1 } }; first.cancel()
        defer { listener.finish(); backend.finishClose() }
        try await until { listener.state.withLock { $0.gate != nil } }
        XCTAssertEqual(backend.state.withLock { $0.closes }, 0)
        XCTAssertTrue(backend.state.withLock { $0.retired }); XCTAssertThrowsError(try updater.acquireExclusive())
        listener.finish(); try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertEqual(finished.value.withLock { $0 }, 0); XCTAssertThrowsError(try updater.acquireExclusive())
        backend.finishClose(); try await first.value; try await second.value
        XCTAssertEqual(finished.value.withLock { $0 }, 2); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testFailedDrainKeepsActivityAndAllowsCleanupRetryWithoutReopeningControl() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(closeFailures: 1), owner = try owner(f, backend: backend, initial: true)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(), host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared())
        try await host.start()
        do { try await host.close(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertTrue(listener.state.withLock { $0.retired }); XCTAssertThrowsError(try updater.acquireExclusive())
        do { try await host.poll(); XCTFail() } catch {}
        try await host.close(); let exclusive = try updater.acquireExclusive(); exclusive.close()
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2)
    }
    func testScopeFailureCannotStartControlAndCleanupDoesNotRequireValidScope() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), owner = try f.owner()
        let files = try ServiceReleaseActivityFixture(), valid = Mutex(true), service = try files.open(verify: {
            guard valid.withLock({ $0 }) else { throw Failed() }
        })
        let activity = try service.acquireShared(), listener = Listener()
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: activity)
        valid.withLock { $0 = false }
        do { try await host.start(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(listener.state.withLock { $0.starts }, 0)
        try await host.close()
    }
    func testCloseDuringAnAcceptedStartKeepsActivityUntilTheReturnedBackendSettles() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdStart: true, holdClose: true), owner = try owner(f, backend: backend)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: Listener(), activity: service.acquireShared())
        try await host.start(); try await accept(owner, f)
        let poll = Task { try await host.poll() }
        defer { backend.finishStart(); backend.finishClose() }
        try await until { backend.state.withLock { $0.startGate != nil } }
        let close = Task { try await host.close() }
        try await Task.sleep(for: .milliseconds(20)); XCTAssertThrowsError(try updater.acquireExclusive())
        backend.finishStart(); try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertThrowsError(try updater.acquireExclusive()); backend.finishClose(); try await close.value
        _ = await poll.result; let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testDroppingHostRetainsActivityUntilDeferredCleanupSettles() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdClose: true), owner = try owner(f, backend: backend, initial: true)
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        var host: GatewaySettingsConsumerHost? = try .init(owner: owner, listener: Listener(), activity: service.acquireShared())
        let weakHost = WeakHost(host); try await host?.start(); host = nil; XCTAssertNil(weakHost.value)
        defer { backend.finishClose() }
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertThrowsError(try updater.acquireExclusive()); backend.finishClose()
        try await until { (try? updater.acquireExclusive()) != nil }
    }
    func testImmutableGatewayBootstrapHasAFixedRoleAndAccountPath() throws {
        let f = try ConsumerHostMetadataFixture(), gateway = try f.host(.gateway)
        let expected = try RuntimePreparationPaths(accountID: gateway.runtime.services.accountID).serviceDirectory
            + "/gateway-settings-consumer-host.cbor"
        XCTAssertEqual(try gateway.gatewayConfigurationPath, expected)
        XCTAssertThrowsError(try f.host(.transport).gatewayConfigurationPath)
    }
    func testNativeEntryRefusesAnOrdinaryOwnedBootstrapWithoutChangingIt() throws {
        let f = try ConsumerHostMetadataFixture(), files = try ServiceReleaseActivityFixture()
        let bytes = try f.host(.gateway).encoded
        let path = files.root.appendingPathComponent("gateway-settings-consumer-host.cbor")
        try bytes.write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        XCTAssertThrowsError(try GatewaySettingsGatewayHost.open(path: path.path))
        XCTAssertEqual(try Data(contentsOf: path), bytes)
    }
    func testRetryDelayBoundsAreExplicit() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), owner = try f.owner(), files = try ServiceReleaseActivityFixture(), service = try files.open()
        let token = try service.acquireShared(); defer { token.close() }
        for value in [0, 99, 60001] {
            XCTAssertThrowsError(try GatewaySettingsConsumerHost(owner: owner, listener: Listener(), activity: token, retryMilliseconds: value))
        }
        try await owner.close()
    }
}
