import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsInitialRuntimeTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Backend: OwnedGatewaySettingsConsumerRuntime, Sendable {
        struct State {
            var starts = 0, closes = 0, retired = false, failStart = false, failClose = false
            var startGate: CheckedContinuation<Void, Never>?, closeGate: CheckedContinuation<Void, Never>?
        }
        let state = Mutex(State())
        let holdStart: Bool, holdClose: Bool
        init(holdStart: Bool = false, holdClose: Bool = false) { self.holdStart = holdStart; self.holdClose = holdClose }
        func retire() { state.withLock { $0.retired = true } }
        func start() async throws {
            state.withLock { $0.starts += 1 }
            if holdStart { await withCheckedContinuation { c in state.withLock { $0.startGate = c } } }
            if state.withLock({ $0.failStart }) { throw Failed() }
        }
        func closeAndWait() async throws {
            state.withLock { $0.closes += 1 }
            if state.withLock({ $0.failClose }) { throw Failed() }
            if holdClose { await withCheckedContinuation { c in state.withLock { $0.closeGate = c } } }
        }
        func finishStart() { state.withLock { s in let c = s.startGate; s.startGate = nil; return c }?.resume() }
        func finishClose() { state.withLock { s in let c = s.closeGate; s.closeGate = nil; return c }?.resume() }
    }
    private final class Listener: OwnedGatewaySettingsConsumerListener, Sendable {
        let starts = Mutex(0)
        func start() { starts.withLock { $0 += 1 } }
        func close() {}
        func closeAndWait() async {}
    }
    private func owner(_ f: GatewaySettingsConsumerControlFixture, accepted: Backend = Backend(),
                       scope: @escaping @Sendable () throws -> Void = {},
                       initial: @escaping @Sendable (GatewaySettingsConsumerBinding) throws -> GatewaySettingsConsumerOwner.InitialRuntime?) throws -> GatewaySettingsConsumerOwner {
        let fence = f.fence, plan = f.plan
        return try .init(role: .gateway, macID: fence.macID, accountID: fence.accountID, operations: .init(
            verifyScope: scope, readFence: { fence }, loadSelected: { binding, fence in
                try .gateway(binding: binding, fence: fence, configuration: .decode(XCTUnwrap(plan.artifacts.first {
                    if case .gatewayConfiguration = $0.file { true } else { false }
                }).selected), commit: plan.commit)
            }, makeRuntime: { _, _ in accepted }, makeInitialRuntime: initial))
    }
    private func act(_ owner: GatewaySettingsConsumerOwner, _ f: GatewaySettingsConsumerControlFixture,
                     _ action: GatewaySettingsControlAction) async throws -> GatewaySettingsConsumerObservation {
        try await owner.performAuthenticated(.init(binding: owner.binding, fence: f.fence, action: action,
            challenge: Data(repeating: 2, count: 32)), verifyCaller: {}).observation
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testControlStartsBeforeInitialFactoryAndPollDoesNotReplaceItsBackend() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(), calls = Mutex(0)
        let owner = try owner(f, initial: { binding in
            XCTAssertEqual(binding.role, .gateway); calls.withLock { $0 += 1 }
            return .init(runtime: backend, verifyCurrent: {})
        })
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: service.acquireShared())
        try await host.start(); XCTAssertEqual(listener.starts.withLock { $0 }, 1); XCTAssertEqual(calls.withLock { $0 }, 0)
        try await host.poll(); try await host.poll()
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(backend.state.withLock { $0.starts }, 1)
        // Initial startup is not a settings acceptance receipt.
        let observation = try await act(owner, f, .observe); XCTAssertEqual(observation, .unknown)
        try await host.close()
    }
    func testProviderFailureDrainsBeforeFreshInitialRetry() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), first = Backend(), second = Backend(), calls = Mutex(0)
        first.state.withLock { $0.failStart = true }
        let owner = try owner(f, initial: { _ in
            let n = calls.withLock { $0 += 1; return $0 }
            return .init(runtime: n == 1 ? first : second, verifyCurrent: {})
        })
        do { _ = try await owner.startConfiguredRuntimeIfNeeded(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertTrue(first.state.withLock { $0.retired }); XCTAssertEqual(first.state.withLock { $0.closes }, 1)
        let started = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertTrue(started)
        XCTAssertEqual(second.state.withLock { $0.starts }, 1); try await owner.close()
    }
    func testQuiescenceBeforeFirstPollPermanentlyExcludesInitialStartupButAllowsAcceptedWork() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), accepted = Backend(), calls = Mutex(0)
        let owner = try owner(f, accepted: accepted, initial: { _ in calls.withLock { $0 += 1 }; throw Failed() })
        let paused = try await act(owner, f, .quiesce); XCTAssertEqual(paused, .paused)
        let started = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertFalse(started); XCTAssertEqual(calls.withLock { $0 }, 0)
        _ = try await act(owner, f, .accept)
        let acceptedStarted = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertTrue(acceptedStarted)
        XCTAssertEqual(accepted.state.withLock { $0.starts }, 1); try await owner.close()
    }
    func testQuiescenceDuringInitialStartJoinsDrainAndNeverFallsBack() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdStart: true, holdClose: true), calls = Mutex(0)
        let owner = try owner(f, initial: { _ in calls.withLock { $0 += 1 }; return .init(runtime: backend, verifyCurrent: {}) })
        let startup = Task { try await owner.startConfiguredRuntimeIfNeeded() }
        defer { backend.finishStart(); backend.finishClose() }
        try await until { backend.state.withLock { $0.startGate != nil } }
        let duplicate = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertFalse(duplicate)
        let paused = Mutex(false), quiesce = Task { let r = try await self.act(owner, f, .quiesce); paused.withLock { $0 = true }; return r }
        try await until { backend.state.withLock { $0.retired } }
        XCTAssertFalse(paused.withLock { $0 }); backend.finishStart()
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertFalse(paused.withLock { $0 }); backend.finishClose()
        let result = try await quiesce.value; XCTAssertEqual(result, .paused)
        do { _ = try await startup.value; XCTFail() } catch {}
        let retry = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertFalse(retry)
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(backend.state.withLock { $0.closes }, 1); try await owner.close()
    }
    func testHostCloseDuringInitialStartRetainsActualReleaseActivityThroughDrain() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdStart: true, holdClose: true)
        let owner = try owner(f, initial: { _ in .init(runtime: backend, verifyCurrent: {}) })
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let host = try GatewaySettingsConsumerHost(owner: owner, listener: Listener(), activity: service.acquireShared())
        try await host.start(); let poll = Task { try await host.poll() }
        defer { backend.finishStart(); backend.finishClose() }
        try await until { backend.state.withLock { $0.startGate != nil } }
        let close = Task { try await host.close() }; close.cancel()
        try await until { backend.state.withLock { $0.retired } }
        XCTAssertThrowsError(try updater.acquireExclusive()); backend.finishStart()
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertThrowsError(try updater.acquireExclusive()); backend.finishClose()
        try await close.value; _ = await poll.result
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testChangedPublicationAfterAsyncStartIsRetiredAndDrained() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(holdStart: true), valid = Mutex(true)
        let owner = try owner(f, initial: { _ in .init(runtime: backend, verifyCurrent: {
            guard valid.withLock({ $0 }) else { throw Failed() }
        }) })
        let start = Task { try await owner.startConfiguredRuntimeIfNeeded() }
        defer { backend.finishStart() }; try await until { backend.state.withLock { $0.startGate != nil } }
        valid.withLock { $0 = false }; backend.finishStart()
        do { _ = try await start.value; XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertTrue(backend.state.withLock { $0.retired }); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
        try await owner.close()
    }
    func testInitialCleanupRetriesBeforeAnyFreshFactoryAndQuiescencePreventsFallback() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(), replacement = Backend(), calls = Mutex(0)
        backend.state.withLock { $0.failStart = true; $0.failClose = true }
        let owner = try owner(f, initial: { _ in
            let n = calls.withLock { $0 += 1; return $0 }
            return .init(runtime: n == 1 ? backend : replacement, verifyCurrent: {})
        })
        do { _ = try await owner.startConfiguredRuntimeIfNeeded(); XCTFail() } catch {}
        do { _ = try await owner.startConfiguredRuntimeIfNeeded(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(backend.state.withLock { $0.closes }, 2)
        backend.state.withLock { $0.failClose = false }
        let retry = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertTrue(retry)
        XCTAssertEqual(backend.state.withLock { $0.closes }, 3); XCTAssertEqual(replacement.state.withLock { $0.starts }, 1)
        let paused = try await act(owner, f, .quiesce); XCTAssertEqual(paused, .paused)
        let after = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertFalse(after); XCTAssertEqual(calls.withLock { $0 }, 2)
        try await owner.close()
    }
    func testInvalidCallerCannotDisableInitialStartupAndScopeFailurePrecedesFactory() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), backend = Backend(), calls = Mutex(0), valid = Mutex(false)
        let owner = try owner(f, scope: { guard valid.withLock({ $0 }) else { throw Failed() } }, initial: { _ in
            calls.withLock { $0 += 1 }; return .init(runtime: backend, verifyCurrent: {})
        })
        do { _ = try await owner.startConfiguredRuntimeIfNeeded(); XCTFail() } catch {}
        XCTAssertEqual(calls.withLock { $0 }, 0); valid.withLock { $0 = true }
        do {
            _ = try await owner.performAuthenticated(.init(binding: owner.binding, fence: f.fence, action: .quiesce,
                challenge: Data(repeating: 2, count: 32)), verifyCaller: { throw Failed() }); XCTFail()
        } catch {}
        let started = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertTrue(started)
        XCTAssertEqual(calls.withLock { $0 }, 1); try await owner.close()
    }
    func testNoCommittedInitialSelectionDoesNotCreateOrStartAnyBackend() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), calls = Mutex(0)
        let owner = try owner(f, initial: { _ in calls.withLock { $0 += 1 }; return nil })
        let started = try await owner.startConfiguredRuntimeIfNeeded(); XCTAssertFalse(started)
        XCTAssertEqual(calls.withLock { $0 }, 1); try await owner.close()
    }
    func testLegacyStartupRequiresVerifiedAbsenceOfTheImmutableHost() throws {
        XCTAssertNoThrow(try GatewaySettingsInitialPublication.requireLegacyStartup { throw JournalLeaseError.system(ENOENT) })
        for code in [EACCES, EIO] {
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.requireLegacyStartup { throw JournalLeaseError.system(code) })
        }
        // Presence blocks even when malformed. Decoding failure cannot become a legacy fallback.
        for bytes in [Data(), Data([0]), Data(repeating: 2, count: 10)] {
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.requireLegacyStartup { bytes })
        }
    }
}
