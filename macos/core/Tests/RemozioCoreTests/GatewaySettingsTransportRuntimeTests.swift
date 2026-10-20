import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsTransportRuntimeTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private final class Flag: Sendable { let value: Mutex<Bool>; init(_ initial: Bool) { value = Mutex(initial) } }
    private final class FactoryGate: Sendable { let value = Mutex<CheckedContinuation<TransportWakeAttempt, Never>?>(nil) }
    private struct Failed: Error {}
    private final class Gates: Sendable {
        struct State {
            var starts = 0, polls = 0, closes = 0
            var start: CheckedContinuation<Void, Never>?, poll: CheckedContinuation<Void, Never>?, close: CheckedContinuation<Void, Never>?
        }
        let value = Mutex(State())
        let holdStart: Bool, holdPoll: Bool, holdClose: Bool, failPoll: Bool
        init(holdStart: Bool = false, holdPoll: Bool = false, holdClose: Bool = false, failPoll: Bool = false) {
            self.holdStart = holdStart; self.holdPoll = holdPoll; self.holdClose = holdClose; self.failPoll = failPoll
        }
        func attempt(verify: @escaping @Sendable () throws -> Void = {}) -> TransportWakeAttempt {
            .init(start: { [self] in
                value.withLock { $0.starts += 1 }
                if holdStart { await withCheckedContinuation { c in value.withLock { $0.start = c } } }
                try verify()
            }, poll: { [self] in
                value.withLock { $0.polls += 1 }
                if holdPoll { await withCheckedContinuation { c in value.withLock { $0.poll = c } } }
                try verify()
                if failPoll { throw GatewayWakeChannelError.closed }
            }, close: { [self] in
                value.withLock { $0.closes += 1 }
                if holdClose { await withCheckedContinuation { c in value.withLock { $0.close = c } } }
            }, intervalMilliseconds: 10)
        }
        func finishStart() { value.withLock { s in let c = s.start; s.start = nil; return c }?.resume() }
        func finishPoll() { value.withLock { s in let c = s.poll; s.poll = nil; return c }?.resume() }
        func finishClose() { value.withLock { s in let c = s.close; s.close = nil; return c }?.resume() }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testStartWaitsForActualHandshakeBeforeReadyAndPolling() async throws {
        let gates = Gates(holdStart: true), done = Flag(false)
        let runtime = try GatewaySettingsTransportRuntime(verifyCurrent: {}, makeAttempt: { verify in gates.attempt(verify: verify) })
        let start = Task { try await runtime.start(); done.value.withLock { $0 = true } }
        defer { gates.finishStart() }; try await until { gates.value.withLock { $0.start != nil } }
        XCTAssertFalse(done.value.withLock { $0 }); XCTAssertEqual(runtime.status, .starting); XCTAssertEqual(gates.value.withLock { $0.polls }, 0)
        gates.finishStart(); try await start.value
        try await until { gates.value.withLock { $0.polls > 0 } }; XCTAssertEqual(runtime.status, .ready)
        try await runtime.closeAndWait(); XCTAssertEqual(gates.value.withLock { $0.closes }, 1); XCTAssertEqual(runtime.status, .closed)
    }
    func testRetireDuringFactoryOwnsTheLateAttemptWithoutStartingIt() async throws {
        let gates = Gates(), factory = FactoryGate()
        let runtime = try GatewaySettingsTransportRuntime(verifyCurrent: {}, makeAttempt: { _ in
            await withCheckedContinuation { c in factory.value.withLock { $0 = c } }
        })
        let start = Task { try await runtime.start() }; try await until { factory.value.withLock { $0 != nil } }
        let done = Flag(false), close = Task { try await runtime.closeAndWait(); done.value.withLock { $0 = true } }; close.cancel()
        runtime.retire(); XCTAssertFalse(done.value.withLock { $0 })
        factory.value.withLock { c in let old = c; c = nil; return old }?.resume(returning: gates.attempt())
        do { try await start.value; XCTFail() } catch {}
        try await close.value; XCTAssertEqual(gates.value.withLock { $0.starts }, 0); XCTAssertEqual(gates.value.withLock { $0.closes }, 1)
    }
    func testConcurrentCancelledClosersJoinHandshakeAndOneActualDrain() async throws {
        let gates = Gates(holdStart: true, holdClose: true), finished = Counter()
        let runtime = try GatewaySettingsTransportRuntime(verifyCurrent: {}, makeAttempt: { _ in gates.attempt() })
        let start = Task { try await runtime.start() }
        defer { gates.finishStart(); gates.finishClose() }; try await until { gates.value.withLock { $0.start != nil } }
        let first = Task { try await runtime.closeAndWait(); finished.value.withLock { $0 += 1 } }
        let second = Task { try await runtime.closeAndWait(); finished.value.withLock { $0 += 1 } }; first.cancel()
        runtime.retire(); XCTAssertEqual(finished.value.withLock { $0 }, 0); gates.finishStart()
        try await until { gates.value.withLock { $0.close != nil } }; XCTAssertEqual(finished.value.withLock { $0 }, 0)
        gates.finishClose(); try await first.value; try await second.value; _ = await start.result
        XCTAssertEqual(finished.value.withLock { $0 }, 2); XCTAssertEqual(gates.value.withLock { $0.closes }, 1)
    }
    func testCloseJoinsPollingAndDrainBeforeReleasingActualRoleActivity() async throws {
        let gates = Gates(holdPoll: true, holdClose: true)
        let runtime = try GatewaySettingsTransportRuntime(verifyCurrent: {}, makeAttempt: { _ in gates.attempt() })
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let activity = try service.acquireShared(); try await runtime.start()
        defer { gates.finishPoll(); gates.finishClose(); activity.close() }
        try await until { gates.value.withLock { $0.poll != nil } }
        let close = Task { try await runtime.closeAndWait(); activity.close() }; close.cancel()
        runtime.retire(); XCTAssertThrowsError(try updater.acquireExclusive())
        gates.finishPoll(); try await until { gates.value.withLock { $0.close != nil } }; XCTAssertThrowsError(try updater.acquireExclusive())
        gates.finishClose(); try await close.value
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testRetryDrainsOldAttemptBeforeOpeningFreshChannels() async throws {
        let first = Gates(holdClose: true, failPoll: true), second = Gates(), calls = Counter()
        let runtime = try GatewaySettingsTransportRuntime(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            verifyCurrent: {}, makeAttempt: { _ in calls.value.withLock { $0 += 1; return $0 } == 1 ? first.attempt() : second.attempt() })
        try await runtime.start(); defer { first.finishClose() }
        try await until { first.value.withLock { $0.close != nil } }
        XCTAssertEqual(calls.value.withLock { $0 }, 1); first.finishClose()
        try await until { second.value.withLock { $0.polls > 0 } }
        XCTAssertEqual(calls.value.withLock { $0 }, 2); try await runtime.closeAndWait()
        XCTAssertEqual(first.value.withLock { $0.closes }, 1); XCTAssertEqual(second.value.withLock { $0.closes }, 1)
    }
    func testRevokedPermitStopsRetryAndCannotOpenAReplacement() async throws {
        let first = Gates(holdPoll: true), live = Flag(true), calls = Counter()
        let runtime = try GatewaySettingsTransportRuntime(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            verifyCurrent: { guard live.value.withLock({ $0 }) else { throw Failed() } }, makeAttempt: { verify in
                calls.value.withLock { $0 += 1 }; return first.attempt(verify: verify)
            })
        try await runtime.start(); defer { first.finishPoll() }; try await until { first.value.withLock { $0.poll != nil } }
        live.value.withLock { $0 = false }; first.finishPoll(); try await until { first.value.withLock { $0.closes == 1 } }
        try await Task.sleep(for: .milliseconds(120)); XCTAssertEqual(calls.value.withLock { $0 }, 1); XCTAssertEqual(runtime.status, .failed)
        try await runtime.closeAndWait()
    }
    func testDeinitRetainsAttemptThroughAsyncDrain() async throws {
        let gates = Gates(holdClose: true)
        var runtime: GatewaySettingsTransportRuntime? = try .init(verifyCurrent: {}, makeAttempt: { _ in gates.attempt() })
        try await runtime?.start(); runtime = nil; defer { gates.finishClose() }
        try await until { gates.value.withLock { $0.close != nil } }
        XCTAssertEqual(gates.value.withLock { $0.closes }, 1); gates.finishClose()
    }
    func testInvalidIntervalsAndScopeFailureNeverOpenChannels() async throws {
        for n: UInt64 in [0, 9, 60001] {
            XCTAssertThrowsError(try GatewaySettingsTransportRuntime(intervalMilliseconds: n, verifyCurrent: {}, makeAttempt: { _ in XCTFail(); throw Failed() }))
        }
        let runtime = try GatewaySettingsTransportRuntime(verifyCurrent: { throw Failed() }, makeAttempt: { _ in XCTFail(); throw Failed() })
        do { try await runtime.start(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        try await runtime.closeAndWait()
    }
    func testAcceptedNativeAdapterRejectsOrdinaryCallerBeforePrivateWakeKeyRestoration() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), fence = f.fence, plan = f.plan
        let owner = try GatewaySettingsConsumerOwner(role: .transport, macID: fence.macID, accountID: fence.accountID,
            operations: .init(verifyScope: {}, readFence: { fence }, loadSelected: { binding, fence in
                try .transport(binding: binding, fence: fence, configuration: plan.pair.transport, commit: plan.commit)
            }, makeRuntime: { try GatewaySettingsTransportRuntime(selection: $0, permit: $1) }))
        for action in [GatewaySettingsControlAction.quiesce, .accept] {
            _ = try await owner.performAuthenticated(.init(binding: owner.binding, fence: fence, action: action,
                challenge: Data(repeating: 2, count: 32)), verifyCaller: {})
        }
        do { try await owner.startAcceptedRuntime(); XCTFail() }
        catch { XCTAssertEqual(error as? ApprovalTransportStartupError, .wrongAccount) }
        try await owner.close()
    }
}
