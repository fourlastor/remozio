import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Runtime: OwnedGatewaySettingsConsumerRuntime, Sendable {
        struct State {
            var starts = 0, closes = 0, settled = 0, retired = false, startFailures = 0, closeFailures = 0
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
            if state.withLock({ s in if s.startFailures > 0 { s.startFailures -= 1; return true }; return false }) { throw Failed() }
        }
        func closeAndWait() async throws {
            state.withLock { $0.closes += 1 }
            if state.withLock({ s in if s.closeFailures > 0 { s.closeFailures -= 1; return true }; return false }) { throw Failed() }
            if holdClose { await withCheckedContinuation { gate in state.withLock { $0.closeGate = gate } } }
            state.withLock { $0.settled += 1 }
        }
        func releaseStart() { state.withLock { s in let gate = s.startGate; s.startGate = nil; return gate }?.resume() }
        func releaseClose() { state.withLock { s in let gate = s.closeGate; s.closeGate = nil; return gate }?.resume() }
    }
    private final class Fixture: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let plan: GatewayRuntimeSettingsPublicationPlan
        let fence: GatewayRuntimeSettingsFence
        let backend: Runtime
        let state = Mutex((scopeValid: true, rejectSelected: false, factories: 0, permit: Optional<GatewaySettingsConsumerPermit>.none))
        let currentFence: Mutex<GatewayRuntimeSettingsFence>
        init(backend: Runtime = Runtime()) throws {
            ready = try .init()
            plan = try .init(revision: ready.revision(1), previous: nil, activation: ready.activation,
                journal: ready.fixture.state(), foreground: ready.fixture.runtime.plan, inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory()))
            fence = try .init(plan); currentFence = Mutex(fence); self.backend = backend
        }
        func selected(_ binding: GatewaySettingsConsumerBinding, _ fence: GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection {
            if state.withLock({ $0.rejectSelected }) { throw Failed() }
            switch binding.role {
            case .gateway: return try .gateway(binding: binding, fence: fence,
                configuration: .decode(XCTUnwrap(plan.artifacts.first { if case .gatewayConfiguration = $0.file { true } else { false } }).selected), commit: plan.commit)
            case .transport: return try .transport(binding: binding, fence: fence, configuration: plan.pair.transport, commit: plan.commit)
            }
        }
        func owner(role: GatewaySettingsConsumerRole = .gateway, initial: Runtime? = nil) throws -> GatewaySettingsConsumerOwner {
            try .init(role: role, macID: fence.macID, accountID: fence.accountID, operations: .init(
                verifyScope: { [self] in if !state.withLock({ $0.scopeValid }) { throw Failed() } },
                readFence: { [self] in currentFence.withLock { $0 } },
                loadSelected: { [self] in try selected($0, $1) },
                makeRuntime: { [self] _, permit in state.withLock { $0.factories += 1; $0.permit = permit }; return backend }), initialRuntime: initial)
        }
        func request(_ owner: GatewaySettingsConsumerOwner, _ action: GatewaySettingsControlAction) throws -> GatewaySettingsConsumerRequest {
            try .init(binding: owner.binding, fence: fence, action: action, challenge: Data(repeating: 4, count: 32))
        }
        func act(_ owner: GatewaySettingsConsumerOwner, _ action: GatewaySettingsControlAction) async throws -> GatewaySettingsConsumerObservation {
            try await owner.performAuthenticated(request(owner, action), verifyCaller: {}).observation
        }
        func accept(_ owner: GatewaySettingsConsumerOwner) async throws {
            let pause = try await act(owner, .quiesce), acceptance = try await act(owner, .accept)
            XCTAssertEqual(pause, .paused); XCTAssertEqual(acceptance, .accepted)
        }
        func permit() throws -> GatewaySettingsConsumerPermit { try XCTUnwrap(state.withLock { $0.permit }) }
        func validate(_ permit: GatewaySettingsConsumerPermit, _ owner: GatewaySettingsConsumerOwner) throws {
            let selection = try selected(owner.binding, fence)
            try permit.requireValid(binding: owner.binding, fence: fence, configuration: selection.configuration, commit: selection.commit)
        }
    }
    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testFreshOwnersRequireQuiescenceAndAcceptanceDoesNotOpenABackend() async throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let f = try Fixture(), owner = try f.owner(role: role)
            let initial = try await f.act(owner, .observe); XCTAssertEqual(initial, .unknown)
            do { _ = try await f.act(owner, .accept); XCTFail() } catch {}
            try await f.accept(owner)
            XCTAssertEqual(f.state.withLock { $0.factories }, 0)
            let accepted = try await f.act(owner, .observe); XCTAssertEqual(accepted, .accepted)
            try await owner.startAcceptedRuntime()
            let started = try await f.act(owner, .observe); XCTAssertEqual(started, .runtimeStarted)
            XCTAssertEqual(f.backend.state.withLock { $0.starts }, 1)
            try await owner.close()
        }
    }
    func testConcurrentCancelledQuiescersJoinActualCleanupBeforeAnyPausedReceipt() async throws {
        let backend = Runtime(holdClose: true), f = try Fixture(backend: backend), owner = try f.owner(initial: backend)
        let completed = Mutex(0)
        let first = Task { @Sendable in let result = try await f.act(owner, .quiesce); completed.withLock { $0 += 1 }; return result }
        defer { backend.releaseClose() }
        try await waitUntil { backend.state.withLock { $0.closeGate != nil } }
        let second = Task { @Sendable in let result = try await f.act(owner, .quiesce); completed.withLock { $0 += 1 }; return result }
        first.cancel()
        let observing = try await f.act(owner, .observe); XCTAssertEqual(observing, .quiescing)
        do { _ = try await f.act(owner, .accept); XCTFail() } catch {}
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(completed.withLock { $0 }, 0); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
        XCTAssertTrue(backend.state.withLock { $0.retired })
        backend.releaseClose()
        let a = try await first.value, b = try await second.value
        XCTAssertEqual(a, .paused); XCTAssertEqual(b, .paused); XCTAssertEqual(completed.withLock { $0 }, 2)
        try await owner.close(); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
    }
    func testFailedCleanupRetainsOwnershipAndCannotAcknowledgePausedOrAccepted() async throws {
        let backend = Runtime(closeFailures: 1), f = try Fixture(backend: backend), owner = try f.owner(initial: backend)
        do { _ = try await f.act(owner, .quiesce); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        let observing = try await f.act(owner, .observe); XCTAssertEqual(observing, .quiescing)
        do { _ = try await f.act(owner, .accept); XCTFail() } catch {}
        XCTAssertEqual(backend.state.withLock { $0.settled }, 0)
        try await f.accept(owner)
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2); XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
        try await owner.close()
    }
    func testGenerationRoleAndAuthenticationFailuresCannotDrainOrMintAPermit() async throws {
        let backend = Runtime(), f = try Fixture(backend: backend), owner = try f.owner(initial: backend), other = try f.owner()
        for request in [try f.request(other, .quiesce), try .init(binding: .init(role: .transport, macID: f.fence.macID,
            accountID: f.fence.accountID, generation: owner.binding.generation), fence: f.fence, action: .quiesce, challenge: Data(repeating: 1, count: 32))] {
            do { _ = try await owner.performAuthenticated(request, verifyCaller: {}); XCTFail() } catch {}
        }
        do { _ = try await owner.performAuthenticated(f.request(owner, .quiesce), verifyCaller: { throw Failed() }); XCTFail() } catch {}
        XCTAssertEqual(backend.state.withLock { $0.closes }, 0)
        XCTAssertEqual(f.state.withLock { $0.factories }, 0)
        try await owner.close(); try await other.close()
    }
    func testAnAcceptedReceiptCannotRestoreAcceptanceInANewOwnerGeneration() async throws {
        let f = try Fixture(), owner = try f.owner(); try await f.accept(owner)
        let receipt = try await owner.performAuthenticated(f.request(owner, .accept), verifyCaller: {}).encoded
        let replacement = try f.owner()
        XCTAssertNotEqual(owner.binding.generation, replacement.binding.generation)
        XCTAssertThrowsError(try GatewaySettingsConsumerResponse.decode(receipt, expected: f.request(replacement, .accept)))
        do { _ = try await f.act(replacement, .accept); XCTFail() } catch {}
        do { try await replacement.startAcceptedRuntime(); XCTFail() } catch {}
        try await owner.close(); try await replacement.close()
    }
    func testPermitsRequireExactConfigurationCommitRoleGenerationAndLiveScope() async throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let f = try Fixture(), owner = try f.owner(role: role); try await f.accept(owner); try await owner.startAcceptedRuntime()
            let permit = try f.permit(), selection = try f.selected(owner.binding, f.fence)
            try f.validate(permit, owner)
            XCTAssertThrowsError(try permit.requireValid(binding: owner.binding, fence: f.fence,
                configuration: selection.configuration + Data([0]), commit: selection.commit))
            XCTAssertThrowsError(try permit.requireValid(binding: owner.binding, fence: f.fence,
                configuration: selection.configuration, commit: f.fence.previous))
            let another = try f.owner(role: role)
            XCTAssertThrowsError(try permit.requireValid(binding: another.binding, fence: f.fence,
                configuration: selection.configuration, commit: selection.commit))
            f.state.withLock { $0.scopeValid = false }; XCTAssertThrowsError(try f.validate(permit, owner))
            f.state.withLock { $0.scopeValid = true }; try await owner.close(); try await another.close()
            XCTAssertThrowsError(try f.validate(permit, owner))
        }
    }
    func testFailedSelectedReadPreservesThePausedOwnerAndAllowsAnExplicitRetry() async throws {
        let f = try Fixture(), owner = try f.owner()
        _ = try await f.act(owner, .quiesce); f.state.withLock { $0.rejectSelected = true }
        do { _ = try await f.act(owner, .accept); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        let observed = try await f.act(owner, .observe); XCTAssertEqual(observed, .paused)
        XCTAssertEqual(f.state.withLock { $0.factories }, 0)
        f.state.withLock { $0.rejectSelected = false }
        let accepted = try await f.act(owner, .accept); XCTAssertEqual(accepted, .accepted)
        try await owner.close()
    }
    func testQuiescenceRevokesThePermitBeforeAnOutstandingStartCanFinish() async throws {
        let backend = Runtime(holdStart: true, holdClose: true), f = try Fixture(backend: backend), owner = try f.owner()
        try await f.accept(owner)
        let start = Task { @Sendable in try await owner.startAcceptedRuntime() }
        defer { backend.releaseStart(); backend.releaseClose() }
        try await waitUntil { backend.state.withLock { $0.startGate != nil } }
        let permit = try f.permit(); try f.validate(permit, owner)
        let pause = Task { @Sendable in try await f.act(owner, .quiesce) }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertThrowsError(try f.validate(permit, owner)); XCTAssertEqual(backend.state.withLock { $0.closes }, 0)
        XCTAssertTrue(backend.state.withLock { $0.retired })
        backend.releaseStart()
        try await waitUntil { backend.state.withLock { $0.closeGate != nil } }
        let observed = try await f.act(owner, .observe); XCTAssertEqual(observed, .quiescing)
        backend.releaseClose()
        let paused = try await pause.value; XCTAssertEqual(paused, .paused)
        do { try await start.value; XCTFail() } catch {}
        XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
        try await owner.close()
    }
    func testBackendStartFailureJoinsCleanupAndRemainsAcceptedWithoutClaimingHealth() async throws {
        let backend = Runtime(startFailures: 1), f = try Fixture(backend: backend), owner = try f.owner()
        try await f.accept(owner)
        do { try await owner.startAcceptedRuntime(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        let observed = try await f.act(owner, .observe); XCTAssertEqual(observed, .accepted)
        XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
        try await owner.startAcceptedRuntime()
        let started = try await f.act(owner, .observe); XCTAssertEqual(started, .runtimeStarted)
        XCTAssertEqual(backend.state.withLock { $0.starts }, 2)
        try await owner.close()
    }
    func testChangedProtectedFenceInvalidatesAnOtherwiseAcceptedPermit() async throws {
        let f = try Fixture(), owner = try f.owner(); try await f.accept(owner); try await owner.startAcceptedRuntime()
        let permit = try f.permit(), r = f.ready
        let replacement = try GatewayRuntimeSettingsFence(.init(revision: r.revision(2), previous: nil, activation: r.activation,
            journal: r.fixture.state(), foreground: r.fixture.runtime.plan, inventory: XCTUnwrap(r.fixture.runtime.machine.inventory())))
        f.currentFence.withLock { $0 = replacement }
        XCTAssertThrowsError(try f.validate(permit, owner))
        do { _ = try await f.act(owner, .observe); XCTFail() } catch {}
        try await owner.close()
    }
    func testCloseDuringStartPreventsLatePublicationAndJoinsTheBackend() async throws {
        let backend = Runtime(holdStart: true, holdClose: true), f = try Fixture(backend: backend), owner = try f.owner()
        try await f.accept(owner)
        let start = Task { @Sendable in try await owner.startAcceptedRuntime() }
        defer { backend.releaseStart(); backend.releaseClose() }
        try await waitUntil { backend.state.withLock { $0.startGate != nil } }
        let closed = Mutex(0), first = Task { @Sendable in try await owner.close(); closed.withLock { $0 += 1 } }
        let second = Task { @Sendable in try await owner.close(); closed.withLock { $0 += 1 } }; first.cancel()
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertThrowsError(try f.validate(f.permit(), owner)); XCTAssertEqual(closed.withLock { $0 }, 0)
        backend.releaseStart(); try await waitUntil { backend.state.withLock { $0.closeGate != nil } }
        backend.releaseClose(); try await first.value; try await second.value
        do { try await start.value; XCTFail() } catch {}
        XCTAssertEqual(closed.withLock { $0 }, 2); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
    }
    func testDeinitRetainsAndRetriesFailedCleanupUntilItSettles() async throws {
        let backend = Runtime(holdClose: true, closeFailures: 1), f = try Fixture(backend: backend)
        var owner: GatewaySettingsConsumerOwner? = try f.owner(initial: backend)
        final class WeakOwner { weak var value: GatewaySettingsConsumerOwner?; init(_ value: GatewaySettingsConsumerOwner?) { self.value = value } }
        let weakOwner = WeakOwner(owner)
        owner = nil
        defer { backend.releaseClose() }
        XCTAssertNil(weakOwner.value)
        try await waitUntil { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2)
        backend.releaseClose(); try await waitUntil { backend.state.withLock { $0.settled == 1 } }
    }
    func testCallerLossAfterDrainCannotAbandonThePausedBackend() async throws {
        let backend = Runtime(), f = try Fixture(backend: backend), owner = try f.owner(initial: backend)
        let checks = Mutex(0)
        do {
            _ = try await owner.performAuthenticated(f.request(owner, .quiesce), verifyCaller: {
                if checks.withLock({ $0 += 1; return $0 }) > 1 { throw Failed() }
            })
            XCTFail()
        } catch { XCTAssertTrue(error is Failed) }
        XCTAssertTrue(backend.state.withLock { $0.retired }); XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
        let state = try await f.act(owner, .observe); XCTAssertEqual(state, .paused)
        try await owner.close()
    }
    func testClosingFailureCanRetryCleanupButCanNeverReopenTheOwner() async throws {
        let backend = Runtime(closeFailures: 1), f = try Fixture(backend: backend), owner = try f.owner(initial: backend)
        do { try await owner.close(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        do { _ = try await f.act(owner, .quiesce); XCTFail() } catch {}
        do { try await owner.startAcceptedRuntime(); XCTFail() } catch {}
        try await owner.close()
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2); XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
        XCTAssertEqual(f.state.withLock { $0.factories }, 0)
    }
    func testSelectionConstructorsRequireTheSelectedMarkerAndExactRoleMaterial() throws {
        let f = try Fixture(), gateway = try f.owner(), transport = try f.owner(role: .transport)
        let oldGateway = try GatewayServiceConfiguration.decode(XCTUnwrap(f.plan.artifacts.first {
            if case .gatewayConfiguration = $0.file { true } else { false }
        }).previous!)
        XCTAssertThrowsError(try GatewaySettingsConsumerSelection.gateway(binding: gateway.binding, fence: f.fence,
            configuration: oldGateway, commit: f.fence.previous))
        // This fixture changes only Transport timing. Identical Gateway bytes remain valid under the selected marker.
        let selected = try GatewaySettingsConsumerSelection.gateway(binding: gateway.binding, fence: f.fence,
            configuration: oldGateway, commit: f.plan.commit)
        XCTAssertEqual(selected.configuration, oldGateway.canonicalBytes)
        XCTAssertThrowsError(try GatewaySettingsConsumerSelection.gateway(binding: transport.binding, fence: f.fence,
            configuration: oldGateway, commit: f.plan.commit))
        XCTAssertThrowsError(try GatewaySettingsConsumerSelection.transport(binding: transport.binding, fence: f.fence,
            configuration: f.plan.pair.authority, commit: f.plan.commit))
        XCTAssertThrowsError(try GatewaySettingsConsumerSelection.transport(binding: transport.binding, fence: f.fence,
            configuration: f.plan.pair.transport, commit: f.fence.previous))
    }

}
