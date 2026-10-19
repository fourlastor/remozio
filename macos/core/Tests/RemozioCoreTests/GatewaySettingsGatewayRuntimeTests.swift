import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsGatewayRuntimeTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private struct Failed: Error {}
    private final class WeakPermit { weak var value: GatewaySettingsConsumerPermit? }
    private final class WeakRuntime {
        weak var value: GatewaySettingsGatewayRuntime?
        init(_ value: GatewaySettingsGatewayRuntime?) { self.value = value }
    }
    private final class Backend: GatewaySettingsGatewayBackend, Sendable {
        struct State {
            var starts = 0, retires = 0, closes = 0, settled = 0, failures = 0
            var closeGate: CheckedContinuation<Void, Never>?
        }
        let state = Mutex(State())
        let holdClose: Bool
        init(holdClose: Bool = false, failures: Int = 0) {
            self.holdClose = holdClose; state.withLock { $0.failures = failures }
        }
        func start() throws { state.withLock { $0.starts += 1 } }
        func retire() { state.withLock { $0.retires += 1 } }
        func close() async throws {
            let fail = state.withLock { value in
                value.closes += 1
                if value.failures > 0 { value.failures -= 1; return true }; return false
            }
            if fail { throw Failed() }
            if holdClose { await withCheckedContinuation { gate in state.withLock { $0.closeGate = gate } } }
            state.withLock { $0.settled += 1 }
        }
        func finish() { state.withLock { value in let gate = value.closeGate; value.closeGate = nil; return gate }?.resume() }
    }
    private actor Gate {
        var waiting = false
        var continuation: CheckedContinuation<Void, Never>?
        func wait() async { waiting = true; await withCheckedContinuation { continuation = $0 } }
        func finish() { continuation?.resume(); continuation = nil }
    }
    private final class Fixture: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let plan: GatewayRuntimeSettingsPublicationPlan
        let fence: GatewayRuntimeSettingsFence
        let currentFence: Mutex<GatewayRuntimeSettingsFence?>
        let publication: Mutex<(configuration: Data, commit: GatewayRuntimeCommit)>
        let scope = Mutex(true)
        let permit = Mutex(WeakPermit())
        init() throws {
            ready = try .init()
            plan = try .init(revision: ready.revision(1), previous: nil, activation: ready.activation,
                journal: ready.fixture.state(), foreground: ready.fixture.runtime.plan,
                inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory()))
            fence = try .init(plan); currentFence = Mutex(fence)
            let artifact = try XCTUnwrap(plan.artifacts.first { if case .gatewayConfiguration = $0.file { true } else { false } })
            publication = Mutex((artifact.selected, plan.commit))
        }
        func verify() throws { guard scope.withLock({ $0 }) else { throw Failed() } }
        func selected(_ binding: GatewaySettingsConsumerBinding, _ fence: GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection {
            let current = publication.withLock { $0 }
            return try .gateway(binding: binding, fence: fence, configuration: .decode(current.configuration), commit: current.commit)
        }
        func published(_ selection: GatewaySettingsConsumerSelection) throws {
            try selection.verifyPublished(readFence: { self.currentFence.withLock { $0 } },
                readSelected: { self.publication.withLock { $0 } }, verifyCurrent: verify)
        }
        func owner(_ backend: Backend) throws -> GatewaySettingsConsumerOwner {
            try .init(role: .gateway, macID: fence.macID, accountID: fence.accountID, operations: .init(
                verifyScope: { try self.verify() }, readFence: { try XCTUnwrap(self.currentFence.withLock { $0 }) },
                loadSelected: { try self.selected($0, $1) }, makeRuntime: { selected, permit in
                    self.permit.withLock { $0.value = permit }
                    return GatewaySettingsGatewayRuntime(verifyCurrent: {
                        try permit.requireValid(binding: selected.binding, fence: selected.fence,
                            configuration: selected.configuration, commit: selected.commit)
                    }, open: { backend })
                }, verifyAccepted: { try self.published($0) }))
        }
        func act(_ owner: GatewaySettingsConsumerOwner, _ action: GatewaySettingsControlAction,
                 fence: GatewayRuntimeSettingsFence? = nil) async throws -> GatewaySettingsConsumerObservation {
            try await owner.performAuthenticated(.init(binding: owner.binding, fence: fence ?? self.fence,
                action: action, challenge: Data(repeating: 7, count: 32)), verifyCaller: {}).observation
        }
        func accept(_ owner: GatewaySettingsConsumerOwner) async throws {
            let paused = try await act(owner, .quiesce), accepted = try await act(owner, .accept)
            XCTAssertEqual(paused, .paused); XCTAssertEqual(accepted, .accepted)
        }
        func replacementFence() throws -> GatewayRuntimeSettingsFence {
            try .init(.init(revision: ready.revision(2), previous: nil, activation: ready.activation,
                journal: ready.fixture.state(), foreground: ready.fixture.runtime.plan,
                inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory())))
        }
    }
    private func until(_ predicate: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await predicate()) {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testAcceptedRuntimeSurvivesFenceRemovalOnlyWithExactSelectedPublication() async throws {
        let f = try Fixture(), backend = Backend(), owner = try f.owner(backend)
        try await f.accept(owner)
        f.currentFence.withLock { $0 = nil }
        try await owner.startAcceptedRuntime()
        XCTAssertEqual(backend.state.withLock { $0.starts }, 1)
        let selection = try f.selected(owner.binding, f.fence), permit = try XCTUnwrap(f.permit.withLock { $0.value })
        try permit.requireValid(binding: owner.binding, fence: f.fence, configuration: selection.configuration, commit: selection.commit)
        let next = try f.replacementFence(); f.currentFence.withLock { $0 = next }
        XCTAssertThrowsError(try permit.requireValid(binding: owner.binding, fence: f.fence,
            configuration: selection.configuration, commit: selection.commit))
        let paused = try await f.act(owner, .quiesce, fence: next)
        XCTAssertEqual(paused, .paused); XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
        try await owner.close()
    }
    func testPublishedSelectionRejectsChangedFilesCommitFenceScopeAndUnstableReads() throws {
        let f = try Fixture(), owner = try f.owner(Backend()), selection = try f.selected(owner.binding, f.fence)
        try f.published(selection)
        f.currentFence.withLock { $0 = nil }; try f.published(selection)
        f.publication.withLock { $0.configuration.append(0) }; XCTAssertThrowsError(try f.published(selection))
        f.publication.withLock { $0.configuration = selection.configuration; $0.commit = f.fence.previous }
        XCTAssertThrowsError(try f.published(selection))
        f.publication.withLock { $0.commit = selection.commit }
        f.currentFence.withLock { $0 = try? f.replacementFence() }; XCTAssertThrowsError(try f.published(selection))
        f.currentFence.withLock { $0 = f.fence }; f.scope.withLock { $0 = false }
        XCTAssertThrowsError(try f.published(selection)); f.scope.withLock { $0 = true }
        var reads = 0
        XCTAssertThrowsError(try selection.verifyPublished(readFence: {
            reads += 1; return reads == 1 ? f.fence : nil
        }, readSelected: { f.publication.withLock { $0 } }, verifyCurrent: f.verify))
        var selectedReads = 0
        XCTAssertThrowsError(try selection.verifyPublished(readFence: { f.fence }, readSelected: {
            selectedReads += 1
            return (selectedReads == 1 ? selection.configuration : selection.configuration + Data([0]), selection.commit)
        }, verifyCurrent: f.verify))
    }
    func testConcurrentCancelledCloseJoinsUnfinishedOpenAndActualBackendDrain() async throws {
        let gate = Gate(), backend = Backend(holdClose: true)
        let runtime = GatewaySettingsGatewayRuntime(verifyCurrent: {}, open: { await gate.wait(); return backend })
        let starting = Task { try await runtime.start() }
        defer { Task { await gate.finish(); backend.finish(); try? await runtime.closeAndWait() } }
        try await until { await gate.waiting }
        let completed = Counter()
        let first = Task { try await runtime.closeAndWait(); completed.value.withLock { $0 += 1 } }
        let second = Task { try await runtime.closeAndWait(); completed.value.withLock { $0 += 1 } }
        first.cancel()
        try await Task.sleep(for: .milliseconds(20)); XCTAssertEqual(completed.value.withLock { $0 }, 0)
        await gate.finish()
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertEqual(backend.state.withLock { $0.starts }, 0)
        XCTAssertGreaterThan(backend.state.withLock { $0.retires }, 0)
        XCTAssertEqual(completed.value.withLock { $0 }, 0)
        backend.finish(); try await first.value; try await second.value
        do { try await starting.value; XCTFail() } catch {}
        XCTAssertEqual(completed.value.withLock { $0 }, 2); XCTAssertEqual(backend.state.withLock { $0.closes }, 1)
    }
    func testQuiescenceDuringProviderDrainRevokesPermitBeforePausedReceipt() async throws {
        let f = try Fixture(), backend = Backend(holdClose: true), owner = try f.owner(backend)
        defer { backend.finish(); Task { try? await owner.close() } }
        try await f.accept(owner); try await owner.startAcceptedRuntime()
        let permit = try XCTUnwrap(f.permit.withLock { $0.value }), selection = try f.selected(owner.binding, f.fence)
        let pause = Task { try await f.act(owner, .quiesce) }
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertThrowsError(try permit.requireValid(binding: owner.binding, fence: f.fence,
            configuration: selection.configuration, commit: selection.commit))
        let observation = try await f.act(owner, .observe); XCTAssertEqual(observation, .quiescing)
        backend.finish(); let receipt = try await pause.value; XCTAssertEqual(receipt, .paused)
        XCTAssertEqual(backend.state.withLock { $0.settled }, 1); try await owner.close()
    }
    func testFailedCleanupRetainsBackendAndExplicitRetryCannotRestartIt() async throws {
        let backend = Backend(failures: 1), runtime = GatewaySettingsGatewayRuntime(verifyCurrent: {}, open: { backend })
        try await runtime.start()
        do { try await runtime.closeAndWait(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(backend.state.withLock { $0.settled }, 0)
        do { try await runtime.start(); XCTFail() } catch {}
        try await runtime.closeAndWait()
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2); XCTAssertEqual(backend.state.withLock { $0.starts }, 1)
    }
    func testScopeLossDuringOpenCannotStartTheReturnedBackend() async throws {
        let gate = Gate(), backend = Backend(), allowed = Mutex(true)
        let runtime = GatewaySettingsGatewayRuntime(verifyCurrent: {
            guard allowed.withLock({ $0 }) else { throw Failed() }
        }, open: { await gate.wait(); return backend })
        let opening = Task { try await runtime.start() }
        defer { Task { await gate.finish(); try? await runtime.closeAndWait() } }
        try await until { await gate.waiting }
        allowed.withLock { $0 = false }; await gate.finish()
        do { try await opening.value; XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(backend.state.withLock { $0.starts }, 0)
        try await runtime.closeAndWait(); XCTAssertEqual(backend.state.withLock { $0.settled }, 1)
    }
    func testDroppedAdapterRetainsAndRetriesUnsettledBackendCleanup() async throws {
        let backend = Backend(holdClose: true, failures: 1)
        var runtime: GatewaySettingsGatewayRuntime? = .init(verifyCurrent: {}, open: { backend })
        let weakRuntime = WeakRuntime(runtime)
        try await runtime?.start(); runtime = nil
        XCTAssertNil(weakRuntime.value)
        defer { backend.finish() }
        try await until { backend.state.withLock { $0.closeGate != nil } }
        XCTAssertEqual(backend.state.withLock { $0.closes }, 2)
        backend.finish(); try await until { backend.state.withLock { $0.settled == 1 } }
    }
    func testNativeAdapterDoesNotBypassTheDedicatedServiceAccount() async throws {
        let f = try Fixture(), owner = try f.owner(Backend())
        try await f.accept(owner); try await owner.startAcceptedRuntime()
        let selection = try f.selected(owner.binding, f.fence), permit = try XCTUnwrap(f.permit.withLock { $0.value })
        let native = try GatewaySettingsGatewayRuntime(selection: selection, permit: permit)
        do { try await native.start(); XCTFail("Owned fixture cannot open the real native service") }
        catch { XCTAssertEqual(error as? GatewayServiceError, .wrongAccount) }
        try await native.closeAndWait(); try await owner.close()
    }
}
