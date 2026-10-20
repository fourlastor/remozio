import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewayRecoverySupervisorTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Initial: @unchecked Sendable {
        let ready = try! GatewayRuntimeSettingsStoreTests.Ready()
    }
    private typealias Fixture = AuthorityGatewayRecoveryAccessTests.Fixture
    private func status(_ fixture: Fixture) throws -> AuthorityGatewayRecoverySnapshot.Status {
        try AuthorityGatewayRecoverySnapshot.status(machine: fixture.machine, authority: fixture.authority)
    }
    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testInitialActivationKeepsTheExistingPathWithoutConstructingARecoveryCoordinator() async throws {
        let f = Initial(), calls = Mutex(0)
        let supervisor = AuthorityGatewayRecoverySupervisor(operations: .init(status: {
            try AuthorityGatewayRecoverySnapshot.status(machine: f.ready.fixture.runtime.machine, authority: f.ready.fixture.runtime.plan.host)
        }, makeCoordinator: { calls.withLock { $0 += 1 }; throw Failed() }))
        let result = try await supervisor.refresh(); XCTAssertTrue(result)
        XCTAssertEqual(calls.withLock { $0 }, 0); await supervisor.close()
        do { _ = try await supervisor.refresh(); XCTFail() } catch {}
    }
    func testCompletedSettingsUseOneActualServiceCoordinatorAndKeepHealthyPollingOnThatOwner() async throws {
        let f = try Fixture(), makes = Mutex(0)
        let supervisor = AuthorityGatewayRecoverySupervisor(operations: .init(status: { [self] in try status(f) },
            makeCoordinator: { makes.withLock { $0 += 1 }; return try f.access().makeCoordinator() }))
        try await f.service.start()
        let first = try await supervisor.refresh(); XCTAssertTrue(first)
        let healthy = try await supervisor.refresh(); XCTAssertTrue(healthy)
        XCTAssertEqual(makes.withLock { $0 }, 1); XCTAssertEqual(f.state.withLock { $0.publications }, 1)
        XCTAssertEqual(f.root.starts.withLock { $0 }, 1); XCTAssertNil(f.root.capability.publication)
        await supervisor.close(); try await f.closeOwners()
    }
    func testPendingExplicitSettingsCloseTheOldRecoveryAndKeepTheForegroundRequest() async throws {
        let f = try Fixture(), supervisor = AuthorityGatewayRecoverySupervisor(operations: .init(
            status: { [self] in try status(f) }, makeCoordinator: { try f.access().makeCoordinator() }))
        try await f.service.start()
        let first = try await supervisor.refresh(); XCTAssertTrue(first)
        let snapshot = try XCTUnwrap(f.state.withLock { $0.snapshot }), request = try f.root.state()
        try await f.service.installPhonePush(f.root.options, commitDigest: snapshot.plan.commit.observationDigest, verifyCurrent: {})
        XCTAssertNotNil(f.root.capability.publication)
        try f.machine.retainGatewaySettingsTransition(f.ready.revision(2, previous: f.revision))
        let pending = try await supervisor.refresh(); XCTAssertFalse(pending)
        XCTAssertNil(f.root.capability.publication); XCTAssertEqual(try f.root.state(), request)
        XCTAssertEqual(f.root.starts.withLock { $0 }, 1); XCTAssertEqual(f.root.closes.withLock { $0 }, 0)
        let state = await f.service.wakeStatus; XCTAssertEqual(state, .suspendedForRecovery)
        await supervisor.close(); try await f.closeOwners()
    }
    func testMissingOrUnreadableStateAfterCompletedSettingsCannotFallBackToInitialActivation() async throws {
        for unreadable in [false, true] {
            let f = try Fixture(), changed = Mutex(false)
            let supervisor = AuthorityGatewayRecoverySupervisor(operations: .init(status: { [self] in
                if changed.withLock({ $0 }) {
                    if unreadable { throw Failed() }
                    return .initial
                }
                return try status(f)
            }, makeCoordinator: { try f.access().makeCoordinator() }))
            try await f.service.start()
            let first = try await supervisor.refresh(); XCTAssertTrue(first)
            let snapshot = try XCTUnwrap(f.state.withLock { $0.snapshot })
            try await f.service.installPhonePush(f.root.options, commitDigest: snapshot.plan.commit.observationDigest, verifyCurrent: {})
            changed.withLock { $0 = true }
            do { _ = try await supervisor.refresh(); XCTFail() } catch {}
            XCTAssertNil(f.root.capability.publication)
            let state = await f.service.wakeStatus; XCTAssertEqual(state, .suspendedForRecovery)
            await supervisor.close(); try await f.closeOwners()
        }
    }
    func testCloseOwnsAnAdmittedActualConsumerOperationBeforeTheServiceCanClose() async throws {
        let f = try Fixture(), closed = Mutex(false)
        let supervisor = AuthorityGatewayRecoverySupervisor(operations: .init(status: { [self] in try status(f) },
            makeCoordinator: { try f.access().makeCoordinator() }))
        f.state.withLock { $0.holdGatewayAcceptance = true }
        try await f.service.start()
        let refresh = Task { try await supervisor.refresh() }
        defer { f.release() }
        try await waitUntil { f.state.withLock { $0.held != nil } }
        let concurrent = try await supervisor.refresh(); XCTAssertFalse(concurrent)
        let close = Task { await supervisor.close(); closed.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(10))
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertEqual(f.root.closes.withLock { $0 }, 0)
        f.release(); await close.value
        do { _ = try await refresh.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertNil(f.root.capability.publication)
        let state = await f.service.wakeStatus; XCTAssertEqual(state, .suspendedForRecovery)
        try await f.closeOwners()
    }
}
