import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class RelayConnectorSupervisorTests: XCTestCase, @unchecked Sendable {
    private typealias Supervisor = RelayConnectorSupervisor
    private typealias Fixture = RelayConnectorProcessTests.Fixture
    private struct Failed: Error {}
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await condition()) {
            guard ContinuousClock.now < end else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    private actor HeldProbe {
        private var pending: CheckedContinuation<RelayConnectorReadiness.State, Never>?
        private(set) var entered = false
        func run() async -> RelayConnectorReadiness.State {
            entered = true
            return await withCheckedContinuation { pending = $0 }
        }
        func release() { let previous = pending; pending = nil; previous?.resume(returning: .connected) }
    }
    func testReadinessCanRecoverWithoutReplacingTheChild() async throws {
        let f = try Fixture(), starts = Mutex(0), checks = Mutex(0)
        let owner = Supervisor(options: try .init(probeMilliseconds: 100), operations: .init(start: { event in
            starts.withLock { $0 += 1 }; return try f.start("normal", event: event)
        }, probe: { _ in
            let index = checks.withLock { let old = $0; $0 += 1; return old }
            if index == 0 { throw Failed() }
            return index == 1 ? .disconnected : .connected
        }))
        try await owner.start()
        try await waitUntil { await owner.status == .unavailable }
        try await waitUntil { await owner.status == .disconnected }
        try await waitUntil { await owner.status == .connected }
        XCTAssertEqual(starts.withLock { $0 }, 1)
        XCTAssertThrowsError(try f.updater.acquireExclusive())
        let settled = await owner.close(); XCTAssertTrue(settled); try f.assertUpdateAvailable()
    }
    func testExitedChildSettlesBeforeAReplacementAndOldEventsCannotAffectIt() async throws {
        let f = try Fixture(), starts = Mutex(0)
        let previous = Mutex<(@Sendable (RelayConnectorProcess.Event) -> Void)?>(nil)
        let owner = Supervisor(options: try .init(retryMilliseconds: 100), operations: .init(start: { event in
            let index = starts.withLock { let old = $0; $0 += 1; return old }
            if index == 0 { previous.withLock { $0 = event } }
            if index == 1 { try f.assertUpdateAvailable() }
            return try f.start(index == 0 ? "exit" : "normal", event: event)
        }, probe: { _ in .disconnected }))
        try await owner.start(); try await waitUntil { await owner.status == .disconnected }
        XCTAssertEqual(starts.withLock { $0 }, 2)
        previous.withLock { $0 }?(.completed(.init(termination: .exited(42), discovery: nil, stopCause: nil)))
        previous.withLock { $0 }?(.discovered(.init(port: 99, connectorID: UUID())))
        try await Task.sleep(for: .milliseconds(150))
        let status = await owner.status; XCTAssertEqual(status, .disconnected)
        XCTAssertEqual(starts.withLock { $0 }, 2)
        let settled = await owner.close(); XCTAssertTrue(settled); try f.assertUpdateAvailable()
    }
    func testCancelledConcurrentClosesWaitForLateProbeAndPreventSuccessPublication() async throws {
        let f = try Fixture(), gate = HeldProbe(), starts = Mutex(0), finished = Mutex(0)
        let owner = Supervisor(operations: .init(start: { event in
            starts.withLock { $0 += 1 }; return try f.start("normal", event: event)
        }, probe: { _ in await gate.run() }))
        try await owner.start(); try await waitUntil { await gate.entered }
        let one = Task { let value = await owner.close(); finished.withLock { $0 += 1 }; return value }
        try await waitUntil { await owner.status == .closing }
        let two = Task { let value = await owner.close(); finished.withLock { $0 += 1 }; return value }
        one.cancel()
        XCTAssertEqual(finished.withLock { $0 }, 0)
        await gate.release()
        let settled = await (one.value, two.value); XCTAssertTrue(settled.0); XCTAssertTrue(settled.1)
        let status = await owner.status; XCTAssertEqual(status, .closed)
        XCTAssertEqual(starts.withLock { $0 }, 1); XCTAssertEqual(finished.withLock { $0 }, 2)
        try f.assertUpdateAvailable()
    }
    func testReplacementWaitsForTheExitedChildsLateReadinessWork() async throws {
        let f = try Fixture(), gate = HeldProbe(), starts = Mutex(0), checks = Mutex(0)
        let first = Mutex<RelayConnectorProcess?>(nil)
        let owner = Supervisor(options: try .init(retryMilliseconds: 100), operations: .init(start: { event in
            let index = starts.withLock { let old = $0; $0 += 1; return old }
            let process = try f.start("normal", event: event)
            if index == 0 { first.withLock { $0 = process } }
            return process
        }, probe: { _ in
            let index = checks.withLock { let old = $0; $0 += 1; return old }
            return index == 0 ? await gate.run() : .disconnected
        }))
        try await owner.start(); try await waitUntil { await gate.entered }
        let process = try XCTUnwrap(first.withLock { $0 })
        let completion = await process.stopAndWait(); XCTAssertTrue(completion.termination.settled)
        try await waitUntil { await owner.status == .stopping }
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertEqual(starts.withLock { $0 }, 1)
        await gate.release()
        try await waitUntil { await owner.status == .disconnected }
        XCTAssertEqual(starts.withLock { $0 }, 2)
        let settled = await owner.close(); XCTAssertTrue(settled); try f.assertUpdateAvailable()
    }
    func testInvalidatedStartupMetadataStopsTheChildWithoutRetry() async throws {
        let f = try Fixture(), allowed = Mutex(true), starts = Mutex(0)
        let owner = Supervisor(options: try .init(probeMilliseconds: 100), operations: .init(start: { event in
            starts.withLock { $0 += 1 }; return try f.start("normal", event: event)
        }, probe: { _ in .connected }, validateCurrent: {
            guard allowed.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
        }))
        try await owner.start(); try await waitUntil { await owner.status == .connected }
        allowed.withLock { $0 = false }
        try await waitUntil { await owner.status == .refused }
        try f.assertUpdateAvailable(); XCTAssertEqual(starts.withLock { $0 }, 1)
        let settled = await owner.close(); XCTAssertTrue(settled)
    }
    func testChangedScopeDuringReadinessCannotPublishItsLateSuccess() async throws {
        let f = try Fixture(), gate = HeldProbe(), allowed = Mutex(true), starts = Mutex(0)
        let owner = Supervisor(operations: .init(start: { event in
            starts.withLock { $0 += 1 }; return try f.start("normal", event: event)
        }, probe: { _ in await gate.run() }, validateCurrent: {
            guard allowed.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
        }))
        try await owner.start(); try await waitUntil { await gate.entered }
        allowed.withLock { $0 = false }; await gate.release()
        try await waitUntil { await owner.status == .refused }
        try f.assertUpdateAvailable(); XCTAssertEqual(starts.withLock { $0 }, 1)
        let settled = await owner.close(); XCTAssertTrue(settled)
    }
    func testTemporaryScopeReadErrorRetriesOnlyAfterTheChildSettles() async throws {
        let f = try Fixture(), starts = Mutex(0), failOnce = Mutex(true)
        let owner = Supervisor(options: try .init(retryMilliseconds: 100), operations: .init(start: { event in
            let index = starts.withLock { let old = $0; $0 += 1; return old }
            if index == 1 { try f.assertUpdateAvailable() }
            return try f.start("normal", event: event)
        }, probe: { _ in .connected }, validateCurrent: {
            let fail = failOnce.withLock { let old = $0; $0 = false; return old }
            if fail { throw JournalLeaseError.system(EIO) }
        }))
        try await owner.start(); try await waitUntil { await owner.status == .connected }
        XCTAssertEqual(starts.withLock { $0 }, 2)
        let settled = await owner.close(); XCTAssertTrue(settled); try f.assertUpdateAvailable()
    }
    func testCloseDuringRetryPreventsAnotherSpawn() async throws {
        let f = try Fixture(), starts = Mutex(0)
        let owner = Supervisor(options: try .init(retryMilliseconds: 60_000, maximumRetryMilliseconds: 60_000),
            operations: .init(start: { event in starts.withLock { $0 += 1 }; return try f.start("exit", event: event) },
                              probe: { _ in XCTFail("Unexpected readiness check"); return .connected }))
        try await owner.start(); try await waitUntil { await owner.status == .waiting }
        let settled = await owner.close(); XCTAssertTrue(settled)
        let status = await owner.status; XCTAssertEqual(status, .closed)
        XCTAssertEqual(starts.withLock { $0 }, 1); try f.assertUpdateAvailable()
    }
    func testOnlyTemporarySpawnFailureRetriesAndAdmissionFailureRefuses() async throws {
        let f = try Fixture(), starts = Mutex(0)
        let owner = Supervisor(options: try .init(retryMilliseconds: 100), operations: .init(start: { event in
            let index = starts.withLock { let old = $0; $0 += 1; return old }
            if index == 0 { throw RelayConnectorProcess.Failure.system(EAGAIN) }
            return try f.start("normal", event: event)
        }, probe: { _ in .connected }))
        try await owner.start(); try await waitUntil { await owner.status == .connected }
        XCTAssertEqual(starts.withLock { $0 }, 2); let settled = await owner.close(); XCTAssertTrue(settled)
        let refusedCalls = Mutex(0)
        let refused = Supervisor(operations: .init(start: { _ in
            refusedCalls.withLock { $0 += 1 }; throw RuntimePreparationError.changedScope
        }, probe: { _ in XCTFail(); return .connected }))
        try await refused.start(); let status = await refused.status; XCTAssertEqual(status, .refused)
        let refusedClosed = await refused.close(); XCTAssertTrue(refusedClosed)
        XCTAssertEqual(refusedCalls.withLock { $0 }, 1); try f.assertUpdateAvailable()
    }
    func testCloseBeforeStartAndInvalidBoundsRefuseWithoutSpawning() async throws {
        let calls = Mutex(0)
        let owner = Supervisor(operations: .init(start: { _ in
            calls.withLock { $0 += 1 }; throw Failed()
        }, probe: { _ in .connected }))
        let settled = await owner.close(); XCTAssertTrue(settled)
        do { try await owner.start(); XCTFail("A closed owner started") } catch {}
        XCTAssertEqual(calls.withLock { $0 }, 0)
        for delay in [0, 99, 60_001] { XCTAssertThrowsError(try Supervisor.Options(retryMilliseconds: delay)) }
        XCTAssertThrowsError(try Supervisor.Options(retryMilliseconds: 1000, maximumRetryMilliseconds: 999))
        XCTAssertThrowsError(try Supervisor.Options(probeMilliseconds: 99))
    }
    func testDroppingOwnerStopsTheChildAndCannotRetry() async throws {
        let f = try Fixture(), starts = Mutex(0), exited = Mutex(false)
        var owner: Supervisor? = Supervisor(operations: .init(start: { event in
            starts.withLock { $0 += 1 }
            return try f.start("normal") { value in
                if case .completed = value { exited.withLock { $0 = true } }
                event(value)
            }
        }, probe: { _ in .connected }))
        try await owner?.start()
        try await waitUntil { await owner?.status == .connected }
        owner = nil
        try await waitUntil { exited.withLock { $0 } }
        try f.assertUpdateAvailable(); XCTAssertEqual(starts.withLock { $0 }, 1)
    }
}
