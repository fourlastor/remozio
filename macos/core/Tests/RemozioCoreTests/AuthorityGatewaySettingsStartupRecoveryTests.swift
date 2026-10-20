import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewaySettingsStartupRecoveryTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private typealias Recovery = AuthorityGatewaySettingsStartupRecovery
    private func retained() throws -> AuthorityGatewaySettingsStartupPlan {
        let r = try GatewayRuntimeSettingsStoreTests.Ready()
        return try XCTUnwrap(AuthorityGatewaySettingsStartupPlan.load(machine: r.fixture.runtime.machine,
            authority: r.fixture.runtime.plan.host))
    }
    func testFailedInitialVerificationPausesOptionalAdmissionBeforeForegroundStartup() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(install: false), service = try f.service([AuthorityWakeSettingsTests.Driver()])
        let plan = try retained(), recovery = Recovery(snapshot: .retained(plan), service: service, reload: { XCTFail(); return .unavailable })
        let ready = try await recovery.prepare(verifyCurrent: { throw Denied() }); XCTAssertFalse(ready)
        try await service.start(); XCTAssertEqual(f.starts.withLock { $0 }, 1)
        do { try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: { XCTFail("Failed startup verification must retain the optional pause") }); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .busy) }
        XCTAssertNil(f.capability.publication); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        try await service.close()
    }
    func testUnknownStateKeepsForegroundAvailableUntilFreshAbsenceCanReleaseThePause() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(install: false), service = try f.service([AuthorityWakeSettingsTests.Driver()])
        let readable = Mutex(false), reloads = PushSignCount()
        let recovery = Recovery(snapshot: .unavailable, service: service, reload: {
            reloads.increment(); if !readable.withLock({ $0 }) { throw Denied() }; return .absent
        })
        let first = try await recovery.prepare(verifyCurrent: {}); XCTAssertFalse(first)
        try await service.start(); XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        do { try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        readable.withLock { $0 = true }
        let second = try await recovery.prepare(verifyCurrent: {}); XCTAssertTrue(second)
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while f.attempts.withLock({ $0 }) == 0 && ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(2)) }
        XCTAssertEqual(f.attempts.withLock { $0 }, 1); XCTAssertNil(f.capability.publication); XCTAssertEqual(reloads.value, 2)
        let again = try await recovery.prepare(verifyCurrent: {}); XCTAssertTrue(again); XCTAssertEqual(reloads.value, 2)
        try await service.close()
    }
    func testRetainedFailureRetriesTheExactPlanWithoutRecapturingOrClaimingReadiness() async throws {
        let plan = try retained(), blocks = PushSignCount(), attempts = PushSignCount(), reject = Mutex(true)
        let recovery = Recovery(snapshot: .retained(plan), reload: { XCTFail("Retained scope must not be replaced during retry"); return .absent },
            operations: .init(block: { blocks.increment() }, absent: { XCTFail("A retained floor cannot become absent") }, restore: { current, verify in
                XCTAssertEqual(current.accountID, plan.accountID); XCTAssertEqual(current.activeCommitDigest, plan.activeCommitDigest)
                XCTAssertEqual(current.options.canonicalBytes, plan.options.canonicalBytes); XCTAssertEqual(current.pendingChange, plan.pendingChange)
                attempts.increment(); try verify(); if reject.withLock({ $0 }) { throw Denied() }
            }))
        let first = try await recovery.prepare(verifyCurrent: {}); XCTAssertFalse(first)
        reject.withLock { $0 = false }
        let second = try await recovery.prepare(verifyCurrent: {}); XCTAssertTrue(second)
        let third = try await recovery.prepare(verifyCurrent: {}); XCTAssertTrue(third)
        XCTAssertEqual(blocks.value, 1); XCTAssertEqual(attempts.value, 2)
    }
    func testLegacyAbsenceDoesNotSuspendOrReplaceTheExistingProvider() async throws {
        let calls = PushSignCount()
        let recovery = Recovery(snapshot: .absent, reload: { XCTFail(); return .unavailable },
            operations: .init(block: { XCTFail("Legacy absence must keep its provider") }, absent: { XCTFail() }, restore: { _, _ in XCTFail() }))
        let ready = try await recovery.prepare(verifyCurrent: { calls.increment() }); XCTAssertTrue(ready); XCTAssertEqual(calls.value, 1)
    }
    func testCaptureDistinguishesRetainedPendingStateFromAnUnreadableStore() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), store = r.fixture.runtime.machine, revision = try r.revision()
        try store.retainGatewaySettingsTransition(revision)
        switch Recovery.capture(machine: store, authority: r.fixture.runtime.plan.host) {
        case .retained(let plan):
            XCTAssertTrue(plan.requiresFreshQuiescence); XCTAssertEqual(plan.pendingChange?.revisionDigest, try revision.digest)
        default: XCTFail("A valid pending revision must retain its exact startup scope")
        }
        try store.close()
        guard case .unavailable = Recovery.capture(machine: store, authority: r.fixture.runtime.plan.host) else {
            return XCTFail("Unreadable state cannot be treated as absence")
        }
    }
    func testCapturedScopeSurvivesActualReceiveRightHandoffAndMachineStoreReopen() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), store = r.fixture.runtime.machine
        let authority = r.fixture.runtime.plan.host, revision = try r.revision()
        try store.retainGatewaySettingsTransition(revision)
        guard case .retained(let before) = Recovery.capture(machine: store, authority: authority) else { return XCTFail() }
        var port = mach_port_t(MACH_PORT_NULL)
        guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS else { return XCTFail() }
        defer { _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1) }
        XCTAssertEqual(try InstalledCommandMachineHandoff.take(machine: store, checkIn: { port }), port)
        guard case .unavailable = Recovery.capture(machine: store, authority: authority) else { return XCTFail("The old owner must be closed") }
        let reopened = try r.fixture.runtime.f.open(); defer { try? reopened.close() }
        guard case .retained(let after) = Recovery.capture(machine: reopened, authority: authority) else { return XCTFail() }
        XCTAssertEqual(before.activeCommitDigest, after.activeCommitDigest); XCTAssertEqual(before.pendingChange, after.pendingChange)
        XCTAssertTrue(after.requiresFreshQuiescence); XCTAssertEqual(after.pendingChange?.revisionDigest, try revision.digest)
    }
    func testCancellationBeforePreparationDoesNotChangeAnyOptionalState() async throws {
        let calls = PushSignCount()
        let recovery = Recovery(snapshot: .unavailable, reload: { calls.increment(); return .absent },
            operations: .init(block: { calls.increment() }, absent: { calls.increment() }, restore: { _, _ in calls.increment() }))
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            do { _ = try await recovery.prepare(verifyCurrent: { calls.increment() }); XCTFail() }
            catch { XCTAssertTrue(error is CancellationError) }
        }
        await task.value; XCTAssertEqual(calls.value, 0)
    }
    private actor Gate {
        var released = false
        var continuation: CheckedContinuation<Void, Never>?
        func wait() async { if released { return }; await withCheckedContinuation { continuation = $0 } }
        func open() { released = true; continuation?.resume(); continuation = nil }
    }
    func testConcurrentMonitorPreparationCannotDuplicateTheActiveRestore() async throws {
        let plan = try retained(), gate = Gate(), entered = expectation(description: "Restore entered"), calls = PushSignCount()
        let recovery = Recovery(snapshot: .retained(plan), reload: { XCTFail(); return .unavailable },
            operations: .init(block: {}, absent: { XCTFail() }, restore: { _, _ in calls.increment(); entered.fulfill(); await gate.wait() }))
        let first = Task { try await recovery.prepare(verifyCurrent: {}) }
        await fulfillment(of: [entered], timeout: 3)
        let second = try await recovery.prepare(verifyCurrent: {}); XCTAssertFalse(second)
        await gate.open(); let completed = try await first.value; XCTAssertTrue(completed); XCTAssertEqual(calls.value, 1)
    }
}
