import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewayExtensionMonitorTests: XCTestCase, @unchecked Sendable {
    private struct Unavailable: Error {}
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private(set) var entered = false
        func wait() async { await withCheckedContinuation { continuation = $0; entered = true } }
        func release() { let current = continuation; continuation = nil; current?.resume() }
    }
    private func waitFor(_ condition: () async -> Bool) async throws {
        for _ in 0..<2000 { if await condition() { return }; try await Task.sleep(for: .milliseconds(1)) }
        XCTFail("Monitor did not reach its expected state"); throw Unavailable()
    }
    func testMissingFailedMalformedAndValidRefreshesKeepDistinctStatesAndCanRecover() async throws {
        let step = Mutex(0), digest = Data(repeating: 81, count: 32)
        let monitor = try AuthorityGatewayExtensionMonitor(intervalMilliseconds: 100) {
            switch step.withLock({ $0 }) {
            case 0: return nil
            case 1: throw Unavailable()
            case 2: return Data([1])
            default: return digest
            }
        }
        try await monitor.start(); try await waitFor { await monitor.status == .absent }
        step.withLock { $0 = 1 }; try await waitFor { await monitor.status == .unavailable }
        step.withLock { $0 = 2 }; try await Task.sleep(for: .milliseconds(150))
        let invalid = await monitor.status; XCTAssertEqual(invalid, .unavailable)
        step.withLock { $0 = 3 }; try await waitFor { await monitor.status == .providerInstalled(digest) }
        await monitor.close(); let closed = await monitor.status; XCTAssertEqual(closed, .closed)
    }
    func testConcurrentClosersWaitForTheAdmittedRefreshAndItsActualReleaseLock() async throws {
        let fixture = try ReleaseActivityFixture(), runtime = try fixture.open(), installer = try fixture.open(), gate = Gate()
        let completions = PushSignCount()
        let monitor = try AuthorityGatewayExtensionMonitor(intervalMilliseconds: 100) {
            let activity = try runtime.acquireShared(); defer { activity.close() }
            await gate.wait() // This fixture intentionally does not acknowledge task cancellation until released.
            try activity.validate(); return Data(repeating: 82, count: 32)
        }
        try await monitor.start(); try await waitFor { await gate.entered }
        let first = Task { await monitor.close(); completions.increment() }
        let second = Task { await monitor.close(); completions.increment() }
        try await waitFor { await monitor.status == .closing }
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertEqual(completions.value, 0)
        await gate.release(); await first.value; await second.value
        XCTAssertEqual(completions.value, 2)
        let closed = await monitor.status; XCTAssertEqual(closed, .closed)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testStartAndIntervalAdmissionRemainBoundedAndCloseBeforeStartIsTerminal() async throws {
        for interval in [0, 99, 60_001] {
            XCTAssertThrowsError(try AuthorityGatewayExtensionMonitor(intervalMilliseconds: interval, refresh: { nil }))
        }
        let monitor = try AuthorityGatewayExtensionMonitor { nil }
        await monitor.close()
        do { try await monitor.start(); XCTFail() } catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        let running = try AuthorityGatewayExtensionMonitor { nil }
        try await running.start()
        do { try await running.start(); XCTFail() } catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        await running.close()
    }
}
