import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateConsumerHealthHostTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Listener: OwnedMachineUpdateConsumerHealthListener {
        struct State {
            var starts = 0, joins = 0, retired = false, failStart = false, failClose = 0
            var hold = false
            var gate: CheckedContinuation<Void, Never>?
        }
        let state = Mutex(State())
        func start() throws {
            if state.withLock({ $0.starts += 1; return $0.failStart }) { throw Failed() }
        }
        func close() { state.withLock { $0.retired = true } }
        func closeAndWait() async throws {
            close()
            if state.withLock({ $0.joins += 1; if $0.failClose > 0 { $0.failClose -= 1; return true }; return false }) { throw Failed() }
            if state.withLock({ $0.hold }) {
                await withCheckedContinuation { gate in state.withLock { $0.gate = gate } }
            }
        }
        func finish() { state.withLock { value in let old = value.gate; value.gate = nil; value.hold = false; return old }?.resume() }
    }
    private final class CheckedActivity: OwnedReleaseActivity {
        let activity: any OwnedReleaseActivity
        let valid = Mutex(true), closes = Mutex(0)
        init(_ activity: any OwnedReleaseActivity) { self.activity = activity }
        func validate() throws { if !valid.withLock({ $0 }) { throw Failed() }; try activity.validate() }
        func close() { closes.withLock { $0 += 1 }; activity.close() }
    }
    private final class WeakHost {
        weak var value: MachineUpdateConsumerHealthHost?
        init(_ value: MachineUpdateConsumerHealthHost?) { self.value = value }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testOnlyTheHealthListenerStartsAndTheBaselineLastsThroughClose() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(), activity = try CheckedActivity(service.acquireShared())
        let host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        do { try await host.poll(); XCTFail() } catch {}
        try await host.start(); try await host.poll()
        XCTAssertEqual(listener.state.withLock { $0.starts }, 1)
        XCTAssertThrowsError(try updater.acquireExclusive())
        do { try await host.start(); XCTFail() } catch {}
        try await host.close(); try await host.close()
        XCTAssertEqual(activity.closes.withLock { $0 }, 1)
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testCloseJoinsAdmittedWorkBeforeReleasingTheBaseline() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(); listener.state.withLock { $0.hold = true }
        let activity = try CheckedActivity(service.acquireShared()), done = Mutex(false)
        let host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        try await host.start()
        let close = Task { try await host.close(); done.withLock { $0 = true } }
        try await until { listener.state.withLock { $0.gate != nil } }
        XCTAssertFalse(done.withLock { $0 }); XCTAssertEqual(activity.closes.withLock { $0 }, 0)
        XCTAssertThrowsError(try updater.acquireExclusive())
        listener.finish(); try await close.value
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testFailedCloseKeepsTheScopeAndAJoinedRetryCanSettleIt() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(); listener.state.withLock { $0.failClose = 1 }
        let activity = try CheckedActivity(service.acquireShared()), host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        try await host.start()
        do { try await host.close(); XCTFail() } catch {}
        XCTAssertEqual(activity.closes.withLock { $0 }, 0); XCTAssertThrowsError(try updater.acquireExclusive())
        do { try await host.start(); XCTFail() } catch {}
        do { try await host.poll(); XCTFail() } catch {}
        try await host.close(); XCTAssertEqual(activity.closes.withLock { $0 }, 1)
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testConcurrentCloseCallsJoinTheSameSettlement() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        listener.state.withLock { $0.hold = true }
        let activity = try CheckedActivity(service.acquireShared()), host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        try await host.start()
        let first = Task { try await host.close() }
        try await until { listener.state.withLock { $0.gate != nil } }
        let second = Task { try await host.close() }
        listener.finish(); try await first.value; try await second.value
        XCTAssertEqual(listener.state.withLock { $0.joins }, 1); XCTAssertEqual(activity.closes.withLock { $0 }, 1)
    }
    func testCancellationCannotAbandonTheAdmittedSettlement() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        listener.state.withLock { $0.hold = true }
        let activity = try CheckedActivity(service.acquireShared()), host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        let done = Mutex(false)
        try await host.start()
        let closing = Task { try await host.close(); done.withLock { $0 = true } }
        try await until { listener.state.withLock { $0.gate != nil } }; closing.cancel()
        XCTAssertFalse(done.withLock { $0 }); XCTAssertEqual(activity.closes.withLock { $0 }, 0)
        listener.finish(); try await closing.value
        XCTAssertEqual(activity.closes.withLock { $0 }, 1)
    }
    func testChangedScopeRetiresTheListenerAndRequiresJoinedClose() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        let activity = try CheckedActivity(service.acquireShared()), host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        try await host.start(); activity.valid.withLock { $0 = false }
        do { try await host.poll(); XCTFail() } catch {}
        XCTAssertTrue(listener.state.withLock { $0.retired }); XCTAssertEqual(activity.closes.withLock { $0 }, 0)
        try await host.close(); XCTAssertEqual(activity.closes.withLock { $0 }, 1)
    }
    func testFailedListenerStartKeepsTheScopeUntilCleanup() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), listener = Listener()
        listener.state.withLock { $0.failStart = true }
        let activity = try CheckedActivity(service.acquireShared()), host = MachineUpdateConsumerHealthHost(listener: listener, activity: activity)
        do { try await host.start(); XCTFail() } catch {}
        XCTAssertTrue(listener.state.withLock { $0.retired }); XCTAssertEqual(activity.closes.withLock { $0 }, 0)
        try await host.close(); XCTAssertEqual(activity.closes.withLock { $0 }, 1)
    }
    func testDroppingTheHostRetainsItsScopeUntilTheListenerSettles() async throws {
        let files = try ServiceReleaseActivityFixture(), service = try files.open(), updater = try files.open(update: true)
        let listener = Listener(); listener.state.withLock { $0.hold = true; $0.failClose = 1 }
        let activity = try CheckedActivity(service.acquireShared())
        var host: MachineUpdateConsumerHealthHost? = .init(listener: listener, activity: activity)
        let weak = WeakHost(host)
        try await host?.start(); host = nil
        try await until { weak.value == nil && listener.state.withLock { $0.gate != nil } }
        XCTAssertEqual(activity.closes.withLock { $0 }, 0); XCTAssertThrowsError(try updater.acquireExclusive())
        listener.finish(); try await until { activity.closes.withLock { $0 == 1 } }
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
}
