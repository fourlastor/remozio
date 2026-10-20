import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportSettingsConsumerHostTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private final class Flag: Sendable { let value: Mutex<Bool>; init(_ initial: Bool) { value = Mutex(initial) } }
    private struct Failed: Error {}
    private final class Control: OwnedTransportSettingsControl, Sendable {
        struct State {
            var starts = 0, polls = 0, closes = 0, failPoll = false
            var start: CheckedContinuation<Void, Never>?, poll: CheckedContinuation<Void, Never>?, close: CheckedContinuation<Void, Never>?
        }
        let value = Mutex(State())
        let holdStart: Bool, holdPoll: Bool, holdClose: Bool
        init(holdStart: Bool = false, holdPoll: Bool = false, holdClose: Bool = false) {
            self.holdStart = holdStart; self.holdPoll = holdPoll; self.holdClose = holdClose
        }
        func start() async throws { value.withLock { $0.starts += 1 }; if holdStart { await withCheckedContinuation { c in value.withLock { $0.start = c } } } }
        func poll() async throws {
            value.withLock { $0.polls += 1 }
            if holdPoll { await withCheckedContinuation { c in value.withLock { $0.poll = c } } }
            if value.withLock({ $0.failPoll }) { throw Failed() }
        }
        func close() async throws { value.withLock { $0.closes += 1 }; if holdClose { await withCheckedContinuation { c in value.withLock { $0.close = c } } } }
        func finishStart() { value.withLock { s in let c = s.start; s.start = nil; return c }?.resume() }
        func finishPoll() { value.withLock { s in let c = s.poll; s.poll = nil; return c }?.resume() }
        func finishClose() { value.withLock { s in let c = s.close; s.close = nil; return c }?.resume() }
    }
    private final class Foreground: OwnedTransportSettingsForeground, Sendable {
        struct State {
            var starts = 0, polls = 0, closes = 0, retired = false, failStart = false, failPoll = false, closeFailures = 0
            var start: CheckedContinuation<Void, Never>?, poll: CheckedContinuation<Void, Never>?, close: CheckedContinuation<Void, Never>?
        }
        let value = Mutex(State())
        let holdStart: Bool, holdPoll: Bool, holdClose: Bool
        init(holdStart: Bool = false, holdPoll: Bool = false, holdClose: Bool = false) {
            self.holdStart = holdStart; self.holdPoll = holdPoll; self.holdClose = holdClose
        }
        func retire() { value.withLock { $0.retired = true } }
        func start() async throws {
            value.withLock { $0.starts += 1 }
            if holdStart { await withCheckedContinuation { c in value.withLock { $0.start = c } } }
            if value.withLock({ $0.failStart }) { throw Failed() }
        }
        func poll() async throws {
            value.withLock { $0.polls += 1 }
            if holdPoll { await withCheckedContinuation { c in value.withLock { $0.poll = c } } }
            if value.withLock({ $0.failPoll }) { throw Failed() }
        }
        func closeAndWait() async throws {
            value.withLock { $0.closes += 1 }
            if value.withLock({ s in if s.closeFailures > 0 { s.closeFailures -= 1; return true }; return false }) { throw Failed() }
            if holdClose { await withCheckedContinuation { c in value.withLock { $0.close = c } } }
        }
        func finishStart() { value.withLock { s in let c = s.start; s.start = nil; return c }?.resume() }
        func finishPoll() { value.withLock { s in let c = s.poll; s.poll = nil; return c }?.resume() }
        func finishClose() { value.withLock { s in let c = s.close; s.close = nil; return c }?.resume() }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testControlStartsBeforeForegroundFactoryAndOptionalHandshakeCannotBlockDirectPolling() async throws {
        let control = Control(holdPoll: true), foreground = Foreground(), made = Counter()
        let files = try ServiceReleaseActivityFixture(), lease = try files.open()
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: {
            XCTAssertEqual(control.value.withLock { $0.starts }, 1); made.value.withLock { $0 += 1 }; return foreground
        })
        try await host.start(); XCTAssertEqual(made.value.withLock { $0 }, 0)
        try await host.poll(); try await until { control.value.withLock { $0.poll != nil } }
        try await host.poll(); XCTAssertEqual(foreground.value.withLock { $0.polls }, 2)
        XCTAssertEqual(control.value.withLock { $0.polls }, 1); control.finishPoll(); try await host.close()
    }
    func testOptionalFailureKeepsForegroundAndItsRelayPolling() async throws {
        let control = Control(), foreground = Foreground(), files = try ServiceReleaseActivityFixture(), lease = try files.open()
        control.value.withLock { $0.failPoll = true }
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { foreground })
        try await host.start(); try await host.poll(); try await Task.sleep(for: .milliseconds(10)); try await host.poll()
        XCTAssertEqual(foreground.value.withLock { $0.starts }, 1); XCTAssertEqual(foreground.value.withLock { $0.polls }, 2)
        XCTAssertFalse(foreground.value.withLock { $0.retired }); try await host.close()
    }
    func testForegroundFailureRetainsControlAndRetriesOnlyAfterCleanup() async throws {
        let control = Control(), first = Foreground(holdClose: true), second = Foreground(), made = Counter()
        first.value.withLock { $0.failStart = true }
        let files = try ServiceReleaseActivityFixture(), lease = try files.open()
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), retryMilliseconds: 100,
            makeForeground: { made.value.withLock { $0 += 1; return $0 } == 1 ? first : second })
        try await host.start(); let poll = Task { try await host.poll() }; defer { first.finishClose() }
        try await until { first.value.withLock { $0.close != nil } }
        XCTAssertEqual(made.value.withLock { $0 }, 1); XCTAssertGreaterThan(control.value.withLock { $0.polls }, 0)
        first.finishClose(); try await poll.value; try await Task.sleep(for: .milliseconds(120)); try await host.poll()
        XCTAssertEqual(made.value.withLock { $0 }, 2); XCTAssertEqual(second.value.withLock { $0.starts }, 1); try await host.close()
    }
    func testCloseStartsBothDrainsAndKeepsActualActivityUntilBothFinish() async throws {
        let control = Control(holdClose: true), foreground = Foreground(holdClose: true)
        let files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { foreground })
        try await host.start(); try await host.poll(); let done = Counter()
        let first = Task { try await host.close(); done.value.withLock { $0 += 1 } }, second = Task { try await host.close(); done.value.withLock { $0 += 1 } }; first.cancel()
        defer { control.finishClose(); foreground.finishClose() }
        try await until { control.value.withLock { $0.close != nil } && foreground.value.withLock { $0.close != nil } }
        XCTAssertEqual(done.value.withLock { $0 }, 0); XCTAssertThrowsError(try updater.acquireExclusive())
        foreground.finishClose(); try await Task.sleep(for: .milliseconds(10)); XCTAssertThrowsError(try updater.acquireExclusive())
        control.finishClose(); try await first.value; try await second.value
        XCTAssertEqual(done.value.withLock { $0 }, 2); XCTAssertEqual(foreground.value.withLock { $0.closes }, 1)
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testCloseJoinsForegroundStartupBeforeReleasingOrReplacingIt() async throws {
        let control = Control(), foreground = Foreground(holdStart: true), files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { foreground })
        try await host.start(); let poll = Task { try await host.poll() }; defer { foreground.finishStart() }
        try await until { foreground.value.withLock { $0.start != nil } }
        let close = Task { try await host.close() }
        try await until { foreground.value.withLock { $0.retired } }
        XCTAssertEqual(foreground.value.withLock { $0.closes }, 0); XCTAssertThrowsError(try updater.acquireExclusive())
        foreground.finishStart(); try await close.value; _ = await poll.result
        XCTAssertEqual(foreground.value.withLock { $0.closes }, 1); let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testCloseJoinsForegroundPollAndOptionalPollBeforeActivityRelease() async throws {
        let control = Control(holdPoll: true), foreground = Foreground(holdPoll: true)
        let files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { foreground })
        try await host.start(); let poll = Task { try await host.poll() }; defer { control.finishPoll(); foreground.finishPoll() }
        try await until { control.value.withLock { $0.poll != nil } && foreground.value.withLock { $0.poll != nil } }
        let close = Task { try await host.close() }; close.cancel()
        try await until { foreground.value.withLock { $0.retired } }; XCTAssertThrowsError(try updater.acquireExclusive())
        foreground.finishPoll(); try await until { foreground.value.withLock { $0.closes == 1 } }
        XCTAssertThrowsError(try updater.acquireExclusive()); control.finishPoll(); try await close.value; _ = await poll.result
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testFailedDrainKeepsActivityAndRetriesCleanupWithoutReopeningForeground() async throws {
        let control = Control(), foreground = Foreground(), made = Counter()
        foreground.value.withLock { $0.closeFailures = 1 }
        let files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { made.value.withLock { $0 += 1 }; return foreground })
        try await host.start(); try await host.poll()
        do { try await host.close(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertThrowsError(try updater.acquireExclusive()); XCTAssertEqual(made.value.withLock { $0 }, 1)
        try await host.close(); XCTAssertEqual(foreground.value.withLock { $0.closes }, 2); let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testDroppedHostRetainsActivityThroughOwnedCleanup() async throws {
        let control = Control(holdClose: true), foreground = Foreground(holdClose: true)
        let files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        var host: TransportSettingsConsumerHost? = try .init(control: control, lifetime: lease.acquireShared(), makeForeground: { foreground })
        try await host?.start(); try await host?.poll(); host = nil
        defer { control.finishClose(); foreground.finishClose() }
        try await until { control.value.withLock { $0.close != nil } && foreground.value.withLock { $0.close != nil } }
        XCTAssertThrowsError(try updater.acquireExclusive()); control.finishClose(); foreground.finishClose()
        try await until { (try? updater.acquireExclusive()) != nil }
    }
    func testScopeFailurePrecedesControlAndForegroundAccess() async throws {
        let files = try ServiceReleaseActivityFixture()
        // Acquire a valid token before invalidating its verification seam.
        let valid = Flag(true), active = try files.open(verify: { guard valid.value.withLock({ $0 }) else { throw Failed() } })
        let token = try active.acquireShared(), control = Control()
        let host = try TransportSettingsConsumerHost(control: control, lifetime: token, makeForeground: { XCTFail(); throw Failed() })
        valid.value.withLock { $0 = false }
        do { try await host.start(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(control.value.withLock { $0.starts }, 0); try await host.close()
    }
    func testCloseDuringControlStartWaitsForItsOwnedWork() async throws {
        let control = Control(holdStart: true), files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), makeForeground: { XCTFail(); throw Failed() })
        let start = Task { try await host.start() }; defer { control.finishStart() }; try await until { control.value.withLock { $0.start != nil } }
        let close = Task { try await host.close() }; close.cancel()
        try await Task.sleep(for: .milliseconds(10)); XCTAssertThrowsError(try updater.acquireExclusive()); control.finishStart()
        try await close.value; _ = await start.result; let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
    func testPollingRetriesFailedStartupCleanupBeforeOpeningReplacementForeground() async throws {
        let control = Control(), first = Foreground(), second = Foreground(), made = Counter()
        first.value.withLock { $0.failStart = true; $0.closeFailures = 1 }
        let files = try ServiceReleaseActivityFixture(), lease = try files.open()
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), retryMilliseconds: 100,
            makeForeground: { made.value.withLock { $0 += 1; return $0 } == 1 ? first : second })
        try await host.start(); try await host.poll()
        XCTAssertEqual(first.value.withLock { $0.closes }, 1)
        XCTAssertEqual(made.value.withLock { $0 }, 1)
        try await host.poll()
        XCTAssertEqual(first.value.withLock { $0.closes }, 2)
        XCTAssertEqual(made.value.withLock { $0 }, 1)
        try await Task.sleep(for: .milliseconds(120)); try await host.poll()
        XCTAssertEqual(made.value.withLock { $0 }, 2)
        XCTAssertEqual(second.value.withLock { $0.starts }, 1)
        try await host.close()
    }
    func testCloseDuringRetryCleanupCannotStartReplacementForeground() async throws {
        let control = Control(), foreground = Foreground(holdClose: true), made = Counter()
        foreground.value.withLock { $0.failStart = true }
        let files = try ServiceReleaseActivityFixture(), lease = try files.open(), updater = try files.open(update: true)
        let host = try TransportSettingsConsumerHost(control: control, lifetime: lease.acquireShared(), retryMilliseconds: 100,
            makeForeground: { made.value.withLock { $0 += 1 }; return foreground })
        try await host.start(); let poll = Task { try await host.poll() }
        defer { foreground.finishClose() }
        try await until { foreground.value.withLock { $0.close != nil } }
        let close = Task { try await host.close() }
        try await until { control.value.withLock { $0.closes > 0 } }
        XCTAssertThrowsError(try updater.acquireExclusive())
        foreground.finishClose(); try await close.value; _ = await poll.result
        XCTAssertEqual(made.value.withLock { $0 }, 1)
        XCTAssertEqual(foreground.value.withLock { $0.closes }, 1)
        let exclusive = try updater.acquireExclusive(); exclusive.close()
    }
}
