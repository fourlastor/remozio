import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportWakeRunnerTests: XCTestCase, @unchecked Sendable {
    private actor Probe {
        var opens = 0
        var starts = 0
        var polls = 0
        var closes = 0
        var events: [String] = []
        var failedStarts: Set<Int> = []
        var failedPolls: Set<Int> = []
        func open() -> Int { opens += 1; events.append("open:\(opens)"); return opens }
        func failStarts(_ ids: Set<Int>) { failedStarts = ids }
        func failPolls(_ ids: Set<Int>) { failedPolls = ids }
        func start(_ id: Int) throws {
            starts += 1; events.append("start:\(id)")
            if failedStarts.contains(id) { throw GatewayWakeChannelError.closed }
        }
        func poll(_ id: Int) throws {
            polls += 1; events.append("poll:\(id)")
            if failedPolls.contains(id) { throw AuthorityWakeHintChannelError.timedOut }
        }
        func close(_ id: Int) { closes += 1; events.append("close:\(id)") }
        func counts() -> (Int, Int, Int, Int) { (opens, starts, polls, closes) }
        nonisolated func attempt(_ id: Int) -> TransportWakeAttempt {
            .init(start: { try await self.start(id) }, poll: { try await self.poll(id) }, close: { await self.close(id) })
        }
    }
    private actor Gate {
        var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func hold() async { await withCheckedContinuation { entered = true; continuation = $0 } }
        func release() { continuation?.resume(); continuation = nil }
    }
    private func waitUntil(_ predicate: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await predicate()) {
            guard ContinuousClock.now < deadline else { throw GatewayWakeChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func testInvalidBoundsAndCloseBeforeStart() async throws {
        for (initial, maximum) in [(UInt64(99), UInt64(1000)), (60_001, 100_000), (1000, 999), (1000, 300_001)] {
            XCTAssertThrowsError(try TransportWakeRunner(initialRetryMilliseconds: initial, maximumRetryMilliseconds: maximum,
                makeAttempt: { XCTFail("Invalid runner opened"); throw GatewayWakeSignerError.unavailable }, report: { _ in }))
        }
        XCTAssertThrowsError(try TransportWakeRunner(intervalMilliseconds: 9,
            makeAttempt: { throw GatewayWakeSignerError.unavailable }, report: { _ in }))
        let probe = Probe()
        let runner = try TransportWakeRunner(makeAttempt: { probe.attempt(await probe.open()) }, report: { _ in })
        await runner.close(); await runner.close()
        do { try await runner.start(); XCTFail("Closed runner started") } catch {}
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 0)
        XCTAssertEqual(runner.status, .closed)
    }
    func testUnavailableSignerRetriesWithCappedBackoffWithoutStartingFailedAttempts() async throws {
        let probe = Probe(), statuses = Mutex<[TransportWakeRunner.Status]>([])
        let runner = try TransportWakeRunner(intervalMilliseconds: 10, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200,
            makeAttempt: {
                let id = await probe.open()
                if id < 4 { throw GatewayWakeSignerError.unavailable }
                return probe.attempt(id)
            }, report: { status in statuses.withLock { $0.append(status) } })
        try await runner.start()
        try await waitUntil { await probe.counts().2 > 0 }
        await runner.close()
        let delays = statuses.withLock { values in values.compactMap { value -> UInt64? in
            if case .waiting(let delay) = value { return delay }; return nil
        } }
        XCTAssertEqual(delays, [100, 200, 200])
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 4); XCTAssertEqual(counts.1, 1); XCTAssertEqual(counts.3, 1)
    }
    func testFailedChannelStartupClosesEveryAttemptBeforeOpeningTheNext() async throws {
        let probe = Probe()
        await probe.failStarts([1, 2])
        let runner = try TransportWakeRunner(intervalMilliseconds: 10, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            makeAttempt: { probe.attempt(await probe.open()) }, report: { _ in })
        try await runner.start()
        try await waitUntil { await probe.counts().2 > 0 }
        await runner.close()
        let events = await probe.events
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "close:1")), try XCTUnwrap(events.firstIndex(of: "open:2")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "close:2")), try XCTUnwrap(events.firstIndex(of: "open:3")))
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 3); XCTAssertEqual(counts.1, 3); XCTAssertEqual(counts.3, 3)
    }
    func testPollingFailureRetiresItsChannelsAndCreatesAFreshAttempt() async throws {
        let probe = Probe()
        await probe.failPolls([1])
        let runner = try TransportWakeRunner(intervalMilliseconds: 10, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            makeAttempt: { probe.attempt(await probe.open()) }, report: { _ in })
        try await runner.start()
        try await waitUntil { await probe.counts().0 == 2 }
        try await waitUntil { runner.status == .ready }
        await runner.close()
        let events = await probe.events
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "close:1")), try XCTUnwrap(events.firstIndex(of: "open:2")))
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 2); XCTAssertEqual(counts.3, 2)
    }
    func testIdentityAndConfigurationFailureDoNotRetryOrSelectAnotherSigner() async throws {
        for failure in [GatewayWakeSignerError.wrongIdentity, .wrongAccount, .invalidRecord, .invalidConfiguration] {
            let probe = Probe()
            let runner = try TransportWakeRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
                makeAttempt: { _ = await probe.open(); throw failure }, report: { _ in })
            try await runner.start()
            try await waitUntil { runner.status == .failed }
            try await Task.sleep(for: .milliseconds(150))
            await runner.close()
            let counts = await probe.counts()
            XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
        }
    }
    func testCloseDuringFactoryOwnsLateAttemptWithoutStartingIt() async throws {
        let probe = Probe(), gate = Gate(), statuses = Mutex<[TransportWakeRunner.Status]>([])
        let runner = try TransportWakeRunner(makeAttempt: {
            let id = await probe.open(); await gate.hold(); return probe.attempt(id)
        }, report: { status in statuses.withLock { $0.append(status) } })
        try await runner.start()
        try await waitUntil { await gate.entered }
        let closing = Task { await runner.close() }
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(runner.status, .starting)
        await gate.release(); await closing.value
        let counts = await probe.counts()
        XCTAssertEqual(counts.1, 0); XCTAssertEqual(counts.3, 1)
        XCTAssertFalse(statuses.withLock { $0.contains(.ready) })
        XCTAssertEqual(runner.status, .closed)
    }
    func testCloseAwaitsActivePollBeforeClosingChannels() async throws {
        let probe = Probe(), gate = Gate()
        let runner = try TransportWakeRunner(makeAttempt: {
            let id = await probe.open()
            return TransportWakeAttempt(start: { try await probe.start(id) }, poll: {
                await gate.hold(); try await probe.poll(id)
            }, close: { await probe.close(id) })
        }, report: { _ in })
        try await runner.start()
        try await waitUntil { await gate.entered }
        let closing = Task { await runner.close() }
        try await Task.sleep(for: .milliseconds(30))
        let before = await probe.counts()
        XCTAssertEqual(before.3, 0)
        await gate.release(); await closing.value
        let after = await probe.counts()
        XCTAssertEqual(after.0, 1); XCTAssertEqual(after.3, 1)
        XCTAssertEqual(runner.status, .closed)
    }
    func testStopDuringBackoffPreventsAnotherAttempt() async throws {
        let probe = Probe()
        await probe.failStarts([1])
        let runner = try TransportWakeRunner(initialRetryMilliseconds: 200, maximumRetryMilliseconds: 200,
            makeAttempt: { probe.attempt(await probe.open()) }, report: { _ in })
        try await runner.start()
        try await waitUntil { runner.status == .waiting(retryMilliseconds: 200) }
        await runner.close()
        try await Task.sleep(for: .milliseconds(250))
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.3, 1)
    }
    func testConcurrentCloseSharesOneCleanupAndNeverReopens() async throws {
        let probe = Probe(), gate = Gate()
        let runner = try TransportWakeRunner(makeAttempt: {
            let id = await probe.open()
            return TransportWakeAttempt(start: { try await probe.start(id) }, poll: { try await probe.poll(id) }, close: {
                await gate.hold(); await probe.close(id)
            })
        }, report: { _ in })
        try await runner.start()
        try await waitUntil { runner.status == .ready }
        let first = Task { await runner.close() }
        try await waitUntil { await gate.entered }
        let second = Task { await runner.close() }
        await gate.release(); await first.value; await second.value
        await runner.close()
        let counts = await probe.counts()
        XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.3, 1)
        XCTAssertEqual(runner.status, .closed)
    }
    func testReleaseCancelsWorkerAndClosesItsAttempt() async throws {
        let probe = Probe()
        var runner: TransportWakeRunner? = try TransportWakeRunner(makeAttempt: { probe.attempt(await probe.open()) }, report: { _ in })
        try await runner?.start()
        try await waitUntil { runner?.status == .ready }
        runner = nil
        try await waitUntil { await probe.counts().3 == 1 }
    }
    func testRetryClassificationKeepsOwnershipAndIdentityErrorsTerminal() {
        let retryable: [any Error] = [AuthorityWakeHintChannelError.closed, AuthorityWakeHintChannelError.timedOut,
            AuthorityWakeHintChannelError.unsupportedVersion, AuthorityWakeHintChannelError.invalidMessage,
            GatewayWakeChannelError.closed, GatewayWakeChannelError.timedOut, GatewayWakeChannelError.rejected,
            GatewayWakeChannelError.unsupportedVersion, GatewayWakeChannelError.invalidMessage,
            TransportWakeRuntimeError.closed, GatewayWakeSignerError.unavailable]
        for error in retryable { XCTAssertTrue(TransportWakeRunner.isRetryable(error)) }
        let terminal: [any Error] = [AuthorityWakeHintChannelError.invalidConfiguration, AuthorityWakeHintChannelError.busy,
            GatewayWakeChannelError.invalidConfiguration, GatewayWakeChannelError.busy,
            GatewayWakeSignerError.wrongIdentity, GatewayWakeSignerError.wrongAccount, GatewayWakeSignerError.invalidRecord,
            TransportWakeRuntimeError.invalidConfiguration, TransportWakeRuntimeError.busy, CancellationError()]
        for error in terminal { XCTAssertFalse(TransportWakeRunner.isRetryable(error)) }
    }
}
