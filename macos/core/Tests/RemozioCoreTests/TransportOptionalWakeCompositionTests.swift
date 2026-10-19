import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportOptionalWakeCompositionTests: XCTestCase, @unchecked Sendable {
    private final class Fixture: @unchecked Sendable {
        let setup: GatewayJournalSetupExchangeTests.Fixture
        let snapshot: GatewayRuntimeLoader.Loaded
        let available = Mutex(true)
        init(authority: Bool = false) throws {
            setup = try .init(); try setup.retainCompletion(.decode(setup.initialize()))
            let pair = try GatewayRuntimeExtensions(journal: setup.state(), foreground: setup.runtime.plan,
                inventory: XCTUnwrap(setup.runtime.machine.inventory()), wakePollMilliseconds: 100)
            snapshot = .init(configuration: authority ? pair.authority : pair.transport, commit: try GatewayRuntimeCommit(pair))
        }
        func load() throws -> GatewayRuntimeLoader.Loaded {
            guard available.withLock({ $0 }) else { throw GatewayWakeSignerError.unavailable }; return snapshot
        }
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private(set) var entered = false
        func wait() async { await withCheckedContinuation { continuation = $0; entered = true } }
        func release() { let current = continuation; continuation = nil; current?.resume() }
    }
    private func waitFor(_ condition: () async -> Bool) async throws {
        for _ in 0..<3000 { if await condition() { return }; try await Task.sleep(for: .milliseconds(1)) }
        XCTFail("Optional wake operation did not settle"); throw GatewayWakeSignerError.unavailable
    }
    func testAbsentConfigurationRetriesThenRestoresOneCompanionWithoutDirectServiceOwnership() async throws {
        let f = try Fixture(), made = PushSignCount(), started = PushSignCount(), polls = PushSignCount(), closed = PushSignCount()
        f.available.withLock { $0 = false }
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { wake in
                XCTAssertEqual(wake.canonicalBytes, f.snapshot.configuration.wake?.canonicalBytes); made.increment()
                return .init(start: { started.increment() }, poll: { polls.increment() }, close: { closed.increment() })
            }, report: { _ in })
        try await runner.start(); try await waitFor { if case .waiting = runner.status { true } else { false } }
        XCTAssertEqual(made.value, 0); f.available.withLock { $0 = true }
        try await waitFor { polls.value >= 2 }
        XCTAssertEqual(runner.status, .ready); XCTAssertEqual(made.value, 1); XCTAssertEqual(started.value, 1); XCTAssertEqual(closed.value, 0)
        await runner.close(); XCTAssertEqual(closed.value, 1); XCTAssertEqual(runner.status, .closed)
    }
    func testMissingMetadataAfterAnAdmittedPollClosesThatCompanionBeforeAnotherPoll() async throws {
        let f = try Fixture(), gate = Gate(), polls = PushSignCount(), closed = PushSignCount()
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { _ in
                .init(start: {}, poll: { polls.increment(); await gate.wait() }, close: { closed.increment() })
            }, report: { _ in })
        try await runner.start(); try await waitFor { await gate.entered }
        f.available.withLock { $0 = false }; XCTAssertEqual(closed.value, 0)
        await gate.release(); try await waitFor { closed.value == 1 }
        try await waitFor { if case .waiting = runner.status { true } else { false } }
        XCTAssertEqual(polls.value, 1); await runner.close(); XCTAssertEqual(closed.value, 1)
    }
    func testWrongRoleCannotConstructChannelsAndFactoryFailureCanRecover() async throws {
        let wrong = try Fixture(authority: true), made = PushSignCount()
        let refused = try TransportWakeRunner(optionalConfiguration: { try wrong.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { _ in made.increment(); return .init(start: {}, poll: {}, close: {}) }, report: { _ in })
        try await refused.start(); try await waitFor { if case .waiting = refused.status { true } else { false } }
        XCTAssertEqual(made.value, 0); await refused.close()
        let f = try Fixture(), fail = Mutex(true), closed = PushSignCount()
        let retry = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { _ in
                if fail.withLock({ $0 }) { throw GatewayWakeSignerError.unavailable }
                return .init(start: {}, poll: {}, close: { closed.increment() })
            }, report: { _ in })
        try await retry.start(); try await waitFor { if case .waiting = retry.status { true } else { false } }
        fail.withLock { $0 = false }; try await waitFor { retry.status == .ready }
        await retry.close(); XCTAssertEqual(closed.value, 1)
    }
    func testCloseRetainsTheCompanionReleaseLockUntilItsPollActuallySettles() async throws {
        let f = try Fixture(), locks = try ReleaseActivityFixture(), runtime = try locks.open(), installer = try locks.open(), gate = Gate()
        let activity = try runtime.acquireShared(), closed = PushSignCount(), finished = PushSignCount()
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, makeRuntime: { _ in
            .init(start: {}, poll: { await gate.wait() }, close: { activity.close(); closed.increment() })
        }, report: { _ in })
        try await runner.start(); try await waitFor { await gate.entered }
        let first = Task { await runner.close(); finished.increment() }
        let second = Task { await runner.close(); finished.increment() }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(finished.value, 0); XCTAssertEqual(closed.value, 0)
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release(); await first.value; await second.value
        XCTAssertEqual(closed.value, 1); XCTAssertEqual(finished.value, 2); XCTAssertEqual(runner.status, .closed)
        let update = try installer.acquireExclusive(); update.close()
    }
}
