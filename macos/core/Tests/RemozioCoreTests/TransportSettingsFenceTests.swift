import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportSettingsFenceTests: XCTestCase, @unchecked Sendable {
    private final class Fixture: @unchecked Sendable {
        struct State { var current: GatewayRuntimeLoader.Loaded; var bytes: Data?; var denied = false }
        let state: Mutex<State>
        let selected: GatewayRuntimeLoader.Loaded
        let fence: Data
        init(pending: Bool = false) throws {
            let r = try GatewayRuntimeSettingsStoreTests.Ready()
            let plan = try GatewayRuntimeSettingsPublicationPlan(revision: r.revision(2), previous: nil,
                activation: r.activation, journal: r.fixture.state(), foreground: r.fixture.runtime.plan,
                inventory: XCTUnwrap(r.fixture.runtime.machine.inventory()))
            fence = try GatewayRuntimeSettingsFence(plan).encoded
            selected = .init(configuration: plan.pair.transport, commit: plan.commit)
            state = Mutex(.init(current: .init(configuration: r.activation.extensions.transport,
                commit: try GatewayRuntimeCommit(r.activation.extensions)), bytes: pending ? fence : nil))
        }
        func load() throws -> GatewayRuntimeLoader.Loaded {
            let current = state.withLock { $0.current }, services = current.configuration.material.runtime.services
            guard try GatewayRuntimeSettingsFenceReader.load(macID: services.macID, accountID: services.accountID, read: {
                try self.state.withLock { if $0.denied { throw JournalLeaseError.system(EACCES) }; return $0.bytes }
            }, verifyCurrent: {}) == nil else { throw GatewayPreparationError.incomplete }
            return current
        }
    }
    private actor Gate {
        var entered = false
        var continuation: CheckedContinuation<Void, Never>?
        func wait() async { await withCheckedContinuation { continuation = $0; entered = true } }
        func release() { let old = continuation; continuation = nil; old?.resume() }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await condition()) {
            guard ContinuousClock.now < end else { throw GatewayWakeSignerError.unavailable }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    private func waiting(_ runner: TransportWakeRunner) -> Bool { if case .waiting = runner.status { true } else { false } }
    func testPendingStartupKeepsItsRetryOwnerAndStartsOnlyTheSelectedCompanionAfterCleanup() async throws {
        let f = try Fixture(pending: true), made = PushSignCount(), polls = PushSignCount(), closes = PushSignCount()
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { wake in
                XCTAssertEqual(wake.canonicalBytes, f.selected.configuration.wake?.canonicalBytes); made.increment()
                return .init(start: {}, poll: { polls.increment() }, close: { closes.increment() })
            }, report: { _ in })
        try await runner.start(); try await waitUntil { self.waiting(runner) }; XCTAssertEqual(made.value, 0)
        f.state.withLock { $0.current = f.selected; $0.bytes = nil }
        try await waitUntil { polls.value > 0 }; XCTAssertEqual(made.value, 1)
        await runner.close(); XCTAssertEqual(closes.value, 1)
    }
    func testFenceDuringPollRetainsTheReleaseScopeUntilThatPollActuallySettles() async throws {
        let f = try Fixture(), gate = Gate(), made = PushSignCount(), polls = PushSignCount(), closes = PushSignCount()
        let locks = try ReleaseActivityFixture(), runtime = try locks.open(), installer = try locks.open(), activity = try runtime.acquireShared()
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { _ in
                made.increment(); return .init(start: {}, poll: { polls.increment(); await gate.wait() }, close: { activity.close(); closes.increment() })
            }, report: { _ in })
        try await runner.start(); try await waitUntil { await gate.entered }
        f.state.withLock { $0.bytes = f.fence }
        XCTAssertEqual(closes.value, 0); XCTAssertThrowsError(try installer.acquireExclusive())
        await gate.release(); try await waitUntil { self.waiting(runner) }
        XCTAssertEqual(made.value, 1); XCTAssertEqual(polls.value, 1); XCTAssertEqual(closes.value, 1)
        let exclusive = try installer.acquireExclusive(); exclusive.close(); await runner.close(); XCTAssertEqual(closes.value, 1)
    }
    func testFenceAppearingDuringFactoryConstructionPreventsStartAndJoinsItsOwner() async throws {
        let f = try Fixture(), made = PushSignCount(), starts = PushSignCount(), closes = PushSignCount()
        let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
            maximumRetryMilliseconds: 100, makeRuntime: { _ in
                made.increment(); f.state.withLock { $0.bytes = f.fence }
                return .init(start: { starts.increment() }, poll: { XCTFail() }, close: { closes.increment() })
            }, report: { _ in })
        try await runner.start(); try await waitUntil { self.waiting(runner) }
        XCTAssertEqual(made.value, 1); XCTAssertEqual(starts.value, 0); XCTAssertEqual(closes.value, 1)
        await runner.close(); XCTAssertEqual(closes.value, 1)
    }
    func testUnreadableAndMalformedRecordsRemainRetryableWithoutConstructingChannels() async throws {
        for malformed in [true, false] {
            let f = try Fixture(), made = PushSignCount(), polls = PushSignCount()
            f.state.withLock { $0.bytes = malformed ? Data([0xff]) : nil; $0.denied = !malformed }
            let runner = try TransportWakeRunner(optionalConfiguration: { try f.load() }, initialRetryMilliseconds: 100,
                maximumRetryMilliseconds: 100, makeRuntime: { _ in made.increment(); return .init(start: {}, poll: { polls.increment() }, close: {}) },
                report: { _ in })
            try await runner.start(); try await waitUntil { self.waiting(runner) }; XCTAssertEqual(made.value, 0)
            f.state.withLock { $0.bytes = nil; $0.denied = false }
            try await waitUntil { polls.value > 0 }; XCTAssertEqual(made.value, 1); await runner.close()
        }
    }
}
