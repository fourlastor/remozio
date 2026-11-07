import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityUpdateSchedulingOfferOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class CloseCompletion: Sendable {
        let finished = Mutex(false)
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private(set) var entered = false
        func wait() async { await withCheckedContinuation { continuation = $0; entered = true } }
        func release() { let current = continuation; continuation = nil; current?.resume() }
    }
    private func waitFor(_ condition: () async -> Bool) async throws {
        for _ in 0..<3000 { if await condition() { return }; try await Task.sleep(for: .milliseconds(1)) }
        XCTFail("The offer owner did not reach its expected state"); throw Failed()
    }
    private func snapshot() throws -> UpdateSchedulingSnapshot {
        try .init(updateID: Data(repeating: 55, count: 32), generation: 1, revision: 0)
    }
    func testAbsentFailedAndVerifiedOffersStayDistinctAndRecoverWithoutRestart() async throws {
        let step = Mutex(0), value = try snapshot()
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) {
            switch step.withLock({ $0 }) {
            case 0: return nil
            case 1: throw Failed()
            default: return value
            }
        }
        let initial = await owner.status; XCTAssertEqual(initial, .idle)
        try await owner.start(); try await waitFor { await owner.status == .absent }
        step.withLock { $0 = 1 }; try await waitFor { await owner.status == .unavailable }
        step.withLock { $0 = 2 }; try await waitFor { await owner.status == .offered(value) }
        await owner.close(); let closed = await owner.status; XCTAssertEqual(closed, .closed)
    }
    private final class CloseCount: Sendable { let value = Mutex(0) }
    func testConcurrentCloseJoinsAnAdmittedRefreshBeforeReleasingItsMachineActivity() async throws {
        let f = try ReleaseActivityFixture(), runtime = try f.open(), installer = try f.open(), gate = Gate()
        // A Sendable box keeps the shared count valid for both close tasks on every supported compiler.
        let completed = CloseCount(), value = try snapshot()
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) {
            let activity = try runtime.acquireShared(); defer { activity.close() }
            await gate.wait()
            try activity.validate(); return value
        }
        try await owner.start(); try await waitFor { await gate.entered }
        let first = Task { await owner.close(); completed.value.withLock { $0 += 1 } }
        let second = Task { await owner.close(); completed.value.withLock { $0 += 1 } }
        try await waitFor { await owner.status == .closing }
        XCTAssertEqual(completed.value.withLock { $0 }, 0)
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release(); await first.value; await second.value
        XCTAssertEqual(completed.value.withLock { $0 }, 2)
        let closed = await owner.status; XCTAssertEqual(closed, .closed)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testInvalidIntervalsRepeatedStartAndCloseBeforeStartCannotAdmitMoreWork() async throws {
        for interval in [0, 99, 60_001] {
            XCTAssertThrowsError(try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: interval) { nil })
        }
        let calls = Mutex(0)
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) { calls.withLock { $0 += 1 }; return nil }
        await owner.close()
        do { try await owner.start(); XCTFail() } catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        XCTAssertEqual(calls.withLock { $0 }, 0)
        let running = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) { nil }
        try await running.start()
        do { try await running.start(); XCTFail() } catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        await running.close()
    }
    func testWakeShutdownJoinsOfferWorkBeforeClosingTheAccountJournal() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(install: false), gate = Gate(), value = try snapshot()
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) {
            guard f.starts.withLock({ $0 }) == 1 else { throw Failed() }
            await gate.wait(); _ = try f.state(); return value
        }
        let startup = AuthorityUpdateSchedulingStartup(provider: { _, _, frame, _ in frame }, offers: owner)
        let service = try f.service([AuthorityWakeSettingsTests.Driver()], updateScheduling: startup)
        let initial = await owner.status; XCTAssertEqual(initial, .idle)
        try await service.start(); try await waitFor { await gate.entered }
        let completion = CloseCompletion()
        let close = Task {
            try await service.close()
            completion.finished.withLock { $0 = true }
        }
        try await waitFor { await owner.status == .closing }
        XCTAssertFalse(completion.finished.withLock { $0 }); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        _ = try f.state()
        await gate.release(); try await close.value
        XCTAssertEqual(f.closes.withLock { $0 }, 1)
        let closed = await owner.status; XCTAssertEqual(closed, .closed)
        XCTAssertThrowsError(try f.state())
    }
    func testOptionalOfferFailureKeepsTheForegroundServiceAvailable() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(install: false)
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) { throw Failed() }
        let startup = AuthorityUpdateSchedulingStartup(provider: { _, _, frame, _ in frame }, offers: owner)
        let service = try f.service([AuthorityWakeSettingsTests.Driver()], updateScheduling: startup)
        try await service.start(); try await waitFor { await owner.status == .unavailable }
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        _ = try f.state()
        try await service.close()
    }
    func testClosingTheWakeServiceBeforeStartNeverRunsOfferWork() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(install: false), calls = Mutex(0)
        let owner = try AuthorityUpdateSchedulingOfferOwner(intervalMilliseconds: 100) { calls.withLock { $0 += 1 }; return nil }
        let startup = AuthorityUpdateSchedulingStartup(provider: { _, _, frame, _ in frame }, offers: owner)
        let service = try f.service([AuthorityWakeSettingsTests.Driver()], updateScheduling: startup)
        try await service.close(); XCTAssertEqual(calls.withLock { $0 }, 0)
        let closed = await owner.status; XCTAssertEqual(closed, .closed)
    }
}
