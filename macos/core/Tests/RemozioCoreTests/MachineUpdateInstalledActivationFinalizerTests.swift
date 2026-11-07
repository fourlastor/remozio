import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateInstalledActivationFinalizerTests: XCTestCase, @unchecked Sendable {
    private typealias Owner = MachineUpdateInstalledActivationFinalizer
    private enum Fault: Error { case injected }
    private actor Gate {
        private var entered = false
        private var arrivals: [CheckedContinuation<Void, Never>] = []
        private var blocked: CheckedContinuation<Void, Never>?
        func arrive() async {
            entered = true; arrivals.forEach { $0.resume() }; arrivals.removeAll()
            await withCheckedContinuation { blocked = $0 }
        }
        func wait() async { if !entered { await withCheckedContinuation { arrivals.append($0) } } }
        func release() { blocked?.resume(); blocked = nil }
    }
    private final class Fixture: Sendable {
        struct State {
            var events: [String] = []
            var joinFailures = 0, observeFailures = 0, releases = 0
            var outcome = Owner.Outcome.completed
        }
        let values = Mutex(State())
        let gate: Gate?
        init(gate: Gate? = nil) { self.gate = gate }
        func owner() -> Owner {
            Owner(operations: .init(join: {
                self.values.withLock { $0.events.append("join-entered") }
                if let gate = self.gate { await gate.arrive() }
                try self.values.withLock {
                    if $0.joinFailures > 0 { $0.joinFailures -= 1; throw Fault.injected }
                    $0.events.append("joined")
                }
            }, observe: {
                try self.values.withLock {
                    $0.events.append("observe")
                    if $0.observeFailures > 0 { $0.observeFailures -= 1; throw Fault.injected }
                    return $0.outcome
                }
            }, release: { self.values.withLock { $0.events.append("release"); $0.releases += 1 } }))
        }
    }
    func testReleaseFollowsJoinedCleanupAndFreshCompletionAndIsIdempotent() async throws {
        let f = Fixture(), owner = f.owner()
        let outcome = try await owner.finish(); XCTAssertEqual(outcome, .completed)
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered", "joined", "observe", "release"])
        let repeated = try await owner.finish(); XCTAssertEqual(repeated, .completed)
        XCTAssertEqual(f.values.withLock { $0.releases }, 1)
        XCTAssertEqual(f.values.withLock { $0.events.count }, 4)
    }
    func testFinishingOutcomeRetainsAdmissionAndEveryRetryReadsAgain() async throws {
        let f = Fixture(); f.values.withLock { $0.outcome = .finishing }; let owner = f.owner()
        let first = try await owner.finish(), second = try await owner.finish()
        XCTAssertEqual(first, .finishing); XCTAssertEqual(second, .finishing)
        XCTAssertEqual(f.values.withLock { $0.releases }, 0)
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered", "joined", "observe", "observe"])
    }
    func testJoinFailureCannotReadOrReleaseAndCleanupCanBeRetried() async throws {
        let f = Fixture(); f.values.withLock { $0.joinFailures = 1 }; let owner = f.owner()
        do { _ = try await owner.finish(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered"])
        _ = try await owner.finish(); XCTAssertEqual(f.values.withLock { $0.releases }, 1)
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered", "join-entered", "joined", "observe", "release"])
    }
    func testUnknownOutcomeReadRetainsAdmissionAndRetriesOnlyTheObservation() async throws {
        let f = Fixture(); f.values.withLock { $0.observeFailures = 1 }; let owner = f.owner()
        do { _ = try await owner.finish(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        XCTAssertEqual(f.values.withLock { $0.releases }, 0)
        _ = try await owner.finish()
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered", "joined", "observe", "observe", "release"])
    }
    func testConcurrentFinishCannotReleaseBeforeTheOriginalJoinCompletes() async throws {
        let gate = Gate(), f = Fixture(gate: gate), owner = f.owner()
        let first = Task { try await owner.finish() }; await gate.wait()
        do { _ = try await owner.finish(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .busy) }
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered"])
        await gate.release(); _ = try await first.value
        XCTAssertEqual(f.values.withLock { $0.releases }, 1)
    }
    func testCancellationAfterJoinRetainsAdmissionAndRequiresANewObservation() async throws {
        let gate = Gate(), f = Fixture(gate: gate), owner = f.owner()
        let first = Task { try await owner.finish() }; await gate.wait(); first.cancel(); await gate.release()
        do { _ = try await first.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(f.values.withLock { $0.events }, ["join-entered", "joined"])
        XCTAssertEqual(f.values.withLock { $0.releases }, 0)
        _ = try await owner.finish(); XCTAssertEqual(f.values.withLock { $0.releases }, 1)
    }
    func testAlreadyCancelledCallerCannotJoinObserveOrRelease() async throws {
        let f = Fixture(), owner = f.owner()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await owner.finish()
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertTrue(f.values.withLock { $0.events.isEmpty })
    }
}
