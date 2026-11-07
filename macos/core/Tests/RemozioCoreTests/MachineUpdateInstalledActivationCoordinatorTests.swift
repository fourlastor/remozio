import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateInstalledActivationCoordinatorTests: XCTestCase, @unchecked Sendable {
    private typealias Owner = MachineUpdateInstalledActivationCoordinator<UUID>
    private enum Fault: Error { case injected, unknownCommit }
    private actor Gate {
        private var entered = false
        private var waiting: [CheckedContinuation<Void, Never>] = []
        private var blocked: CheckedContinuation<Void, Never>?
        func arrive() async {
            entered = true; waiting.forEach { $0.resume() }; waiting.removeAll()
            await withCheckedContinuation { blocked = $0 }
        }
        func waitForArrival() async { if !entered { await withCheckedContinuation { waiting.append($0) } } }
        func release() { blocked?.resume(); blocked = nil }
    }
    private final class CleanupCounter: Sendable {
        struct Values { var inFlight = 0, maximum = 0, failures: Int }
        let values: Mutex<Values>
        init(failures: Int) { values = Mutex(.init(failures: failures)) }
    }
    /// Issue #588: a caller that waited on a failed cleanup must not drop a newer one, so two cleanups never overlap.
    func testFailedCleanupWaitersNeverStartAnOverlappingCleanup() async throws {
        for _ in 0..<200 {
            let counter = CleanupCounter(failures: 3)
            let owner = Owner(operations: .init(validate: {}, pollRegistrations: { throw Fault.injected }, closeRegistrations: {
                counter.values.withLock { $0.inFlight += 1; $0.maximum = max($0.maximum, $0.inFlight) }
            }, commitReadiness: { throw Fault.injected }, closeReadiness: {
                await Task.yield()
                try counter.values.withLock {
                    $0.inFlight -= 1
                    if $0.failures > 0 { $0.failures -= 1; throw Fault.injected }
                }
            }))
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<6 { group.addTask { while (try? await owner.close()) == nil { await Task.yield() } } }
            }
            XCTAssertEqual(counter.values.withLock { $0.maximum }, 1)
            XCTAssertEqual(counter.values.withLock { $0.failures }, 0)
            XCTAssertTrue(owner.isClosed)
        }
    }
    private final class Fixture: Sendable {
        struct Values {
            var checkpoints: [Owner.RegistrationCheckpoint]
            var events: [String] = []
            var commitCalls = 0, closeCalls = 0, pollCalls = 0
            var closeFailures = 0, registrationCloseFailures = 0
            var unknownCommit = false
        }
        let values: Mutex<Values>
        let receipt = UUID()
        let gate: Gate?
        init(_ checkpoints: [Owner.RegistrationCheckpoint], gate: Gate? = nil) {
            values = Mutex(.init(checkpoints: checkpoints)); self.gate = gate
        }
        func owner() -> Owner {
            let receipt = receipt, gate = gate
            return Owner(operations: .init(validate: { self.values.withLock { $0.events.append("validate") } }, pollRegistrations: {
                try self.values.withLock {
                    $0.pollCalls += 1; $0.events.append("poll")
                    guard !$0.checkpoints.isEmpty else { throw Fault.injected }
                    return $0.checkpoints.removeFirst()
                }
            }, closeRegistrations: {
                try self.values.withLock {
                    $0.events.append("closeRegistrations")
                    if $0.registrationCloseFailures > 0 { $0.registrationCloseFailures -= 1; throw Fault.injected }
                }
            }, commitReadiness: {
                self.values.withLock { $0.commitCalls += 1; $0.events.append("commitEntered") }
                if let gate { await gate.arrive() }
                self.values.withLock { $0.events.append("commitExited") }
                try Task.checkCancellation()
                if self.values.withLock({ $0.unknownCommit }) { throw Fault.unknownCommit }
                return receipt
            }, closeReadiness: {
                try self.values.withLock {
                    $0.closeCalls += 1; $0.events.append("closeReadiness")
                    if $0.closeFailures > 0 { $0.closeFailures -= 1; throw Fault.injected }
                }
            }))
        }
    }
    private let a = Data(repeating: 1, count: 16), b = Data(repeating: 2, count: 16)
    func testPendingRegistrationsNeverOpenReadinessAndConfirmationJoinsCleanup() async throws {
        let f = Fixture([.init(expected: [a, b], progress: .pending([b])), .init(expected: [a, b], progress: .confirmed([a, b]))])
        let owner = f.owner()
        guard case .pending(let pending) = try await owner.advance() else { return XCTFail() }
        XCTAssertEqual(pending, [b]); XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0)
        guard case .committed(let receipt) = try await owner.advance() else { return XCTFail() }
        XCTAssertEqual(receipt, f.receipt); XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1)
        let events = f.values.withLock { $0.events }
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "closeRegistrations")), try XCTUnwrap(events.firstIndex(of: "commitEntered")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "commitExited")), try XCTUnwrap(events.firstIndex(of: "closeReadiness")))
        try await owner.close()
    }
    func testPartialConfirmationCannotStandForTheDeclaredCohort() async throws {
        let f = Fixture([.init(expected: [a, b], progress: .confirmed([a]))]), owner = f.owner()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .changedScope) }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0); try await owner.close()
    }
    func testAChangedCohortCannotBeAdoptedOnALaterPoll() async throws {
        let f = Fixture([.init(expected: [a], progress: .pending([a])), .init(expected: [a, b], progress: .confirmed([a, b]))]), owner = f.owner()
        _ = try await owner.advance()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .changedScope) }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0); try await owner.close()
    }
    func testUnknownCommitOutcomeCannotBeRetriedByAnotherAdvance() async throws {
        let f = Fixture([.init(expected: [a], progress: .confirmed([a]))]); f.values.withLock { $0.unknownCommit = true }
        let owner = f.owner()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .recoveryRequired) }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1); try await owner.close()
    }
    func testKnownCommitRetainsItsReceiptUntilCleanupSucceedsWithoutAnotherCommit() async throws {
        let f = Fixture([.init(expected: [a], progress: .confirmed([a]))]); f.values.withLock { $0.closeFailures = 1 }
        let owner = f.owner()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        guard case .committed(let receipt) = try await owner.advance() else { return XCTFail() }
        XCTAssertEqual(receipt, f.receipt); XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1)
        XCTAssertEqual(f.values.withLock { $0.pollCalls }, 1); XCTAssertEqual(f.values.withLock { $0.closeCalls }, 2)
        try await owner.close()
    }
    func testRegistrationCleanupMustFinishBeforeReadinessCanOpen() async throws {
        let f = Fixture([.init(expected: [a], progress: .confirmed([a]))]); f.values.withLock { $0.registrationCloseFailures = 1 }
        let owner = f.owner()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0)
        guard case .committed = try await owner.advance() else { return XCTFail() }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1); XCTAssertEqual(f.values.withLock { $0.pollCalls }, 1)
        try await owner.close()
    }
    func testConcurrentAdvanceCannotDuplicateTheCommit() async throws {
        let gate = Gate(), f = Fixture([.init(expected: [a], progress: .confirmed([a]))], gate: gate), owner = f.owner()
        let first = Task { try await owner.advance() }; await gate.waitForArrival()
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .busy) }
        await gate.release(); _ = try await first.value
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1); try await owner.close()
    }
    func testCloseCancelsAndJoinsTheBlockedCommitBeforeResourceCleanup() async throws {
        let gate = Gate(), f = Fixture([.init(expected: [a], progress: .confirmed([a]))], gate: gate), owner = f.owner()
        let operation = Task { try await owner.advance() }; await gate.waitForArrival()
        let closing = Task { try await owner.close() }
        while !owner.isClosed { await Task.yield() }
        XCTAssertEqual(f.values.withLock { $0.closeCalls }, 0)
        await gate.release()
        do { _ = try await operation.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError || error as? Owner.Failure == .closed) }
        try await closing.value
        let events = f.values.withLock { $0.events }
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "commitExited")), try XCTUnwrap(events.firstIndex(of: "closeReadiness")))
    }
    func testCallerCancellationReachesTheCommitAndCannotStartAnotherAttempt() async throws {
        let gate = Gate(), f = Fixture([.init(expected: [a], progress: .confirmed([a]))], gate: gate), owner = f.owner()
        let operation = Task { try await owner.advance() }; await gate.waitForArrival()
        operation.cancel(); await gate.release()
        do { _ = try await operation.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .recoveryRequired) }
        XCTAssertEqual(f.values.withLock { $0.commitCalls }, 1)
        try await owner.close()
    }
    func testInvalidPendingScopesCannotOpenReadiness() async throws {
        for checkpoint in [Owner.RegistrationCheckpoint(expected: [a], progress: .pending([b])),
                           .init(expected: [a], progress: .pending([])),
                           .init(expected: [Data([1])], progress: .confirmed([Data([1])]))] {
            let f = Fixture([checkpoint]), owner = f.owner()
            do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .changedScope) }
            XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0); try await owner.close()
        }
    }
    func testCloseFailureRetainsCleanupUntilTheSameOwnerCanRetryIt() async throws {
        let f = Fixture([]); f.values.withLock { $0.registrationCloseFailures = 1 }
        let owner = f.owner()
        do { try await owner.close(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        XCTAssertTrue(owner.isClosed); XCTAssertEqual(f.values.withLock { $0.closeCalls }, 0)
        try await owner.close(); XCTAssertEqual(f.values.withLock { $0.closeCalls }, 1)
        try await owner.close(); XCTAssertEqual(f.values.withLock { $0.closeCalls }, 1)
        XCTAssertEqual(f.values.withLock { $0.pollCalls }, 0); XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0)
    }
    func testClosedOwnerRejectsNewWorkAndRepeatedCloseJoinsTheSameCleanup() async throws {
        let f = Fixture([]), owner = f.owner()
        try await owner.close(); let closed = f.values.withLock { $0.closeCalls }; try await owner.close()
        XCTAssertEqual(f.values.withLock { $0.closeCalls }, closed)
        do { _ = try await owner.advance(); XCTFail() } catch { XCTAssertEqual(error as? Owner.Failure, .closed) }
        XCTAssertEqual(f.values.withLock { $0.pollCalls }, 0); XCTAssertEqual(f.values.withLock { $0.commitCalls }, 0)
    }
}
