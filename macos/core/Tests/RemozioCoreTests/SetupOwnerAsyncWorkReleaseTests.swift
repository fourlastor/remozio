import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// A restart claim reads whether an executor run still holds a Setup admission while that run releases it.
/// The read must never see a state that is neither idle nor held by the releasing token (issue 825).
final class SetupOwnerAsyncWorkReleaseTests: XCTestCase {
    private final class Round: @unchecked Sendable {
        let ready = Atomic<Int>(0)
        let released = Atomic<Bool>(false)
        let refusals = Atomic<Int>(0)
    }

    /// Each round admits one token. One thread closes it while another thread reads the restart claim's predicate
    /// until the release is complete. No other admission happens during a round, so every `false` is the race.
    /// Returns the number of rounds in which the predicate read `false` at least once.
    private func refusedRoundsWhileReleasing(rounds: Int) throws -> Int {
        let work = SetupOwnerAsyncWork()
        var refused = 0
        for _ in 0..<rounds {
            let token = try work.admit(), round = Round()
            DispatchQueue.concurrentPerform(iterations: 2) { index in
                round.ready.add(1, ordering: .sequentiallyConsistent)
                while round.ready.load(ordering: .sequentiallyConsistent) < 2 {}
                if index == 0 {
                    token.close()
                    round.released.store(true, ordering: .sequentiallyConsistent)
                } else {
                    var finalRead = false
                    while !finalRead {
                        finalRead = round.released.load(ordering: .sequentiallyConsistent)
                        if !work.isIdleOrPermits(token) { round.refusals.add(1, ordering: .sequentiallyConsistent) }
                    }
                }
            }
            XCTAssertTrue(work.isIdle)
            if round.refusals.load(ordering: .sequentiallyConsistent) > 0 { refused += 1 }
        }
        return refused
    }

    func testReleasingTokenIsAlwaysIdleOrPermittedToTheRestartClaim() throws {
        XCTAssertEqual(try refusedRoundsWhileReleasing(rounds: 2_000), 0)
    }

    func testIdleOrPermitsRefusesOtherTokensAndForgetsAClosedOne() throws {
        let work = SetupOwnerAsyncWork(), other = SetupOwnerAsyncWork()
        XCTAssertTrue(work.isIdleOrPermits(nil))
        let token = try work.admit(), foreign = try other.admit()
        XCTAssertTrue(work.isIdleOrPermits(token))
        XCTAssertFalse(work.isIdleOrPermits(nil))
        XCTAssertFalse(work.isIdleOrPermits(foreign))
        token.close(); token.close()
        XCTAssertTrue(work.isIdle)
        XCTAssertFalse(work.permits(token))
        let next = try work.admit()
        XCTAssertFalse(work.isIdleOrPermits(token))
        XCTAssertTrue(work.isIdleOrPermits(next))
        next.close(); foreign.close()
    }

    /// Two threads closing the same token both return, and the set ends idle once.
    func testConcurrentCloseOfOneTokenSettlesOnce() throws {
        let work = SetupOwnerAsyncWork()
        for _ in 0..<500 {
            let token = try work.admit()
            DispatchQueue.concurrentPerform(iterations: 2) { _ in token.close() }
            XCTAssertTrue(work.isIdle)
        }
    }
}
