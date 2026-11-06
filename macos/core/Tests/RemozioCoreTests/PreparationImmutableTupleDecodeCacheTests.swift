import Darwin
import Dispatch
import Foundation
import XCTest
@testable import RemozioCore

final class PreparationImmutableTupleDecodeCacheTests: XCTestCase {
    private enum Failed: Error { case decode }
    private let account = Data(repeating: 1, count: 16)
    private let inputs = [Data([1]), Data([2]), Data([3])]
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock(); private var calls = 0
        func next() -> Int { lock.withLock { calls += 1; return calls } }
        var value: Int { lock.withLock { calls } }
    }
    func testAnExactTupleReusesOnlyItsSuccessfulDecodedValue() throws {
        let cache = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter()
        for _ in 0..<3 { XCTAssertEqual(try cache.value(accountID: account, inputs: inputs, decode: calls.next), 1) }
        XCTAssertEqual(calls.value, 1)
    }
    func testChangingAnyTupleMemberRequiresAnotherDecode() throws {
        for index in 0..<3 {
            let cache = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter()
            _ = try cache.value(accountID: account, inputs: inputs, decode: calls.next)
            var changed = inputs; changed[index].append(0)
            XCTAssertEqual(try cache.value(accountID: account, inputs: changed, decode: calls.next), 2)
            XCTAssertEqual(try cache.value(accountID: account, inputs: inputs, decode: calls.next), 3)
        }
    }
    func testAccountsAndCacheInstancesRemainSeparate() throws {
        let first = PreparationImmutableTupleDecodeCache<Int>(), second = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter()
        XCTAssertEqual(try first.value(accountID: account, inputs: inputs, decode: calls.next), 1)
        XCTAssertEqual(try first.value(accountID: Data(repeating: 2, count: 16), inputs: inputs, decode: calls.next), 2)
        XCTAssertEqual(try second.value(accountID: account, inputs: inputs, decode: calls.next), 3)
        XCTAssertEqual(try first.value(accountID: account, inputs: inputs, decode: calls.next), 1)
    }
    func testAFailedChangedTupleRetiresThePreviousEntryAndRetries() throws {
        let cache = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter()
        _ = try cache.value(accountID: account, inputs: inputs, decode: calls.next)
        var changed = inputs; changed[1].append(0)
        for _ in 0..<2 {
            XCTAssertThrowsError(try cache.value(accountID: account, inputs: changed) { _ = calls.next(); throw Failed.decode })
        }
        XCTAssertEqual(try cache.value(accountID: account, inputs: inputs, decode: calls.next), 4)
    }
    func testCapacityAndByteBudgetEvictionRequireFreshDecoding() throws {
        for cache in [PreparationImmutableTupleDecodeCache<Int>(capacity: 1),
            PreparationImmutableTupleDecodeCache<Int>(maximumBytes: 5)] {
            let calls = Counter()
            _ = try cache.value(accountID: account, inputs: inputs, decode: calls.next)
            _ = try cache.value(accountID: Data(repeating: 2, count: 16), inputs: inputs, decode: calls.next)
            XCTAssertEqual(try cache.value(accountID: account, inputs: inputs, decode: calls.next), 3)
        }
    }
    func testInvalidAndOverBudgetInputsAreNeverRetained() throws {
        let cache = PreparationImmutableTupleDecodeCache<Int>(maximumBytes: 4), calls = Counter()
        let cases: [(Data, [Data])] = [(Data(count: 15), inputs), (account, []), (account, Array(inputs.prefix(2))),
            (account, [Data(), inputs[1], inputs[2]]), (account, [Data(count: 5), inputs[1], inputs[2]])]
        for (id, tuple) in cases {
            let before = calls.value
            _ = try cache.value(accountID: id, inputs: tuple, decode: calls.next)
            _ = try cache.value(accountID: id, inputs: tuple, decode: calls.next)
            XCTAssertEqual(calls.value, before + 2)
        }
        let large = [Data(count: 2_097_153), inputs[1], inputs[2]]
        let bounded = PreparationImmutableTupleDecodeCache<Int>(), fresh = Counter()
        _ = try bounded.value(accountID: account, inputs: large, decode: fresh.next)
        _ = try bounded.value(accountID: account, inputs: large, decode: fresh.next)
        XCTAssertEqual(fresh.value, 2)
    }
    func testClearRequiresAnotherDecodeForPreviouslyAcceptedBytes() throws {
        let cache = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter()
        _ = try cache.value(accountID: account, inputs: inputs, decode: calls.next); cache.clear()
        XCTAssertEqual(try cache.value(accountID: account, inputs: inputs, decode: calls.next), 2)
    }
    func testConcurrentExactTuplesDecodeOnce() {
        let cache = PreparationImmutableTupleDecodeCache<Int>(), calls = Counter(), account = account, inputs = inputs
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            _ = try? cache.value(accountID: account, inputs: inputs, decode: calls.next)
        }
        XCTAssertEqual(calls.value, 1)
    }
    func testForkedReadsBypassTheInheritedCacheAndLock() throws {
        let cache = PreparationImmutableTupleDecodeCache<Int>()
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0), account = account, inputs = inputs
        DispatchQueue.global().async {
            _ = try? cache.value(accountID: account, inputs: inputs) {
                entered.signal()
                _ = resume.wait(timeout: .now() + 5)
                return 1
            }
            finished.signal()
        }
        defer {
            resume.signal()
            XCTAssertEqual(finished.wait(timeout: .now() + 5), .success)
        }
        guard entered.wait(timeout: .now() + 2) == .success else {
            XCTFail("The parent decoder did not acquire the cache lock")
            return
        }
        let child = Self.forkProcess()
        guard child >= 0 else { throw JournalLeaseError.system(errno) }
        if child == 0 {
            cache.clear()
            do {
                let value = try cache.value(accountID: account, inputs: inputs) { 101 }
                _exit(value == 101 ? 0 : 1)
            } catch { _exit(2) }
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        var status: Int32 = 0
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let result = waitpid(child, &status, WNOHANG)
            if result == child { XCTAssertEqual(status, 0); return }
            if result < 0, errno != EINTR { throw JournalLeaseError.system(errno) }
            usleep(10_000)
        }
        _ = kill(child, SIGKILL)
        while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        XCTFail("The child used the inherited cache lock")
    }

    // Swift marks fork() unavailable on this SDK. The child only runs one cache read and exits.
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is not available") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
}
