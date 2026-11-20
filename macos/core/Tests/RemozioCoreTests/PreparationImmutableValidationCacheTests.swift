import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class PreparationImmutableValidationCacheTests: XCTestCase {
    private typealias Cache = PreparationImmutableValidationCache
    private let key = Cache.key(domain: "test", [Data([1, 2]), Data([3])])

    func testOnlyTheExactKeyBytesHit() {
        let cache = Cache()
        XCTAssertFalse(cache.contains(key))
        cache.insert(key)
        XCTAssertTrue(cache.contains(key))
        var changed = key
        changed[changed.index(before: changed.endIndex)] ^= 1
        XCTAssertFalse(cache.contains(changed))
        XCTAssertFalse(cache.contains(Cache.key(domain: "other", [Data([1, 2]), Data([3])])))
        cache.clear()
        XCTAssertFalse(cache.contains(key))
    }

    func testTheKeyEncodingSeparatesPartsAndDomains() {
        XCTAssertNotEqual(Cache.key(domain: "d", [Data([1, 2]), Data([3])]), Cache.key(domain: "d", [Data([1]), Data([2, 3])]))
        XCTAssertNotEqual(Cache.key(domain: "d", [Data([1])]), Cache.key(domain: "d", [Data([1]), Data()]))
        XCTAssertNotEqual(Cache.key(domain: "a", []), Cache.key(domain: "b", []))
    }

    func testTheCacheStaysBoundedAndRefusesOversizedKeys() {
        let cache = Cache(capacity: 2, maximumBytes: 64)
        let keys = (0..<3).map { Cache.key(domain: "k", [Data([UInt8($0)])]) }
        cache.insert(keys[0]); cache.insert(keys[1])
        XCTAssertTrue(cache.contains(keys[0]) && cache.contains(keys[1]))
        cache.insert(keys[2])
        XCTAssertFalse(cache.contains(keys[0]) || cache.contains(keys[1]))
        XCTAssertTrue(cache.contains(keys[2]))
        let large = Data(repeating: 7, count: 65)
        cache.insert(large)
        XCTAssertFalse(cache.contains(large))
        XCTAssertFalse(cache.contains(Data()))
    }

    func testTwoThreadsInsertAndReadWithoutLosingEntries() {
        let cache = Cache(), missing = Mutex(0)
        DispatchQueue.concurrentPerform(iterations: 2) { thread in
            for index in 0..<32 {
                let value = Cache.key(domain: "thread", [Data([UInt8(thread), UInt8(index)])])
                cache.insert(value)
                if !cache.contains(value) { missing.withLock { $0 += 1 } }
            }
        }
        XCTAssertEqual(missing.withLock { $0 }, 0)
        for thread in 0..<2 {
            for index in 0..<32 {
                XCTAssertTrue(cache.contains(Cache.key(domain: "thread", [Data([UInt8(thread), UInt8(index)])])))
            }
        }
    }

    func testTwoStoresNeverShareEntries() {
        let first = PreparationEpochDecodeCaches.unshared(), second = PreparationEpochDecodeCaches.unshared()
        first.configurationValidations.insert(key); first.backendValidations.insert(key)
        XCTAssertFalse(second.configurationValidations.contains(key))
        XCTAssertFalse(second.backendValidations.contains(key))
        XCTAssertFalse(first.configurations === second.configurations)
        XCTAssertFalse(first.backends === second.backends)
    }

    func testAForkedChildNeverUsesTheParentEntries() throws {
        let cache = Cache()
        cache.insert(key)
        XCTAssertTrue(cache.contains(key))
        let child = Self.forkProcess()
        guard child >= 0 else { throw JournalLeaseError.system(errno) }
        if child == 0 {
            // The child refuses before it takes the inherited lock, and it cannot add entries either.
            let inherited = cache.contains(key)
            cache.insert(key)
            _exit(!inherited && !cache.contains(key) ? 0 : 1)
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
        XCTFail("The child did not finish its cache check")
    }

    // Swift marks fork() unavailable on this SDK. The child only runs one cache check and exits.
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is not available") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
}
