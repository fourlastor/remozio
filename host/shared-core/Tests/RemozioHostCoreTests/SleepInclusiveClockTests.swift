import XCTest
@testable import RemozioHostCore
#if os(Linux)
import Glibc
import Synchronization
#endif

final class SleepInclusiveClockTests: XCTestCase {
    func testIntegerConversionFloorsFractionalMilliseconds() throws {
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(ticks: 999_999, numerator: 1, denominator: 1), 0)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(ticks: 1_000_000, numerator: 1, denominator: 1), 1)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(ticks: 24_000, numerator: 125, denominator: 3), 1)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(ticks: 23_999, numerator: 125, denominator: 3), 0)
    }

    func testWideIntermediateAndInvalidTimebase() throws {
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(ticks: .max, numerator: .max, denominator: .max),
                       UInt64.max / 1_000_000)
        for pair: (UInt32, UInt32) in [(0, 1), (1, 0)] {
            XCTAssertThrowsError(try SleepInclusiveClock.milliseconds(ticks: 1, numerator: pair.0, denominator: pair.1)) {
                XCTAssertEqual($0 as? SleepInclusiveClockError, .invalidTimebase)
            }
        }
        XCTAssertThrowsError(try SleepInclusiveClock.milliseconds(ticks: .max, numerator: .max, denominator: 1)) {
            XCTAssertEqual($0 as? SleepInclusiveClockError, .overflow)
        }
    }

    #if os(Linux)
    func testTimespecConversionFloorsFractionalMilliseconds() throws {
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(seconds: 0, nanoseconds: 0), 0)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(seconds: 0, nanoseconds: 999_999), 0)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(seconds: 0, nanoseconds: 1_000_000), 1)
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(seconds: 1, nanoseconds: 999_999_999), 1999)
    }

    func testTimespecConversionRejectsInvalidSamples() {
        for sample: (Int64, Int64) in [(-1, 0), (0, -1), (0, 1_000_000_000), (.min, 0), (0, .max)] {
            XCTAssertThrowsError(try SleepInclusiveClock.milliseconds(seconds: sample.0, nanoseconds: sample.1)) {
                XCTAssertEqual($0 as? SleepInclusiveClockError, .invalidSample)
            }
        }
    }

    func testTimespecConversionChecksMultiplicationAndAdditionOverflow() throws {
        let lastWholeSecond: Int64 = 18_446_744_073_709_551
        XCTAssertEqual(try SleepInclusiveClock.milliseconds(seconds: lastWholeSecond, nanoseconds: 615_999_999), .max)
        XCTAssertThrowsError(try SleepInclusiveClock.milliseconds(seconds: lastWholeSecond, nanoseconds: 616_000_000)) {
            XCTAssertEqual($0 as? SleepInclusiveClockError, .overflow)
        }
        XCTAssertThrowsError(try SleepInclusiveClock.milliseconds(seconds: lastWholeSecond + 1, nanoseconds: 0)) {
            XCTAssertEqual($0 as? SleepInclusiveClockError, .overflow)
        }
    }

    func testInitializationRequiresBoottimeAndPropagatesReadFailureWithoutFallback() {
        for failure in [EINVAL, EPERM] {
            let calls = Mutex(0)
            XCTAssertThrowsError(try SleepInclusiveClock(readTime: { clockID, sample in
                XCTAssertEqual(clockID, CLOCK_BOOTTIME)
                calls.withLock { $0 += 1 }
                sample.pointee = timespec(tv_sec: 1, tv_nsec: 0)
                errno = failure
                return -1
            })) {
                XCTAssertEqual($0 as? SleepInclusiveClockError, .readFailed(failure))
            }
            XCTAssertEqual(calls.withLock { $0 }, 1)
        }
    }

    func testInitializationRejectsInvalidKernelSample() {
        XCTAssertThrowsError(try SleepInclusiveClock(readTime: { clockID, sample in
            XCTAssertEqual(clockID, CLOCK_BOOTTIME)
            sample.pointee = timespec(tv_sec: 1, tv_nsec: 1_000_000_000)
            return 0
        })) {
            XCTAssertEqual($0 as? SleepInclusiveClockError, .invalidSample)
        }
    }

    func testReadFailureAfterInitializationDoesNotReturnCachedTimeOrFallback() throws {
        let calls = Mutex(0)
        let clock = try SleepInclusiveClock(readTime: { clockID, sample in
            XCTAssertEqual(clockID, CLOCK_BOOTTIME)
            let call = calls.withLock { $0 += 1; return $0 }
            sample.pointee = timespec(tv_sec: call, tv_nsec: 250_000_000)
            if call == 2 {
                errno = EIO
                return -1
            }
            return 0
        })
        XCTAssertEqual(calls.withLock { $0 }, 1)
        XCTAssertThrowsError(try clock.milliseconds()) {
            XCTAssertEqual($0 as? SleepInclusiveClockError, .readFailed(EIO))
        }
        XCTAssertEqual(calls.withLock { $0 }, 2)
        XCTAssertEqual(try clock.milliseconds(), 3250)
        XCTAssertEqual(calls.withLock { $0 }, 3)
    }

    func testLiveSamplerFallsBetweenDirectBoottimeReads() throws {
        func directMilliseconds() throws -> UInt64 {
            var sample = timespec()
            guard clock_gettime(CLOCK_BOOTTIME, &sample) == 0 else {
                throw SleepInclusiveClockError.readFailed(errno)
            }
            return UInt64(sample.tv_sec) * 1000 + UInt64(sample.tv_nsec) / 1_000_000
        }
        let clock = try SleepInclusiveClock()
        for _ in 0..<3 {
            let before = try directMilliseconds(), actual = try clock.milliseconds(), after = try directMilliseconds()
            XCTAssertGreaterThanOrEqual(actual, before)
            XCTAssertLessThanOrEqual(actual, after)
        }
    }

    func testLinuxAuthorityClockPreservesEpochAcrossCopiesAndRenewsItForReplacement() throws {
        let clock = try LinuxAuthorityClock(), copy = clock, replacement = try LinuxAuthorityClock()
        let first = try clock.now(), second = try copy.now(), next = try replacement.now()
        XCTAssertEqual(first.epoch, clock.epoch)
        XCTAssertEqual(second.epoch, first.epoch)
        XCTAssertGreaterThanOrEqual(second.milliseconds, first.milliseconds)
        XCTAssertEqual(next.epoch, replacement.epoch)
        XCTAssertNotEqual(next.epoch, first.epoch)
        XCTAssertGreaterThanOrEqual(next.milliseconds, second.milliseconds)
    }
    #endif
}
