#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

public enum SleepInclusiveClockError: Error, Equatable {
    case invalidTimebase, invalidSample, readFailed(Int32), overflow
}

/// Platform elapsed time that includes suspend. This sampler does not own an authority epoch.
public struct SleepInclusiveClock: Sendable {
    #if os(Linux)
    private let readTime: @Sendable (clockid_t, UnsafeMutablePointer<timespec>) -> Int32

    public init() throws {
        try self.init(readTime: { clock_gettime($0, $1) })
    }

    init(readTime: @escaping @Sendable (clockid_t, UnsafeMutablePointer<timespec>) -> Int32) throws {
        self.readTime = readTime
        _ = try milliseconds()
    }

    public func milliseconds() throws -> UInt64 {
        var sample = timespec()
        guard readTime(CLOCK_BOOTTIME, &sample) == 0 else {
            let code = errno
            throw SleepInclusiveClockError.readFailed(code)
        }
        return try Self.milliseconds(seconds: Int64(sample.tv_sec), nanoseconds: Int64(sample.tv_nsec))
    }
    #elseif os(macOS)
    private let numerator: UInt32
    private let denominator: UInt32

    public init() throws {
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS,
              timebase.numer != 0, timebase.denom != 0 else { throw SleepInclusiveClockError.invalidTimebase }
        numerator = timebase.numer
        denominator = timebase.denom
    }

    public func milliseconds() throws -> UInt64 {
        try Self.milliseconds(ticks: mach_continuous_time(), numerator: numerator, denominator: denominator)
    }
    #else
    #error("SleepInclusiveClock requires Linux or macOS")
    #endif

    static func milliseconds(ticks: UInt64, numerator: UInt32, denominator: UInt32) throws -> UInt64 {
        guard numerator != 0, denominator != 0 else { throw SleepInclusiveClockError.invalidTimebase }
        let product = ticks.multipliedFullWidth(by: UInt64(numerator))
        let divisor = UInt64(denominator) * 1_000_000
        guard product.high < divisor else { throw SleepInclusiveClockError.overflow }
        return divisor.dividingFullWidth(product).quotient
    }

    static func milliseconds(seconds: Int64, nanoseconds: Int64) throws -> UInt64 {
        guard seconds >= 0, (0..<1_000_000_000).contains(nanoseconds) else {
            throw SleepInclusiveClockError.invalidSample
        }
        let whole = UInt64(seconds).multipliedReportingOverflow(by: 1000)
        guard !whole.overflow else { throw SleepInclusiveClockError.overflow }
        let total = whole.partialValue.addingReportingOverflow(UInt64(nanoseconds) / 1_000_000)
        guard !total.overflow else { throw SleepInclusiveClockError.overflow }
        return total.partialValue
    }
}
