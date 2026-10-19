#if os(Linux)
import Foundation

/// One Linux authority incarnation's clock. Share this value across its request owners.
public struct LinuxAuthorityClock: Sendable {
    public let epoch: UUID
    private let clock: SleepInclusiveClock

    public init() throws { self.init(clock: try SleepInclusiveClock()) }

    init(clock: SleepInclusiveClock) {
        epoch = UUID()
        self.clock = clock
    }

    public func now() throws -> AuthorityMoment {
        AuthorityMoment(epoch: epoch, milliseconds: try clock.milliseconds())
    }
}
#endif
