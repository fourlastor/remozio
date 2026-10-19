import Foundation
import RemozioHostCore

public typealias AuthorityClockError = RemozioHostCore.SleepInclusiveClockError

/// One authority incarnation's sleep-inclusive clock. Share this value across its request owners.
public struct AuthorityClock: Sendable {
    public let epoch: UUID
    private let clock: SleepInclusiveClock

    public init() throws { try self.init(epoch: UUID()) }

    init(epoch: UUID) throws {
        self.epoch = epoch
        clock = try SleepInclusiveClock()
    }

    public func now() throws -> AuthorityMoment {
        AuthorityMoment(epoch: epoch, milliseconds: try clock.milliseconds())
    }
}
