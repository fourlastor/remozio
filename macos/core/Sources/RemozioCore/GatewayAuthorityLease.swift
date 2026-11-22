import Foundation

/// A connection lease uses the Mac's shared continuous clock. It never creates a new request deadline.
final class GatewayAuthorityLease: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let sample: @Sendable () throws -> AuthorityMoment
    private let maximumLifetime: UInt64
    private let gatewayEpoch: UUID
    private var rootEpoch: UUID?
    private var sequence: UInt64 = 0
    private var deadline: UInt64 = 0
    private var lastTime: UInt64 = 0
    private var closed = false

    convenience init(clock: AuthorityClock, maximumLifetime: UInt64) throws {
        try self.init(epoch: clock.epoch, maximumLifetime: maximumLifetime, sample: { try clock.now() })
    }
    init(epoch: UUID, maximumLifetime: UInt64, sample: @escaping @Sendable () throws -> AuthorityMoment) throws {
        guard (1...60_000).contains(maximumLifetime) else { throw GatewayServiceError.invalidConfiguration }
        gatewayEpoch = epoch; self.maximumLifetime = maximumLifetime; self.sample = sample
    }

    /// Execute on the coordinator actor after replacing trust and routing, without an intervening await.
    func renew(rootEpoch: UUID, sequence: UInt64, observedAt: UInt64, deadline: UInt64, update: () throws -> Void = {}) throws {
        try lock.withLock {
            let now = try current()
            guard self.rootEpoch == nil || self.rootEpoch == rootEpoch, sequence > self.sequence,
                  observedAt <= now, deadline > now, deadline > observedAt,
                  deadline - observedAt <= maximumLifetime else { throw GatewayServiceError.invalidMessage }
            self.deadline = 0
            try update()
            self.rootEpoch = rootEpoch; self.sequence = sequence; self.deadline = deadline
        }
    }
    func validate() throws { try withCurrentLease {} }

    /// Serialize a synchronous recovery commit with retirement of its Root connection.
    func withCurrentLease<Value>(_ body: () throws -> Value) throws -> Value {
        try lock.withLock {
            guard try current() < deadline, rootEpoch != nil else { throw GatewayServiceError.unavailable }
            return try body()
        }
    }
    func retire() { lock.withLock { closed = true; deadline = 0 } }

    /// Keep the original continuous-clock times. Only translate the authenticated Root incarnation into this process's epoch.
    func normalize(_ delivery: PhoneRequestDelivery) throws -> PhoneRequestDelivery {
        try lock.withLock {
            let now = try current()
            guard now < deadline, delivery.admittedAt.epoch == rootEpoch,
                  delivery.admittedAt.milliseconds <= now, now < delivery.deadlineMilliseconds else {
                throw GatewayServiceError.unavailable
            }
            return PhoneRequestDelivery(id: delivery.id, recipient: delivery.recipient, requestID: delivery.requestID,
                admittedAt: AuthorityMoment(epoch: gatewayEpoch, milliseconds: delivery.admittedAt.milliseconds),
                deadlineMilliseconds: delivery.deadlineMilliseconds)
        }
    }
    private func current() throws -> UInt64 {
        guard !closed else { throw GatewayServiceError.unavailable }
        let now: AuthorityMoment
        do { now = try sample() } catch { closed = true; throw error }
        guard now.epoch == gatewayEpoch, now.milliseconds >= lastTime else {
            closed = true; throw GatewayServiceError.unavailable
        }
        lastTime = now.milliseconds
        return now.milliseconds
    }
}
