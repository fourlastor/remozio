/// One bounded token bucket for a pairing window. Owners serialize calls to spend.
struct PairingRegistrationBudget {
    static let burst: UInt64 = 8
    static let registrationsPerSecond: UInt64 = 8
    private static let millisecondsPerSecond: UInt64 = 1_000
    private static let capacity = burst * millisecondsPerSecond
    private static let refillInterval = (capacity + registrationsPerSecond - 1) / registrationsPerSecond

    private var credit = capacity
    private var last: AuthorityMoment?
    private var invalidClock = false

    mutating func spend(at now: AuthorityMoment) -> Bool {
        guard !invalidClock else { return false }
        if let last {
            guard last.epoch == now.epoch, now.milliseconds >= last.milliseconds else {
                invalidClock = true
                return false
            }
            let elapsed = min(now.milliseconds - last.milliseconds, Self.refillInterval)
            credit = min(Self.capacity, credit + elapsed * Self.registrationsPerSecond)
        }
        last = now
        guard credit >= Self.millisecondsPerSecond else { return false }
        credit -= Self.millisecondsPerSecond
        return true
    }
}
