/// One bounded token bucket for a pairing window. Owners serialize calls to spend.
struct PairingRegistrationBudget {
    static let ingressBurst: UInt64 = 8
    static let authorityBurst: UInt64 = 16
    static let registrationsPerSecond: UInt64 = 32
    private static let millisecondsPerSecond: UInt64 = 1_000

    static var ingress: Self { Self(burst: ingressBurst) }
    static var authority: Self { Self(burst: authorityBurst) }

    private let capacity: UInt64
    private let refillInterval: UInt64
    private var credit: UInt64
    private var last: AuthorityMoment?
    private var invalidClock = false

    private init(burst: UInt64) {
        capacity = burst * Self.millisecondsPerSecond
        refillInterval = (capacity + Self.registrationsPerSecond - 1) / Self.registrationsPerSecond
        credit = capacity
    }

    mutating func spend(at now: AuthorityMoment) -> Bool {
        guard !invalidClock else { return false }
        if let last {
            guard last.epoch == now.epoch, now.milliseconds >= last.milliseconds else {
                invalidClock = true
                return false
            }
            let elapsed = min(now.milliseconds - last.milliseconds, refillInterval)
            credit = min(capacity, credit + elapsed * Self.registrationsPerSecond)
        }
        last = now
        guard credit >= Self.millisecondsPerSecond else { return false }
        credit -= Self.millisecondsPerSecond
        return true
    }
}
