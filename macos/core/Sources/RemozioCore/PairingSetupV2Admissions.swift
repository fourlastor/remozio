import Foundation

/// Admission state for the listener's incomplete v2 connections. The listener lock guards each transition.
struct PairingSetupV2Admissions {
    enum Admission: Equatable {
        case rejected
        case admitted(evicting: UUID?)
    }

    private enum Phase { case unproved, verifying }

    private struct Pending {
        let id: UUID
        let source: PairingSetupV2Source
        let deadline: ContinuousClock.Instant
        var phase: Phase = .unproved
    }

    static let proofTimeout: Duration = .seconds(3)
    static let maximumPending = 4
    private static let maximumDraining = 4
    private static let maximumSourceAttempts = 2
    private static let maximumSources = 64

    private var pending: [Pending] = []
    private var sources: [PairingSetupV2Source: (until: ContinuousClock.Instant, attempts: Int)] = [:]
    private var budget = PairingRegistrationBudget()

    mutating func admit(_ id: UUID, source: PairingSetupV2Source, accepted: ContinuousClock.Instant,
                        clock: AuthorityMoment, draining: [PairingSetupV2Source]) -> Admission {
        // Keep one pending turn per source. A repeat can replace its own unproved slot only.
        guard draining.lazy.filter({ $0 == source }).count < 2,
              pending.count + draining.count < Self.maximumPending + Self.maximumDraining else { return .rejected }

        var victim: Int?
        if let sameSource = pending.firstIndex(where: { $0.source == source }) {
            guard draining.count < Self.maximumDraining, pending[sameSource].phase == .unproved else { return .rejected }
            victim = sameSource
        } else if pending.count == Self.maximumPending {
            return .rejected
        }
        guard chargeAdmission(source, at: accepted, clock: clock) else { return .rejected }
        let evicted = victim.map { pending.remove(at: $0).id }
        pending.append(.init(id: id, source: source, deadline: accepted.advanced(by: Self.proofTimeout)))
        return .admitted(evicting: evicted)
    }

    private mutating func chargeAdmission(_ source: PairingSetupV2Source, at now: ContinuousClock.Instant,
                                          clock: AuthorityMoment) -> Bool {
        sources = sources.filter { $0.value.until > now }
        let current = sources[source]
        guard current != nil || sources.count < Self.maximumSources,
              (current?.attempts ?? 0) < Self.maximumSourceAttempts,
              budget.spend(at: clock) else { return false }
        sources[source] = (current?.until ?? now.advanced(by: .seconds(1)), (current?.attempts ?? 0) + 1)
        return true
    }

    mutating func beginVerification(_ id: UUID, at now: ContinuousClock.Instant) -> Bool {
        guard let index = pending.firstIndex(where: { $0.id == id && $0.phase == .unproved && now < $0.deadline }) else {
            return false
        }
        pending[index].phase = .verifying
        return true
    }

    func isVerifying(_ id: UUID, at now: ContinuousClock.Instant) -> Bool {
        pending.contains { $0.id == id && $0.phase == .verifying && now < $0.deadline }
    }

    mutating func completeVerification(_ id: UUID, at now: ContinuousClock.Instant) -> Bool {
        guard let index = pending.firstIndex(where: { $0.id == id && $0.phase == .verifying && now < $0.deadline }) else {
            return false
        }
        pending.remove(at: index)
        return true
    }

    mutating func expire(_ id: UUID, at now: ContinuousClock.Instant) -> Bool {
        guard let index = pending.firstIndex(where: { $0.id == id && now >= $0.deadline }) else { return false }
        pending.remove(at: index)
        return true
    }

    @discardableResult
    mutating func remove(_ id: UUID) -> Bool {
        guard let index = pending.firstIndex(where: { $0.id == id }) else { return false }
        pending.remove(at: index)
        return true
    }

    mutating func removeAll() { pending.removeAll(); sources.removeAll() }
}
