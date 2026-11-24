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
        let deadline: ContinuousClock.Instant
        var phase: Phase = .unproved
    }

    static let proofTimeout: Duration = .seconds(3)
    private static let maximumPending = 4
    private static let maximumDraining = 4
    private var pending: [Pending] = []

    mutating func admit(_ id: UUID, deadline: ContinuousClock.Instant, draining: Int) -> Admission {
        // Expired or cancelled work continues to occupy the total capacity until it returns.
        guard pending.count + draining < Self.maximumPending + Self.maximumDraining else { return .rejected }
        var evicted: UUID?
        if pending.count == Self.maximumPending {
            guard draining < Self.maximumDraining,
                  let index = pending.firstIndex(where: { $0.phase == .unproved }) else { return .rejected }
            evicted = pending.remove(at: index).id
        }
        pending.append(.init(id: id, deadline: deadline))
        return .admitted(evicting: evicted)
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

    mutating func removeAll() { pending.removeAll() }
}
