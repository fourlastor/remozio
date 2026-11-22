import Foundation

/// One asynchronous setup operation. Closing admission does not prove that the current operation has settled.
final class SetupOwnerAsyncWork: @unchecked Sendable {
    private let lock = NSLock()
    private var accepting = true
    private var active: UUID?
    private let ownedFixture: Bool
    init() { ownedFixture = false }
    private init(ownedFixture: Bool) { self.ownedFixture = ownedFixture }
    /// Private fixture admissions cannot be confused with a Setup owner's admission sets.
    static func fixtureOwned() throws -> SetupOwnerAsyncWork {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(ownedFixture: true)
    }
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var availabilityWaiters: [UUID: AsyncStream<Void>.Continuation] = [:]
    /// A notification grants no admission. Cancellation removes the subscriber; the lifecycle retains its 60-second fallback.
    func availability() -> AsyncStream<Void> {
        let signal = AsyncStream<Void>.makeStream(), id = UUID()
        signal.continuation.onTermination = { [weak self] _ in self?.removeAvailability(id) }
        let idle = lock.withLock {
            if active == nil { return true }
            if availabilityWaiters.count < 64 { availabilityWaiters[id] = signal.continuation }
            return false
        }
        if idle { signal.continuation.finish() }
        return signal.stream
    }
    private func removeAvailability(_ id: UUID) { _ = lock.withLock { availabilityWaiters.removeValue(forKey: id) } }

    func admit() throws -> Token {
        try lock.withLock {
            guard accepting, active == nil else { throw AdministrativeSetupError.unavailable }
            let id = UUID(); active = id; return Token(owner: self, id: id)
        }
    }
    /// Ordinary machine operations cannot enter while an asynchronous operation owns the reservation.
    func permits(_ token: Token?) -> Bool {
        lock.withLock {
            guard let active else { return token == nil }
            return token?.belongs(to: self, id: active) == true
        }
    }
    var isIdle: Bool { lock.withLock { active == nil } }
    /// True when no operation is active, or when `token` owns the active one. One read under this set's lock:
    /// separate `isIdle` and `permits` reads can fall on both sides of a release and see neither.
    func isIdleOrPermits(_ token: Token?) -> Bool {
        lock.withLock {
            guard let active else { return true }
            return token?.belongs(to: self, id: active) == true
        }
    }
    func closeAdmission() { lock.withLock { accepting = false } }
    func waitUntilIdle() async {
        await withCheckedContinuation { continuation in
            let idle = lock.withLock { if active == nil { return true }; waiters.append(continuation); return false }
            if idle { continuation.resume() }
        }
    }
    private func finish(_ id: UUID) {
        let (completed, available): ([CheckedContinuation<Void, Never>], [AsyncStream<Void>.Continuation]) = lock.withLock {
            guard active == id else { return ([], []) }; active = nil
            let completed = waiters, available = Array(availabilityWaiters.values)
            waiters = []; availabilityWaiters = [:]; return (completed, available)
        }
        for continuation in completed { continuation.resume() }
        for continuation in available { continuation.finish() }
    }
    final class Token: @unchecked Sendable {
        private let lock = NSLock()
        private var owner: SetupOwnerAsyncWork?
        private let id: UUID
        fileprivate init(owner: SetupOwnerAsyncWork, id: UUID) { self.owner = owner; self.id = id }
        fileprivate func belongs(to expected: SetupOwnerAsyncWork, id: UUID) -> Bool {
            lock.withLock { owner === expected && self.id == id }
        }
        /// Only a live token from an explicitly created Owned fixture set can back a fixture hold.
        func requireOwnedFixture() throws {
            try RuntimeMaintenanceOwnedControl.require()
            let source = lock.withLock { owner }
            guard let source, source.ownedFixture, source.permits(self) else { throw AdministrativeSetupError.unavailable }
        }
        /// Ends the operation before the token forgets its owner. While the set still has this operation active,
        /// `belongs` stays true, so `isIdleOrPermits(self)` never reads `false` during a release. This method never
        /// holds the token's lock while it calls `finish`: `permits` takes the set's lock and then the token's lock.
        func close() {
            guard let previous = lock.withLock({ owner }) else { return }
            previous.finish(id)
            lock.withLock { owner = nil }
        }
        deinit { close() }
    }
}
