import Foundation

/// Setup listener connection accounting. Below a total of 3 it behaves exactly like the shared registry: every slot is
/// normal and there is no status lane. From 3 up, one slot is the status lane and the rest are normal. A new connection
/// holds a normal slot provisionally while undecided, and moves to the status slot only when it selects status, so two
/// connections opened together are both accepted and normal capacity never shrinks below the status reservation.
final class SetupConnectionSlots: @unchecked Sendable {
    enum Mode: Equatable, Sendable { case undecided, statusOnly, normal }
    private struct Entry {
        var mode = Mode.undecided
        var connection: (any OwnedAuthorityConnection)?
        var ready = false
        var deadline: Task<Void, Never>?
        var generation = 0
    }
    // Recursive like the shared registry: install activates the connection under this lock.
    private let lock = NSRecursiveLock()
    let maximum: Int, maximumNormal: Int, maximumStatus: Int
    private let timeoutMilliseconds: UInt64
    private var entries: [UUID: Entry] = [:]
    private var running = false
    private var closed = false

    init(maximumConnections: Int, timeoutMilliseconds: UInt64) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(timeoutMilliseconds) else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        maximum = maximumConnections
        maximumStatus = maximumConnections >= 3 ? 1 : 0
        maximumNormal = maximumConnections - maximumStatus
        self.timeoutMilliseconds = timeoutMilliseconds
    }
    deinit { close() }
    func start() throws {
        try lock.withLock { guard !running, !closed else { throw AdministrativeSetupError.unavailable }; running = true }
    }
    private var normalCount: Int { entries.values.reduce(0) { $0 + ($1.mode == .statusOnly ? 0 : 1) } }
    private var statusCount: Int { entries.values.reduce(0) { $0 + ($1.mode == .statusOnly ? 1 : 0) } }
    /// Must be called under the lock. Each arm replaces the previous deadline of the same entry.
    private func arm(_ id: UUID) {
        guard var entry = entries[id] else { return }
        entry.deadline?.cancel(); entry.generation += 1
        let generation = entry.generation
        entry.deadline = Task { [weak self, timeoutMilliseconds] in
            do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
            self?.expire(id, generation: generation)
        }
        entries[id] = entry
    }
    /// A new connection is undecided and holds a normal slot with the unchanged handshake deadline.
    func reserve() -> UUID? {
        lock.withLock {
            guard running, !closed, normalCount < maximumNormal else { return nil }
            let id = UUID()
            entries[id] = Entry()
            arm(id)
            return id
        }
    }
    func install(_ connection: any OwnedAuthorityConnection, id: UUID) -> Bool {
        let accepted = lock.withLock {
            guard !closed, var entry = entries[id], entry.connection == nil else { return false }
            entry.connection = connection; entries[id] = entry
            connection.activate()
            return entries[id] != nil
        }
        if !accepted { connection.close() }
        return accepted
    }
    /// Normal keeps the provisional slot. Status moves it to the status slot, or refuses when that slot is taken or absent.
    func select(_ mode: Mode, id: UUID) -> Bool {
        lock.withLock {
            guard !closed, var entry = entries[id], entry.mode == .undecided else { return false }
            switch mode {
            case .undecided: return false
            case .normal: entry.mode = .normal; entries[id] = entry
            case .statusOnly:
                guard statusCount < maximumStatus else { return false }
                // A status-only connection never completes a handshake. Its deadline becomes an idle limit.
                entry.mode = .statusOnly; entry.ready = false; entries[id] = entry
                arm(id)
            }
            return true
        }
    }
    /// Each status call restarts the idle limit, so one idle reader cannot hold the single status slot.
    func touch(_ id: UUID) {
        lock.withLock { if entries[id]?.mode == .statusOnly { arm(id) } }
    }
    /// A normal connection keeps its handshake deadline until the existing hello succeeds. A successful normal
    /// handshake on a provisional slot also selects normal; a status-only connection never completes one.
    func handshake(_ id: UUID) {
        lock.withLock {
            guard var entry = entries[id], entry.mode != .statusOnly else { return }
            entry.mode = .normal; entry.ready = true; entry.deadline?.cancel(); entry.deadline = nil; entries[id] = entry
        }
    }
    func mode(_ id: UUID) -> Mode? { lock.withLock { entries[id]?.mode } }
    func remove(_ id: UUID) {
        let entry = lock.withLock { entries.removeValue(forKey: id) }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func expire(_ id: UUID) { expire(id, generation: nil) }
    private func expire(_ id: UUID, generation: Int?) {
        let entry = lock.withLock { () -> Entry? in
            guard let entry = entries[id], !entry.ready, generation == nil || entry.generation == generation else { return nil }
            return entries.removeValue(forKey: id)
        }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func close() {
        let removed = lock.withLock { () -> [Entry] in
            closed = true; running = false
            let removed = Array(entries.values); entries.removeAll(); return removed
        }
        for entry in removed { entry.deadline?.cancel(); entry.connection?.close() }
    }
}
