import Foundation

/// Setup listener connection accounting. Each mode has its own bound inside the fixed total, so normal
/// connections cannot consume the status lane and one slow status reader cannot consume normal capacity.
final class SetupConnectionSlots: @unchecked Sendable {
    enum Mode: Equatable, Sendable { case undecided, statusOnly, normal }
    private struct Entry {
        var mode = Mode.undecided
        var connection: (any OwnedAuthorityConnection)?
        var ready = false
        var deadline: Task<Void, Never>?
    }
    private let lock = NSLock()
    let maximum: Int, maximumNormal: Int, maximumStatus: Int, maximumUndecided: Int
    private let timeoutMilliseconds: UInt64
    private var entries: [UUID: Entry] = [:]
    private var running = false
    private var closed = false

    /// The existing total is split as normal + one status-only + one undecided (6 + 1 + 1 for the default 8).
    /// A stored total below 3 keeps one undecided and at least one normal slot; it has no status lane.
    init(maximumConnections: Int, timeoutMilliseconds: UInt64) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(timeoutMilliseconds) else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        maximum = maximumConnections; maximumUndecided = 1
        maximumStatus = maximumConnections >= 3 ? 1 : 0
        maximumNormal = max(1, maximumConnections - 2)
        self.timeoutMilliseconds = timeoutMilliseconds
    }
    deinit { close() }
    func start() throws {
        try lock.withLock { guard !running, !closed else { throw AdministrativeSetupError.unavailable }; running = true }
    }
    private func count(_ mode: Mode) -> Int { entries.values.reduce(0) { $0 + ($1.mode == mode ? 1 : 0) } }
    /// A new connection starts undecided. Its handshake deadline is unchanged from the shared registry.
    func reserve() -> UUID? {
        lock.withLock {
            guard running, !closed, entries.count < maximum, count(.undecided) < maximumUndecided else { return nil }
            let id = UUID()
            let deadline = Task { [weak self, timeoutMilliseconds] in
                do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
                self?.expire(id)
            }
            entries[id] = Entry(deadline: deadline)
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
    /// Moves an undecided slot atomically. A full target mode refuses and leaves the caller to close the connection.
    func select(_ mode: Mode, id: UUID) -> Bool {
        guard mode != .undecided else { return false }
        return lock.withLock {
            guard !closed, var entry = entries[id], entry.mode == .undecided else { return false }
            guard count(mode) < (mode == .normal ? maximumNormal : maximumStatus) else { return false }
            entry.mode = mode
            if mode == .statusOnly { entry.ready = true; entry.deadline?.cancel(); entry.deadline = nil }
            entries[id] = entry
            return true
        }
    }
    /// A normal connection keeps its handshake deadline until the existing hello succeeds.
    func handshake(_ id: UUID) {
        lock.withLock {
            guard var entry = entries[id], entry.mode == .normal else { return }
            entry.ready = true; entry.deadline?.cancel(); entry.deadline = nil; entries[id] = entry
        }
    }
    func mode(_ id: UUID) -> Mode? { lock.withLock { entries[id]?.mode } }
    func remove(_ id: UUID) {
        let entry = lock.withLock { entries.removeValue(forKey: id) }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func expire(_ id: UUID) {
        let entry = lock.withLock { () -> Entry? in
            guard let entry = entries[id], !entry.ready else { return nil }
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
