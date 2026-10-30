import os

/// Remembers inputs a deterministic check accepted, because scope validation rebuilds the same records often.
/// Only pure checks belong here. A refused input keeps no record and runs the check again.
struct AcceptedInputMemo<Key: Hashable & Sendable>: Sendable {
    private let accepted = OSAllocatedUnfairLock(initialState: Set<Key>())
    private let capacity: Int
    init(capacity: Int = 32) { self.capacity = capacity }

    func check(_ key: Key, _ body: () throws -> Void) rethrows {
        guard !accepted.withLock({ $0.contains(key) }) else { return }
        try body()
        accepted.withLock {
            if $0.count >= capacity { $0.removeAll() }
            $0.insert(key)
        }
    }
}
