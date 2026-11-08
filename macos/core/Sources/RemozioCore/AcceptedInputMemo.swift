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

/// Remembers the result a pure function returned for an exact input, because verification decodes and re-encodes
/// the same stored records many times. Only functions whose result depends on nothing but the key belong here: no
/// clock, file, account or process state. An input the function refuses keeps no record and runs it again.
struct PureResultMemo<Key: Hashable & Sendable, Value: Sendable>: Sendable {
    private let results = OSAllocatedUnfairLock(initialState: [Key: Value]())
    private let capacity: Int
    init(capacity: Int = 32) { self.capacity = capacity }

    func value(for key: Key, _ body: () throws -> Value) rethrows -> Value {
        if let known = results.withLock({ $0[key] }) { return known }
        let value = try body()
        results.withLock {
            if $0.count >= capacity { $0.removeAll() }
            $0[key] = value
        }
        return value
    }
}
