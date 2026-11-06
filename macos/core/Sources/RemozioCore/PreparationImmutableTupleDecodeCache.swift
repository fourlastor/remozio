import Darwin
import Foundation

/// Bounded successful decoding of exact public payload tuples. Callers must validate current rows and scope separately.
final class PreparationImmutableTupleDecodeCache<Value> {
    private struct Entry { let inputs: [Data]; let bytes: Int; let value: Value }
    private let lock = NSLock()
    private let processID = getpid()
    private let capacity: Int, maximumBytes: Int
    private var entries: [Data: Entry] = [:]
    private var retainedBytes = 0
    init(capacity: Int = 64, maximumBytes: Int = 16_777_216) {
        precondition((1...64).contains(capacity) && (1...16_777_216).contains(maximumBytes))
        self.capacity = capacity; self.maximumBytes = maximumBytes
    }
    func value(accountID: Data, inputs: [Data], decode: () throws -> Value) throws -> Value {
        guard getpid() == processID else { return try decode() }
        let size = inputs.count == 3 ? inputs.reduce(0) { $0 + min($1.count, 2_097_153) } : 0
        let eligible = accountID.count == 16 && inputs.count == 3 && size > 0 && size <= maximumBytes &&
            inputs.allSatisfy { !$0.isEmpty && $0.count <= 2_097_152 }
        return try lock.withLock {
            if eligible, let entry = entries[accountID], entry.inputs == inputs { return entry.value }
            if let previous = entries.removeValue(forKey: accountID) { retainedBytes -= previous.bytes }
            let value = try decode()
            guard eligible else { return value }
            if entries.count >= capacity || size > maximumBytes - retainedBytes {
                entries.removeAll(keepingCapacity: true); retainedBytes = 0
            }
            entries[accountID] = .init(inputs: inputs, bytes: size, value: value); retainedBytes += size
            return value
        }
    }
    func clear() {
        guard getpid() == processID else { return }
        lock.withLock { entries.removeAll(); retainedBytes = 0 }
    }
}
extension PreparationImmutableTupleDecodeCache: @unchecked Sendable where Value: Sendable {}
