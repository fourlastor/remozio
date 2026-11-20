import Darwin
import Foundation

/// Remembers exact byte keys whose pure validation already succeeded in this process.
/// It never answers whether a value is current: callers keep every database, lease and scope check.
final class PreparationImmutableValidationCache: @unchecked Sendable {
    private let lock = NSLock()
    private let processID = getpid()
    private let capacity: Int, maximumBytes: Int
    private var keys: Set<Data> = []
    private var retainedBytes = 0
    init(capacity: Int = 64, maximumBytes: Int = 16_777_216) {
        precondition((1...64).contains(capacity) && (1...16_777_216).contains(maximumBytes))
        self.capacity = capacity; self.maximumBytes = maximumBytes
    }
    /// The full key bytes are compared, not a digest. A forked child never sees a parent's entry.
    func contains(_ key: Data) -> Bool {
        guard getpid() == processID, !key.isEmpty else { return false }
        return lock.withLock { keys.contains(key) }
    }
    /// Callers insert only after the pure validation of exactly these bytes returned without error.
    func insert(_ key: Data) {
        guard getpid() == processID, !key.isEmpty, key.count <= maximumBytes else { return }
        lock.withLock {
            guard !keys.contains(key) else { return }
            if keys.count >= capacity || key.count > maximumBytes - retainedBytes {
                keys.removeAll(keepingCapacity: true); retainedBytes = 0
            }
            keys.insert(key); retainedBytes += key.count
        }
    }
    func clear() {
        guard getpid() == processID else { return }
        lock.withLock { keys.removeAll(); retainedBytes = 0 }
    }
    /// An unambiguous encoding: a domain label, then each part with its 8-byte big-endian length.
    static func key(domain: String, _ parts: [Data]) -> Data {
        var bytes = Data(domain.utf8); bytes.append(0)
        for part in parts {
            var length = UInt64(part.count).bigEndian
            withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
            bytes.append(part)
        }
        return bytes
    }
}

/// The decode and validation caches of one store. They live as long as the store and are never global.
/// An archive built outside a store gets `unshared()`, which behaves like the former private caches.
/// Every member locks its own state and is bound to the creating process.
struct PreparationEpochDecodeCaches: @unchecked Sendable {
    let configurations: PreparationImmutableTupleDecodeCache<MachineUpdateConfigurationEpoch.Configuration>
    let configurationValidations: PreparationImmutableValidationCache
    let backends: PreparationImmutableTupleDecodeCache<MachineUpdateBackendEpoch.Capture>
    let backendValidations: PreparationImmutableValidationCache
    /// Returns a fresh, empty set. "Unshared" means no other owner holds it; the caller decides how long to reuse it.
    static func unshared() -> Self {
        .init(configurations: .init(), configurationValidations: .init(), backends: .init(), backendValidations: .init())
    }
}
