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

/// Remembers the value that a pure decode or validation computed from exactly one key in this process.
/// The key must encode every input of that computation. A failed computation stores nothing and runs again next time.
final class PreparationImmutableValueCache<Value> {
    private let lock = NSLock()
    private let processID = getpid()
    private let capacity: Int, maximumBytes: Int
    private var entries: [Data: Value] = [:]
    private var retainedBytes = 0
    init(capacity: Int = 64, maximumBytes: Int = 16_777_216) {
        precondition((1...64).contains(capacity) && (1...16_777_216).contains(maximumBytes))
        self.capacity = capacity; self.maximumBytes = maximumBytes
    }
    /// The full key bytes are compared, not a digest. A forked child never reads or adds an entry.
    /// The computation runs outside the lock; when two threads miss together, the first retained value wins,
    /// and both values are equal because the computation is pure.
    func value(key: Data, compute: () throws -> Value) rethrows -> Value {
        let eligible = getpid() == processID && !key.isEmpty && key.count <= maximumBytes
        if eligible, let known = lock.withLock({ entries[key] }) { return known }
        let computed = try compute()
        guard eligible else { return computed }
        return lock.withLock {
            if let known = entries[key] { return known }
            if entries.count >= capacity || key.count > maximumBytes - retainedBytes {
                entries.removeAll(keepingCapacity: true); retainedBytes = 0
            }
            entries[key] = computed; retainedBytes += key.count
            return computed
        }
    }
    func contains(_ key: Data) -> Bool {
        guard getpid() == processID, !key.isEmpty else { return false }
        return lock.withLock { entries[key] != nil }
    }
    func clear() {
        guard getpid() == processID else { return }
        lock.withLock { entries.removeAll(); retainedBytes = 0 }
    }
}
// Only immutable values are retained: every cached type has `let` stored properties only, and its shared
// CanonicalBytesCache is lock-protected. Every access to `entries` holds the lock.
extension PreparationImmutableValueCache: @unchecked Sendable {}

/// The decode and validation caches of one store. They live as long as the store and are never global.
/// An archive built outside a store gets `unshared()`, which behaves like the former private caches.
/// Every member locks its own state and is bound to the creating process.
struct PreparationEpochDecodeCaches: @unchecked Sendable {
    let configurations: PreparationImmutableTupleDecodeCache<MachineUpdateConfigurationEpoch.Configuration>
    let configurationValidations: PreparationImmutableValidationCache
    let backends: PreparationImmutableTupleDecodeCache<MachineUpdateBackendEpoch.Capture>
    let backendValidations: PreparationImmutableValidationCache
    /// Successful `MachineUpdateInstalledReleaseEpoch.Archive.validate(candidate:)` runs, keyed by the record's canonical
    /// bytes, every artifact's kind, account and bytes, and the candidate's exact bytes.
    let installedValidations: PreparationImmutableValidationCache
    /// Successful `MachineUpdateInstalledReleaseEpoch.Archive.completionIntent()` results, keyed by the exact header and policy rows.
    let installedCompletionIntents: PreparationImmutableValueCache<MachineUpdateCompletionIntentArchive>
    /// Successful `RuntimeRetainedSetupCompletionPublication.decode(_:)` results, keyed by the exact encoded bytes.
    let completionPublications: PreparationImmutableValueCache<RuntimeRetainedSetupCompletionPublication>
    /// Returns a fresh, empty set. "Unshared" means no other owner holds it; the caller decides how long to reuse it.
    static func unshared() -> Self {
        .init(configurations: .init(), configurationValidations: .init(), backends: .init(), backendValidations: .init(),
            installedValidations: .init(), installedCompletionIntents: .init(), completionPublications: .init())
    }
    /// An unambiguous encoding of every candidate field that a check can read. The manifest's canonical bytes are
    /// injective over its fields: its initializer rejects any field that the encoding of its schema version omits.
    /// Dictionary entries are sorted, so the key does not depend on iteration order.
    static func candidateKey(_ candidate: SignedReleaseEvidence) throws -> Data {
        let hashes = candidate.codeDirectoryHashes.sorted { $0.key.rawValue < $1.key.rawValue }.flatMap { entry -> [Data] in
            var role = entry.key.rawValue.bigEndian
            return [withUnsafeBytes(of: &role) { Data($0) }, entry.value]
        }
        let dependencies = candidate.dependencyCodeDirectoryHashes.sorted { $0.key < $1.key }.flatMap { [Data($0.key.utf8), $0.value] }
        return PreparationImmutableValidationCache.key(domain: "remozio.signed-release-evidence.v1", [
            try candidate.manifest.canonicalBytes,
            PreparationImmutableValidationCache.key(domain: "code-directory-hashes", hashes),
            PreparationImmutableValidationCache.key(domain: "dependency-code-directory-hashes", dependencies)])
    }
}

/// Carries a store's caches inside a value type without taking part in its equality.
final class PreparationEpochDecodeCachesHolder: Equatable, Sendable {
    let caches: PreparationEpochDecodeCaches
    init(_ caches: PreparationEpochDecodeCaches) { self.caches = caches }
    static func == (lhs: PreparationEpochDecodeCachesHolder, rhs: PreparationEpochDecodeCachesHolder) -> Bool { true }
}
