import Foundation
import os

/// Holds the canonical encoding of one immutable value once it has been computed from that value's fields.
/// Only values whose stored properties are all `let`, and whose fields are themselves immutable, may own one, because the
/// cached bytes must remain a pure function of those fields. A failed computation stores nothing and runs again on the next
/// access, so errors and validation are unchanged. The holder never takes part in equality or coding: every instance
/// compares equal, and owners list their original fields in explicit CodingKeys. An owner that later adopts Hashable must
/// exclude this holder from hashing as well, or write hash(into:) over its original fields.
final class CanonicalBytesCache: Equatable, Sendable {
    private let stored = OSAllocatedUnfairLock<Data?>(initialState: nil)
    init() {}

    /// Returns the retained bytes, or computes, retains and returns them. Concurrent first readers may both compute; the
    /// first result retained wins, and both results are equal because the computation is pure.
    func bytes(_ compute: () throws -> Data) rethrows -> Data {
        if let known = stored.withLock({ $0 }) { return known }
        let computed = try compute()
        return stored.withLock { state in
            if let known = state { return known }
            state = computed
            return computed
        }
    }

    static func == (lhs: CanonicalBytesCache, rhs: CanonicalBytesCache) -> Bool { true }
}
