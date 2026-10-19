import Foundation
import RemozioProtocol

public enum ContinuityStoreError: Error, Equatable {
    case invalidCheckpoint, incompatibleStore, wrongScope, staleState, recoveryRequired, closed, unavailable
    case historyRecoveryPending
    case storage(Int32)
}

/// A retained boundary, never permission to dispatch. Digests must come from the authority's canonical state encoder.
/// Construction, decoding and successor calculation validate data only; they do not establish provenance
/// or prove that a protected store committed this boundary.
public struct ContinuityCheckpoint: Equatable, Sendable {
    public let generation: UInt64
    /// Nil identifies a legacy checkpoint without a dedicated authority generation.
    public let authorityGeneration: UInt64?
    public let authorityDigest: Data
    public let ledgerDigest: Data
    public let journalEpoch: Data
    public let journalHead: UInt64

    public init(generation: UInt64, authorityDigest: Data, ledgerDigest: Data, journalEpoch: Data, journalHead: UInt64, authorityGeneration: UInt64? = nil) throws {
        guard generation > 0, authorityGeneration != 0, authorityDigest.count == 32, ledgerDigest.count == 32, journalEpoch.count == 16 else {
            throw ContinuityStoreError.invalidCheckpoint
        }
        self.generation = generation; self.authorityGeneration = authorityGeneration
        self.authorityDigest = authorityDigest; self.ledgerDigest = ledgerDigest
        self.journalEpoch = journalEpoch; self.journalHead = journalHead
    }

    /// A legacy baseline comes from the protected checkpoint, never from replaceable audit history.
    public var currentAuthorityGeneration: UInt64 { authorityGeneration ?? generation }

    func successorAuthorityGeneration(authorityDigest: Data) throws -> UInt64 {
        let current = currentAuthorityGeneration
        guard self.authorityDigest != authorityDigest else { return current }
        guard current < UInt64.max else { throw ContinuityStoreError.invalidCheckpoint }
        return current + 1
    }

    /// Calculates a candidate value only. The host must independently commit and reconcile its stores.
    public func successor(authorityDigest: Data, ledgerDigest: Data, journalEpoch: Data, journalHead: UInt64) throws -> Self {
        guard generation < UInt64.max else { throw ContinuityStoreError.invalidCheckpoint }
        return try Self(generation: generation + 1, authorityDigest: authorityDigest, ledgerDigest: ledgerDigest,
            journalEpoch: journalEpoch, journalHead: journalHead,
            authorityGeneration: successorAuthorityGeneration(authorityDigest: authorityDigest))
    }

    public var bytes: Data {
        get throws {
            var fields: [UInt64: CBORValue] = [0: .unsigned(authorityGeneration == nil ? 1 : 2), 1: .unsigned(generation),
                2: .bytes(authorityDigest), 3: .bytes(ledgerDigest), 4: .bytes(journalEpoch), 5: .unsigned(journalHead)]
            if let authorityGeneration { fields[6] = .unsigned(authorityGeneration) }
            return try DeterministicCBOR.encode(.map(fields), limits: Self.limits())
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              case .unsigned(let version) = fields[0], version == 1 || version == 2,
              Set(fields.keys) == Set((0...(version == 1 ? 5 : 6)).map(UInt64.init)),
              case .unsigned(let generation) = fields[1], case .bytes(let authority) = fields[2],
              case .bytes(let ledger) = fields[3], case .bytes(let epoch) = fields[4],
              case .unsigned(let head) = fields[5] else { throw ContinuityStoreError.invalidCheckpoint }
        let authorityGeneration: UInt64?
        if version == 2 {
            guard case .unsigned(let value) = fields[6] else { throw ContinuityStoreError.invalidCheckpoint }
            authorityGeneration = value
        } else { authorityGeneration = nil }
        let value = try Self(generation: generation, authorityDigest: authority, ledgerDigest: ledger,
                             journalEpoch: epoch, journalHead: head, authorityGeneration: authorityGeneration)
        guard try value.bytes == bytes else { throw ContinuityStoreError.invalidCheckpoint }
        return value
    }
    private static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 16) }
}

/// Pending contains both possible journal boundaries. Startup must reconcile them without dispatching or replaying an action.
/// This value checks generation relationships, not the origin or durability of the supplied boundaries.
public struct ContinuityState: Equatable, Sendable {
    public let committed: ContinuityCheckpoint
    public let pending: ContinuityCheckpoint?
    public let recoveryRequired: Bool
    public init(committed: ContinuityCheckpoint, pending: ContinuityCheckpoint?, recoveryRequired: Bool) throws {
        if let pending {
            guard committed.generation < UInt64.max, pending.generation == committed.generation + 1 else {
                throw ContinuityStoreError.invalidCheckpoint
            }
            if let authorityGeneration = pending.authorityGeneration {
                guard authorityGeneration == (try committed.successorAuthorityGeneration(authorityDigest: pending.authorityDigest)) else {
                    throw ContinuityStoreError.invalidCheckpoint
                }
            } else if committed.authorityGeneration != nil {
                throw ContinuityStoreError.invalidCheckpoint
            }
        }
        self.committed = committed; self.pending = pending; self.recoveryRequired = recoveryRequired
    }
}
