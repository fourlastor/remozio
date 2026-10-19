import Foundation
import RemozioProtocol

/// Preserves both interrupted commit boundaries while history recovery prepares a fresh epoch.
/// This record does not validate external authority, grant admission, or permit action replay.
/// Construction and decoding validate the supplied data, not its provenance or protected storage.
public struct HistoryRecoveryIntent: Equatable, Sendable {
    public let previous: ContinuityState
    public let authorityDigest: Data
    public let ledgerDigest: Data
    public let recoveryEpoch: Data

    public init(previous: ContinuityState, authorityDigest: Data, ledgerDigest: Data, recoveryEpoch: Data) throws {
        guard !previous.recoveryRequired,
              authorityDigest.count == 32, ledgerDigest.count == 32, recoveryEpoch.count == 16,
              previous.committed.authorityDigest == authorityDigest || previous.pending?.authorityDigest == authorityDigest,
              max(previous.committed.generation, previous.pending?.generation ?? 0) < UInt64.max,
              recoveryEpoch != previous.committed.journalEpoch,
              recoveryEpoch != previous.pending?.journalEpoch else { throw ContinuityStoreError.invalidCheckpoint }
        self.previous = previous
        self.authorityDigest = authorityDigest
        self.ledgerDigest = ledgerDigest
        self.recoveryEpoch = recoveryEpoch
    }

    /// Prefer the proposed authority when both retained boundaries describe the same authority bytes.
    public var authorityGeneration: UInt64 {
        if let pending = previous.pending, pending.authorityDigest == authorityDigest {
            return pending.currentAuthorityGeneration
        }
        return previous.committed.currentAuthorityGeneration
    }

    /// Recovery must not reuse the generation of either retained commit boundary.
    public var checkpointGeneration: UInt64 {
        max(previous.committed.generation, previous.pending?.generation ?? 0) + 1
    }

    public var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(try previous.committed.bytes),
                2: try previous.pending.map { .bytes(try $0.bytes) } ?? .null,
                3: .bytes(authorityDigest), 4: .bytes(ledgerDigest), 5: .bytes(recoveryEpoch)
            ]), limits: Self.limits())
        }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set((0...5).map(UInt64.init)), fields[0] == .unsigned(1),
              case .bytes(let committed) = fields[1],
              case .bytes(let authority) = fields[3], case .bytes(let ledger) = fields[4],
              case .bytes(let epoch) = fields[5] else { throw ContinuityStoreError.invalidCheckpoint }
        let pending: ContinuityCheckpoint?
        switch fields[2] {
        case .null: pending = nil
        case .bytes(let value): pending = try ContinuityCheckpoint.decode(value)
        default: throw ContinuityStoreError.invalidCheckpoint
        }
        let previous = try ContinuityState(committed: ContinuityCheckpoint.decode(committed), pending: pending,
            recoveryRequired: false)
        let result = try Self(previous: previous, authorityDigest: authority, ledgerDigest: ledger, recoveryEpoch: epoch)
        guard try result.bytes == bytes else { throw ContinuityStoreError.invalidCheckpoint }
        return result
    }

    private static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 16) }
}
