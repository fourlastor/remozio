import Foundation
import RemozioProtocol

/// Reads exact promotion operands and historical phase. It grants no file access, writer, native health, or startup authority.
struct MachineUpdateRetainedSetupPromotionIntentRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Sendable { case prepared = 1, publishing, filesPublished }
    static let formatName = "authority.retained-setup-promotion-intent"
    static let currentFormatVersion: UInt64 = 1
    static let maximumBytes = RuntimeRetainedSetupCompletionPublication.maximumBytes + 4096
    let id: UUID
    let revision: UUID
    let phase: Phase
    let publicationBytes: Data
    var description: String { "MachineUpdateRetainedSetupPromotionIntentRecord(redacted)" }
    var debugDescription: String { description }

    private init(id: UUID, revision: UUID, phase: Phase, publicationBytes: Data) throws {
        guard !publicationBytes.isEmpty, publicationBytes.count <= RuntimeRetainedSetupCompletionPublication.maximumBytes else {
            throw PreparationStoreError.corruptRecord
        }
        _ = try RuntimeRetainedSetupCompletionPublication.decode(publicationBytes)
        self.id = id; self.revision = revision; self.phase = phase; self.publicationBytes = publicationBytes
    }
    func publication() throws -> RuntimeRetainedSetupCompletionPublication { try .decode(publicationBytes) }
    private static func uuidBytes(_ value: UUID) -> Data {
        var bytes = value.uuid; return withUnsafeBytes(of: &bytes) { Data($0) }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(Self.currentFormatVersion), 1: .text(Self.formatName),
            2: .bytes(Self.uuidBytes(id)), 3: .bytes(Self.uuidBytes(revision)),
            4: .unsigned(phase.rawValue), 5: .bytes(publicationBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes,
                  case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(currentFormatVersion), fields[1] == .text(formatName),
                  case .bytes(let id) = fields[2], id.count == 16,
                  case .bytes(let revision) = fields[3], revision.count == 16,
                  case .unsigned(let raw) = fields[4], let phase = Phase(rawValue: raw),
                  case .bytes(let publication) = fields[5] else { throw PreparationStoreError.corruptRecord }
            let value = try Self(id: id.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) },
                revision: revision.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) },
                phase: phase, publicationBytes: publication)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 13)
}
