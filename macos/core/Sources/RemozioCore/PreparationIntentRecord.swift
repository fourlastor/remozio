import Darwin
import Foundation

enum PreparationRecordError: Error, Equatable { case invalidRecord, corruptRecord }
enum PreparationRecordPhase: UInt64, Codable { case intent = 1, copyRecorded = 2, abandoned = 3 }

struct PreparationFileIdentity: Codable, Equatable {
    let device: UInt32
    let inode: UInt64
}

/// Persisted bookkeeping. Decoding this value grants no signature or activation authority.
struct PreparationIntentRecord: Codable, Equatable {
    let id: UUID
    let revision: UUID
    let parent: String
    let ancestry: [PreparationFileIdentity]
    let phase: PreparationRecordPhase
    let copyIdentity: PreparationFileIdentity?
    let copyDigest: Data?
    var bundleName: String { id.uuidString + ".app" }
    static let maximumBytes = 16_384

    init(id: UUID, revision: UUID, parent: String, ancestry: [PreparationFileIdentity],
         phase: PreparationRecordPhase, copyIdentity: PreparationFileIdentity? = nil, copyDigest: Data? = nil) throws {
        self.id = id; self.revision = revision; self.parent = parent; self.ancestry = ancestry
        self.phase = phase; self.copyIdentity = copyIdentity; self.copyDigest = copyDigest
        try validate()
    }
    func validate() throws {
        let parts = parent.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard parent.hasPrefix("/"), parent.utf8.count < Int(PATH_MAX), !parent.utf8.contains(0),
              !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 }),
              (1...64).contains(ancestry.count), ancestry.allSatisfy({ $0.inode > 0 }),
              (copyIdentity == nil) == (copyDigest == nil), copyIdentity == nil || copyIdentity!.inode > 0,
              copyDigest == nil || copyDigest!.count == 32 else { throw PreparationRecordError.invalidRecord }
        switch phase {
        case .intent: guard copyIdentity == nil else { throw PreparationRecordError.invalidRecord }
        case .copyRecorded: guard copyIdentity != nil else { throw PreparationRecordError.invalidRecord }
        case .abandoned: break
        }
    }
    var encoded: Data {
        get throws {
            try validate()
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(self)
            guard bytes.count <= Self.maximumBytes else { throw PreparationRecordError.invalidRecord }
            return bytes
        }
    }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationRecordError.corruptRecord }
            let record = try JSONDecoder().decode(Self.self, from: bytes)
            try record.validate()
            guard try record.encoded == bytes else { throw PreparationRecordError.corruptRecord }
            return record
        } catch { throw PreparationRecordError.corruptRecord }
    }
}
