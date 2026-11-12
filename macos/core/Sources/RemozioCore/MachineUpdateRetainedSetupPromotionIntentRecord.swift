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

    init(publication: RuntimeRetainedSetupCompletionPublication,
        snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        id: UUID = UUID(), revision: UUID = UUID()) throws {
        try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(candidate)
        try publication.requireSourceForPublication(snapshot, current: current, candidate: candidate)
        try self.init(id: id, revision: revision, phase: .prepared, publicationBytes: publication.encoded)
        try requireSnapshot(snapshot, candidate: candidate)
    }
    private init(id: UUID, revision: UUID, phase: Phase, publicationBytes: Data) throws {
        guard !publicationBytes.isEmpty, publicationBytes.count <= RuntimeRetainedSetupCompletionPublication.maximumBytes else {
            throw PreparationStoreError.corruptRecord
        }
        _ = try RuntimeRetainedSetupCompletionPublication.decode(publicationBytes)
        self.id = id; self.revision = revision; self.phase = phase; self.publicationBytes = publicationBytes
    }
    func publication() throws -> RuntimeRetainedSetupCompletionPublication { try .decode(publicationBytes) }
    func requireSnapshot(_ snapshot: MachineUpdateRetainedSetupCompletionSnapshot, candidate: SignedReleaseEvidence) throws {
        try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(candidate)
        try snapshot.requireSame(as: .init(activation: snapshot.activation, intent: snapshot.intent, candidate: candidate))
        let publication = try publication(), archive = publication.configuration.archive
        guard snapshot.intent?.phase == .recorded,
              try snapshot.intent?.encoded == archive.completionIntentBytes,
              try snapshot.activation.state.plan?.encoded == archive.originalActivationBytes,
              snapshot.activation.runtime.setup.source.actual.inventory.canonicalBytes == archive.recordedInventoryBytes else {
            throw PreparationStoreError.staleRevision
        }
    }
    func requireSource(_ snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence) throws {
        try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(candidate)
        try requireSnapshot(snapshot, candidate: candidate)
        try publication().requireSourceForPublication(snapshot, current: current, candidate: candidate)
    }
    func beginningPublication(snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence) throws -> Self {
        guard phase == .prepared else { throw PreparationStoreError.invalidTransition }
        try requireSource(snapshot, current: current, candidate: candidate)
        return try .init(id: id, revision: UUID(), phase: .publishing, publicationBytes: publicationBytes)
    }
    func recordingPublishedFiles(snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        observation: RuntimeRetainedSetupCompletionPublication.Observation) throws -> Self {
        guard phase == .publishing else { throw PreparationStoreError.invalidTransition }
        try requireSource(snapshot, current: current, candidate: candidate)
        guard try publication().progress(observation: observation) == .selected else { throw RuntimeActivationError.incomplete }
        try requireSource(snapshot, current: current, candidate: candidate)
        return try .init(id: id, revision: UUID(), phase: .filesPublished, publicationBytes: publicationBytes)
    }
    /// Validates adjacent historical phases. This comparison grants no writer or publication authority.
    func requireTransition(from previous: Self) throws {
        _ = try publication(); _ = try previous.publication()
        guard id == previous.id, revision != previous.revision, publicationBytes == previous.publicationBytes,
              previous.phase == .prepared && phase == .publishing || previous.phase == .publishing && phase == .filesPublished else {
            throw PreparationStoreError.invalidTransition
        }
    }

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
