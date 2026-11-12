import Foundation
import RemozioProtocol

/// Reads a historical signed exchange. It grants no live readiness, startup, publication, or writer authority.
struct MachineUpdateRetainedSetupPromotionReadyRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "authority.retained-setup-promotion-ready"
    static let maximumBytes = 70 * 1024
    let id: UUID
    let revision: UUID
    let promotionID: UUID
    let promotionRevision: UUID
    let promotionDigest: Data
    let request: Data
    let response: Data
    var description: String { "MachineUpdateRetainedSetupPromotionReadyRecord(redacted)" }
    var debugDescription: String { description }

    private init(id: UUID, revision: UUID, promotionID: UUID, promotionRevision: UUID,
        promotionDigest: Data, request: Data, response: Data) throws {
        guard promotionDigest.count == 32, !request.isEmpty, request.count <= 16512,
              !response.isEmpty, response.count <= 50240 else { throw PreparationStoreError.corruptRecord }
        _ = try Self.verifyTranscript(request: request, response: response, promotionDigest: promotionDigest)
        self.id = id; self.revision = revision; self.promotionID = promotionID; self.promotionRevision = promotionRevision
        self.promotionDigest = promotionDigest; self.request = request; self.response = response
    }
    func requirePublishedIntent(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord) throws {
        guard intent.phase == .filesPublished, intent.id == promotionID, intent.revision == promotionRevision,
              try Self.promotionDigest(intent) == promotionDigest else {
            throw PreparationStoreError.staleRevision
        }
    }
    /// Compares recorded operands only. The native owner must separately verify the current installation and actual paired stores.
    func requirePublication(_ intent: MachineUpdateRetainedSetupPromotionIntentRecord) throws {
        try requirePublishedIntent(intent)
        let configuration = try intent.publication().configuration, archive = configuration.archive
        let original = try archive.originalActivation(), completion = try archive.completionIntent()
        let binding = original.binding
        let selected = try Self.verifyTranscript(request: request, response: response, promotionDigest: promotionDigest)
        let activationDigest = MachineUpdateActivationRecord.digest(archive.originalActivationBytes)
        let inventoryDigest = MachineUpdateActivationRecord.digest(archive.recordedInventoryBytes)
        let boundaryDigest = try Self.recordedCompletionBoundaryDigest(completion)
        for value in [selected.root, selected.transport] {
            guard value.binding == binding, value.activationPlanDigest == activationDigest,
                  value.inventoryDigest == inventoryDigest, value.completionBoundaryDigest == boundaryDigest else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
        }
        guard let transport = configuration.transport.settingsHost, transport.role == .transport else {
            throw RuntimeActivationError.incomplete
        }
        let transportKey = try original.reference.transportPublicKeyX963
        guard selected.root.executionUID == 0, selected.root.publicKey == original.reference.services.authorityPublicKey,
              let rootCode = configuration.host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              selected.root.code == rootCode, selected.transport.code == transport.consumerCode,
              selected.transport.executionUID == transport.serviceUID, selected.transport.publicKey == transportKey else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
    }
    private static func verifyTranscript(request: Data, response: Data, promotionDigest: Data) throws
        -> (root: MachineUpdateRetainedSetupHealthEvidence.Requirement, transport: MachineUpdateRetainedSetupHealthEvidence.Requirement) {
        let root = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(request)
        let packet = try MachineUpdateRetainedSetupJointHealthPacket.decode(response)
        let transport = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(packet.transportRequest)
        guard root.role == .authority, root.promotionDigest == promotionDigest,
              transport.role == .transport, transport.promotionDigest == promotionDigest,
              root.completionBoundaryDigest != nil else { throw MachineUpdateRoleChallengeError.changedScope }
        let digest = try MachineUpdateRetainedSetupJointHealthPacket.transportDigest(
            request: packet.transportRequest, reply: packet.transportReply)
        try MachineUpdateRetainedSetupHealthEvidence.verifyTransportReply(request: packet.transportRequest,
            response: packet.transportReply, expected: transport, boundTo: request)
        try MachineUpdateRetainedSetupHealthEvidence.verifyJointRootReply(request: request,
            response: packet.rootReply, expected: root, transportDigest: digest)
        return (root, transport)
    }
    var transcriptDigest: Data { get throws {
        let bytes = try DeterministicCBOR.encode(.map([0: .bytes(request), 1: .bytes(response)]), limits: Self.limits)
        return MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionReadyTranscript/v1\0".utf8) + bytes)
    } }
    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: formatName, readVersions: [1], writeVersions: [])
        }
    } }
    private static func uuidBytes(_ value: UUID) -> Data {
        var bytes = value.uuid; return withUnsafeBytes(of: &bytes) { Data($0) }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(Self.uuidBytes(id)), 3: .bytes(Self.uuidBytes(revision)),
            4: .bytes(Self.uuidBytes(promotionID)), 5: .bytes(Self.uuidBytes(promotionRevision)),
            6: .bytes(promotionDigest), 7: .bytes(request), 8: .bytes(response)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes,
                  case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...8), fields[0] == .unsigned(1), fields[1] == .text(formatName),
                  case .bytes(let id) = fields[2], id.count == 16,
                  case .bytes(let revision) = fields[3], revision.count == 16,
                  case .bytes(let promotionID) = fields[4], promotionID.count == 16,
                  case .bytes(let promotionRevision) = fields[5], promotionRevision.count == 16,
                  case .bytes(let digest) = fields[6], case .bytes(let request) = fields[7],
                  case .bytes(let response) = fields[8] else { throw PreparationStoreError.corruptRecord }
            func uuid(_ bytes: Data) -> UUID { bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) } }
            let record = try Self(id: uuid(id), revision: uuid(revision), promotionID: uuid(promotionID),
                promotionRevision: uuid(promotionRevision), promotionDigest: digest, request: request, response: response)
            guard try record.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return record
        } catch { throw PreparationStoreError.corruptRecord }
    }
    private static func promotionDigest(_ record: MachineUpdateRetainedSetupPromotionIntentRecord) throws -> Data {
        guard record.phase == .filesPublished else { throw RuntimeActivationError.incomplete }
        return try MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionHealthScope/v3\0".utf8) + record.encoded)
    }
    private static func recordedCompletionBoundaryDigest(_ record: MachineUpdateRetainedSetupCompletionIntentRecord) throws -> Data {
        guard record.phase == .recorded, let policy = record.committedPolicy, let checkpoint = record.committedCheckpoint else {
            throw RuntimeActivationError.incomplete
        }
        _ = try record.encoded
        return try completionBoundaryDigest(macID: record.startupIntent.macID, accountID: record.startupIntent.accountID,
            policy: policy.snapshot(), checkpoint: .decode(checkpoint))
    }
    private static func completionBoundaryDigest(macID: Data, accountID: Data,
        policy: AuthorityCodePolicySnapshot, checkpoint: ContinuityCheckpoint) throws -> Data {
        var revision = policy.revision.uuid
        let revisionBytes = withUnsafeBytes(of: &revision) { Data($0) }
        let bytes = try DeterministicCBOR.encode(.map([0: .bytes(macID), 1: .bytes(accountID),
            2: .bytes(policy.storedBytes), 3: .bytes(checkpoint.bytes), 4: .bytes(revisionBytes)]),
            limits: CBORLimits(maxBytes: 524288, maxDepth: 1, maxItems: 11))
        return MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupCompletionHealthBoundary/v2\0".utf8) + bytes)
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 19)
}
