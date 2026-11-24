import Foundation

/// Retained release operands only. This record grants no native startup, retirement, policy writer or admission authority.
struct MachineUpdateInstalledReleaseRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Operand: Codable, Equatable, Sendable {
        let kind: Int64
        let accountID: Data
        let length: Int
        let digest: Data
    }
    static let formatName = "authority.installed-release-state"
    static let maximumBytes = 262144
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let sourceSchemaVersion: Int64
    let activationAttempt: UUID
    let macID: Data
    let installationID: Data
    let inventoryRevision: Data
    let releaseDigest: Data
    let operands: [Operand]
    var description: String { "MachineUpdateInstalledReleaseRecord(redacted)" }
    var debugDescription: String { description }

    init(sourceSchemaVersion: Int64, activationAttempt: UUID, inventory: InstallationInventory,
        publication: MachineUpdateCompletionPublicationRecord, artifacts: [MachineUpdateInstalledReleaseEpoch.Artifact]) throws {
        guard let configuration = artifacts.first(where: { $0.kind == 2 && $0.accountID == MachineUpdateInstalledReleaseEpoch.global }) else {
            throw PreparationStoreError.corruptRecord
        }
        formatVersion = try MachineUpdateConfigurationEpochRecord.decode(configuration.bytes).carriesProvenance ? 2 : 1
        id = publication.id; revision = publication.revision
        self.sourceSchemaVersion = sourceSchemaVersion; self.activationAttempt = activationAttempt
        macID = inventory.macID; installationID = inventory.installationID
        inventoryRevision = inventory.revision; releaseDigest = inventory.releaseDigest
        operands = artifacts.map { .init(kind: $0.kind, accountID: $0.accountID, length: $0.bytes.count,
            digest: MachineUpdateActivationRecord.digest($0.bytes)) }
        try validate()
    }
    static func ordered(_ lhs: Operand, _ rhs: Operand) -> Bool {
        lhs.kind == rhs.kind ? lhs.accountID.lexicographicallyPrecedes(rhs.accountID) : lhs.kind < rhs.kind
    }
    static func maximumArtifactBytes(kind: Int64) throws -> Int {
        switch kind {
        case 1: return 65536
        case 2: return MachineUpdateConfigurationEpochRecord.maximumBytes
        case 3: return MachineUpdateBackendEpochRecord.maximumBytes
        case 4: return MachineUpdateCompletionIntentRecord.maximumBytes
        case 5: return MachineUpdateCompletionPublicationRecord.maximumBytes
        case 101...109: return RuntimeReleaseConfigurationSource.maximumBytes
        case 201: return RuntimeReleaseBackendSource.maximumBytes
        case 202, 203: return RuntimeReleaseBackendPlan.maximumBytes
        case 300: return MachineUpdatePolicyIntentRecord.maximumBytes
        default: throw PreparationStoreError.corruptRecord
        }
    }
    private func validate() throws {
        guard [UInt64(1), 2].contains(formatVersion), sourceSchemaVersion == 22,
              [macID, installationID, inventoryRevision].allSatisfy({ $0.count == 16 }), releaseDigest.count == 32,
              (5...1034).contains(operands.count), operands == operands.sorted(by: Self.ordered),
              Set(operands.map { String($0.kind) + ":" + $0.accountID.base64EncodedString() }).count == operands.count,
              Set(operands.filter { $0.accountID.count == 16 }.map(\.accountID)).count <= 128 else {
            throw PreparationStoreError.corruptRecord
        }
        for operand in operands {
            let global = (1...5).contains(operand.kind) || (105...109).contains(operand.kind)
            guard operand.digest.count == 32, operand.length > 0,
                  try operand.length <= Self.maximumArtifactBytes(kind: operand.kind),
                  global ? operand.accountID == MachineUpdateInstalledReleaseEpoch.global : operand.accountID.count == 16 else {
                throw PreparationStoreError.corruptRecord
            }
        }
        for kind in Int64(1)...5 {
            guard operands.contains(where: { $0.kind == kind && $0.accountID == MachineUpdateInstalledReleaseEpoch.global }) else {
                throw PreparationStoreError.corruptRecord
            }
        }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var provenanceRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: formatName, readVersions: [1, 2], writeVersions: [2])
        }
    } }
    static func requireProvenanceFormats(_ candidate: SignedReleaseEvidence) throws {
        try MachineUpdateConfigurationEpoch.requireProvenanceFormats(candidate)
        for requirement in try provenanceRequirements {
            guard let declared = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declared.readers), requirement.writeVersions.isSubset(of: declared.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [22, 23], writeVersions: [23]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}

enum MachineUpdateInstalledReleaseEpoch {
    static let global = Data([0])
    struct Artifact: Equatable, Sendable {
        let kind: Int64
        let accountID: Data
        let bytes: Data
    }
    struct Archive: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        private final class Decoded: @unchecked Sendable {
            private let lock = NSRecursiveLock()
            private var configuration: MachineUpdateConfigurationEpoch.Archive?
            private var backend: MachineUpdateBackendEpoch.Archive?
            func configuration(_ decode: () throws -> MachineUpdateConfigurationEpoch.Archive) throws -> MachineUpdateConfigurationEpoch.Archive {
                try lock.withLock {
                    if let configuration { return configuration }
                    let value = try decode(); configuration = value; return value
                }
            }
            func backend(_ decode: () throws -> MachineUpdateBackendEpoch.Archive) throws -> MachineUpdateBackendEpoch.Archive {
                try lock.withLock {
                    if let backend { return backend }
                    let value = try decode(); backend = value; return value
                }
            }
        }
        let record: MachineUpdateInstalledReleaseRecord
        let artifacts: [Artifact]
        // Each immutable archive owns its decoded values. Candidate validation and current database checks remain separate.
        private let decoded = Decoded()
        // A store-decoded archive shares the store's epoch caches. A proposal captured from completion facts does not.
        /// Internal so that tests can observe the shared entries. Production code reads it only through the methods below.
        let caches: PreparationEpochDecodeCaches
        var description: String { "MachineUpdateInstalledReleaseEpoch.Archive(redacted)" }
        var debugDescription: String { description }

        /// Captures a proposal from actual completion facts. The caller still owns the storage loan and current paired checks.
        init(snapshot: MachineUpdateCompletionPublicationSnapshot, candidate: SignedReleaseEvidence,
            currentSourceDigest: Data, boundaries: [AuthorityJournal.MachineUpdatePolicyBoundary]) throws {
            guard let publication = snapshot.publication, publication.filesPublished, publication.inventoryState == .pending else {
                throw PreparationStoreError.invalidTransition
            }
            let plan = try MachineUpdateCompletionPublicationPlan(snapshot: snapshot.completion, candidate: candidate,
                currentSourceDigest: currentSourceDigest, boundaries: boundaries)
            try publication.requirePlan(plan)
            let restart = snapshot.completion.restart
            var rows = try [Artifact(kind: 1, accountID: global, bytes: plan.inventory.canonicalBytes),
                Artifact(kind: 2, accountID: global, bytes: restart.configuration.record.encoded),
                Artifact(kind: 3, accountID: global, bytes: restart.backend.record.encoded),
                Artifact(kind: 4, accountID: global, bytes: snapshot.completion.intent.record.encoded),
                Artifact(kind: 5, accountID: global, bytes: publication.encoded)]
            rows += restart.configuration.artifacts.map { .init(kind: 100 + $0.kind, accountID: $0.account, bytes: $0.bytes) }
            rows += restart.backend.artifacts.map { .init(kind: 200 + $0.kind, accountID: $0.accountID, bytes: $0.bytes) }
            rows += try snapshot.completion.intent.policies.map { .init(kind: 300, accountID: $0.binding.accountID, bytes: try $0.encoded) }
            rows.sort { $0.kind == $1.kind ? $0.accountID.lexicographicallyPrecedes($1.accountID) : $0.kind < $1.kind }
            artifacts = rows; caches = .unshared()
            record = try .init(sourceSchemaVersion: 22,
                activationAttempt: restart.source.replacement.activation.attemptID, inventory: plan.inventory,
                publication: publication, artifacts: rows)
            try validate(candidate: candidate)
        }

        private init(record: MachineUpdateInstalledReleaseRecord, artifacts: [Artifact], candidate: SignedReleaseEvidence,
            caches: PreparationEpochDecodeCaches) throws {
            self.record = record; self.artifacts = artifacts; self.caches = caches; try validate(candidate: candidate)
        }
        func artifact(_ kind: Int64, accountID: Data = global) throws -> Data {
            guard let value = artifacts.first(where: { $0.kind == kind && $0.accountID == accountID }) else {
                throw PreparationStoreError.corruptRecord
            }
            return value.bytes
        }
        func configuration() throws -> MachineUpdateConfigurationEpoch.Archive {
            try decoded.configuration {
                let header = try MachineUpdateConfigurationEpochRecord.decode(artifact(2))
                let rows = artifacts.filter { (101...109).contains($0.kind) }.map {
                    MachineUpdateConfigurationEpoch.Artifact(kind: $0.kind - 100, account: $0.accountID, bytes: $0.bytes)
                }
                let result = MachineUpdateConfigurationEpoch.Archive(record: header, artifacts: rows, caches: caches)
                try result.validate(); return result
            }
        }
        func backend() throws -> MachineUpdateBackendEpoch.Archive {
            try decoded.backend {
                let header = try MachineUpdateBackendEpochRecord.decode(artifact(3))
                let rows = artifacts.filter { (201...203).contains($0.kind) }.map {
                    MachineUpdateBackendEpoch.Artifact(kind: $0.kind - 200, accountID: $0.accountID, bytes: $0.bytes)
                }
                let result = MachineUpdateBackendEpoch.Archive(record: header, artifacts: rows, caches: caches)
                try result.validate(epoch: configuration()); return result
            }
        }
        /// A pure function of the kind 4 row and the kind 300 rows in their order; a success is shared through the store's cache.
        func completionIntent() throws -> MachineUpdateCompletionIntentArchive {
            let headerBytes = try artifact(4)
            let policyRows = artifacts.filter { $0.kind == 300 }
            let key = PreparationImmutableValidationCache.key(domain: "remozio.installed-release-epoch.completion-intent.v1",
                [headerBytes] + policyRows.flatMap { [$0.accountID, $0.bytes] })
            return try caches.installedCompletionIntents.value(key: key) { try Self.decodeCompletionIntent(headerBytes, policyRows) }
        }
        private static func decodeCompletionIntent(_ headerBytes: Data, _ policyRows: [Artifact]) throws -> MachineUpdateCompletionIntentArchive {
            let header = try MachineUpdateCompletionIntentRecord.decode(headerBytes)
            let policies = try policyRows.map { artifact in
                let policy = try MachineUpdatePolicyIntentRecord.decode(artifact.bytes)
                guard policy.binding.accountID == artifact.accountID else { throw PreparationStoreError.corruptRecord }
                return policy
            }
            return try .init(record: header, policies: policies)
        }
        func publicationSource() throws -> MachineUpdateCompletionPublicationRecord {
            try .decode(artifact(5))
        }
        func inventory() throws -> InstallationInventory {
            try .decode(artifact(1), expectedMacID: record.macID)
        }
        func plan(candidate: SignedReleaseEvidence) throws -> MachineUpdateCompletionPublicationPlan {
            try .init(retainedConfiguration: configuration(), retainedBackend: backend(), intent: completionIntent(), candidate: candidate)
        }
        /// A pure function of the record, the artifacts and the candidate. Only a success is remembered, under a key that holds
        /// all three exactly, so a different byte or a different candidate runs every check again in the original order.
        func validate(candidate: SignedReleaseEvidence) throws {
            let recordBytes = try record.encoded
            // The candidate key cannot fail today; if it ever does, the checks run uncached rather than reorder an error.
            guard let key = validationKey(recordBytes: recordBytes, candidate: candidate) else {
                return try validateUncached(candidate: candidate)
            }
            if caches.installedValidations.contains(key) { return }
            try validateUncached(candidate: candidate)
            caches.installedValidations.insert(key)
        }
        /// Every input of `validateUncached`: the record's canonical bytes, the candidate's exact key, and each artifact's
        /// kind, account and bytes in order. Each part is length-prefixed, so distinct inputs give distinct keys.
        func validationKey(recordBytes: Data, candidate: SignedReleaseEvidence) -> Data? {
            guard let candidateKey = try? PreparationEpochDecodeCaches.candidateKey(candidate) else { return nil }
            return PreparationImmutableValidationCache.key(domain: "remozio.installed-release-epoch.validation.v1",
                [recordBytes, candidateKey] + artifacts.flatMap { artifact -> [Data] in
                    var kind = artifact.kind.bigEndian
                    return [withUnsafeBytes(of: &kind) { Data($0) }, artifact.accountID, artifact.bytes]
                })
        }
        private func validateUncached(candidate: SignedReleaseEvidence) throws {
            if record.formatVersion == 2 { try MachineUpdateInstalledReleaseRecord.requireProvenanceFormats(candidate) }
            guard artifacts.count == record.operands.count else { throw PreparationStoreError.corruptRecord }
            for (artifact, operand) in zip(artifacts, record.operands) {
                guard artifact.kind == operand.kind, artifact.accountID == operand.accountID,
                      artifact.bytes.count == operand.length,
                      MachineUpdateActivationRecord.digest(artifact.bytes) == operand.digest else { throw PreparationStoreError.corruptRecord }
            }
            guard try configuration().record.carriesProvenance == (record.formatVersion == 2) else { throw PreparationStoreError.corruptRecord }
            let plan = try self.plan(candidate: candidate), publication = try publicationSource(), inventory = try self.inventory()
            try publication.requirePlan(plan)
            guard publication.filesPublished, publication.inventoryState == .pending,
                  publication.id == record.id, publication.revision == record.revision,
                  inventory == plan.inventory, inventory.macID == record.macID,
                  inventory.installationID == record.installationID, inventory.revision == record.inventoryRevision,
                  inventory.releaseDigest == record.releaseDigest,
                  try configuration().record.activationAttempt == record.activationAttempt else { throw PreparationStoreError.staleRevision }
        }
        static func decode(record bytes: Data, artifacts: [Artifact], candidate: SignedReleaseEvidence,
            caches: PreparationEpochDecodeCaches) throws -> Self {
            do {
                return try .init(record: MachineUpdateInstalledReleaseRecord.decode(bytes), artifacts: artifacts,
                    candidate: candidate, caches: caches)
            } catch { throw PreparationStoreError.corruptRecord }
        }
    }
}
