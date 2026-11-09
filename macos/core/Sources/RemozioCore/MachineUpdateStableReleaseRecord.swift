import Foundation
import RemozioProtocol

/// Terminal metadata operands only. The native owner must retain admission and verify the actual source around the write.
struct MachineUpdateStableReleaseRecord: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "authority.stable-release-state"
    static let maximumBytes = 16_384
    let id: UUID
    let revision: UUID
    let macID: Data
    let installationID: Data
    let releaseDigest: Data
    let initialInventoryRevision: Data
    let initialInventoryDigest: Data
    let installedRecordDigest: Data
    let historicalSourceSchemaVersion: Int64
    let historicalSourceDigest: Data
    let finishing: MachineUpdateActivationRecord
    let completed: MachineUpdateActivationRecord
    var description: String { "MachineUpdateStableReleaseRecord(redacted)" }
    var debugDescription: String { description }

    init(readiness: MachineUpdateInstalledReadinessPlan, completed: MachineUpdateActivationRecord,
        candidate: SignedReleaseEvidence) throws {
        let source = readiness.view.compatibility.source, actual = source.actual
        guard readiness.focusedAccountID == nil, actual.schemaVersion == 23, actual.activation.phase == .finishing else {
            throw PreparationStoreError.invalidTransition
        }
        try completed.requireCompletionSource(actual.activation)
        try self.init(id: actual.installed.record.id, revision: completed.revision,
            macID: actual.inventory.macID, installationID: actual.inventory.installationID,
            releaseDigest: actual.inventory.releaseDigest, initialInventoryRevision: actual.inventory.revision,
            initialInventoryDigest: MachineUpdateActivationRecord.digest(actual.inventory.canonicalBytes),
            installedRecordDigest: MachineUpdateActivationRecord.digest(actual.installed.record.encoded),
            historicalSourceSchemaVersion: source.historicalSchemaVersion, historicalSourceDigest: source.historicalSourceDigest,
            finishing: actual.activation, completed: completed)
        try requireEpoch(actual.installed, candidate: candidate)
    }
    private init(id: UUID, revision: UUID, macID: Data, installationID: Data, releaseDigest: Data,
        initialInventoryRevision: Data, initialInventoryDigest: Data, installedRecordDigest: Data,
        historicalSourceSchemaVersion: Int64, historicalSourceDigest: Data,
        finishing: MachineUpdateActivationRecord, completed: MachineUpdateActivationRecord) throws {
        self.id = id; self.revision = revision; self.macID = macID; self.installationID = installationID
        self.releaseDigest = releaseDigest; self.initialInventoryRevision = initialInventoryRevision
        self.initialInventoryDigest = initialInventoryDigest; self.installedRecordDigest = installedRecordDigest
        self.historicalSourceSchemaVersion = historicalSourceSchemaVersion; self.historicalSourceDigest = historicalSourceDigest
        self.finishing = finishing; self.completed = completed
        try validate()
    }
    private func validate() throws {
        guard [macID, installationID, initialInventoryRevision].allSatisfy({ $0.count == 16 }),
              [releaseDigest, initialInventoryDigest, installedRecordDigest, historicalSourceDigest].allSatisfy({ $0.count == 32 }),
              (1...24).contains(historicalSourceSchemaVersion), revision == completed.revision,
              macID == finishing.macID, installationID == finishing.installationID else { throw PreparationStoreError.corruptRecord }
        try completed.requireCompletionSource(finishing)
    }
    func requireEpoch(_ epoch: MachineUpdateInstalledReleaseEpoch.Archive, candidate: SignedReleaseEvidence) throws {
        try validate(); try epoch.validate(candidate: candidate)
        let inventory = try epoch.inventory(), intent = try epoch.completionIntent()
        guard epoch.record.id == id, epoch.record.macID == macID, epoch.record.installationID == installationID,
              epoch.record.activationAttempt == finishing.attemptID, epoch.record.releaseDigest == releaseDigest,
              try MachineUpdateActivationRecord.digest(epoch.record.encoded) == installedRecordDigest,
              inventory.revision == initialInventoryRevision,
              MachineUpdateActivationRecord.digest(inventory.canonicalBytes) == initialInventoryDigest,
              intent.record.sourceSchemaVersion == historicalSourceSchemaVersion,
              intent.record.sourceMachineDigest == historicalSourceDigest,
              try epoch.backend().record.currentSourceDigest == historicalSourceDigest else { throw PreparationStoreError.staleRevision }
        try finishing.requireFinalizationSource(.decode(intent.record.activation))
    }
    /// Compares release and namespace only. Current account rows and native owners need their separate protected checks.
    func requireCurrentInventory(_ inventory: InstallationInventory,
        epoch: MachineUpdateInstalledReleaseEpoch.Archive, candidate: SignedReleaseEvidence) throws {
        try requireEpoch(epoch, candidate: candidate)
        guard inventory.macID == macID, inventory.installationID == installationID, inventory.releaseDigest == releaseDigest,
              try inventory.bundlePath == epoch.inventory().bundlePath else { throw PreparationStoreError.staleRevision }
        try inventory.compareRelease(candidate)
    }
    /// A future stable-state writer must check these declarations before any schema change.
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [22, 23, 24], writeVersions: [23, 24]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateInstalledReleaseRecord.formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateActivationRecord.formatName, readVersions: [1, 2, 3, 4], writeVersions: [3, 4]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    var encoded: Data { get throws {
        try validate()
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(Self.bytes(id)), 3: .bytes(Self.bytes(revision)), 4: .bytes(macID), 5: .bytes(installationID),
            6: .bytes(releaseDigest), 7: .bytes(initialInventoryRevision), 8: .bytes(initialInventoryDigest),
            9: .bytes(installedRecordDigest), 10: .unsigned(UInt64(historicalSourceSchemaVersion)),
            11: .bytes(historicalSourceDigest), 12: .bytes(finishing.encoded), 13: .bytes(completed.encoded)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...13),
                  fields[0] == .unsigned(1), fields[1] == .text(formatName), case .unsigned(let rawSchema) = fields[10],
                  let schema = Int64(exactly: rawSchema) else { throw PreparationStoreError.corruptRecord }
            func data(_ key: UInt64) throws -> Data {
                guard case .bytes(let value) = fields[key] else { throw PreparationStoreError.corruptRecord }; return value
            }
            let value = try Self(id: uuid(data(2)), revision: uuid(data(3)), macID: data(4), installationID: data(5),
                releaseDigest: data(6), initialInventoryRevision: data(7), initialInventoryDigest: data(8),
                installedRecordDigest: data(9), historicalSourceSchemaVersion: schema, historicalSourceDigest: data(11),
                finishing: .decode(data(12)), completed: .decode(data(13)))
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    private static func bytes(_ value: UUID) -> Data {
        var value = value.uuid; return withUnsafeBytes(of: &value) { Data($0) }
    }
    private static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw PreparationStoreError.corruptRecord }
        let b = [UInt8](bytes)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 29)
}
