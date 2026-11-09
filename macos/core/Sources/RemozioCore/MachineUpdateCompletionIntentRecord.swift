import Foundation

/// Retained machine operands only. Decoding grants no writer, policy change, inventory publication or admission authority.
struct MachineUpdateCompletionIntentRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Account: Codable, Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let sourceDigest: Data
        let inInventory: Bool
        let policyRecordID: UUID?
        let policyRecordDigest: Data?
    }
    static let formatName = "authority.machine-update-completion-intent"
    static let maximumBytes = 131072
    let formatVersion: UInt64
    let id: UUID
    private(set) var revision: UUID
    let sourceSchemaVersion: Int64
    let sourceMachineDigest: Data
    let activation: Data
    let epochs: MachineUpdatePolicyIntentRecord.EpochScope
    let sourceInventoryRevision: Data
    let targetInventory: Data
    private(set) var accounts: [Account]
    var description: String { "MachineUpdateCompletionIntentRecord(redacted)" }
    var debugDescription: String { description }

    init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
         policyRecords: [MachineUpdatePolicyIntentRecord], targetRevision: Data,
         id: UUID = UUID(), revision: UUID = UUID()) throws {
        _ = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)
        let source = snapshot.source, context = source.replacement
        let expected = Set(snapshot.configuration.record.accounts.filter(\.configurationPublished).map(\.accountID))
        guard Set(policyRecords.map { $0.binding.accountID }) == expected,
              Set(policyRecords.map { $0.binding.accountID }).count == policyRecords.count,
              policyRecords.allSatisfy({ $0.phase == .prepared }),
              targetRevision.count == 16, targetRevision != context.inventory.revision else {
            throw PreparationStoreError.invalidTransition
        }
        for policy in policyRecords { try policy.requireSnapshot(snapshot, candidate: candidate) }
        let target = try InstallationInventory(macID: context.inventory.macID, installationID: context.inventory.installationID,
            revision: targetRevision, bundlePath: context.inventory.bundlePath, releaseDigest: InstallationInventory.digest(candidate),
            accounts: context.inventory.accounts, services: context.inventory.services, formatVersion: context.inventory.formatVersion)
        try target.compareRelease(candidate)
        self.formatVersion = 1; self.id = id; self.revision = revision
        sourceSchemaVersion = context.runtime.schemaVersion; sourceMachineDigest = snapshot.backend.record.currentSourceDigest
        activation = try context.activation.encoded
        epochs = try .init(configuration: snapshot.configuration.record, backend: snapshot.backend.record)
        sourceInventoryRevision = context.inventory.revision; targetInventory = target.canonicalBytes
        accounts = try source.accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }.map { account in
            let policy = policyRecords.first { $0.binding.accountID == account.accountID }
            return try .init(accountID: account.accountID, ownerUID: account.ownerUID,
                sourceDigest: source.accountDigest(accountID: account.accountID),
                inInventory: context.inventory.accounts.contains { $0.accountID == account.accountID },
                policyRecordID: policy?.id, policyRecordDigest: policy.map { try MachineUpdateActivationRecord.digest($0.encoded) })
        }
        try validate()
    }

    /// Checks historical operands under the caller's separately verified machine source digest.
    func requireSnapshot(_ snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
                         currentSourceDigest: Data) throws {
        try validate()
        _ = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)
        let source = snapshot.source, context = source.replacement
        let version = context.runtime.schemaVersion
        guard currentSourceDigest == sourceMachineDigest,
              version == sourceSchemaVersion || (sourceSchemaVersion == 20 && (version == 21 || version == 22)) ||
                  (sourceSchemaVersion == 21 && version == 22),
              try context.activation.encoded == activation,
              try MachineUpdatePolicyIntentRecord.EpochScope(configuration: snapshot.configuration.record,
                  backend: snapshot.backend.record) == epochs,
              context.inventory.revision == sourceInventoryRevision,
              source.accounts.count == accounts.count else { throw PreparationStoreError.staleRevision }
        let target = try InstallationInventory.decode(targetInventory, expectedMacID: context.inventory.macID)
        let expected = try InstallationInventory(macID: context.inventory.macID, installationID: context.inventory.installationID,
            revision: target.revision, bundlePath: context.inventory.bundlePath, releaseDigest: InstallationInventory.digest(candidate),
            accounts: context.inventory.accounts, services: context.inventory.services, formatVersion: context.inventory.formatVersion)
        guard target == expected else { throw PreparationStoreError.staleRevision }
        try target.compareRelease(candidate)
        let configured = Set(snapshot.configuration.record.accounts.filter(\.configurationPublished).map(\.accountID))
        guard Set(accounts.filter { $0.policyRecordID != nil }.map(\.accountID)) == configured else {
            throw PreparationStoreError.staleRevision
        }
        for account in accounts {
            guard let actual = source.accounts.first(where: { $0.accountID == account.accountID }),
                  actual.ownerUID == account.ownerUID,
                  account.inInventory == context.inventory.accounts.contains(where: { $0.accountID == account.accountID }),
                  try source.accountDigest(accountID: account.accountID) == account.sourceDigest else {
                throw PreparationStoreError.staleRevision
            }
        }
    }

    fileprivate func replacingPolicy(_ policy: MachineUpdatePolicyIntentRecord) throws -> Self {
        guard let index = accounts.firstIndex(where: { $0.accountID == policy.binding.accountID }),
              accounts[index].policyRecordID == policy.id else { throw PreparationStoreError.staleRevision }
        var next = self; next.revision = UUID()
        let previous = accounts[index]
        next.accounts[index] = try .init(accountID: previous.accountID, ownerUID: previous.ownerUID,
            sourceDigest: previous.sourceDigest, inInventory: previous.inInventory,
            policyRecordID: policy.id, policyRecordDigest: MachineUpdateActivationRecord.digest(policy.encoded))
        try next.validate(); return next
    }

    private func validate() throws {
        let activation = try MachineUpdateActivationRecord.decode(self.activation)
        guard formatVersion == 1, activation.phase == .restartChecking, activation.formatVersion == 2,
              sourceSchemaVersion == 20 || sourceSchemaVersion == 21, sourceMachineDigest.count == 32,
              sourceInventoryRevision.count == 16, targetInventory.count <= 65536,
              epochs.configurationDigest.count == 32, epochs.backendDigest.count == 32,
              accounts.count <= 128, Set(accounts.map(\.accountID)).count == accounts.count,
              Set(accounts.map(\.ownerUID)).count == accounts.count,
              accounts.map(\.accountID) == accounts.map(\.accountID).sorted(by: { $0.lexicographicallyPrecedes($1) }),
              accounts.allSatisfy({ $0.accountID.count == 16 && $0.ownerUID > 0 && $0.ownerUID < UInt32.max &&
                  $0.sourceDigest.count == 32 && (($0.policyRecordID == nil) == ($0.policyRecordDigest == nil)) &&
                  ($0.policyRecordDigest == nil || $0.policyRecordDigest?.count == 32) }) else {
            throw PreparationStoreError.corruptRecord
        }
        let target = try InstallationInventory.decode(targetInventory, expectedMacID: activation.macID)
        let retained = try accounts.filter(\.inInventory).map { try InstallationAccount(accountID: $0.accountID, ownerUID: $0.ownerUID) }
        guard target.installationID == activation.installationID, target.revision != sourceInventoryRevision,
              target.accounts == retained,
              Set(accounts.compactMap(\.policyRecordID)).count == accounts.filter({ $0.policyRecordID != nil }).count else {
            throw PreparationStoreError.corruptRecord
        }
    }

    var encoded: Data { get throws {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
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

    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [20, 21, 22], writeVersions: [21]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: MachineUpdatePolicyIntentRecord.formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}

/// Bounded header and policy rows only. This archive does not establish storage provenance or native completion authority.
struct MachineUpdateCompletionIntentArchive: Equatable, Sendable {
    let record: MachineUpdateCompletionIntentRecord
    let policies: [MachineUpdatePolicyIntentRecord]
    var policyMarkersRecorded: Bool { policies.allSatisfy(\.policyRecorded) }

    init(record: MachineUpdateCompletionIntentRecord, policies: [MachineUpdatePolicyIntentRecord]) throws {
        self.record = record
        self.policies = policies.sorted { $0.binding.accountID.lexicographicallyPrecedes($1.binding.accountID) }
        try validate()
    }

    func validate() throws {
        _ = try record.encoded
        let activation = try MachineUpdateActivationRecord.decode(record.activation)
        let target = try InstallationInventory.decode(record.targetInventory, expectedMacID: activation.macID)
        let expected = record.accounts.filter { $0.policyRecordID != nil }
        guard policies.count == expected.count,
              policies.map({ $0.binding.accountID }) == expected.map(\.accountID),
              policies.filter({ $0.phase == .writing }).count <= 1 else { throw PreparationStoreError.corruptRecord }
        for (policy, account) in zip(policies, expected) {
            guard policy.id == account.policyRecordID,
                  try MachineUpdateActivationRecord.digest(policy.encoded) == account.policyRecordDigest,
                  policy.epochs == record.epochs, policy.binding.accountID == account.accountID,
                  policy.binding.macID == activation.macID, policy.binding.installationID == activation.installationID,
                  policy.binding.activationAttempt == activation.attemptID, policy.binding.updateID == activation.updateID,
                  policy.binding.candidateDigest == activation.candidateDigest,
                  policy.binding.sourceInventoryDigest == activation.inventoryDigest,
                  policy.binding.admissionDigest == activation.admissionDigest,
                  policy.binding.sourceAccountDigest == account.sourceDigest,
                  policy.binding.installedReleaseDigest == target.releaseDigest else { throw PreparationStoreError.corruptRecord }
        }
    }

    func requireSnapshot(_ snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
                         currentSourceDigest: Data) throws {
        try validate()
        try record.requireSnapshot(snapshot, candidate: candidate, currentSourceDigest: currentSourceDigest)
        for policy in policies { try policy.requireSnapshot(snapshot, candidate: candidate) }
    }

    func preparingWrite(accountID: Data, expected: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Self {
        try validate()
        guard !policies.contains(where: { $0.phase == .writing }),
              let current = policies.first(where: { $0.binding.accountID == accountID }) else {
            throw PreparationStoreError.invalidTransition
        }
        return try replacing(current.preparingWrite(expected: expected))
    }

    /// Retains only a proven committed result. An unchanged source keeps its unresolved write marker.
    func recordingRecoveredBoundary(_ boundary: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Self {
        try validate()
        guard let current = policies.first(where: { $0.binding.accountID == boundary.accountID }) else {
            throw PreparationStoreError.staleRevision
        }
        switch try current.reconciling(boundary) {
        case .sourceUnchanged: throw PreparationStoreError.invalidTransition
        case .recorded(let policy): return try replacing(policy)
        }
    }

    private func replacing(_ policy: MachineUpdatePolicyIntentRecord) throws -> Self {
        guard let index = policies.firstIndex(where: { $0.binding.accountID == policy.binding.accountID }) else {
            throw PreparationStoreError.staleRevision
        }
        var values = policies; values[index] = policy
        return try Self(record: record.replacingPolicy(policy), policies: values)
    }
}
