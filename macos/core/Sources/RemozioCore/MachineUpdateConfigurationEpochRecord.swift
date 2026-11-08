import Foundation

/// Retained recovery operands. This archive grants no publication, native startup, health or floor authority.
struct MachineUpdateConfigurationEpochRecord: Codable, Equatable, Sendable, CustomStringConvertible {
    static let formatName = "authority.machine-update-configuration-epoch"
    static let maximumBytes = 131072
    static let globalAccount = Data([0])
    struct Account: Codable, Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let sourceDigest: Data
        let runtimeDigest: Data?
        let configurationPublished: Bool
        let policyRevision: UUID?
        let provisioningDigest: Data?
        init(accountID: Data, ownerUID: UInt32, sourceDigest: Data, runtimeDigest: Data?, configurationPublished: Bool,
            policyRevision: UUID?, provisioningDigest: Data? = nil) {
            self.accountID = accountID; self.ownerUID = ownerUID; self.sourceDigest = sourceDigest
            self.runtimeDigest = runtimeDigest; self.configurationPublished = configurationPublished
            self.policyRevision = policyRevision; self.provisioningDigest = provisioningDigest
        }
    }
    struct Operand: Codable, Equatable, Sendable {
        let kind: Int64
        let account: Data
        let digest: Data
    }
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let activationAttempt: UUID
    let macID: Data
    let installationID: Data
    let updateID: Data
    let candidateDigest: Data
    let inventoryDigest: Data
    let admissionDigest: Data
    let installedReleaseDigest: Data
    let sourceMachineDigest: Data
    let accounts: [Account]
    let operands: [Operand]
    let publication: MachineUpdatePublicationProgress?
    var carriesProvenance: Bool { formatVersion == 3 || formatVersion == 4 }
    var description: String { "MachineUpdateConfigurationEpochRecord(redacted)" }

    init(id: UUID, revision: UUID, source: MachineUpdateRestartSource, candidate: SignedReleaseEvidence,
         sourceMachineDigest: Data, policies: [MachineUpdateConfigurationEpoch.PolicyCapture],
         configurations: [MachineUpdateConfigurationEpoch.Configuration]) throws {
        let context = source.replacement, activation = context.activation
        guard activation.phase.irreversible, context.replacement?.phase == .observed,
              Set(policies.map(\.accountID)).count == policies.count,
              Set(policies.map(\.accountID)) == Set(source.accounts.map(\.accountID)),
              Set(configurations.map { $0.startup.binding.accountID }).count == configurations.count,
              Set(configurations.map { $0.startup.binding.accountID }) == Set(context.runtime.runtimes.filter(\.configurationPublished).map { $0.reference.services.accountID }),
              try DurableReleasePreparation.digest(candidate) == activation.updateID else { throw RuntimePreparationError.changedScope }
        try MachineUpdateConfigurationEpoch.requireArchiveFormats(candidate)
        try activation.requireScope(candidate: context.candidate, inventory: context.inventory, admission: context.admission)
        try MachineUpdatePolicyPreflight.requireRetained(source, policies: policies)
        let history = try MachineUpdateConfigurationEpoch.provisioningHistory(source: source, candidate: candidate)
        var accounts: [Account] = []
        for account in source.accounts {
            let capture = policies.first { $0.accountID == account.accountID }!
            if let policy = capture.snapshot {
                guard account.initialization != nil else { throw RuntimePreparationError.changedScope }
                _ = try MachineUpdatePolicyPlan(source: policy, candidate: candidate)
            } else if account.initialization?.complete == true { throw RuntimePreparationError.changedScope }
            let runtime = context.runtime.runtimes.first { $0.reference.services.accountID == account.accountID }
            if let config = configurations.first(where: { $0.startup.binding.accountID == account.accountID }) {
                guard let policy = capture.snapshot else { throw RuntimePreparationError.changedScope }
                try config.requireSource(source, policy: policy, candidate: candidate)
            }
            let provisioningDigest: Data?
            if let history, history.accounts.contains(where: { $0.accountID == account.accountID }) {
                provisioningDigest = try MachineUpdateActivationRecord.digest(history.account(account.accountID).encoded)
            } else { provisioningDigest = nil }
            accounts.append(try .init(accountID: account.accountID, ownerUID: account.ownerUID,
                sourceDigest: source.accountDigest(accountID: account.accountID),
                runtimeDigest: runtime.map { try MachineUpdateActivationRecord.digest($0.reference.encoded) },
                configurationPublished: runtime?.configurationPublished ?? false, policyRevision: capture.snapshot?.revision,
                provisioningDigest: provisioningDigest))
        }
        formatVersion = history == nil ? 1 : 3; publication = nil; self.id = id; self.revision = revision; activationAttempt = activation.attemptID
        macID = context.inventory.macID; installationID = context.inventory.installationID; updateID = activation.updateID
        candidateDigest = activation.candidateDigest; inventoryDigest = activation.inventoryDigest; admissionDigest = activation.admissionDigest
        installedReleaseDigest = try InstallationInventory.digest(candidate); self.sourceMachineDigest = sourceMachineDigest
        self.accounts = accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        operands = try MachineUpdateConfigurationEpoch.artifacts(source: source, policies: policies, configurations: configurations, provenance: history).map {
            .init(kind: $0.kind, account: $0.account, digest: MachineUpdateActivationRecord.digest($0.bytes))
        }
        try validate()
    }
    private var publishedAccountIDs: [Data] {
        accounts.filter(\.configurationPublished).map(\.accountID)
    }

    private func validate() throws {
        guard ((formatVersion == 1 || formatVersion == 3) && publication == nil || (formatVersion == 2 || formatVersion == 4) && publication != nil), macID.count == 16, installationID.count == 16,
              [updateID, candidateDigest, inventoryDigest, admissionDigest, installedReleaseDigest, sourceMachineDigest].allSatisfy({ $0.count == 32 }),
              (0...128).contains(accounts.count), Set(accounts.map(\.accountID)).count == accounts.count,
              Set(accounts.map(\.ownerUID)).count == accounts.count,
              accounts.map(\.accountID) == accounts.map(\.accountID).sorted(by: { $0.lexicographicallyPrecedes($1) }),
              accounts.allSatisfy({ $0.accountID.count == 16 && $0.sourceDigest.count == 32 && ($0.runtimeDigest == nil || $0.runtimeDigest?.count == 32) && (!$0.configurationPublished || ($0.runtimeDigest != nil && $0.policyRevision != nil)) }),
              operands.count <= 517, operands.allSatisfy({ (1...9).contains($0.kind) && $0.digest.count == 32 }),
              operands == operands.sorted(by: Self.ordered), Set(operands.map { "\($0.kind):\($0.account.base64EncodedString())" }).count == operands.count else {
            throw PreparationStoreError.corruptRecord
        }
        guard accounts.allSatisfy({ account in
            if let digest = account.provisioningDigest { return carriesProvenance && digest.count == 32 }
            return true
        }) else { throw PreparationStoreError.corruptRecord }
        try publication?.validate(accountIDs: publishedAccountIDs)
        var expected: [(Int64, Data)] = (5...9).map { (Int64($0), Self.globalAccount) }
        for account in accounts {
            if account.configurationPublished { for kind in 1...3 { expected.append((Int64(kind), account.accountID)) } }
            if account.policyRevision != nil || account.provisioningDigest != nil { expected.append((4, account.accountID)) }
        }
        guard Set(expected.map { "\($0.0):\($0.1.base64EncodedString())" }) == Set(operands.map { "\($0.kind):\($0.account.base64EncodedString())" }) else {
            throw PreparationStoreError.corruptRecord
        }
    }
    private init(_ previous: Self, publication: MachineUpdatePublicationProgress) throws {
        formatVersion = previous.carriesProvenance ? 4 : 2; id = previous.id; revision = UUID(); activationAttempt = previous.activationAttempt
        macID = previous.macID; installationID = previous.installationID; updateID = previous.updateID
        candidateDigest = previous.candidateDigest; inventoryDigest = previous.inventoryDigest; admissionDigest = previous.admissionDigest
        installedReleaseDigest = previous.installedReleaseDigest; sourceMachineDigest = previous.sourceMachineDigest
        accounts = previous.accounts; operands = previous.operands; self.publication = publication
        try validate()
    }
    func applying(_ operation: MachineUpdatePublicationOperation) throws -> Self {
        let next: MachineUpdatePublicationProgress
        switch operation {
        case .begin:
            guard publication == nil else { throw PreparationStoreError.invalidTransition }
            next = .init(accountIDs: publishedAccountIDs)
        case .prepare(let account, let file):
            guard let publication else { throw PreparationStoreError.invalidTransition }
            next = try publication.advancing(accountID: account, file: file, to: .writing)
        case .complete(let account, let file):
            guard let publication else { throw PreparationStoreError.invalidTransition }
            next = try publication.advancing(accountID: account, file: file, to: .published)
        }
        return try Self(self, publication: next)
    }
    static var publicationRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map { role in
            try RetainedReleaseFormat(role: role, name: formatName, readVersions: [1, 2], writeVersions: [2])
        }
    } }
    static var provenanceRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: formatName, readVersions: [1, 2, 3, 4], writeVersions: [3, 4])
        }
    } }
    private static func ordered(_ a: Operand, _ b: Operand) -> Bool {
        a.kind == b.kind ? a.account.lexicographicallyPrecedes(b.account) : a.kind < b.kind
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }; return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [19], writeVersions: [19]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: RuntimeReleaseConfigurationSource.formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: RuntimeReleaseConfigurationPlan.formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: RuntimeReleaseBinding.formatName, readVersions: [1, 2], writeVersions: [2])]
        }
    } }
}
