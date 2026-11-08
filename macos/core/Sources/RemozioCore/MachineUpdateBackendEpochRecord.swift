import Foundation

/// Backend recovery operands only. Retention grants no native startup, health or floor authority.
struct MachineUpdateBackendEpochRecord: Codable, Equatable, Sendable {
    static let formatName = "authority.machine-update-backend-epoch"
    static let maximumBytes = 131072
    struct Account: Codable, Equatable, Sendable { let accountID: Data; let sourceDigest: Data? }
    struct Operand: Codable, Equatable, Sendable { let kind: Int64; let accountID: Data; let digest: Data }
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let configurationEpochID: UUID
    let configurationEpochDigest: Data
    let macID: Data
    let installationID: Data
    let updateID: Data
    let originalSourceDigest: Data
    let currentSourceDigest: Data
    let accounts: [Account]?
    let operands: [Operand]
    let publication: MachineUpdateBackendPublicationProgress?

    init(epoch: MachineUpdateConfigurationEpoch.Archive, currentSourceDigest: Data) throws {
        try epoch.validate()
        guard epoch.record.publication?.complete == true, currentSourceDigest.count == 32 else { throw PreparationStoreError.invalidTransition }
        formatVersion = 1; id = UUID(); revision = UUID(); configurationEpochID = epoch.record.id
        configurationEpochDigest = try MachineUpdateActivationRecord.digest(epoch.record.encoded)
        macID = epoch.record.macID; installationID = epoch.record.installationID; updateID = epoch.record.updateID
        originalSourceDigest = epoch.record.sourceMachineDigest; self.currentSourceDigest = currentSourceDigest
        accounts = nil; operands = []; publication = nil; try validate()
    }
    private init(previous: Self, accounts: [Account], operands: [Operand]) throws {
        formatVersion = 1; id = previous.id; revision = UUID(); configurationEpochID = previous.configurationEpochID
        configurationEpochDigest = previous.configurationEpochDigest; macID = previous.macID; installationID = previous.installationID
        updateID = previous.updateID; originalSourceDigest = previous.originalSourceDigest; currentSourceDigest = previous.currentSourceDigest
        self.accounts = accounts; self.operands = operands; publication = nil; try validate()
    }
    func retaining(_ captures: [MachineUpdateBackendEpoch.Capture], epoch: MachineUpdateConfigurationEpoch.Archive) throws -> Self {
        try requireScope(epoch)
        let artifacts = try MachineUpdateBackendEpoch.artifacts(captures, epoch: epoch)
        let accounts = try captures.map { try Account(accountID: $0.accountID, sourceDigest: $0.source?.digest) }
            .sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        let operands = artifacts.map { Operand(kind: $0.kind, accountID: $0.accountID, digest: MachineUpdateActivationRecord.digest($0.bytes)) }
        if self.accounts != nil {
            guard self.accounts == accounts, self.operands == operands else { throw PreparationStoreError.staleRevision }; return self
        }
        return try Self(previous: self, accounts: accounts, operands: operands)
    }
    func requireScope(_ epoch: MachineUpdateConfigurationEpoch.Archive) throws {
        try validate(); try epoch.validate()
        guard epoch.record.publication?.complete == true, configurationEpochID == epoch.record.id,
              try configurationEpochDigest == MachineUpdateActivationRecord.digest(epoch.record.encoded),
              macID == epoch.record.macID, installationID == epoch.record.installationID, updateID == epoch.record.updateID,
              originalSourceDigest == epoch.record.sourceMachineDigest else { throw PreparationStoreError.staleRevision }
        if let accounts {
            guard accounts.map(\.accountID) == epoch.record.accounts.filter(\.configurationPublished).map(\.accountID) else {
                throw PreparationStoreError.corruptRecord
            }
        }
    }
    private init(_ previous: Self, publication: MachineUpdateBackendPublicationProgress) throws {
        formatVersion = 2; id = previous.id; revision = UUID(); configurationEpochID = previous.configurationEpochID
        configurationEpochDigest = previous.configurationEpochDigest; macID = previous.macID; installationID = previous.installationID
        updateID = previous.updateID; originalSourceDigest = previous.originalSourceDigest; currentSourceDigest = previous.currentSourceDigest
        accounts = previous.accounts; operands = previous.operands; self.publication = publication; try validate()
    }
    func applying(_ operation: MachineUpdateBackendPublicationOperation) throws -> Self {
        try validate(); guard accounts != nil else { throw PreparationStoreError.invalidTransition }
        let next: MachineUpdateBackendPublicationProgress
        switch operation {
        case .begin:
            guard publication == nil else { throw PreparationStoreError.invalidTransition }
            next = .init(record: self)
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
        var values = try [AuthorityCodeRole.authority, .setupController].map {
            try RetainedReleaseFormat(role: $0, name: formatName, readVersions: [1, 2], writeVersions: [2])
        }
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            let writes = role == .authority || role == .setupController
            values += try [RetainedReleaseFormat(role: role, name: GatewayRuntimeCommit.formatName, readVersions: [3], writeVersions: writes ? [3] : []),
                RetainedReleaseFormat(role: role, name: GatewayRuntimeExtension.formatName, readVersions: [1], writeVersions: writes ? [1] : []),
                RetainedReleaseFormat(role: role, name: GatewayServiceConfiguration.formatName, readVersions: [2], writeVersions: writes ? [2] : []),
                RetainedReleaseFormat(role: role, name: RuntimeReleaseBinding.formatName, readVersions: [2], writeVersions: writes ? [2] : [])]
        }
        return values
    } }
    private func validate() throws {
        guard (formatVersion == 1 && publication == nil || formatVersion == 2 && publication != nil && accounts != nil),
              macID.count == 16, installationID.count == 16,
              [configurationEpochDigest, updateID, originalSourceDigest, currentSourceDigest].allSatisfy({ $0.count == 32 }),
              accounts == nil && operands.isEmpty || accounts != nil else { throw PreparationStoreError.corruptRecord }
        if let accounts {
            guard accounts.count <= 128, Set(accounts.map(\.accountID)).count == accounts.count,
                  accounts.map(\.accountID) == accounts.map(\.accountID).sorted(by: { $0.lexicographicallyPrecedes($1) }),
                  accounts.allSatisfy({ $0.accountID.count == 16 && ($0.sourceDigest == nil || $0.sourceDigest?.count == 32) }) else {
                throw PreparationStoreError.corruptRecord
            }
            let expected = accounts.filter { $0.sourceDigest != nil }.flatMap { a in (1...3).map { "\($0):\(a.accountID.base64EncodedString())" } }
            guard operands.count <= 384, operands.allSatisfy({ (1...3).contains($0.kind) && $0.digest.count == 32 }),
                  Set(operands.map { "\($0.kind):\($0.accountID.base64EncodedString())" }) == Set(expected), operands.count == expected.count,
                  operands == operands.sorted(by: { $0.kind == $1.kind ? $0.accountID.lexicographicallyPrecedes($1.accountID) : $0.kind < $1.kind }) else {
                throw PreparationStoreError.corruptRecord
            }
        }
        try publication?.validate(record: self)
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self); guard bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }; return bytes
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
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [19, 20], writeVersions: [20]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: RuntimeReleaseBackendSource.formatName, readVersions: [1], writeVersions: [1]),
                 RetainedReleaseFormat(role: role, name: RuntimeReleaseBackendPlan.formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}
