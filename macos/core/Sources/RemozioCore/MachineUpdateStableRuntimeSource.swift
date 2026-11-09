import Foundation

/// Current stable metadata and original provisioning facts. This source grants no native startup, write, or admission authority.
struct MachineUpdateStableRuntimeSource: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum ProvisioningOrigin: Equatable, Sendable { case retained, currentRelease }
    struct Account: Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let inInventory: Bool
        let origin: ProvisioningOrigin
        let preparation: AccountPreparationIntent?
        let initialization: AuthorityInitializationIntent?
    }
    let actual: MachineUpdateStableReleaseSnapshot
    let historicalInventory: InstallationInventory
    let provisioningHistory: MachineUpdateProvisioningHistory
    let preparations: [AccountPreparationIntent]
    let initializations: [AuthorityInitializationIntent]
    let accounts: [Account]
    var description: String { "MachineUpdateStableRuntimeSource(redacted)" }
    var debugDescription: String { description }

    init(actual: MachineUpdateStableReleaseSnapshot, preparations: [AccountPreparationIntent],
        initializations: [AuthorityInitializationIntent], candidate: SignedReleaseEvidence) throws {
        try actual.seal.requireCurrentInventory(actual.inventory, epoch: actual.installed, candidate: candidate)
        let configuration = try actual.installed.configuration(), intent = try actual.installed.completionIntent()
        let historical = try InstallationInventory.decode(configuration.artifact(5), expectedMacID: actual.inventory.macID)
        guard actual.activation == actual.seal.completed,
              historical.installationID == actual.inventory.installationID,
              preparations.count <= 64, initializations.count <= 64,
              Set(preparations.map(\.accountID)).count == preparations.count,
              Set(preparations.map(\.ownerUID)).count == preparations.count,
              Set(initializations.map(\.accountID)).count == initializations.count,
              initializations.allSatisfy({ initial in preparations.contains(where: { $0.accountID == initial.accountID }) }) else {
            throw RuntimePreparationError.changedScope
        }
        let archivedProvenance = try configuration.provisioningHistory()
        if archivedProvenance != nil { try MachineUpdateInstalledReleaseRecord.requireProvenanceFormats(candidate) }
        let retainedIDs = Set(intent.record.accounts.map(\.accountID))
        let retainedPreparations = preparations.filter { retainedIDs.contains($0.accountID) }
        let provenance = try archivedProvenance ?? MachineUpdateProvisioningHistory.capture(current: historical,
            preparations: retainedPreparations)
        try provenance.requireScope(actual.inventory)
        guard Set(provenance.accounts.map(\.accountID)) == Set(retainedPreparations.map(\.accountID)) else {
            throw RuntimePreparationError.changedScope
        }
        let ids = Set(actual.inventory.accounts.map(\.accountID) + preparations.map(\.accountID))
        guard ids.count <= 128 else { throw RuntimePreparationError.changedScope }
        var values: [Account] = []
        for id in ids.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            let enrolled = actual.inventory.accounts.first { $0.accountID == id }
            let preparation = preparations.first { $0.accountID == id }
            let initial = initializations.first { $0.accountID == id }
            let retained = intent.record.accounts.first { $0.accountID == id }
            guard let owner = enrolled?.ownerUID ?? preparation?.ownerUID,
                  preparation == nil || preparation?.ownerUID == owner,
                  retained == nil || retained?.ownerUID == owner else { throw RuntimePreparationError.changedScope }
            let origin: ProvisioningOrigin = retained == nil ? .currentRelease : .retained
            if let preparation {
                guard preparation.macID == actual.inventory.macID, preparation.installationID == actual.inventory.installationID,
                      origin == .retained || preparation.releaseDigest == actual.inventory.releaseDigest else {
                    throw RuntimePreparationError.changedScope
                }
                if origin == .retained { _ = try provenance.inventory(for: preparation, current: actual.inventory) }
            }
            if let initial {
                guard let preparation, initial.macID == actual.inventory.macID,
                      initial.installationID == actual.inventory.installationID, initial.accountID == preparation.accountID,
                      initial.releaseDigest == preparation.releaseDigest,
                      initial.initializationBytes == preparation.initializationBytes else { throw RuntimePreparationError.changedScope }
            }
            values.append(.init(accountID: id, ownerUID: owner, inInventory: enrolled != nil,
                origin: origin, preparation: preparation, initialization: initial))
        }
        guard Set(values.map(\.ownerUID)).count == values.count else { throw RuntimePreparationError.changedScope }
        self.actual = actual; historicalInventory = historical; provisioningHistory = provenance
        self.preparations = preparations.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        self.initializations = initializations.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        accounts = values
    }
    /// Selects a current member only. Preparation and initialization completion remain separate startup prerequisites.
    func account(_ accountID: Data, ownerUID: UInt32) throws -> Account {
        guard let value = accounts.first(where: { $0.accountID == accountID && $0.ownerUID == ownerUID && $0.inInventory }) else {
            throw PreparationStoreError.notFound
        }
        return value
    }
    /// Returns retained provenance or the actual current inventory. This operation grants no enrollment or startup authority.
    func provisioningInventory(accountID: Data, ownerUID: UInt32, releaseDigest: Data) throws -> InstallationInventory {
        guard let value = accounts.first(where: { $0.accountID == accountID && $0.ownerUID == ownerUID }),
              let preparation = value.preparation, preparation.releaseDigest == releaseDigest else {
            throw RuntimePreparationError.changedScope
        }
        switch value.origin {
        case .retained:
            return try provisioningHistory.inventory(for: preparation, current: actual.inventory)
        case .currentRelease:
            guard releaseDigest == actual.inventory.releaseDigest else { throw RuntimePreparationError.changedScope }
            return actual.inventory
        }
    }
    /// Selects an account that had no published runtime during the update. Removed members cannot regain enrollment through setup.
    func unconfiguredRetainedAccount(accountID: Data, ownerUID: UInt32) throws -> MachineUpdateCompletionIntentRecord.Account {
        let epoch = try actual.installed.configuration(), intent = try actual.installed.completionIntent()
        guard let account = accounts.first(where: { $0.accountID == accountID && $0.ownerUID == ownerUID }),
              account.origin == .retained,
              let original = intent.record.accounts.first(where: { $0.accountID == accountID && $0.ownerUID == ownerUID }),
              original.policyRecordID == nil, original.policyRecordDigest == nil,
              !original.inInventory || account.inInventory,
              let configured = epoch.record.accounts.first(where: { $0.accountID == accountID }),
              configured.ownerUID == ownerUID, configured.sourceDigest == original.sourceDigest,
              !configured.configurationPublished else { throw RuntimePreparationError.changedScope }
        return original
    }
    func requireSame(as other: Self) throws {
        try actual.requireSame(as: other.actual)
        guard historicalInventory == other.historicalInventory, provisioningHistory == other.provisioningHistory,
              preparations == other.preparations,
              initializations == other.initializations, accounts == other.accounts else { throw PreparationStoreError.staleRevision }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableRuntimeSource(candidate: candidate).requireSame(as: self)
    }
}
