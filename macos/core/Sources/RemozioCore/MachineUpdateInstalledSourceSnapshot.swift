import Foundation

/// A comparison with retained source facts. This value grants no ordinary startup, migration, write or admission authority.
struct MachineUpdateInstalledSourceSnapshot: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let actual: MachineUpdateFinalizationSnapshot
    let historicalInventory: InstallationInventory
    let historicalSchemaVersion: Int64
    let historicalSourceDigest: Data
    var description: String { "MachineUpdateInstalledSourceSnapshot(redacted)" }
    var debugDescription: String { description }

    /// Selects exact account provisioning facts. This operation grants no startup or storage authority.
    func provisioningInventory(accountID: Data, ownerUID: UInt32, releaseDigest: Data) throws -> InstallationInventory {
        let configuration = try actual.installed.configuration()
        guard let account = configuration.record.accounts.first(where: { $0.accountID == accountID && $0.ownerUID == ownerUID }),
              let preparation = actual.preparations.first(where: { $0.accountID == account.accountID && $0.ownerUID == account.ownerUID }),
              preparation.releaseDigest == releaseDigest else { throw RuntimePreparationError.changedScope }
        if let history = try configuration.provisioningHistory() {
            return try history.inventory(for: preparation, current: actual.inventory)
        }
        let historical = try MachineUpdateProvisioningHistory.capture(current: historicalInventory, preparations: [preparation])
        return try historical.inventory(for: preparation, current: actual.inventory)
    }

    func requireSame(as other: Self) throws {
        try actual.requireSame(as: other.actual)
        guard historicalInventory == other.historicalInventory, historicalSchemaVersion == other.historicalSchemaVersion,
              historicalSourceDigest == other.historicalSourceDigest else { throw PreparationStoreError.staleRevision }
    }
}
