import Foundation

/// Installed values and original provisioning facts. This view grants no native startup, writer or admission authority.
struct MachineUpdateInstalledRuntimeView: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Account: Sendable {
        let scope: MachineUpdateCompletionIntentRecord.Account
        let preparation: AccountPreparationIntent?
        let provisioning: RuntimeReleaseCompatibilitySnapshot.Runtime?
        let gateway: RuntimeReleaseCompatibilitySnapshot.Gateway?
        let initialization: AuthorityInitializationIntent?
        let configuration: RuntimeReleaseConfigurationPlan?
        let backend: RuntimeReleaseBackendPlan?
        var accountID: Data { scope.accountID }
    }
    let compatibility: MachineUpdateInstalledCompatibilitySnapshot
    let sourceInventory: InstallationInventory
    let installedInventory: InstallationInventory
    let accounts: [Account]
    var description: String { "MachineUpdateInstalledRuntimeView(redacted)" }
    var debugDescription: String { description }

    init(compatibility: MachineUpdateInstalledCompatibilitySnapshot, candidate: SignedReleaseEvidence) throws {
        let source = compatibility.source, actual = source.actual, inputs = compatibility.runtime.inputs
        let historical = source.historicalInventory, installed = actual.inventory
        guard actual.schemaVersion == 23, actual.activation.phase == .finishing,
              inputs.schemaVersion == 23, inputs.macID == installed.macID, inputs.inventory == installed.canonicalBytes,
              historical.macID == installed.macID, historical.installationID == installed.installationID,
              historical.bundlePath == installed.bundlePath, historical.accounts == installed.accounts,
              historical.services == installed.services, historical.formatVersion == installed.formatVersion,
              try InstallationInventory.digest(candidate) == installed.releaseDigest else {
            throw RuntimePreparationError.changedScope
        }
        let archive = actual.installed
        try archive.validate(candidate: candidate)
        guard try archive.inventory() == installed else { throw PreparationStoreError.staleRevision }
        let intent = try archive.completionIntent(), epoch = try archive.configuration(), backend = try archive.backend()
        let records = intent.record.accounts, ids = Set(records.map(\.accountID))
        guard records.count <= 128, ids.count == records.count,
              Set(records.map(\.ownerUID)).count == records.count,
              Set(epoch.record.accounts.map(\.accountID)) == ids,
              Set(installed.accounts.map(\.accountID)).isSubset(of: ids),
              Set(inputs.runtimes.map { $0.reference.services.accountID }).count == inputs.runtimes.count,
              Set(inputs.gateways.map(\.accountID)).count == inputs.gateways.count,
              Set(actual.initializations.map(\.accountID)).count == actual.initializations.count,
              actual.initializations.allSatisfy({ ids.contains($0.accountID) }),
              Set(actual.preparations.map(\.accountID)).count == actual.preparations.count,
              actual.preparations.allSatisfy({ ids.contains($0.accountID) }),
              inputs.runtimes.allSatisfy({ ids.contains($0.reference.services.accountID) }),
              inputs.gateways.allSatisfy({ ids.contains($0.accountID) }) else { throw RuntimePreparationError.changedScope }
        var values: [Account] = []
        for record in records.sorted(by: { $0.accountID.lexicographicallyPrecedes($1.accountID) }) {
            let enrolled = installed.accounts.first { $0.accountID == record.accountID }
            guard record.inInventory == (enrolled != nil), enrolled == nil || enrolled?.ownerUID == record.ownerUID,
                  let captured = epoch.record.accounts.first(where: { $0.accountID == record.accountID }),
                  captured.sourceDigest == record.sourceDigest else { throw RuntimePreparationError.changedScope }
            let runtime = inputs.runtimes.first { $0.reference.services.accountID == record.accountID }
            let gateway = inputs.gateways.first { $0.accountID == record.accountID }
            let configuration = try epoch.configuration(accountID: record.accountID)?.completion
            let completed: RuntimeReleaseBackendPlan?
            if configuration != nil { completed = try backend.capture(accountID: record.accountID)?.completion }
            else { completed = nil }
            let initial = actual.initializations.first { $0.accountID == record.accountID }
            let preparation = actual.preparations.first { $0.accountID == record.accountID }
            guard captured.configurationPublished == (runtime?.configurationPublished ?? false),
                  captured.configurationPublished == (configuration != nil) else { throw RuntimePreparationError.changedScope }
            if let runtime {
                let services = runtime.reference.services
                guard let preparation, services.macID == installed.macID, services.installationID == installed.installationID,
                      services.ownerUID == record.ownerUID, services.releaseDigest == preparation.releaseDigest else {
                    throw RuntimePreparationError.changedScope
                }
                try services.validate(account: preparation)
            }
            if let configuration {
                let binding = configuration.binding
                guard let runtime, let preparation, let initial, initial.complete,
                      initial.macID == installed.macID, initial.installationID == installed.installationID,
                      initial.releaseDigest == preparation.releaseDigest,
                      initial.initializationBytes == preparation.initializationBytes,
                      configuration.policyStage == .completion, binding.activationAttempt == actual.activation.attemptID,
                      binding.candidateDigest == actual.activation.candidateDigest,
                      binding.admissionDigest == actual.activation.admissionDigest,
                      binding.sourceAccountDigest == record.sourceDigest,
                      binding.sourceInventoryDigest == MachineUpdateActivationRecord.digest(historical.canonicalBytes),
                      binding.previousInstalledReleaseDigest == historical.releaseDigest,
                      binding.installedReleaseDigest == installed.releaseDigest else { throw RuntimePreparationError.changedScope }
                try binding.requireHistoricalRuntime(runtime.reference)
                if let completed {
                    guard try completed.configuration.encoded == configuration.encoded,
                          completed.source.foreground.reference == runtime.reference,
                          completed.source.inventory == historical else { throw RuntimePreparationError.changedScope }
                }
            } else if completed != nil { throw RuntimePreparationError.changedScope }
            if let preparation {
                guard preparation.macID == installed.macID, preparation.installationID == installed.installationID,
                      preparation.ownerUID == record.ownerUID else { throw RuntimePreparationError.changedScope }
                _ = try source.provisioningInventory(accountID: record.accountID, ownerUID: record.ownerUID,
                    releaseDigest: preparation.releaseDigest)
            }
            values.append(.init(scope: record, preparation: preparation, provisioning: runtime, gateway: gateway,
                initialization: initial, configuration: configuration, backend: completed))
        }
        self.compatibility = compatibility; sourceInventory = historical
        installedInventory = installed; accounts = values
    }
    func account(_ accountID: Data) throws -> Account {
        guard let value = accounts.first(where: { $0.accountID == accountID }) else { throw PreparationStoreError.notFound }
        return value
    }
    func requireSame(as other: Self) throws {
        try compatibility.requireSame(as: other.compatibility)
        guard sourceInventory == other.sourceInventory, installedInventory == other.installedInventory,
              accounts.count == other.accounts.count else { throw PreparationStoreError.staleRevision }
        for (left, right) in zip(accounts, other.accounts) {
            guard left.scope == right.scope, left.preparation == right.preparation,
                  left.provisioning == right.provisioning, left.gateway == right.gateway,
                  left.initialization == right.initialization,
                  try left.configuration?.encoded == right.configuration?.encoded,
                  try left.backend?.encoded == right.backend?.encoded else { throw PreparationStoreError.staleRevision }
        }
    }
    func requireCurrent(scope: PreparationIntentStore.CompletionFinalizationScope, candidate: SignedReleaseEvidence) throws {
        try Self(compatibility: scope.readCompatibility(), candidate: candidate).requireSame(as: self)
    }
}
