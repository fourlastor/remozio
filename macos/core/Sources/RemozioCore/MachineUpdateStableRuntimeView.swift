import Foundation

/// Selects current runtime metadata. Native owners must verify identity, keys, files, recovery, and admission separately.
struct MachineUpdateStableRuntimeView: CustomStringConvertible, CustomDebugStringConvertible {
    struct Account {
        let scope: MachineUpdateStableRuntimeSource.Account
        let runtime: RuntimeReleaseCompatibilitySnapshot.Runtime?
        let gateway: RuntimeReleaseCompatibilitySnapshot.Gateway?
        let configuration: RuntimeReleaseConfigurationPlan?
        let ordinaryActivation: RuntimeActivationPlan?
        let backend: RuntimeReleaseBackendPlan?
        let pendingPublication: GatewayRuntimeSettingsPublicationPlan?
        let settingsStartup: AuthorityGatewaySettingsStartupPlan?
        var accountID: Data { scope.accountID }
        var host: InstalledAuthorityCommandConfiguration? { configuration?.host ?? ordinaryActivation?.host }
    }
    let compatibility: MachineUpdateStableRuntimeViewInputs
    let currentJournals: [Data: GatewayJournalPreparationState]
    let accounts: [Account]
    var description: String { "MachineUpdateStableRuntimeView(redacted)" }
    var debugDescription: String { description }

    private static func settings(_ gateway: RuntimeReleaseCompatibilitySnapshot.Gateway) throws -> GatewayRuntimeSettingsState {
        let phase: GatewayRuntimeSettingsPhase?
        if let raw = gateway.settingsPhase {
            guard let value = GatewayRuntimeSettingsPhase(rawValue: raw) else { throw GatewayPreparationError.changedScope }
            phase = value
        } else { phase = nil }
        let active = try gateway.activeSettings.map(GatewayRuntimeSettingsRevision.decode)
        let pending = try gateway.pendingSettings.map(GatewayRuntimeSettingsRevision.decode)
        guard (pending == nil) == (phase == nil) else { throw GatewayPreparationError.changedScope }
        return .init(active: active, pending: pending, phase: phase)
    }
    init(compatibility: MachineUpdateStableRuntimeViewInputs, candidate: SignedReleaseEvidence) throws {
        let currentJournals = compatibility.currentJournals
        let source = compatibility.source, actual = source.actual, inputs = compatibility.runtime.inputs
        let ids = Set(source.accounts.map(\.accountID))
        guard (24...MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion).contains(inputs.schemaVersion), inputs.inventory == actual.inventory.canonicalBytes,
              Set(inputs.runtimes.map { $0.reference.services.accountID }).count == inputs.runtimes.count,
              Set(inputs.gateways.map(\.accountID)).count == inputs.gateways.count,
              inputs.runtimes.allSatisfy({ ids.contains($0.reference.services.accountID) }),
              inputs.gateways.allSatisfy({ ids.contains($0.accountID) }) else { throw RuntimePreparationError.changedScope }
        let expectedJournals = Set(source.accounts.filter { account in
            account.origin == .currentRelease && inputs.gateways.contains(where: { $0.accountID == account.accountID })
        }.map(\.accountID))
        guard Set(currentJournals.keys) == expectedJournals else { throw RuntimePreparationError.changedScope }
        let epoch = try actual.installed.configuration(), archivedBackend = try actual.installed.backend()
        let intent = try actual.installed.completionIntent()
        var values: [Account] = []
        for account in source.accounts {
            let runtime = inputs.runtimes.first { $0.reference.services.accountID == account.accountID }
            let gateway = inputs.gateways.first { $0.accountID == account.accountID }
            let configuration: RuntimeReleaseConfigurationPlan?, ordinary: RuntimeActivationPlan?
            var selectedBackend: RuntimeReleaseBackendPlan?, pending: GatewayRuntimeSettingsPublicationPlan?
            var startup: AuthorityGatewaySettingsStartupPlan?
            switch account.origin {
            case .retained:
                configuration = try epoch.configuration(accountID: account.accountID)?.completion; ordinary = nil
                if let configuration {
                    guard let preparation = account.preparation, let initialization = account.initialization,
                          initialization.complete, let runtime, runtime.configurationPublished,
                          runtime.reference == configuration.gateway.runtime,
                          initialization.releaseDigest == preparation.releaseDigest,
                          configuration.policyStage == .completion,
                          configuration.binding.installedReleaseDigest == actual.inventory.releaseDigest,
                          configuration.binding.activationAttempt == actual.seal.finishing.attemptID,
                          configuration.binding.candidateDigest == actual.seal.finishing.candidateDigest,
                          configuration.binding.admissionDigest == actual.seal.finishing.admissionDigest,
                          let origin = intent.record.accounts.first(where: { $0.accountID == account.accountID }),
                          configuration.binding.sourceAccountDigest == origin.sourceDigest,
                          configuration.binding.sourceInventoryDigest == MachineUpdateActivationRecord.digest(source.historicalInventory.canonicalBytes),
                          configuration.binding.previousInstalledReleaseDigest == source.historicalInventory.releaseDigest else {
                        throw RuntimePreparationError.changedScope
                    }
                    try configuration.binding.requireHistoricalRuntime(runtime.reference)
                    if account.inInventory {
                        _ = try configuration.host.validate(inventory: actual.inventory, release: candidate, bundlePath: actual.inventory.bundlePath)
                        try configuration.gateway.validate(account: preparation, inventory: actual.inventory)
                    }
                    if let gateway {
                        guard let base = try archivedBackend.capture(accountID: account.accountID)?.completion,
                              try base.configuration.encoded == configuration.encoded else { throw GatewayPreparationError.incomplete }
                        let state = try Self.settings(gateway)
                        let floor = try base.projectingSettledInstalledSettings(.init(active: state.active, pending: nil, phase: nil), candidate: candidate)
                        selectedBackend = floor
                        if let revision = state.pending {
                            pending = try .init(installed: floor, revision: revision, previous: state.active, candidate: candidate)
                        }
                        startup = try .init(installed: base, authority: configuration.host, state: state, candidate: candidate)
                    }
                } else {
                    guard runtime?.jobsRegistered != true, runtime?.activationRecord == nil, gateway == nil else {
                        throw RuntimePreparationError.incomplete
                    }
                    if runtime?.configurationPublished == true {
                        _ = try source.unconfiguredRetainedAccount(accountID: account.accountID, ownerUID: account.ownerUID)
                    }
                }
            case .currentRelease:
                configuration = nil
                ordinary = try runtime?.activationRecord.map(RuntimeActivationPlan.decode)
                if let ordinary {
                    guard let preparation = account.preparation, let initial = account.initialization, initial.complete,
                          let runtime, runtime.configurationPublished, ordinary.reference == runtime.reference,
                          preparation.releaseDigest == actual.inventory.releaseDigest,
                          ordinary.host.releaseDigest == actual.inventory.releaseDigest else { throw RuntimePreparationError.changedScope }
                    try ordinary.validate(account: preparation, reference: runtime.reference)
                    if account.inInventory {
                        _ = try ordinary.host.validate(inventory: actual.inventory, release: candidate, bundlePath: actual.inventory.bundlePath)
                    }
                }
                if let gateway {
                    guard let ordinary, let journal = currentJournals[account.accountID] else { throw GatewayPreparationError.incomplete }
                    let activation = try GatewayRuntimeActivationPlan.decode(gateway.activationRecord)
                    let state = try Self.settings(gateway)
                    startup = try .init(authority: ordinary.host, state: state, activation: activation,
                        journal: journal, foreground: ordinary, inventory: actual.inventory)
                    if let revision = state.pending {
                        pending = try .init(revision: revision, previous: state.active, activation: activation,
                            journal: journal, foreground: ordinary, inventory: actual.inventory)
                    }
                }
            }
            values.append(.init(scope: account, runtime: runtime, gateway: gateway, configuration: configuration,
                ordinaryActivation: ordinary, backend: selectedBackend, pendingPublication: pending, settingsStartup: startup))
        }
        self.compatibility = compatibility; self.currentJournals = currentJournals; accounts = values
    }
    /// Selects metadata for a current member. This operation grants no native startup or command admission.
    func account(_ accountID: Data, ownerUID: UInt32) throws -> Account {
        guard let account = accounts.first(where: { $0.accountID == accountID && $0.scope.ownerUID == ownerUID && $0.scope.inInventory }) else {
            throw PreparationStoreError.notFound
        }
        return account
    }
    /// Historical completion flags alone cannot select unfinished or unregistered runtime metadata.
    func startupAccount(_ accountID: Data, ownerUID: UInt32) throws -> Account {
        let account = try self.account(accountID, ownerUID: ownerUID)
        guard account.scope.preparation?.storagePrepared == true, account.scope.initialization?.complete == true,
              account.runtime?.configurationPublished == true, account.runtime?.jobsRegistered == true, account.host != nil,
              account.gateway == nil || (account.gateway?.configurationPublished == true && account.gateway?.jobRegistered == true) else {
            throw RuntimePreparationError.incomplete
        }
        return account
    }
    func requireSame(as other: Self) throws {
        try compatibility.requireSame(as: other.compatibility)
        guard currentJournals == other.currentJournals, accounts.count == other.accounts.count else { throw PreparationStoreError.staleRevision }
        for (a, b) in zip(accounts, other.accounts) {
            guard a.scope == b.scope, a.runtime == b.runtime, a.gateway == b.gateway,
                  try a.configuration?.encoded == b.configuration?.encoded,
                  try a.ordinaryActivation?.encoded == b.ordinaryActivation?.encoded,
                  try a.backend?.encoded == b.backend?.encoded else { throw PreparationStoreError.staleRevision }
            switch (a.pendingPublication, b.pendingPublication) {
            case (nil, nil): break
            case (.some(let left), .some(let right)):
                guard try left.revision.encoded == right.revision.encoded, try left.activation.encoded == right.activation.encoded,
                      try left.commit.encoded == right.commit.encoded, left.artifacts.count == right.artifacts.count else {
                    throw PreparationStoreError.staleRevision
                }
                for (left, right) in zip(left.artifacts, right.artifacts) {
                    guard left.file.name == right.file.name, left.file.mode == right.file.mode, left.previous == right.previous, left.selected == right.selected else {
                        throw PreparationStoreError.staleRevision
                    }
                }
            default: throw PreparationStoreError.staleRevision
            }
        }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        let inputs = try machine.stableRuntimeViewInputs(expected: compatibility.source,
            retained: compatibility.retained, candidate: candidate)
        try Self(compatibility: inputs, candidate: candidate).requireSame(as: self)
    }
}
