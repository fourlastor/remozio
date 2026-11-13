import Foundation

/// A startup fence derived from retained state. Historical stages do not prove that a new process is quiesced.
/// The native owner must authenticate this scope before applying it to the running capability.
struct AuthorityGatewaySettingsStartupPlan: Sendable, CustomStringConvertible {
    let accountID: Data
    let options: AuthorityPhonePushStartupConfiguration
    let activeCommitDigest: Data
    let pendingChange: AuthorityPhonePushSettingsChange?
    let requiresConsumerRecovery: Bool
    var description: String { "AuthorityGatewaySettingsStartupPlan(redacted)" }
    var requiresFreshQuiescence: Bool { pendingChange != nil }

    init(authority: InstalledAuthorityCommandConfiguration, state: GatewayRuntimeSettingsState,
         activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
         foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        guard authority.canonicalBytes == foreground.host.canonicalBytes,
              authority.command.accountID == activation.accountID,
              (state.pending == nil) == (state.phase == nil) else { throw GatewayPreparationError.changedScope }
        _ = try activation.proposal(journal: journal, foreground: foreground, inventory: inventory)
        let current: GatewayRuntimeCommit
        if let active = state.active {
            let proposal = try active.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            let pair = try GatewayRuntimeExtensions(settings: active, activation: activation,
                journal: journal, foreground: foreground, inventory: inventory)
            current = try .init(pair, settings: active, gateway: proposal.gateway)
        } else { current = try .init(activation.extensions) }
        if let pending = state.pending {
            let publication = try GatewayRuntimeSettingsPublicationPlan(revision: pending, previous: state.active,
                activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            let change = try AuthorityPhonePushSettingsChange(publication)
            guard try change.previousCommitDigest == current.observationDigest else { throw GatewayPreparationError.changedScope }
            pendingChange = change
        } else { pendingChange = nil }
        requiresConsumerRecovery = state.active != nil && state.pending == nil
        accountID = activation.accountID; options = activation.extensions.authority.material.phonePush
        activeCommitDigest = try current.observationDigest
    }
    /// Restores retained settings from a validated finishing selection. It grants no consumer readiness or command admission.
    init(installed backend: RuntimeReleaseBackendPlan, authority: InstalledAuthorityCommandConfiguration) throws {
        guard backend.policyStage == .completion, backend.configuration.host.canonicalBytes == authority.canonicalBytes,
              backend.binding.installedReleaseDigest == authority.releaseDigest,
              backend.binding.accountID == authority.command.accountID else { throw GatewayPreparationError.changedScope }
        try backend.binding.requireCompletionPolicy(authority.codePolicy)
        let pair = try GatewayRuntimeExtensions(release: backend)
        let commit = try GatewayRuntimeCommit(release: backend, pair: pair)
        accountID = backend.binding.accountID; options = pair.authority.material.phonePush
        activeCommitDigest = try commit.observationDigest; pendingChange = nil
        requiresConsumerRecovery = backend.source.revision != nil
    }

    /// Restores a current settings floor without granting native quiescence or command admission.
    init(installed backend: RuntimeReleaseBackendPlan, authority: InstalledAuthorityCommandConfiguration,
        state: GatewayRuntimeSettingsState, candidate: SignedReleaseEvidence) throws {
        guard (state.pending == nil) == (state.phase == nil) else { throw GatewayPreparationError.changedScope }
        let current = try backend.projectingSettledInstalledSettings(.init(active: state.active, pending: nil, phase: nil),
            candidate: candidate)
        let base = try Self(installed: current, authority: authority)
        if let pending = state.pending {
            let publication = try GatewayRuntimeSettingsPublicationPlan(installed: current, revision: pending,
                previous: state.active, candidate: candidate)
            let change = try AuthorityPhonePushSettingsChange(installed: publication)
            guard change.previousCommitDigest == base.activeCommitDigest else { throw GatewayPreparationError.changedScope }
            pendingChange = change
        } else { pendingChange = nil }
        accountID = base.accountID; options = base.options; activeCommitDigest = base.activeCommitDigest
        // A pending change requires fresh quiescence instead of settled consumer recovery.
        requiresConsumerRecovery = state.active != nil && state.pending == nil
    }
    /// Read through the same protected machine owner before native check-in transfers and closes that owner.
    /// This helper does not acquire native rights or authorize a settings transition.
    static func load(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration) throws -> Self? {
        let accountID = authority.command.accountID
        guard let inventory = try machine.inventory(), inventory.macID == authority.command.macID,
              inventory.installationID == authority.installationID, inventory.releaseDigest == authority.releaseDigest,
              inventory.accounts.contains(where: { $0.accountID == accountID && $0.ownerUID == authority.command.callerUID }) else {
            throw GatewayPreparationError.changedScope
        }
        let settings = try machine.gatewaySettingsTransition(accountID: accountID)
        let runtime = try machine.gatewayRuntimeActivation(accountID: accountID)
        guard let activation = runtime.plan else {
            guard settings.active == nil, settings.pending == nil, settings.phase == nil else { throw GatewayPreparationError.changedScope }
            return nil
        }
        guard runtime.filesPublished, runtime.jobRegistered,
              let foreground = try machine.runtimeActivation(accountID: accountID).plan else { throw GatewayPreparationError.incomplete }
        return try .init(authority: authority, state: settings, activation: activation,
            journal: machine.gatewayJournalPreparation(accountID: accountID), foreground: foreground, inventory: inventory)
    }
    /// Initial installation only. A later authorized acceptance must update the live capability's floor explicitly.
    func allowsInitialInstallation(commitDigest: Data) -> Bool {
        pendingChange == nil && !requiresConsumerRecovery && commitDigest == activeCommitDigest
    }
}
