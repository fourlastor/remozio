import Foundation

/// Exact bytes for recovery of completed settings. This plan grants no native rights or consumer permits.
struct GatewayRuntimeSettingsRecoveryPlan: Sendable, CustomStringConvertible {
    let revision: GatewayRuntimeSettingsRevision
    let pair: GatewayRuntimeExtensions
    let gateway: GatewayServiceConfiguration
    let commit: GatewayRuntimeCommit
    let fence: GatewayRuntimeSettingsFence
    var description: String { "GatewayRuntimeSettingsRecoveryPlan(redacted)" }

    init(state: GatewayRuntimeSettingsState, activation: GatewayRuntimeActivationPlan,
         journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan,
         inventory: InstallationInventory, attemptID: Data) throws {
        guard let revision = state.active, state.pending == nil, state.phase == nil else {
            throw GatewayPreparationError.incomplete
        }
        let proposal = try revision.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        pair = try .init(settings: revision, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        gateway = proposal.gateway
        commit = try .init(pair, settings: revision, gateway: proposal.gateway)
        fence = try .init(recovering: revision, commit: commit, services: pair.authority.material.runtime.services, attemptID: attemptID)
        self.revision = revision
    }
    /// The protected owner must recheck this floor before and after every external operation.
    func validate(state: GatewayRuntimeSettingsState) throws {
        guard state.pending == nil, state.phase == nil, try state.active?.encoded == revision.encoded else {
            throw GatewayPreparationError.changedScope
        }
    }
}
