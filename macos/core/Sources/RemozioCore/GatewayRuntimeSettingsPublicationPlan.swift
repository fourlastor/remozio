import Foundation

enum GatewayRuntimeSettingsFileResult: Equatable, Sendable { case created, retained, replaced }

/// Exact old and new bytes for an authorized settings transition. Construction performs no file operation.
struct GatewayRuntimeSettingsPublicationPlan {
    struct Artifact {
        let file: AdministrativeSetupPublication.File
        let previous: Data?
        let selected: Data
    }
    let revision: GatewayRuntimeSettingsRevision
    let activation: GatewayRuntimeActivationPlan
    let pair: GatewayRuntimeExtensions
    let commit: GatewayRuntimeCommit
    let artifacts: [Artifact]

    init(revision: GatewayRuntimeSettingsRevision, previous: GatewayRuntimeSettingsRevision?,
         activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
         foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        try revision.validateSuccessor(of: previous, activation: activation)
        let oldProposal: GatewayConfigurationBundle, oldPair: GatewayRuntimeExtensions, oldCommit: GatewayRuntimeCommit
        if let previous {
            oldProposal = try previous.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            oldPair = try .init(settings: previous, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            oldCommit = try .init(oldPair, settings: previous, gateway: oldProposal.gateway)
        } else {
            oldProposal = try activation.proposal(journal: journal, foreground: foreground, inventory: inventory)
            oldPair = activation.extensions; oldCommit = try .init(oldPair)
        }
        let proposal = try revision.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        pair = try .init(settings: revision, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        commit = try .init(pair, settings: revision, gateway: proposal.gateway)
        self.revision = revision; self.activation = activation
        artifacts = try [
            .init(file: .gatewayConfiguration, previous: oldProposal.gateway.canonicalBytes, selected: proposal.gateway.canonicalBytes),
            .init(file: .authorityGatewayRuntime, previous: oldPair.authority.encoded, selected: pair.authority.encoded),
            .init(file: .transportGatewayRuntime, previous: oldPair.transport.encoded, selected: pair.transport.encoded),
            .init(file: .gatewaySettingsRevision, previous: previous.map { try $0.encoded }, selected: revision.encoded),
            .init(file: .gatewayRuntimeCommit, previous: oldCommit.encoded, selected: commit.encoded)
        ]
    }
}
