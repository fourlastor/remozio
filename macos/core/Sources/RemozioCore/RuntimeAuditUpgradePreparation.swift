import Foundation

/// Candidate values only. Construction does not prove current file scope, dependency completeness or quiescence.
struct RuntimeAuditUpgradePreparation: CustomStringConvertible, CustomDebugStringConvertible {
    let intent: RuntimeAuditUpgradeIntent
    let source: RuntimeActivationPlan
    let target: RuntimeActivationPlan
    var description: String { "RuntimeAuditUpgradePreparation(redacted)" }
    var debugDescription: String { description }
    init(source: RuntimeActivationPlan, intent: RuntimeAuditUpgradeIntent, installedRelease: SignedReleaseEvidence,
         currentPolicy: AuthorityCodePolicy) throws {
        target = try source.preparingAuditUpgrade(intent, installedRelease: installedRelease, currentPolicy: currentPolicy)
        self.source = source; self.intent = intent
    }
    /// Rebind the baseline gateway proposal. Active and pending settings revisions still require coordinated preparation.
    func gateway(material: GatewayPreparationMaterial, expected: GatewayMaterialReference,
                 journal: GatewayJournalPreparationState, activation: GatewayRuntimeActivationPlan,
                 inventory: InstallationInventory) throws -> Gateway {
        guard journal.initialized, let retained = journal.intent, retained.material == expected,
              let wake = activation.extensions.transport.wake else { throw GatewayPreparationError.incomplete }
        let oldProposal = try activation.proposal(journal: journal, foreground: source, inventory: inventory)
        let nextMaterial = try material.preparingAuditUpgrade(self, expected: expected)
        let nextIntent = try GatewayJournalSetupIntent(id: retained.id, material: nextMaterial.reference,
            configuration: retained.configuration, files: retained.files)
        let nextJournal = GatewayJournalPreparationState(intent: nextIntent, initialized: journal.initialized)
        let nextActivation = try GatewayRuntimeActivationPlan(journal: nextJournal, foreground: target, inventory: inventory,
            wakePollMilliseconds: wake.pollMilliseconds, wakeTimeoutMilliseconds: wake.wake.timeoutMilliseconds)
        let nextProposal = try nextActivation.proposal(journal: nextJournal, foreground: target, inventory: inventory)
        guard oldProposal.gateway.canonicalBytes == nextProposal.gateway.canonicalBytes,
              oldProposal.transport.wake?.canonicalBytes == nextProposal.transport.wake?.canonicalBytes else {
            throw GatewayPreparationError.changedScope
        }
        return try .init(material: nextMaterial, journal: nextJournal, activation: nextActivation,
            sourceActivationDigest: activation.digest, upgradeID: intent.id)
    }
    struct Gateway: CustomStringConvertible, CustomDebugStringConvertible {
        let material: GatewayPreparationMaterial
        let journal: GatewayJournalPreparationState
        let activation: GatewayRuntimeActivationPlan
        let sourceActivationDigest: Data
        let upgradeID: Data
        fileprivate init(material: GatewayPreparationMaterial, journal: GatewayJournalPreparationState,
                         activation: GatewayRuntimeActivationPlan, sourceActivationDigest: Data, upgradeID: Data) {
            self.material = material; self.journal = journal; self.activation = activation
            self.sourceActivationDigest = sourceActivationDigest; self.upgradeID = upgradeID
        }
        var description: String { "RuntimeAuditUpgradePreparation.Gateway(redacted)" }
        var debugDescription: String { description }
    }
}
