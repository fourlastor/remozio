import Foundation

/// Immutable retained inputs after a short machine read. This value retains no store, lease or readiness grant.
struct AuthorityGatewayRecoverySnapshot: Sendable {
    enum Status: Sendable, Equatable { case initial, pending, completed }
    let plan: GatewayRuntimeSettingsRecoveryPlan
    let activation: GatewayRuntimeActivationPlan
    let account: AccountPreparationIntent
    let foreground: RuntimeActivationPlan
    let inventory: InstallationInventory

    static func status(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration) throws -> Status {
        guard let startup = try AuthorityGatewaySettingsStartupPlan.load(machine: machine, authority: authority) else { return .initial }
        if startup.pendingChange != nil { return .pending }
        return startup.requiresConsumerRecovery ? .completed : .initial
    }
    static func load(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration,
                     attemptID: Data) throws -> Self {
        let accountID = authority.command.accountID
        guard let inventory = try machine.inventory(),
              let account = try machine.accountPreparation(ownerUID: authority.command.callerUID), account.accountID == accountID,
              inventory.macID == authority.command.macID, inventory.installationID == authority.installationID,
              inventory.releaseDigest == authority.releaseDigest else { throw GatewayPreparationError.changedScope }
        let current = try machine.runtimeActivation(accountID: accountID)
        let gateway = try machine.gatewayRuntimeActivation(accountID: accountID)
        guard current.jobsRegistered, gateway.filesPublished, gateway.jobRegistered,
              let foreground = current.plan, let activation = gateway.plan,
              foreground.host.canonicalBytes == authority.canonicalBytes else { throw GatewayPreparationError.incomplete }
        let plan = try GatewayRuntimeSettingsRecoveryPlan(state: machine.gatewaySettingsTransition(accountID: accountID),
            activation: activation, journal: machine.gatewayJournalPreparation(accountID: accountID),
            foreground: foreground, inventory: inventory, attemptID: attemptID)
        let result = Self(plan: plan, activation: activation, account: account, foreground: foreground, inventory: inventory)
        try result.validate(machine: machine, authority: authority)
        return result
    }
    func validate(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration) throws {
        try withPublicationScope(machine: machine, authority: authority) { _ in }
    }
    /// The native caller owns this synchronous writer. No machine store crosses an asynchronous callback here.
    func withPublicationScope(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration,
                              perform: (GatewayRuntimeSettingsRecoveryPublication.Scope) throws -> Void) throws {
        guard foreground.host.canonicalBytes == authority.canonicalBytes else { throw GatewayPreparationError.changedScope }
        let scope = GatewayRuntimeSettingsRecoveryPublication.Scope(plan: plan, activation: activation, machine: machine,
            account: account, foreground: foreground, inventory: inventory)
        try scope.validate(); try perform(scope); try scope.validate()
    }
}
