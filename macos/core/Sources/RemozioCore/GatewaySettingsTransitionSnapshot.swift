import Foundation

/// Immutable settings inputs after a short protected read. This value retains no machine lease or native grant.
struct GatewaySettingsTransitionSnapshot: Sendable {
    let account: AccountPreparationIntent
    let initialization: AuthorityInitializationIntent
    let foreground: RuntimeActivationPlan
    let inventory: InstallationInventory
    let plan: GatewayRuntimeSettingsPublicationPlan

    static func load(machine: PreparationIntentStore, ownerUID: UInt32,
                     expected: SetupGatewayActivationProgress,
                     revision: GatewayRuntimeSettingsRevision) throws -> Self {
        guard ownerUID > 0, ownerUID < UInt32.max, expected.setup.ownerUID == ownerUID else {
            throw AdministrativeSetupError.wrongAccount
        }
        guard let account = try machine.accountPreparation(ownerUID: ownerUID),
              account.accountID == revision.accountID,
              let inventory = try machine.inventory(),
              let initialization = try machine.initialization(accountID: account.accountID), initialization.complete else {
            throw GatewayPreparationError.incomplete
        }
        try machine.validateAccountPreparation(account)
        let runtime = try machine.runtimeActivation(accountID: account.accountID)
        let gateway = try machine.gatewayRuntimeActivation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        let setup = try SetupGatewayProgress(account: account,
            runtime: machine.runtimePreparation(accountID: account.accountID), activation: runtime,
            material: machine.gatewayPreparation(accountID: account.accountID), journal: journal)
        guard try SetupGatewayActivationProgress(setup: setup, state: gateway) == expected,
              runtime.jobsRegistered, gateway.filesPublished, gateway.jobRegistered,
              let foreground = runtime.plan, let activation = gateway.plan else {
            throw AdministrativeSetupError.staleProgress
        }
        let state = try machine.gatewaySettingsTransition(accountID: account.accountID)
        guard try state.pending?.encoded == revision.encoded, state.phase != nil else {
            throw GatewayPreparationError.changedScope
        }
        let plan = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: state.active,
            activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        let snapshot = Self(account: account, initialization: initialization,
            foreground: foreground, inventory: inventory, plan: plan)
        try snapshot.withPendingScope(machine: machine) { _, _ in }
        return snapshot
    }
    private func scope(machine: PreparationIntentStore) throws -> GatewayRuntimeSettingsFencePublication.Scope {
        guard try machine.initialization(accountID: account.accountID) == initialization else {
            throw GatewayPreparationError.changedScope
        }
        return .init(plan: plan, machine: machine, account: account, foreground: foreground, inventory: inventory)
    }
    /// The caller owns this synchronous lease. No store or publication scope is returned to asynchronous code.
    func withPendingScope(machine: PreparationIntentStore,
        perform: (GatewayRuntimeSettingsFencePublication.Scope, AuthorityInitializationIntent) throws -> Void) throws {
        let scope = try scope(machine: machine)
        try scope.validatePending(); try perform(scope, initialization); try scope.validatePending()
    }
    func withCompleteScope(machine: PreparationIntentStore,
        perform: (GatewayRuntimeSettingsFencePublication.Scope, AuthorityInitializationIntent) throws -> Void) throws {
        let scope = try scope(machine: machine)
        try scope.validateComplete(); try perform(scope, initialization); try scope.validateComplete()
    }
}
