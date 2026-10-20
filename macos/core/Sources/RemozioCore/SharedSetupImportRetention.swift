import Foundation

/// The authenticated setup owner holds the machine lease and imports fresh administrator rights before this call.
/// This admission step retains a public recipe. It neither provisions credentials nor activates a service.
enum SharedSetupImportRetention {
    static func retain(machine: PreparationIntentStore, account: AccountPreparationIntent,
                       expectedRuntime: SetupRuntimeProgress, expectedImport: SharedSetupImportIntent?,
                       proposal: PortableSetup, journal: SharedSetupImportJournal,
                       verifyCurrent: () throws -> Void) throws -> SharedSetupImportIntent {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        let services = try machine.serviceAccountPlan(accountID: account.accountID)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        guard try SetupRuntimeProgress(account: account, services: services, state: runtime) == expectedRuntime else {
            throw AdministrativeSetupError.staleProgress
        }
        var retained = try journal.current(scope: scope)
        guard retained == expectedImport else { throw SharedSetupImportError.staleRevision }
        let startingNewImport = retained == nil
        if let retained {
            guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
            if retained.phase != .retained {
                guard runtime.configurationPublished, runtime.reference != nil else { throw RuntimePreparationError.incomplete }
            }
        } else {
            try requireUnconfiguredDestination(machine: machine, account: account, runtime: runtime)
        }
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account)
            guard try machine.inventory() == inventory,
                  try machine.serviceAccountPlan(accountID: account.accountID) == services,
                  try machine.runtimePreparation(accountID: account.accountID) == runtime,
                  try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
            if startingNewImport { try requireUnconfiguredDestination(machine: machine, account: account, runtime: runtime) }
        }
        try verify()
        if retained == nil {
            let intent = try SharedSetupImportIntent(scope: scope, proposal: proposal)
            try journal.begin(intent)
            retained = intent
        }
        try verify()
        guard let retained else { throw SharedSetupImportError.invalidRecord }
        return retained
    }
    static func requireUnconfiguredDestination(machine: PreparationIntentStore, account: AccountPreparationIntent,
                                                       runtime: RuntimePreparationState) throws {
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        let gateway = try machine.gatewayPreparation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        let gatewayActivation = try machine.gatewayRuntimeActivation(accountID: account.accountID)
        let settings = try machine.gatewaySettingsTransition(accountID: account.accountID)
        guard runtime.reference == nil, !runtime.configurationPublished, activation.plan == nil, !activation.jobsRegistered,
              gateway.reference == nil, journal.intent == nil, gatewayActivation.plan == nil,
              !gatewayActivation.filesPublished, !gatewayActivation.jobRegistered,
              settings.active == nil, settings.pending == nil, settings.phase == nil else {
            throw SharedSetupImportError.conflict
        }
    }
}
