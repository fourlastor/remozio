import Foundation

/// The owner holds the machine lease before each import read. No journal lease spans a native registration command.
enum SharedSetupImportActivationScope {
    static func current(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SharedSetupImportIntent? {
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        return try machine.withSharedImportJournal { journal in
            let retained = try journal?.current(scope: scope)
            guard retained?.phase != .retained else { throw RuntimeActivationError.incomplete }
            return retained
        }
    }
    static func verify(machine: PreparationIntentStore, account: AccountPreparationIntent,
                       initialization: AuthorityInitializationIntent, plan: RuntimeActivationPlan,
                       inventory: InstallationInventory, expected: SharedSetupImportIntent?) throws {
        guard try machine.inventory() == inventory, try current(machine: machine, account: account) == expected else {
            throw SharedSetupImportError.staleRevision
        }
        let relayPlan = try expected.flatMap { try machine.sharedImportRelayPlan(expected: $0) }
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization,
            reference: plan.reference, inventory: inventory, importIntent: expected, relayPlan: relayPlan)
        guard bundle.command.canonicalBytes == plan.host.command.canonicalBytes,
              bundle.transport.canonicalBytes == plan.transport.canonicalBytes else { throw RuntimeActivationError.changedScope }
    }
}
