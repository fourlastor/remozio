import Foundation

/// The setup owner holds the release barrier and machine lease before acquiring the import journal.
enum SharedSetupImportGatewayScope {
    static func requireLegacyMutationAllowed(machine: PreparationIntentStore, account: AccountPreparationIntent) throws {
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        try machine.withSharedImportJournal { journal in
            if let retained = try journal?.current(scope: scope), retained.phase != .rootComplete {
                throw SharedSetupImportError.conflict
            }
        }
    }

    static func completedDefaults(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> GatewayRuntimeSettingsSelection? {
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        return try machine.withSharedImportJournal { journal in
            guard let retained = try journal?.current(scope: scope) else { return nil }
            guard retained.phase == .rootComplete else { throw SharedSetupImportError.conflict }
            guard retained.recipe.firebaseProject == nil, retained.recipe.pushClient == nil else { return nil }
            return try retained.recipe.settings.defaults.gateway
        }
    }
}
